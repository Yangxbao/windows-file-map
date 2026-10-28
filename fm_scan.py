# -*- coding: utf-8 -*-
"""
文件地图助手 v2 · 全量只读扫描引擎 (fm_scan.py)
=============================================
目标：尽可能完整地递归盘点本机所有本地固定磁盘的文件与文件夹（元数据级），
数据写入本工具目录下的 SQLite 数据库 fmdata.db，供本地服务分页展示与报告生成。

v2 相比 v1 移除的限制（逐项对应）：
  * 无全局条目上限、无单目录条目上限、无递归深度上限、无时间预算硬上限；
  * Windows / Program Files / ProgramData / Users / AppData 等一律递归枚举，
    只有「明确排除清单」（回收站、卷影副本）和真正无法访问的目录例外，且逐条记录原因；
  * node_modules / .git / target / build / dist 等大型目录同样保留完整树与清单；
  * 错误分类：权限不足 / 对象丢失 / 被占用 / 路径超长 / 其他 IO，分别计数并可重试被占用类错误；
  * 支持断点续扫（--resume）、增量扫描（--incremental）、对历史"拒绝访问"目录的
    管理员权限定向重试（--admin-retry）、仅重算大小与报告（--recompute）；
  * 分批写入 + 定期提交，中断不丢失已有成果；进度写入 scan_progress.json。

安全承诺：
  * 全程只读：不重命名/移动/删除/覆盖任何被扫描文件；不在被扫描目录写任何文件；
  * 不读取普通文件正文，仅读取 package.json / pom.xml / README 等小型标识文件开头片段；
  * 疑似敏感文件（.env、密钥、凭证）只记录路径与类型，绝不读取内容；
  * 符号链接/目录联接记录目标但不跟随，防止循环与重复扫描；
  * 不执行被扫描项目中的任何代码；不修改注册表/权限/系统配置。

用法：
  python fm_scan.py                 # 全量扫描（重建数据库）
  python fm_scan.py --resume        # 续扫上次中断的扫描
  python fm_scan.py --incremental   # 增量扫描（基于目录修改时间跳过未变化部分）
  python fm_scan.py --admin-retry   # 对历史"拒绝访问"目录做定向重试（建议管理员终端运行）
  python fm_scan.py --recompute     # 仅重算目录大小统计并重新生成报告
"""

import os
import sys
import json
import time
import ctypes
import shutil
import sqlite3
import argparse
import traceback
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fm_kb as kb

TOOL_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(TOOL_DIR, "fmdata.db")
PROGRESS_PATH = os.path.join(TOOL_DIR, "scan_progress.json")
SUMMARY_PATH = os.path.join(TOOL_DIR, "scan_summary.json")

BATCH_SIZE = 4000            # 每批写入行数（分批保存，中断不丢）
EVENT_ROW_CAP = 20000        # events 表最多保存的明细条数（计数始终完整）
RETRY_TIMES = 2              # "被占用"类错误的重试次数
RETRY_DELAY = 0.1

SCHEMA = """
CREATE TABLE IF NOT EXISTS entries(
  path TEXT PRIMARY KEY,
  parent TEXT NOT NULL DEFAULT '',
  name TEXT NOT NULL,
  is_dir INTEGER NOT NULL,
  depth INTEGER NOT NULL DEFAULT 0,
  size INTEGER,
  mtime INTEGER,
  ctime INTEGER,
  attrs INTEGER,
  flags INTEGER NOT NULL DEFAULT 0,
  scanned INTEGER NOT NULL DEFAULT 0,
  err TEXT,
  link_target TEXT,
  n_children INTEGER,
  cat TEXT,
  zh TEXT,
  conf TEXT
);
CREATE TABLE IF NOT EXISTS events(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts REAL, kind TEXT, path TEXT, detail TEXT
);
CREATE TABLE IF NOT EXISTS projects(
  path TEXT PRIMARY KEY,
  name TEXT, ptype TEXT, conf TEXT, git INTEGER,
  basis TEXT, brief TEXT, entry TEXT, configs TEXT, srcs TEXT,
  docs TEXT, deps TEXT, builds TEXT, size INTEGER, mtime INTEGER
);
CREATE TABLE IF NOT EXISTS meta(k TEXT PRIMARY KEY, v TEXT);
"""


def lp(p):
    """转为支持超长路径的内部读取路径（仅用于系统调用，不改变真实文件）"""
    p = os.path.abspath(p)
    if p.startswith("\\\\?\\"):
        return p
    if p.startswith("\\\\"):
        return "\\\\?\\UNC\\" + p.lstrip("\\")
    return "\\\\?\\" + p


def classify_oserr(e):
    win = getattr(e, "winerror", None)
    if isinstance(e, PermissionError) or win == 5:
        return "denied"
    if win in (2, 3):
        return "missing"
    if win in (32, 33):
        return "locked"
    if win == 206:
        return "longpath"
    return "ioerror"


def list_dir(disp):
    """枚举目录，返回 (entries|None, (kind,msg)|None)。被占用类错误自动重试。"""
    p = lp(disp)
    for attempt in range(RETRY_TIMES + 1):
        try:
            with os.scandir(p) as it:
                return list(it), None
        except FileNotFoundError as e:
            return None, ("missing", str(e))
        except NotADirectoryError as e:
            return None, ("missing", str(e))
        except PermissionError as e:
            return None, ("denied", str(e))
        except OSError as e:
            k = classify_oserr(e)
            if k == "locked" and attempt < RETRY_TIMES:
                time.sleep(RETRY_DELAY)
                continue
            return None, (k, str(e))
    return None, ("ioerror", "")


def stat_entry(e):
    """读取条目元数据，返回 (st|None, kind|None)"""
    for attempt in range(RETRY_TIMES + 1):
        try:
            return e.stat(follow_symlinks=False), None
        except FileNotFoundError as ex:
            return None, "missing"
        except PermissionError as ex:
            return None, "denied"
        except OSError as ex:
            k = classify_oserr(ex)
            if k == "locked" and attempt < RETRY_TIMES:
                time.sleep(RETRY_DELAY)
                continue
            return None, k
    return None, "ioerror"


def path_stat(disp):
    try:
        return os.stat(lp(disp), follow_symlinks=False), None
    except OSError as e:
        return None, classify_oserr(e)


def read_head(path, cap):
    """读取小型标识文件开头片段（仅限非敏感的说明/配置文件）"""
    try:
        with open(lp(path), "rb") as f:
            return f.read(cap).decode("utf-8", "replace")
    except Exception:
        return ""


def clean_text(s):
    """Windows 上极少数文件名含有无法按 UTF-8 编码的代理字符（\ud800-\udfff 孤立项），
    SQLite 无法存储。此处把无法编码的字符替换为 �，其余保持原样。仅影响存储展示，
    不触碰真实文件。"""
    try:
        s.encode("utf-8")
        return s
    except UnicodeEncodeError:
        return s.encode("utf-8", "replace").decode("utf-8")


def get_drives():
    bitmask = ctypes.windll.kernel32.GetLogicalDrives()
    out = []
    for i, letter in enumerate("ABCDEFGHIJKLMNOPQRSTUVWXYZ"):
        if bitmask & (1 << i):
            root = letter + ":\\"
            t = ctypes.windll.kernel32.GetDriveTypeW(ctypes.c_wchar_p(root))
            tn = {2: "可移动磁盘", 3: "本地磁盘", 4: "网络驱动器", 5: "光盘", 6: "RAM 磁盘"}.get(t, "未知类型")
            total = free = None
            try:
                u = shutil.disk_usage(root)
                total, free = u.total, u.free
            except OSError:
                pass
            out.append({"letter": letter, "root": root, "type": tn, "total": total, "free": free})
    return out


class Store:
    """SQLite 批量写入器：分批提交，中断不丢数据"""

    def __init__(self, fresh=False):
        if fresh:
            for suffix in ("", "-wal", "-shm"):
                fp = DB_PATH + suffix
                if os.path.exists(fp):
                    os.remove(fp)
        self.conn = sqlite3.connect(DB_PATH, check_same_thread=False)
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA synchronous=NORMAL")
        self.conn.execute("PRAGMA cache_size=-65536")
        self.conn.execute("PRAGMA temp_store=MEMORY")
        self.conn.executescript(SCHEMA)
        self.conn.commit()
        self.buf = []
        self.inserted = 0
        self.dirs_done = 0
        self.files_done = 0
        self.errors = {}
        self.event_counts = {}
        self.event_rows = 0
        self.current = ""
        self.phase = ""
        self.started = time.time()
        self.last_progress = 0.0

    # ---------- 写入 ----------
    def insert(self, row):
        self.buf.append(row)
        self.inserted += 1
        if len(self.buf) >= BATCH_SIZE:
            self.flush()

    def flush(self):
        if self.buf:
            self.conn.executemany(
                "INSERT OR REPLACE INTO entries(path,parent,name,is_dir,depth,size,mtime,ctime,"
                "attrs,flags,scanned,err,link_target,n_children,cat,zh,conf) "
                "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", self.buf)
            self.buf.clear()
        self.conn.commit()

    def add_event(self, kind, path, detail):
        self.errors[kind] = self.errors.get(kind, 0) + 1
        self.event_counts[kind] = self.event_counts.get(kind, 0) + 1
        if self.event_rows < EVENT_ROW_CAP:
            try:
                self.conn.execute("INSERT INTO events(ts,kind,path,detail) VALUES(?,?,?,?)",
                                  (time.time(), kind, clean_text(str(path)),
                                   clean_text(str(detail))[:500]))
                self.event_rows += 1
            except sqlite3.Error:
                pass

    def note_progress(self, force=False):
        now = time.time()
        if not force and now - self.last_progress < 3.0:
            return
        self.last_progress = now
        info = {
            "phase": self.phase, "current": self.current,
            "dirs_done": self.dirs_done, "files_done": self.files_done,
            "inserted": self.inserted, "errors": self.errors,
            "elapsed_s": round(now - self.started, 1),
            "updated_at": datetime.now().strftime("%H:%M:%S"),
        }
        try:
            with open(PROGRESS_PATH, "w", encoding="utf-8") as f:
                json.dump(info, f, ensure_ascii=False)
        except OSError:
            pass
        print("[%s] 目录 %d | 文件 %d | 错误 %s | 当前 %s"
              % (info["updated_at"], self.dirs_done, self.files_done,
                 json.dumps(self.errors, ensure_ascii=False), self.current[:90]),
              flush=True)

    def ensure_indexes(self):
        c = self.conn
        c.execute("CREATE INDEX IF NOT EXISTS idx_parent ON entries(parent, is_dir DESC, name COLLATE NOCASE)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_depth ON entries(depth)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_scanned ON entries(scanned)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_events_kind ON events(kind)")
        c.commit()

    def set_meta(self, k, v):
        self.conn.execute("INSERT OR REPLACE INTO meta(k,v) VALUES(?,?)", (k, json.dumps(v, ensure_ascii=False)))

    def close(self):
        self.flush()
        self.conn.close()


# ---------- 名称/分类 ----------

def zh_dir(name, low, in_proj):
    z = kb.zh_for_dir(name, low, in_proj)
    if z:
        return z
    return ("用途待确认（已检查：名称知识库、子条目类型、项目标识文件，均无充分证据）",
            "unknown", "低")


def file_cat_zh(name):
    low = name.lower()
    ext = kb.ext_of(name)
    if kb.is_sensitive_name(name):
        return "sensitive", "疑似敏感文件（可能含密钥/凭证，仅记录路径，未读取内容）", True
    if low in kb.ZH_FILES:
        cat = kb.EXT_TABLE.get(ext, ("other", ""))[0]
        return cat, kb.ZH_FILES[low], False
    if ext in kb.EXT_TABLE:
        return kb.EXT_TABLE[ext][0], None, False
    return "other", None, False


# ---------- 项目识别 ----------

def detect_project(store, disp, name, children, depth, in_heavy, in_proj, mtime):
    """children: list of (name, is_dir, entry_or_None)。返回是否注册为项目。"""
    if depth > 6 or in_heavy:
        return False
    childmap = {}
    for nm, is_d, _e in children:
        childmap[nm.lower()] = is_d
    markers = [m for m in kb.PROJECT_MARKERS if childmap.get(m) is False]
    slns = [nm for nm, is_d, _e in children if not is_d and nm.lower().endswith(".sln")]
    git = childmap.get(".git") is True

    if not markers and not git and not slns:
        code_files = [nm for nm, is_d, _e in children
                      if not is_d and kb.ext_of(nm) in kb.CODE_EXTS]
        code_dirs = [k for k, v in childmap.items()
                     if v and k in ("src", "lib", "app", "java", "python")]
        if (len(code_files) >= 3 or (code_dirs and code_files)) and not in_proj:
            basis = ["目录内发现 %d 个代码文件，但未发现标准项目标识文件（pom.xml/package.json 等）" % len(code_files),
                     "已检查：目录名称、子条目类型、常见标识文件是否存在"]
            store.conn.execute(
                "INSERT OR REPLACE INTO projects(path,name,ptype,conf,git,basis,brief,entry,configs,"
                "srcs,docs,deps,builds,size,mtime) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (disp, name, "unknown", "低", 0, json.dumps(basis, ensure_ascii=False), "",
                 json.dumps(["未发现入口/构建文件（需人工确认）"], ensure_ascii=False),
                 "[]", "[]", "[]", "[]", "[]", None, mtime))
            store.conn.commit()
        return False

    ptype, tzh, brief = None, None, ""
    basis = []
    if "pom.xml" in markers:
        text = read_head(os.path.join(disp, "pom.xml"), 128 * 1024)
        import re
        m = re.search(r"<description>([^<]{1,200})</description>", text)
        if m:
            brief = m.group(1).strip()
        else:
            m = re.search(r"<name>([^<]{1,120})</name>", text)
            if m:
                brief = m.group(1).strip()
        if "spring-boot" in text:
            ptype, tzh = "springboot", kb.TYPE_ZH["springboot"]
        else:
            ptype, tzh = "maven", kb.TYPE_ZH["maven"]
        basis.append("根目录存在 pom.xml（%s）" % kb.PROJECT_MARKERS["pom.xml"])
    elif any(g in markers for g in ("build.gradle", "build.gradle.kts", "settings.gradle")):
        gname = next(g for g in ("build.gradle", "build.gradle.kts", "settings.gradle") if g in markers)
        gtext = read_head(os.path.join(disp, gname), 128 * 1024)
        if "spring" in gtext.lower():
            ptype, tzh = "springboot", kb.TYPE_ZH["springboot"]
        else:
            ptype, tzh = "gradle", kb.TYPE_ZH["gradle"]
        basis.append("根目录存在 %s（%s）" % (gname, kb.PROJECT_MARKERS.get(gname, "Gradle 构建配置")))
    elif "package.json" in markers:
        try:
            pkg = json.loads(read_head(os.path.join(disp, "package.json"), 128 * 1024))
            brief = (pkg.get("description") or "").strip()[:200]
            deps = set((pkg.get("dependencies") or {})) | set((pkg.get("devDependencies") or {}))
        except Exception:
            deps = set()
        if "vue" in deps or "@vue/cli-service" in deps:
            ptype, tzh = "vue", kb.TYPE_ZH["vue"]
        elif "react" in deps or "react-dom" in deps:
            ptype, tzh = "react", kb.TYPE_ZH["react"]
        elif "electron" in deps:
            ptype, tzh = "electron", kb.TYPE_ZH["electron"]
        elif {"express", "koa", "@nestjs/core", "fastify"} & deps:
            ptype, tzh = "nodejs", "Node.js 后端项目"
        else:
            ptype, tzh = "nodejs", kb.TYPE_ZH["nodejs"]
        basis.append("根目录存在 package.json（%s）" % kb.PROJECT_MARKERS["package.json"])
    elif "manage.py" in markers:
        ptype, tzh = "django", kb.TYPE_ZH["django"]
        basis.append("根目录存在 manage.py（Django 管理脚本）")
    elif any(m in markers for m in ("requirements.txt", "pyproject.toml", "setup.py", "pipfile")):
        ptype, tzh = "python", kb.TYPE_ZH["python"]
        basis.append("根目录存在 Python 项目配置文件")
    elif "cargo.toml" in markers:
        ptype, tzh = "rust", kb.TYPE_ZH["rust"]
        basis.append("根目录存在 Cargo.toml（Rust 项目配置）")
    elif "go.mod" in markers:
        ptype, tzh = "go", kb.TYPE_ZH["go"]
        basis.append("根目录存在 go.mod（Go 模块定义）")
    elif "composer.json" in markers:
        ptype, tzh = "php", kb.TYPE_ZH["php"]
        basis.append("根目录存在 composer.json（PHP 依赖配置）")
    elif slns:
        ptype, tzh = "dotnet", kb.TYPE_ZH["dotnet"]
        basis.append("根目录存在 %s（Visual Studio 解决方案）" % slns[0])

    if git:
        basis.append("存在 .git 目录（Git 版本库，可查看提交历史确认来源）")
    if childmap.get("src") is True:
        basis.append("存在 src 源代码目录")
    if not ptype:
        if git:
            ptype, tzh = "gitrepo", kb.TYPE_ZH["gitrepo"]
        elif childmap.get("index.html") is False:
            ptype, tzh = "static", kb.TYPE_ZH["static"]

    for rn in ("readme.md", "readme.txt", "readme"):
        if childmap.get(rn) is False and not kb.is_sensitive_name(rn):
            text = read_head(os.path.join(disp, rn), 4096)
            snippet = " ".join(text.split())[:200]
            if snippet:
                brief = brief or snippet[:120]
                basis.append("%s 开头提及：%s" % (rn, snippet[:60]))
            break

    if len(markers) >= 2 or (markers and childmap.get("src") is True) or (git and markers):
        conf = "高"
    elif markers or slns:
        conf = "中"
    else:
        conf = "低"
    if in_proj:
        basis.append("位于另一个项目目录内部（可能是子模块）")
        if conf == "高":
            conf = "中"

    dirset = {k for k, v in childmap.items() if v}
    lowset = set(childmap)
    entry = []
    if ptype in ("nodejs", "vue", "react", "electron"):
        entry.append("package.json（npm start / npm run dev 启动）")
    if ptype in ("maven", "springboot"):
        entry.append("pom.xml；主代码通常在 src\\main\\java")
    if ptype == "gradle":
        entry.append("build.gradle；主代码通常在 src\\main\\java")
    if ptype == "django":
        entry.append("manage.py（python manage.py runserver）")
    if ptype == "python":
        for cand in ("main.py", "app.py", "run.py", "start.py"):
            if cand in lowset:
                entry.append(cand)
                break
        else:
            entry.append("未发现 main.py/app.py 等常见入口（需人工确认）")
    if ptype == "go":
        for cand in ("main.go", "cmd"):
            if cand in lowset:
                entry.append(cand)
                break
    if ptype == "rust":
        entry.append("src\\main.rs（Rust 默认入口）")
    if ptype == "dotnet" and slns:
        entry.append(slns[0])
    if ptype == "static" and "index.html" in lowset:
        entry.append("index.html")
    if ptype in ("gitrepo", "unknown"):
        entry.append("未发现入口/构建文件（需人工确认）")

    cfg_names = ("pom.xml", "package.json", "build.gradle", "build.gradle.kts", "settings.gradle",
                 "requirements.txt", "pyproject.toml", "setup.py", "go.mod", "cargo.toml",
                 "composer.json", "dockerfile", "docker-compose.yml", "docker-compose.yaml",
                 "makefile", "application.yml", "application.yaml", "application.properties",
                 "tsconfig.json", "vue.config.js", ".gitignore")
    configs = [nm for nm, is_d, _e in children if not is_d and nm.lower() in cfg_names]
    if ".env" in lowset:
        configs.append(".env（疑似敏感，未读取）")
    srcs = [k for k in ("src", "app", "lib", "packages", "cmd", "internal", "webapp") if k in dirset]
    docs = [k for k in ("docs", "doc", "documentation", "wiki") if k in dirset]
    deps = [k for k in ("node_modules", "venv", ".venv", "vendor", "packages") if k in dirset]
    builds = [k for k in ("target", "build", "dist", "out", ".next", ".nuxt", "coverage") if k in dirset]

    store.conn.execute(
        "INSERT OR REPLACE INTO projects(path,name,ptype,conf,git,basis,brief,entry,configs,"
        "srcs,docs,deps,builds,size,mtime) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (disp, name, ptype or "unknown", conf, 1 if git else 0,
         json.dumps(basis, ensure_ascii=False), brief,
         json.dumps(entry, ensure_ascii=False), json.dumps(configs, ensure_ascii=False),
         json.dumps(srcs, ensure_ascii=False), json.dumps(docs, ensure_ascii=False),
         json.dumps(deps, ensure_ascii=False), json.dumps(builds, ensure_ascii=False),
         None, mtime))
    store.conn.commit()
    return True


# ---------- 递归扫描 ----------

ALWAYS_HEAVY = {k for k in kb.HEAVY_DIRS if k not in kb.CONTEXT_HEAVY}


def delete_subtree(conn, path, include_self=False):
    """用递归 CTE 删除某目录的整棵子树（不用 LIKE，避免路径含 %/_ 时误删）。"""
    sql = ("WITH RECURSIVE sub(p) AS ("
           " SELECT ? UNION ALL SELECT e.path FROM entries e JOIN sub s ON e.parent = s.p) "
           "DELETE FROM entries WHERE path IN (SELECT p FROM sub)")
    if not include_self:
        sql += " AND path != ?"
        conn.execute(sql, (path, path))
    else:
        conn.execute(sql, (path,))


def scan_dir(store, disp, depth, in_heavy, in_proj):
    """递归枚举一个目录（只读）。子目录行在其自身完成后写入，本目录行最后写入。"""
    name = disp.rstrip("\\").rsplit("\\", 1)[-1] or disp
    low = name.lower()
    # parent 必须与父目录的存储 path 完全一致（盘符根带尾部反斜杠，其余不带）
    if disp.endswith("\\"):
        parent = ""
    else:
        parent = disp.rsplit("\\", 1)[0]
        if parent.endswith(":"):
            parent = parent + "\\"
    store.current = disp
    store.note_progress()

    entries, err = list_dir(disp)
    if entries is None:
        kind, msg = err
        st, serr = path_stat(disp)
        flags = kb.F_DENIED if kind == "denied" else 0
        zh, cat, conf = zh_dir(name, low, in_proj)
        store.insert((disp, parent, name, 1, depth, None,
                      int(st.st_mtime) if st else None, int(st.st_ctime) if st else None,
                      getattr(st, "st_file_attributes", None) if st else None,
                      flags, kb.S_FAIL, "%s: %s" % (kind, msg[:300]), None, 0, cat, zh, conf))
        store.add_event(kind, disp, "op=list_dir; %s" % msg[:300])
        store.dirs_done += 1
        return

    # 分类排序：目录在前，名称不区分大小写；名称先做可编码清洗（极少数非法字符）
    dirs_list, files_list = [], []
    for e in entries:
        nm = clean_text(e.name)
        try:
            st = e.stat(follow_symlinks=False)
        except OSError:
            st = None
        fa = getattr(st, "st_file_attributes", 0) if st else 0
        if st and (fa & 0x10):
            dirs_list.append((nm, e, st))
        else:
            files_list.append((nm, e, st))
    dirs_list.sort(key=lambda x: x[0].lower())
    files_list.sort(key=lambda x: x[0].lower())
    n_children = len(dirs_list) + len(files_list)

    # 项目识别（进入子目录前完成，供子目录继承 in_proj）
    child_tuples = [(nm, True, e) for nm, e, _st in dirs_list] + \
                   [(nm, False, e) for nm, e, _st in files_list]
    self_is_project = detect_project(store, disp, name, child_tuples, depth, in_heavy, in_proj,
                                     None) if depth >= 1 else False

    # 自身行延后到完成时写入；先处理子条目
    subdirs = []
    child_in_proj = in_proj or self_is_project
    for nm, e, st in dirs_list:
        low2 = nm.lower()
        cdisp = disp + ("" if disp.endswith("\\") else "\\") + nm
        cdepth = depth + 1
        if st and (getattr(st, "st_file_attributes", 0) & 0x400):  # reparse point
            tgt, terr = None, None
            try:
                tgt = os.readlink(lp(cdisp))
                tgt = clean_text(tgt.replace("/", "\\"))
                if tgt.startswith("\\\\?\\"):
                    tgt = tgt[4:]
                elif tgt.startswith("\\??\\"):
                    tgt = tgt[4:]
            except OSError as ex:
                terr = classify_oserr(ex)
            zh, cat, conf = zh_dir(nm, low2, child_in_proj)
            store.insert((cdisp, disp, nm, 1, cdepth, None,
                          int(st.st_mtime), int(st.st_ctime), st.st_file_attributes,
                          kb.F_LINK, kb.S_DONE,
                          ("link_target_read_failed:%s" % terr) if terr else "reparse point（未跟随，防循环）",
                          tgt, 0, cat, zh, conf))
            if terr:
                store.add_event(terr, cdisp, "op=readlink")
            continue
        if low2 in kb.EXCLUDE_DIRS:
            zh, cat, conf = zh_dir(nm, low2, child_in_proj)
            reason = kb.EXCLUDE_DIRS[low2]
            store.insert((cdisp, disp, nm, 1, cdepth, None,
                          int(st.st_mtime), int(st.st_ctime), st.st_file_attributes,
                          kb.F_SKIP, kb.S_EXCL, reason, None, None, cat, zh, conf))
            store.add_event("excluded", cdisp, reason)
            continue
        if os.path.normcase(os.path.abspath(cdisp)) == os.path.normcase(TOOL_DIR):
            store.insert((cdisp, disp, nm, 1, cdepth, None,
                          int(st.st_mtime), int(st.st_ctime), st.st_file_attributes,
                          kb.F_SKIP, kb.S_EXCL, "本工具自身目录（数据库/报告所在），不扫描",
                          None, None, "other", "文件地图助手（本工具所在目录）", "高"))
            store.add_event("excluded", cdisp, "本工具目录")
            continue
        c_heavy = in_heavy or low2 in ALWAYS_HEAVY or \
            (child_in_proj and low2 in kb.CONTEXT_HEAVY) or \
            bool(kb.GO_PKG_RE.search(cdisp.lower()))
        subdirs.append((nm, e, st, cdisp, cdepth, c_heavy, child_in_proj))

    file_cats = []
    for nm, e, st in files_list:
        low2 = nm.lower()
        cdisp = disp + ("" if disp.endswith("\\") else "\\") + nm
        st2, serr = (st, None) if st else stat_entry(e)
        if st2 is None:
            cat, zh, sens = "other", None, kb.is_sensitive_name(nm)
            if sens:
                zh = "疑似敏感文件（可能含密钥/凭证，仅记录路径，未读取内容）"
                cat = "sensitive"
            store.insert((cdisp, disp, nm, 0, depth + 1, None, None, None, None,
                          kb.F_SENS if sens else 0, kb.S_FAIL, "stat: %s" % serr, None, None,
                          cat, zh, "低"))
            store.add_event(serr or "ioerror", cdisp, "op=stat")
            continue
        fa = st2.st_file_attributes
        cat, zh, sens = file_cat_zh(nm)
        file_cats.append(cat)
        flags = 0
        if sens:
            flags |= kb.F_SENS
        if fa & 0x400:
            flags |= kb.F_LINK
        store.insert((cdisp, disp, nm, 0, depth + 1, st2.st_size,
                      int(st2.st_mtime), int(st2.st_ctime), fa,
                      flags, kb.S_DONE, None, None, None, cat, zh, "高" if zh else None))
        store.files_done += 1

    # 递归进入子目录
    for nm, e, st, cdisp, cdepth, c_heavy, c_proj in subdirs:
        scan_dir(store, cdisp, cdepth, c_heavy, c_proj)
        store.note_progress()

    # 写入自身行（枚举完成）
    zh, cat, conf = zh_dir(name, low, in_proj)
    if cat == "unknown" and len(file_cats) >= 3:
        # 按子文件类型构成做温和推断（证据不足时不强行归类）
        counts = {}
        for c in file_cats:
            counts[c] = counts.get(c, 0) + 1
        top_cat, cnt = max(counts.items(), key=lambda kv: kv[1])
        if cnt / len(file_cats) >= 0.6:
            mapping = {
                "media": ("图片/图像目录（按内容推断）", "media", "中"),
                "video": ("视频目录（按内容推断）", "video", "中"),
                "audio": ("音频目录（按内容推断）", "audio", "中"),
                "archive": ("压缩包目录（按内容推断）", "archive", "中"),
                "exe": ("安装包/程序目录（按内容推断）", "exe", "中"),
                "docs": ("文档资料目录（按内容推断）", "docs", "中"),
                "data": ("数据文件目录（按内容推断）", "data", "中"),
                "code": ("代码文件目录（按内容推断，未发现标准项目标识文件）", "code", "低"),
            }
            if top_cat in mapping:
                zh, cat, conf = mapping[top_cat]
    if self_is_project:
        cat = "project"
        if zh and ("用途待确认" in zh or "按内容推断" in zh or "按名称推断" in zh):
            zh = "独立开发项目（详见项目地图）"
    flags = kb.F_PROJ if self_is_project else 0
    if cat == "sensitive":
        flags |= kb.F_SENS
    st_self, serr_self = path_stat(disp)
    store.insert((disp, parent, name, 1, depth, None,
                  int(st_self.st_mtime) if st_self else None,
                  int(st_self.st_ctime) if st_self else None,
                  getattr(st_self, "st_file_attributes", None) if st_self else None,
                  flags, kb.S_DONE, None, None, n_children, cat, zh, conf))
    store.dirs_done += 1


def scan_drive(store, drv, is_system):
    root = drv["root"]
    letter = drv["letter"]
    node_path = letter + ":\\"
    store.conn.execute(
        "INSERT OR REPLACE INTO entries(path,parent,name,is_dir,depth,size,mtime,ctime,attrs,"
        "flags,scanned,err,link_target,n_children,cat,zh,conf) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (node_path, "", letter + ":", 1, 0, None, None, None, None, 0, kb.S_NONE, None, None, None,
         "sys", "系统磁盘（Windows 所在盘）" if is_system else "本地数据磁盘", "高"))
    store.conn.commit()
    print("== 磁盘 %s: 开始（%s，总 %s / 可用 %s）==" % (
        letter, drv["type"],
        "%.0fGB" % (drv["total"] / 2**30) if drv["total"] else "?",
        "%.0fGB" % (drv["free"] / 2**30) if drv["free"] else "?"), flush=True)
    scan_dir(store, node_path, 0, False, False)
    # 完成驱动器行
    store.flush()
    st, _ = path_stat(node_path)
    nroot = store.conn.execute("SELECT COUNT(*) FROM entries WHERE parent=?",
                               (node_path,)).fetchone()[0]
    store.conn.execute(
        "UPDATE entries SET scanned=?, mtime=COALESCE(?,mtime), n_children=? WHERE path=?",
        (kb.S_DONE, int(st.st_mtime) if st else None, nroot, node_path))
    store.conn.commit()
    store.dirs_done += 1
    print("== 磁盘 %s: 枚举完成，累计写入 %d 行 ==" % (letter, store.inserted), flush=True)


# ---------- 大小聚合 ----------

def aggregate(store):
    """自底向上聚合目录大小；子树内存在无法访问/失败部分时标记 F_EST（大小为下限）。"""
    print("… 聚合目录大小统计（自底向上）…", flush=True)
    conn = store.conn
    store.ensure_indexes()
    # 先按路径规范化 depth（自愈历史数据中的深度错误，保证逐层聚合的前提成立）
    conn.execute("UPDATE entries SET depth = "
                 "(length(path) - length(replace(path, '\\', ''))) - "
                 "(CASE WHEN path LIKE '%\\' THEN 1 ELSE 0 END)")
    conn.commit()
    row = conn.execute("SELECT MAX(depth) FROM entries").fetchone()
    maxd = row[0] or 0
    acc = {}
    bad = set()
    t0 = time.time()
    for d in range(maxd, -1, -1):
        cur = conn.execute("SELECT path, parent, is_dir, size, flags, scanned FROM entries WHERE depth=?", (d,))
        ups = []
        for path, parent, is_dir, size, flags, scanned in cur:
            sub = acc.pop(path, 0)
            incomplete = path in bad
            bad.discard(path)
            if is_dir:
                if scanned in (kb.S_FAIL, kb.S_EXCL, kb.S_NONE, kb.S_PART) or \
                        (flags & (kb.F_DENIED | kb.F_SKIP | kb.F_LINK)):
                    incomplete = True
                total = sub
                ups.append((total, 1 if incomplete else 0, path))
                acc[parent] = acc.get(parent, 0) + total
                if incomplete:
                    bad.add(parent)
            else:
                if size is None:
                    incomplete = True
                else:
                    acc[parent] = acc.get(parent, 0) + size
                if incomplete:
                    bad.add(parent)
        if ups:
            conn.executemany(
                "UPDATE entries SET size=?, "
                "flags=(CASE WHEN ?=1 THEN flags|? ELSE flags END) WHERE path=?",
                [(t, inc, kb.F_EST, p) for t, inc, p in ups])
        conn.commit()
    conn.execute("UPDATE projects SET size=(SELECT size FROM entries e WHERE e.path=projects.path),"
                 " mtime=(SELECT mtime FROM entries e WHERE e.path=projects.path)")
    conn.commit()
    print("… 大小聚合完成，用时 %.1f 秒 …" % (time.time() - t0), flush=True)


# ---------- 统计 ----------

def compute_stats(store, drives_meta, mode, extra=None):
    conn = store.conn
    q = lambda s, *a: conn.execute(s, a).fetchone()[0]
    stats = {
        "mode": mode,
        "rows": q("SELECT COUNT(*) FROM entries"),
        "dirs": q("SELECT COUNT(*) FROM entries WHERE is_dir=1"),
        "files": q("SELECT COUNT(*) FROM entries WHERE is_dir=0"),
        "dirs_done": q("SELECT COUNT(*) FROM entries WHERE is_dir=1 AND scanned=?", kb.S_DONE),
        "dirs_part": q("SELECT COUNT(*) FROM entries WHERE is_dir=1 AND scanned=?", kb.S_PART),
        "dirs_fail": q("SELECT COUNT(*) FROM entries WHERE is_dir=1 AND scanned=?", kb.S_FAIL),
        "dirs_excl": q("SELECT COUNT(*) FROM entries WHERE is_dir=1 AND scanned=?", kb.S_EXCL),
        "dirs_gone": q("SELECT COUNT(*) FROM entries WHERE is_dir=1 AND scanned=?", kb.S_GONE),
        "files_meta_ok": q("SELECT COUNT(*) FROM entries WHERE is_dir=0 AND scanned=?", kb.S_DONE),
        "files_meta_fail": q("SELECT COUNT(*) FROM entries WHERE is_dir=0 AND scanned=?", kb.S_FAIL),
        "flags_denied": q("SELECT COUNT(*) FROM entries WHERE flags & ?", kb.F_DENIED),
        "flags_link": q("SELECT COUNT(*) FROM entries WHERE flags & ?", kb.F_LINK),
        "flags_sens": q("SELECT COUNT(*) FROM entries WHERE flags & ?", kb.F_SENS),
        "flags_est": q("SELECT COUNT(*) FROM entries WHERE flags & ? AND is_dir=1", kb.F_EST),
        "flags_skip": q("SELECT COUNT(*) FROM entries WHERE flags & ?", kb.F_SKIP),
        "projects": q("SELECT COUNT(*) FROM projects WHERE ptype != 'unknown'"),
        "pending": q("SELECT COUNT(*) FROM projects WHERE ptype = 'unknown'"),
        "bytes": q("SELECT COALESCE(SUM(size),0) FROM entries WHERE depth=0"),
        # 事件统计读数据库（跨运行累计），而非本次进程内存
        "events_by_kind": dict(conn.execute(
            "SELECT kind, COUNT(*) FROM events GROUP BY kind").fetchall()),
    }
    per_drive = []
    for d in drives_meta:
        root = d["letter"] + ":\\"
        per_drive.append({
            "letter": d["letter"], "type": d["type"], "total": d["total"], "free": d["free"],
            "scanned": d.get("scanned", True),
            "bytes": q("SELECT size FROM entries WHERE path=?", root),
            "rows": q("SELECT COUNT(*) FROM entries WHERE path LIKE ?", root + "%"),
            "dirs": q("SELECT COUNT(*) FROM entries WHERE is_dir=1 AND path LIKE ?", root + "%"),
            "files": q("SELECT COUNT(*) FROM entries WHERE is_dir=0 AND path LIKE ?", root + "%"),
        })
    stats["per_drive"] = per_drive
    if extra:
        stats.update(extra)
    store.set_meta("stats", stats)
    store.set_meta("drives", drives_meta)
    store.set_meta("scanned_at", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    store.set_meta("duration_s", round(time.time() - store.started, 1))
    store.set_meta("version", kb.VERSION)
    store.set_meta("user", os.environ.get("USERNAME", ""))
    store.conn.commit()
    try:
        with open(SUMMARY_PATH, "w", encoding="utf-8") as f:
            json.dump({"stats": stats, "drives": drives_meta,
                       "scanned_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")},
                      f, ensure_ascii=False, indent=1)
    except OSError:
        pass
    return stats


def print_stats(stats):
    print("-" * 60)
    print("条目总数 %d（目录 %d / 文件 %d）" % (stats["rows"], stats["dirs"], stats["files"]))
    print("目录枚举：完成 %d | 中断 %d | 失败 %d | 规则排除 %d | 已消失 %d"
          % (stats["dirs_done"], stats["dirs_part"], stats["dirs_fail"],
             stats["dirs_excl"], stats["dirs_gone"]))
    print("文件元数据：读取成功 %d | 读取失败 %d" % (stats["files_meta_ok"], stats["files_meta_fail"]))
    print("错误分类：%s" % json.dumps(stats["events_by_kind"], ensure_ascii=False))
    print("链接 %d | 疑似敏感 %d | 大小不完整目录 %d | 项目 %d | 待识别 %d"
          % (stats["flags_link"], stats["flags_sens"], stats["flags_est"],
             stats["projects"], stats["pending"]))
    for d in stats["per_drive"]:
        print("  %s: 盘点 %s（目录 %d / 文件 %d）"
              % (d["letter"], "%.1f GB" % (d["bytes"] / 2**30) if d["bytes"] else "未统计",
                 d["dirs"], d["files"]))


# ---------- 各运行模式 ----------

def mode_full(store):
    drives = get_drives()
    fixed = [d for d in drives if d["type"] == "本地磁盘"]
    others = [d for d in drives if d["type"] != "本地磁盘"]
    sysdrive = (os.environ.get("SystemDrive", "C:") or "C:").rstrip(":").lower()
    for d in others:
        d["scanned"] = False
    print("发现磁盘：%s" % ", ".join(x["letter"] + ":" for x in drives))
    print("全量递归扫描（无条目/深度上限；排除清单：%s）"
          % "、".join(kb.EXCLUDE_DIRS.keys()))
    for d in fixed:
        scan_drive(store, d, d["letter"].lower() == sysdrive)
    return [dict(x, scanned=True) for x in fixed] + others


def _incomplete_parents(conn):
    rows = conn.execute(
        "SELECT DISTINCT e.parent FROM entries e WHERE e.parent != '' "
        "AND NOT EXISTS (SELECT 1 FROM entries d WHERE d.path = e.parent)").fetchall()
    return [r[0] for r in rows]


def _root_of(path):
    return path[:3] if len(path) >= 3 and path[1:2] == ":" else path


def _depth_of(conn, path):
    """从数据库读取父目录的真实深度；找不到时按路径分量数推算（盘符根=0）。"""
    parent = path if path.endswith("\\") else path.rsplit("\\", 1)[0]
    if parent == path:
        return 0
    row = conn.execute("SELECT depth FROM entries WHERE path=?", (parent,)).fetchone()
    if row and row[0] is not None:
        return row[0] + 1
    comps = len([x for x in path.split("\\") if x])
    return max(0, comps - 1)


def mode_resume(store):
    store.ensure_indexes()
    # 1) 确保每块本地磁盘都开始过扫描（崩溃可能发生在任何阶段，meta 可能尚未写入）
    meta_row = store.conn.execute("SELECT v FROM meta WHERE k='drives'").fetchone()
    sysdrive = (os.environ.get("SystemDrive", "C:") or "C:").rstrip(":").lower()
    if meta_row:
        drives_meta = json.loads(meta_row[0])
    else:
        drives = get_drives()
        fixed = [d for d in drives if d["type"] == "本地磁盘"]
        others = [d for d in drives if d["type"] != "本地磁盘"]
        for d in others:
            d["scanned"] = False
        drives_meta = [dict(x, scanned=True) for x in fixed] + others
    for d in drives_meta:
        if not d.get("scanned"):
            continue
        root = d["letter"] + ":\\"
        row = store.conn.execute("SELECT scanned FROM entries WHERE path=?", (root,)).fetchone()
        if row is None:
            print("续扫：磁盘 %s 从未完成过，开始补扫" % d["letter"], flush=True)
            scan_drive(store, {"letter": d["letter"], "root": d["letter"] + ":\\",
                               "type": d["type"], "total": d.get("total"), "free": d.get("free")},
                       d["letter"].lower() == sysdrive)
            store.flush()
    # 2) 修复所有未完成目录（崩溃时正在枚举的目录链）
    pending = _incomplete_parents(store.conn)
    roots = [r[0] for r in store.conn.execute(
        "SELECT path FROM entries WHERE is_dir=1 AND scanned=?", (kb.S_NONE,)).fetchall()]
    todo = sorted(set(pending) | set(roots))
    print("续扫：发现 %d 个未完成目录" % len(todo), flush=True)
    for p in todo:
        delete_subtree(store.conn, p, include_self=False)
        store.conn.commit()
    for p in todo:
        depth = _depth_of(store.conn, p)
        scan_dir(store, p, depth, False, False)
        store.flush()
    return drives_meta


def mode_incremental(store):
    store.ensure_indexes()
    print("增量扫描：校对各目录修改时间…", flush=True)
    cur = store.conn.execute(
        "SELECT path, mtime FROM entries WHERE is_dir=1 AND scanned IN (?,?)",
        (kb.S_DONE, kb.S_FAIL))
    todo = []
    skipped = 0
    batch = []
    for path, mtime in cur:
        batch.append((path, mtime))
        if len(batch) >= 20000:
            todo.extend(batch)
            batch.clear()
    todo.extend(batch)
    changed = []
    for path, old_mtime in todo:
        st, err = path_stat(path)
        if st is None and err in ("missing",):
            store.conn.execute("UPDATE entries SET scanned=? WHERE path=?", (kb.S_GONE, path))
            delete_subtree(store.conn, path, include_self=False)
            store.conn.commit()
            continue
        if st is not None and old_mtime is not None and int(st.st_mtime) == old_mtime:
            skipped += 1
            continue
        changed.append(path)
    print("增量：未变化 %d 个目录，需重新枚举 %d 个" % (skipped, len(changed)), flush=True)
    for path in changed:
        delete_subtree(store.conn, path, include_self=False)
        store.conn.commit()
        depth = _depth_of(store.conn, path)
        try:
            scan_dir(store, path, depth, False, False)
        except Exception:
            store.flush()
            traceback.print_exc()
        store.flush()
    drives_meta = json.loads(store.conn.execute(
        "SELECT v FROM meta WHERE k='drives'").fetchone()[0])
    return drives_meta


def mode_admin_retry(store):
    store.ensure_indexes()
    rows = store.conn.execute(
        "SELECT path FROM entries WHERE is_dir=1 AND scanned=? AND flags & ?",
        (kb.S_FAIL, kb.F_DENIED)).fetchall()
    print("管理员定向重试：共 %d 个此前被拒绝的目录" % len(rows), flush=True)
    ok = fail = 0
    for (p,) in rows:
        proj = store.conn.execute(
            "SELECT 1 FROM projects WHERE ? LIKE path || '\\%' LIMIT 1", (p,)).fetchone()
        depth = max(0, p.count("\\") - 1)
        before = store.inserted
        try:
            scan_dir(store, p, depth, False, bool(proj))
        except Exception:
            traceback.print_exc()
        store.flush()
        if store.inserted > before:
            ok += 1
            print("  ✓ 重试成功：%s" % p, flush=True)
        else:
            fail += 1
            print("  ✗ 仍失败：%s" % p, flush=True)
    print("重试结果：成功 %d，仍失败 %d（已保留错误记录）" % (ok, fail), flush=True)
    store.set_meta("admin_retry", {"ok": ok, "fail": fail,
                                   "at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")})
    store.conn.commit()
    drives_meta = json.loads(store.conn.execute(
        "SELECT v FROM meta WHERE k='drives'").fetchone()[0])
    return drives_meta


def main():
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    ap = argparse.ArgumentParser(description="文件地图助手 · 全量只读扫描引擎 v2")
    ap.add_argument("--resume", action="store_true", help="续扫上次中断的扫描")
    ap.add_argument("--incremental", action="store_true", help="增量扫描（跳过未变化目录）")
    ap.add_argument("--admin-retry", action="store_true", help="定向重试历史“拒绝访问”目录")
    ap.add_argument("--recompute", action="store_true", help="仅重算大小统计并重新生成报告")
    args = ap.parse_args()

    mode = ("recompute" if args.recompute else
            "admin_retry" if args.admin_retry else
            "incremental" if args.incremental else
            "resume" if args.resume else "full")
    print("=" * 64)
    print("文件地图助手 v%s —— 只读扫描引擎（模式：%s）" % (kb.VERSION, mode))
    print("承诺：不修改/移动/删除任何原始文件；不读取文件正文；")
    print("      疑似敏感文件只记录路径；所有输出只写入本工具目录。")
    print("=" * 64)

    if mode != "full" and not os.path.exists(DB_PATH):
        print("未找到现有数据库 fmdata.db，请先执行一次全量扫描。")
        return 1

    store = Store(fresh=(mode == "full"))
    if mode == "recompute":
        store.ensure_indexes()

    try:
        if mode == "full":
            # 清理 v1 遗留的静态数据文件（属于本工具自身的旧输出）
            for old in ("data.js", "data.json", "目录总览.csv"):
                fp = os.path.join(TOOL_DIR, old)
                if os.path.exists(fp):
                    try:
                        os.remove(fp)
                        print("已清理旧版输出文件：%s" % old)
                    except OSError:
                        pass
            store.phase = "full-scan"
            drives_meta = mode_full(store)
        else:
            store.phase = mode
            if mode == "resume":
                drives_meta = mode_resume(store)
            elif mode == "incremental":
                drives_meta = mode_incremental(store)
            elif mode == "admin_retry":
                drives_meta = mode_admin_retry(store)
            else:
                drives_meta = json.loads(store.conn.execute(
                    "SELECT v FROM meta WHERE k='drives'").fetchone()[0])

        store.flush()
        store.phase = "aggregate"
        aggregate(store)
        store.phase = "stats"
        stats = compute_stats(store, drives_meta, mode)
        print_stats(stats)
        store.phase = "report"
        store.close()

        try:
            import fm_report
            fm_report.generate()
        except Exception:
            traceback.print_exc()
            print("报告生成失败，但数据库已完整保存。可单独运行：python fm_report.py")
            return 1
        print("全部数据与报告生成完毕。数据文件：%s" % DB_PATH)
        return 0
    except KeyboardInterrupt:
        store.flush()
        store.phase = "interrupted"
        store.note_progress(force=True)
        print("\n扫描被手动中断。已保存的数据不会丢失；"
              "运行 python fm_scan.py --resume 可从断点继续。")
        return 130
    except Exception:
        try:
            store.flush()
        except Exception:
            pass
        store.phase = "error"
        store.note_progress(force=True)
        traceback.print_exc()
        print("扫描出现异常。已完成的数据已保存；可运行 python fm_scan.py --resume 继续。")
        return 1


if __name__ == "__main__":
    sys.exit(main())
