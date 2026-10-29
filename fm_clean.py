# -*- coding: utf-8 -*-
"""
本机文件地图与一键清理助手 · 安全清理引擎 v4 (fm_clean.py)
==========================================================
设计原则（与 BleachBit / CCleaner / Windows 存储感知等实现对齐的部分见
THIRD_PARTY_NOTICES.md，仅借鉴公开的设计思路，未集成任何第三方代码）：
  * 白名单驱动：只清理本文件中【明确列出】的规则目录与文件模式；
    前端只能传"规则 ID"，永远不能传路径或命令。
  * 与文件地图模块完全隔离：本模块独立维护路径校验与删除逻辑，
    不共享任何任意路径删除接口。
  * 不跟随符号链接/目录联接（reparse point 一律跳过，绝不进入）。
  * 每个被删除的文件都记录到 fmdata.db 的 clean_log（可追溯到规则）。
  * 被占用/只读/权限不足的对象一律跳过并记录原因，绝不扩大范围、
    绝不结束进程、绝不修改权限、绝不修改文件属性。
  * 取消安全：收到取消信号后不再开始任何新的删除。

v4 相比 v3 的改动（全部是"更准 / 更快 / 更安全"，一条也没有放宽授权范围）：
  1. 【修复】清理记录一直"加载失败"：数据库连接没有设置 row_factory，
     get_history()/get_run_log() 里 dict(元组) 直接抛 TypeError，
     服务端又只捕获 sqlite3.Error，异常逃逸后连接被断开，前端只能显示
     "加载失败"。现统一设置 sqlite3.Row 并把所有读取包在 try 里。
  2. 【修复】清理完成后界面没有完成标志：结果只存在进程内存，且前端轮询
     到头只弹一个 toast。现把逐类明细/原因统计/磁盘变化写入
     clean_runs.detail，并新增 get_last_run()，刷新页面也能看到"上次清理"。
  3. 【性能】逐文件日志原来每写一条就 commit 一次（每条一次 fsync），
     十万文件级别会明显拖慢。现改为批量提交（每 200 条或每 1 秒）。
  4. 【性能】清理策略状态改为内存缓存，轮询接口不再每 500 毫秒建两次连接、
     跑一次 executescript。
  5. 【更安全】目录候选在删除前检查子树内"最新修改时间"（借鉴 BleachBit /
     CCleaner 的 min_age 语义）。v3 只看目录自身的 mtime，可能删掉一个
     目录属性很旧、但里面正有程序在写新文件的临时目录。
  6. 【更准】失败原因分类：被占用 / 拒绝访问 / 只读属性 / 已消失 / 其他。
     界面上直接解释"WER 目录权限不足属正常"，而不是让用户以为清理坏了。
  7. 【更稳】支持超过 260 字符的长路径（自动加 \\\\?\\ 前缀）。
  8. 【可控】新增 clean_excludes.txt 排除名单：只能本地文件编辑，
     网页端没有任何写入入口（前端依旧不能传路径）。
  9. 【可核对】记录清理前后磁盘可用空间，界面同时显示"文件字节数"与
     "磁盘实际可用空间变化"，避免把预留簇/压缩差异误读成清理失败。
 10. 【自愈】进程崩溃后遗留的 running 记录，下次启动自动标记为 interrupted，
     不会一直卡在"清理中"。
"""

import os
import json
import time
import shutil
import fnmatch
import sqlite3
import threading
from datetime import datetime

import fm_scan  # 复用其 DB 路径与工具目录常量（只取常量，不共用删除逻辑）

DB_PATH = fm_scan.DB_PATH
TOOL_DIR = os.path.dirname(os.path.abspath(__file__))
EXCLUDES_PATH = os.path.join(TOOL_DIR, "clean_excludes.txt")

F_READONLY = 0x1
F_REPARSE = 0x400
F_DIR = 0x10

# Windows 错误码（区分"正在被使用"和"权限不足"，两者处理方式不同）
ERR_ACCESS_DENIED = 5
ERR_SHARING_VIOLATION = 32
ERR_LOCK_VIOLATION = 33
ERR_FILE_NOT_FOUND = 2
ERR_PATH_NOT_FOUND = 3

LOG_BATCH_ROWS = 200          # 日志每累计多少条提交一次
LOG_BATCH_SECONDS = 1.0       # 或距上次提交超过多少秒
SCAN_CACHE_TTL = 60           # 预览结果缓存秒数（避免连点预览重复扫描）
DIR_SIZE_CAP = 20000          # 估算单个目录大小时最多枚举的条目数
STALE_RUN_HOURS = 6           # 超过该时长仍是 running 的记录视为崩溃遗留


# ---------------------------------------------------------------------------
# 白名单规则定义（唯一授权来源；新增规则必须经过人工核对）
# id 同时是前端可传的唯一合法参数
#
# mode:
#   children —— 清理 root 下的子条目（不删 root 本身）
#   matches  —— 只清理 root 下名字匹配 include 的条目
# min_age_days: 只清理"最后修改时间早于 N 天前"的对象（0 = 不限）
# group/impact: 仅用于界面分组与影响说明，不参与任何授权判断
# ---------------------------------------------------------------------------
def _rules():
    local = os.environ.get("LOCALAPPDATA") or os.path.join(
        os.environ.get("USERPROFILE", ""), "AppData", "Local")
    windir = os.environ.get("SystemRoot", r"C:\Windows")
    programdata = os.environ.get("ProgramData", r"C:\ProgramData")
    return [
        {
            "id": "user_temp",
            "name": "用户临时文件（%TEMP%）",
            "desc": "当前用户临时目录中超过 24 小时未被修改的条目。跳过正在使用、只读、"
                    "无法验证的对象与符号链接/目录联接；失败的条目只记录不重试。",
            "roots": [os.environ.get("TEMP") or os.path.join(local, "Temp")],
            "mode": "children",
            "include": None,
            "min_age_days": 1,
            "group": "临时文件",
            "impact": "无影响。正在运行的程序会重新生成自己需要的临时文件。",
        },
        {
            "id": "windows_temp",
            "name": "Windows 临时文件（C:\\Windows\\Temp）",
            "desc": "Windows 系统临时目录中超过 24 小时的条目。普通权限通常只能清理其中"
                    "属于当前用户的部分；无法访问的条目记录原因后跳过，绝不修改权限。",
            "roots": [os.path.join(windir, "Temp")],
            "mode": "children",
            "include": None,
            "min_age_days": 1,
            "group": "临时文件",
            "impact": "无影响；少数需要管理员权限的条目会被跳过并如实记录。",
        },
        {
            "id": "thumbcache",
            "name": "缩略图与图标缓存",
            "desc": "资源管理器的缩略图缓存（thumbcache_*.db）与图标缓存（iconcache_*.db），"
                    "删除后浏览文件夹时会自动重建。Explorer 正在运行时这些文件通常被占用，"
                    "会被如实记为跳过。",
            "roots": [os.path.join(local, "Microsoft", "Windows", "Explorer")],
            "mode": "matches",
            "include": ["thumbcache_*.db", "iconcache_*.db"],
            "min_age_days": 0,
            "group": "缓存（自动重建）",
            "impact": "首次再打开图片较多的文件夹时缩略图会重新生成；图标缓存清空后"
                      "桌面/文件夹图标可能短暂空白，通常几十秒内自动恢复。",
        },
        {
            "id": "d3d_shader_cache",
            "name": "DirectX 着色器缓存",
            "desc": "Windows 图形着色器缓存（D3DSCache），删除后由系统与游戏自动重建，"
                    "首次启动游戏可能稍慢。正在使用的文件会被跳过。",
            "roots": [os.path.join(local, "D3DSCache")],
            "mode": "children",
            "include": None,
            "min_age_days": 0,
            "group": "缓存（自动重建）",
            "impact": "游戏首次启动时编译着色器会慢一点，之后恢复。",
        },
        {
            "id": "nvidia_shader_cache",
            "name": "NVIDIA 着色器缓存（DXCache/GLCache）",
            "desc": "NVIDIA 显卡的着色器缓存目录，删除后由驱动自动重建。"
                    "未安装 NVIDIA 驱动时该类别为空，属正常现象。",
            "roots": [os.path.join(local, "NVIDIA", "DXCache"),
                      os.path.join(local, "NVIDIA", "GLCache")],
            "mode": "children",
            "include": None,
            "min_age_days": 0,
            "group": "缓存（自动重建）",
            "impact": "游戏首次启动时编译着色器会慢一点，之后恢复。",
        },
        {
            "id": "crash_dumps",
            "name": "应用崩溃转储（CrashDumps）",
            "desc": "应用崩溃时留下的 .dmp 调试转储文件（超过 24 小时），仅用于排查崩溃，"
                    "可安全清理。",
            "roots": [os.path.join(local, "CrashDumps")],
            "mode": "matches",
            "include": ["*.dmp"],
            "min_age_days": 1,
            "group": "诊断与日志",
            "impact": "无影响。若正在排查某个程序崩溃，请先自行保留对应 .dmp。",
        },
        {
            "id": "wer_reports",
            "name": "Windows 错误报告队列",
            "desc": "Windows 错误报告（WER）的 ReportQueue/ReportArchive 中超过 7 天的旧报告，"
                    "与系统错误诊断系统相同，普通权限下无法删除的部分会跳过（通常占多数，"
                    "属正常现象）。",
            "roots": [os.path.join(programdata, "Microsoft", "Windows", "WER", "ReportQueue"),
                      os.path.join(programdata, "Microsoft", "Windows", "WER", "ReportArchive")],
            "mode": "children",
            "include": None,
            "min_age_days": 7,
            "group": "诊断与日志",
            "impact": "无影响。这些报告只用于微软收集崩溃信息。",
        },
    ]


# 默认一键清理的规则集合（经过确认的安全范围）
DEFAULT_CATEGORY_IDS = ["user_temp", "windows_temp", "thumbcache", "d3d_shader_cache",
                        "nvidia_shader_cache", "crash_dumps", "wer_reports"]

# 明确不清理的说明（用于界面展示与文档）
NEVER_CLEAN_TEXT = [
    "桌面、文档、下载、图片、视频等所有个人目录",
    "任何开发项目、GitHub 仓库、学习资料与安装包",
    ".git / .env / src / node_modules / target / build / dist 等项目目录与依赖",
    "浏览器历史、Cookie、密码、扩展与用户配置",
    "回收站内容",
    "Windows Installer 缓存、系统组件、驱动、注册表、分页文件与休眠文件",
    "npm / Maven / Gradle / Python 等开发缓存（可重建但可能影响离线开发，默认关闭）",
    "所有无法确认用途的文件——名字看不懂绝不等于垃圾",
]

# 失败/跳过原因分类（界面直接按这三类统计，用户一眼能看懂）
REASON_TEXT = {
    "in_use": "正在被程序使用（正常，关闭相关程序后下次可清理）",
    "denied": "权限不足（需管理员权限，本工具不会提权）",
    "readonly": "只读属性（不改属性，按策略跳过）",
    "gone": "已不存在（扫描后被程序自己删掉）",
    "excluded": "在排除名单中（clean_excludes.txt）",
    "fresh": "目录内有近期修改的文件（避免影响正在运行的程序）",
    "guard": "路径校验未通过（安全保护）",
    "io": "其他 IO 错误",
}


# ---------------------------------------------------------------------------
# 全局状态
# ---------------------------------------------------------------------------
_policy_lock = threading.Lock()
_state_lock = threading.Lock()
_state = {
    "phase": "idle", "mode": None, "categories": [], "started": None,
    "finished": None, "cancel": False, "results": [], "error": None,
    "run_id": None, "totals": {}, "progress": {}, "notes": [],
}
_cancel_event = threading.Event()
_db_lock = threading.Lock()
_init_lock = threading.Lock()

_inited_path = None            # 已初始化的数据库路径（测试会改写 DB_PATH）
_policy_cache = None           # 清理策略确认状态缓存
_scan_cache = {}               # {tuple(rule_ids): (ts, result)}


# ---------------------------------------------------------------------------
# 数据库（独立读写连接；只写本工具目录内的 fmdata.db）
# ---------------------------------------------------------------------------
_SCHEMA = """
CREATE TABLE IF NOT EXISTS meta(k TEXT PRIMARY KEY, v TEXT);
CREATE TABLE IF NOT EXISTS clean_runs(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  started TEXT, finished TEXT, mode TEXT, status TEXT,
  categories TEXT, candidates INTEGER, deleted INTEGER,
  skipped INTEGER, failed INTEGER, freed_bytes INTEGER, scanned_bytes INTEGER
);
CREATE TABLE IF NOT EXISTS clean_log(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  run_id INTEGER, rule_id TEXT, path TEXT, size INTEGER,
  status TEXT, reason TEXT, ts REAL
);
"""

# v4 新增列（老库用 ALTER TABLE 平滑升级，不重建表、不动历史数据）
_RUN_COLUMNS = [
    ("detail", "TEXT"),          # 逐类明细 + 原因统计 + 磁盘变化的 JSON
    ("error", "TEXT"),           # 异常信息（status=error 时）
    ("duration_s", "REAL"),      # 实际耗时
    ("free_before", "INTEGER"),  # 清理前相关磁盘可用空间合计
    ("free_after", "INTEGER"),   # 清理后相关磁盘可用空间合计
]


def _ensure_db():
    """建表 + 平滑升级 + 启动自愈（只做一次）"""
    global _inited_path, _policy_cache
    if _inited_path == DB_PATH:
        return
    with _init_lock:
        if _inited_path == DB_PATH:
            return
        conn = sqlite3.connect(DB_PATH, timeout=15)
        try:
            conn.execute("PRAGMA busy_timeout=15000")
            conn.executescript(_SCHEMA)
            cols = {r[1] for r in conn.execute("PRAGMA table_info(clean_runs)")}
            for name, decl in _RUN_COLUMNS:
                if name not in cols:
                    conn.execute("ALTER TABLE clean_runs ADD COLUMN %s %s" % (name, decl))
            conn.execute("CREATE INDEX IF NOT EXISTS idx_clean_log_run "
                         "ON clean_log(run_id)")
            # 崩溃遗留的 running 记录：标记为 interrupted，避免界面一直"清理中"
            conn.execute(
                "UPDATE clean_runs SET status='interrupted', "
                "finished=COALESCE(finished, ?) WHERE status='running'",
                (datetime.now().strftime("%Y-%m-%d %H:%M:%S"),))
            conn.commit()
        finally:
            conn.close()
        _inited_path = DB_PATH
        _policy_cache = None
        _scan_cache.clear()


def _db():
    """可写连接（设置 Row 工厂——v3 缺这一行导致记录读取必然崩溃）"""
    _ensure_db()
    conn = sqlite3.connect(DB_PATH, check_same_thread=False, timeout=15)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout=15000")
    return conn


def _ro_db():
    """只读连接（读多写少，避免无谓的写锁）"""
    _ensure_db()
    conn = sqlite3.connect("file:%s?mode=ro" % DB_PATH.replace("\\", "/"), uri=True,
                           timeout=15)
    conn.row_factory = sqlite3.Row
    return conn


def _row2dict(row):
    return {k: row[k] for k in row.keys()} if row is not None else None


def get_policy():
    global _policy_cache
    if _policy_cache is not None:
        return _policy_cache
    with _policy_lock:
        if _policy_cache is not None:
            return _policy_cache
        try:
            conn = _ro_db()
            try:
                row = conn.execute("SELECT v FROM meta WHERE k='clean_policy_accepted'"
                                   ).fetchone()
                _policy_cache = bool(row and row["v"] == "1")
            finally:
                conn.close()
        except sqlite3.Error:
            return False
        return _policy_cache


def set_policy():
    global _policy_cache
    with _db_lock:
        conn = _db()
        try:
            conn.execute("INSERT OR REPLACE INTO meta(k,v) "
                         "VALUES('clean_policy_accepted','1')")
            conn.commit()
        finally:
            conn.close()
    _policy_cache = True
    return True


def count_runs():
    conn = _ro_db()
    try:
        return conn.execute("SELECT COUNT(*) FROM clean_runs").fetchone()[0]
    finally:
        conn.close()


def get_history(limit=50, offset=0):
    conn = _ro_db()
    try:
        rows = conn.execute("SELECT * FROM clean_runs ORDER BY id DESC LIMIT ? OFFSET ?",
                            (int(limit), int(offset))).fetchall()
        return [_row2dict(r) for r in rows]
    finally:
        conn.close()


def get_last_run():
    """最后一次清理（含逐类明细），供页面刷新后恢复"上次清理"卡片"""
    conn = _ro_db()
    try:
        row = conn.execute("SELECT * FROM clean_runs ORDER BY id DESC LIMIT 1").fetchone()
        if not row:
            return None
        d = _row2dict(row)
        d["detail"] = _safe_json(d.get("detail"))
        try:
            d["categories"] = json.loads(d.get("categories") or "[]")
        except (ValueError, TypeError):
            d["categories"] = []
        return d
    finally:
        conn.close()


def get_run_log(run_id, limit=200, offset=0, status=None):
    """逐文件日志（分页 + 可选状态筛选）。返回 (items, total)"""
    conn = _ro_db()
    try:
        sql_where = "WHERE run_id=?"
        args = [int(run_id)]
        if status in ("deleted", "skipped", "failed", "dir_done", "dir_partial"):
            sql_where += " AND status=?"
            args.append(status)
        total = conn.execute("SELECT COUNT(*) FROM clean_log %s" % sql_where,
                             args).fetchone()[0]
        rows = conn.execute(
            "SELECT rule_id, path, size, status, reason, ts FROM clean_log %s "
            "ORDER BY id LIMIT ? OFFSET ?" % sql_where,
            args + [int(limit), int(offset)]).fetchall()
        return [_row2dict(r) for r in rows], total
    finally:
        conn.close()


def iter_run_log(run_id, status=None):
    """流式读取整次运行的日志（用于导出 CSV，不一次性占满内存）"""
    conn = _ro_db()
    try:
        sql = "SELECT rule_id, path, size, status, reason, ts FROM clean_log WHERE run_id=?"
        args = [int(run_id)]
        if status in ("deleted", "skipped", "failed", "dir_done", "dir_partial"):
            sql += " AND status=?"
            args.append(status)
        sql += " ORDER BY id"
        for row in conn.execute(sql, args):
            yield _row2dict(row)
    finally:
        conn.close()


def _safe_json(s):
    if not s:
        return {}
    try:
        return json.loads(s)
    except (ValueError, TypeError):
        return {}


# ---------------------------------------------------------------------------
# 路径与删除保护（核心安全层）
# ---------------------------------------------------------------------------
def _norm(p):
    return os.path.normcase(os.path.normpath(p))


def _long(p):
    """超过 260 字符的路径加 \\\\?\\ 前缀（API 仍接受原始路径）"""
    if len(p) < 240:
        return p
    ap = os.path.abspath(p)
    if ap.startswith("\\\\?\\"):
        return ap
    if ap.startswith("\\\\"):
        return "\\\\?\\UNC" + ap[1:]
    return "\\\\?\\" + ap


def _is_reparse(st):
    return bool(getattr(st, "st_file_attributes", 0) & F_REPARSE)


def _in_root(candidate, root):
    """candidate 必须严格位于 root 内部（不得等于 root，不得越界）"""
    c, r = _norm(candidate), _norm(root)
    if not r.endswith("\\"):
        r += "\\"
    return c.startswith(r) and len(c) > len(r)


def _match_include(name, include):
    if not include:
        return True
    low = name.lower()
    return any(fnmatch.fnmatch(low, pat.lower()) for pat in include)


def _load_excludes():
    """读取本地排除名单（只有本地文件能改，网页端无权写入）"""
    out = []
    try:
        with open(EXCLUDES_PATH, encoding="utf-8") as f:
            for line in f:
                s = line.strip()
                if not s or s.startswith("#"):
                    continue
                out.append(os.path.expandvars(s))
    except OSError:
        return []
    return out


def _is_excluded(path, excludes):
    if not excludes:
        return False
    np = _norm(path)
    for ex in excludes:
        e = _norm(ex)
        if np == e or np.startswith(e.rstrip("\\") + "\\"):
            return True
    return False


def _classify_oserr(e):
    """把 OSError 归类成界面能直接解释的原因码"""
    code = getattr(e, "winerror", None) or getattr(e, "errno", None)
    if code in (ERR_SHARING_VIOLATION, ERR_LOCK_VIOLATION):
        return "in_use", "正在被程序使用，已跳过"
    if code in (ERR_FILE_NOT_FOUND, ERR_PATH_NOT_FOUND):
        return "gone", "已不存在（跳过）"
    if code == ERR_ACCESS_DENIED or isinstance(e, PermissionError):
        return "denied", "权限不足（本工具不会提权），已跳过"
    return "io", "删除失败：%s" % e


def _status_of(code):
    """原因码 → 结果状态。只有真正的 IO 异常才算"失败"；
    占用 / 权限不足 / 只读 / 已消失 都属于"正常的跳过"，避免用户误以为清理坏了。"""
    return "failed" if code == "io" else "skipped"


def _delete_file(path):
    """删除单个文件；返回 (状态, 大小) 或 (状态, (原因码, 说明))"""
    try:
        st = os.stat(_long(path), follow_symlinks=False)
    except OSError as e:
        code, text = _classify_oserr(e)
        return _status_of(code), (code, text)
    if _is_reparse(st):
        return "skipped", ("guard", "符号链接/联接，跳过")
    if getattr(st, "st_file_attributes", 0) & F_READONLY:
        # 只读属性只跳过、不 chmod：宁可少删，也不改用户的文件属性
        return "skipped", ("readonly", "只读属性，按策略跳过（不修改属性）")
    size = st.st_size
    try:
        os.remove(_long(path))
        return "deleted", size
    except OSError as e:
        code, text = _classify_oserr(e)
        return _status_of(code), (code, text)


def _tree_newest_mtime(path, cutoff=0, cap=DIR_SIZE_CAP):
    """子树内最新的修改时间；一旦发现不早于 cutoff 的条目就立即返回（提前退出，
    正常情况只扫几个条目就有结论，不必遍历整棵树）"""
    newest = 0
    seen = 0
    stack = [path]
    while stack and seen < cap:
        cur = stack.pop()
        try:
            with os.scandir(_long(cur)) as it:
                for e in it:
                    seen += 1
                    if seen >= cap:
                        break
                    try:
                        st = e.stat(follow_symlinks=False)
                    except OSError:
                        continue
                    if st.st_mtime > newest:
                        newest = st.st_mtime
                    if cutoff and newest >= cutoff:
                        return newest
                    if st.st_file_attributes & F_DIR and not _is_reparse(st):
                        stack.append(e.path)
        except OSError:
            continue
    return newest


def _delete_tree(path, on_event):
    """删除目录内容（不跟随任何 reparse point）。
    返回 dict(deleted, skipped, failed, freed, cancelled, reasons{})"""
    res = {"deleted": 0, "skipped": 0, "failed": 0, "freed": 0,
           "cancelled": False, "reasons": {}}
    stack = [path]
    while stack:
        if _cancel_event.is_set():
            res["cancelled"] = True
            return res
        cur = stack.pop()
        try:
            with os.scandir(_long(cur)) as it:
                entries = list(it)
        except OSError as e:
            code, text = _classify_oserr(e)
            st_code = _status_of(code)
            res[st_code] += 1
            res["reasons"][code] = res["reasons"].get(code, 0) + 1
            on_event(cur, st_code, None, code, text)
            continue
        removable = True
        for e in entries:
            if _cancel_event.is_set():
                res["cancelled"] = True
                return res
            try:
                st = e.stat(follow_symlinks=False)
            except OSError as ex:
                code, text = _classify_oserr(ex)
                st_code = _status_of(code)
                res[st_code] += 1
                res["reasons"][code] = res["reasons"].get(code, 0) + 1
                on_event(e.path, st_code, None, code, text)
                continue
            if _is_reparse(st):
                res["skipped"] += 1
                res["reasons"]["guard"] = res["reasons"].get("guard", 0) + 1
                on_event(e.path, "skipped", None, "guard", "符号链接/联接，不跟随")
                removable = False
                continue
            if st.st_file_attributes & F_DIR:
                stack.append(e.path)
                continue
            status, info = _delete_file(e.path)
            if status == "deleted":
                res["deleted"] += 1
                res["freed"] += info
                on_event(e.path, "deleted", info, None, None)
            else:
                res[status] += 1
                code, text = info
                res["reasons"][code] = res["reasons"].get(code, 0) + 1
                on_event(e.path, status, None, code, text)
                removable = False
        if not removable:
            continue  # 内容未清空则不删目录本身
        try:
            os.rmdir(_long(cur))
        except OSError:
            pass  # 目录非空或被占用：保留目录，不报为失败（内容级结果已记录）
    return res


# ---------------------------------------------------------------------------
# 扫描（只读预览）
# ---------------------------------------------------------------------------
def _dir_size_quick(path):
    """估算目录大小与条目数（有界，用于预览与进度分母）返回 (bytes, count)"""
    total = 0
    count = 0
    stack = [path]
    seen = 0
    while stack and seen < DIR_SIZE_CAP:
        cur = stack.pop()
        try:
            with os.scandir(_long(cur)) as it:
                for e in it:
                    seen += 1
                    if seen >= DIR_SIZE_CAP:
                        break
                    try:
                        st = e.stat(follow_symlinks=False)
                    except OSError:
                        continue
                    if _is_reparse(st):
                        continue
                    if st.st_file_attributes & F_DIR:
                        stack.append(e.path)
                        count += 1
                    else:
                        total += st.st_size
                        count += 1
        except OSError:
            continue
    return total, count


def _iter_candidates(rule):
    """按规则枚举候选对象。返回 (candidates, notes)。不删除任何东西。"""
    candidates = []
    notes = []
    seen = set()
    now = time.time()
    min_age = rule.get("min_age_days", 0) * 86400
    excludes = _load_excludes()
    for root in rule["roots"]:
        root = os.path.expandvars(root)
        if not os.path.isdir(root):
            notes.append("目录不存在（%s）：本机可能没有该缓存，属正常" % root)
            continue
        try:
            with os.scandir(_long(root)) as it:
                entries = list(it)
        except PermissionError:
            notes.append("目录无法访问（权限不足，按规则跳过）：%s" % root)
            continue
        except OSError as e:
            notes.append("目录读取失败：%s（%s）" % (root, e))
            continue
        for e in entries:
            try:
                st = e.stat(follow_symlinks=False)
            except OSError:
                continue
            if _is_reparse(st):
                continue  # 链接一律不作为候选
            if not _match_include(e.name, rule.get("include")):
                continue
            if now - st.st_mtime < min_age:
                continue
            key = _norm(e.path)
            if key in seen:
                continue  # 多根目录重叠时去重，避免重复计数
            seen.add(key)
            if _is_excluded(e.path, excludes):
                continue
            if st.st_file_attributes & F_DIR:
                size, n = _dir_size_quick(e.path)
                candidates.append({"path": e.path, "name": e.name, "is_dir": True,
                                   "size": size, "n_items": n + 1,
                                   "mtime": int(st.st_mtime)})
            else:
                candidates.append({"path": e.path, "name": e.name, "is_dir": False,
                                   "size": st.st_size, "n_items": 1,
                                   "mtime": int(st.st_mtime)})
    return candidates, notes


def scan(rule_ids, use_cache=True):
    rule_ids = list(rule_ids)
    key = tuple(sorted(rule_ids))
    if use_cache:
        hit = _scan_cache.get(key)
        if hit and time.time() - hit[0] < SCAN_CACHE_TTL:
            return hit[1]
    results = []
    total_count = 0
    total_bytes = 0
    total_items = 0
    notes = []
    for rule in _rules():
        if rule["id"] not in rule_ids:
            continue
        cands, note = _iter_candidates(rule)
        notes.extend(["[%s] %s" % (rule["name"], n) for n in note])
        c_bytes = sum(c["size"] for c in cands)
        c_items = sum(c.get("n_items", 1) for c in cands)
        results.append({"id": rule["id"], "name": rule["name"], "desc": rule["desc"],
                        "group": rule.get("group", ""), "impact": rule.get("impact", ""),
                        "risk": rule.get("risk", "safe"),
                        "min_age_days": rule.get("min_age_days", 0),
                        "candidates": len(cands), "items": c_items, "bytes": c_bytes,
                        "items_preview": cands[:50], "truncated": len(cands) > 50})
        total_count += len(cands)
        total_bytes += c_bytes
        total_items += c_items
    out = {"ok": True, "phase": "scan_done", "results": results,
           "totals": {"candidates": total_count, "items": total_items,
                      "bytes": total_bytes},
           "notes": notes, "at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
    if use_cache:
        _scan_cache[key] = (time.time(), out)
    return out


# ---------------------------------------------------------------------------
# 日志批量写入（性能：v3 每条一次 commit，十万文件级别明显拖慢）
# ---------------------------------------------------------------------------
class _LogWriter:
    def __init__(self, conn, run_id):
        self.conn = conn
        self.run_id = run_id
        self.buf = []
        self.last = time.time()

    def add(self, rule_id, path, size, status, reason):
        self.buf.append((self.run_id, rule_id, path, size, status, reason, time.time()))
        if len(self.buf) >= LOG_BATCH_ROWS or time.time() - self.last >= LOG_BATCH_SECONDS:
            self.flush()

    def flush(self):
        if not self.buf:
            return
        rows, self.buf = self.buf, []
        self.last = time.time()
        with _db_lock:
            try:
                self.conn.executemany(
                    "INSERT INTO clean_log(run_id, rule_id, path, size, status, reason, ts) "
                    "VALUES(?,?,?,?,?,?,?)", rows)
                self.conn.commit()
            except sqlite3.Error:
                pass  # 日志写失败不影响删除流程，界面以计数为准


# ---------------------------------------------------------------------------
# 磁盘可用空间快照（用于"真实释放量"对照）
# ---------------------------------------------------------------------------
def _drive_of(p):
    d = os.path.splitdrive(os.path.abspath(p))[0]
    return (d + "\\") if d else None


def _disk_snapshot(roots):
    out = {}
    for r in roots:
        drv = _drive_of(r)
        if not drv or drv in out:
            continue
        try:
            out[drv] = shutil.disk_usage(drv).free
        except OSError:
            continue
    return out


# ---------------------------------------------------------------------------
# 执行清理（白名单 + 全程日志 + 可取消 + 实时进度）
# ---------------------------------------------------------------------------
def run(rule_ids):
    with _state_lock:
        if _state["phase"] not in ("idle", "done", "cancelled", "error", "scan_done",
                                   "interrupted"):
            return {"ok": False, "error": "已有清理任务在执行中，请等待完成后再试"}
        _state.update({
            "phase": "running", "mode": "run", "categories": list(rule_ids),
            "started": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "finished": None, "cancel": False, "results": [], "error": None,
            "notes": [],
            "totals": {"candidates": 0, "items": 0, "deleted": 0, "skipped": 0,
                       "failed": 0, "freed_bytes": 0, "scanned_bytes": 0},
            "progress": {"pct": 0, "current": "准备中…", "processed": 0, "total": 0,
                         "elapsed": 0, "eta_s": None, "freed_bytes": 0},
        })
    _cancel_event.clear()
    t = threading.Thread(target=_run_impl, args=(list(rule_ids),), daemon=True)
    t.start()
    return {"ok": True, "phase": "running"}


def _run_impl(rule_ids):
    conn = _db()
    run_id = None
    t0 = time.time()
    logw = _LogWriter(conn, 0)
    totals = {"candidates": 0, "items": 0, "deleted": 0, "skipped": 0,
              "failed": 0, "freed_bytes": 0, "scanned_bytes": 0}
    all_reasons = {}
    notes = []
    results = []
    roots_all = []
    try:
        cur = conn.execute(
            "INSERT INTO clean_runs(started, finished, mode, status, categories) "
            "VALUES(?,?,?,?,?)",
            (_state["started"], None, "run", "running", json.dumps(rule_ids)))
        conn.commit()
        run_id = cur.lastrowid
        logw.run_id = run_id
        with _state_lock:
            _state["run_id"] = run_id

        selected = [r for r in _rules() if r["id"] in rule_ids]
        for r in selected:
            roots_all.extend(os.path.expandvars(x) for x in r["roots"])
        free_before_map = _disk_snapshot(roots_all)

        # 第一阶段：枚举候选（给出进度分母，并缓存扫描说明）
        planned = []
        total_items = 0
        for rule in selected:
            if _cancel_event.is_set():
                break
            with _state_lock:
                _state["progress"].update({"current": "正在分析：%s" % rule["name"]})
            cands, note = _iter_candidates(rule)
            notes.extend(["[%s] %s" % (rule["name"], n) for n in note])
            n_items = sum(c.get("n_items", 1) for c in cands)
            total_items += n_items
            totals["candidates"] += len(cands)
            totals["items"] += n_items
            totals["scanned_bytes"] += sum(c["size"] for c in cands)
            planned.append((rule, cands))
            with _state_lock:
                _state["totals"] = dict(totals)
                _state["progress"].update({"total": total_items, "processed": 0, "pct": 0})

        processed = 0
        for rule, cands in planned:
            if _cancel_event.is_set():
                break
            with _state_lock:
                _state["phase"] = "running:" + rule["id"]
                _state["progress"]["current"] = rule["name"]
            cat = {"id": rule["id"], "name": rule["name"], "group": rule.get("group", ""),
                   "candidates": len(cands), "items": sum(c.get("n_items", 1) for c in cands),
                   "deleted": 0, "skipped": 0, "failed": 0, "freed_bytes": 0,
                   "reasons": {}}
            roots = [os.path.expandvars(r) for r in rule["roots"]]

            prog = {"n": processed}

            def push_progress(_name=rule["name"]):
                with _state_lock:
                    elapsed = max(0.001, time.time() - t0)
                    done = prog["n"]
                    pct = 0 if total_items <= 0 else min(99, int(done * 100 / total_items))
                    eta = None
                    if pct > 2 and done > 0:
                        eta = int((elapsed / done) * max(0, total_items - done))
                    _state["totals"] = dict(totals)
                    _state["progress"].update({
                        "pct": pct, "processed": done, "total": total_items,
                        "elapsed": round(elapsed, 1), "eta_s": eta,
                        "freed_bytes": totals["freed_bytes"], "current": _name})

            def bump(k=1):
                prog["n"] += k
                if prog["n"] % 5 == 0:      # 每 5 项推一次，减少锁竞争
                    push_progress()

            def on_event(path, status, size, code, text, _rid=rule["id"]):
                if status == "deleted":
                    logw.add(_rid, path, size, "deleted", None)
                else:
                    logw.add(_rid, path, None, status,
                             (REASON_TEXT.get(code, code) + "：" + text) if code else text)
                bump(1)

            for c in cands:
                if _cancel_event.is_set():
                    break
                if not any(_in_root(c["path"], root) for root in roots):
                    # 双重校验：任何候选必须仍位于该规则的某个授权根目录内
                    cat["skipped"] += 1
                    cat["reasons"]["guard"] = cat["reasons"].get("guard", 0) + 1
                    with _state_lock:
                        totals["skipped"] += 1
                    logw.add(rule["id"], c["path"], c["size"], "skipped",
                             "路径校验未通过（安全保护）")
                    bump(1)
                    continue

                if c["is_dir"]:
                    # 目录：先确认子树里没有"近期修改"的文件（避免影响正在运行的程序）
                    min_age = rule.get("min_age_days", 0) * 86400
                    if min_age > 0:
                        newest = _tree_newest_mtime(c["path"], cutoff=time.time() - min_age)
                        if newest and time.time() - newest < min_age:
                            cat["skipped"] += 1
                            cat["reasons"]["fresh"] = cat["reasons"].get("fresh", 0) + 1
                            with _state_lock:
                                totals["skipped"] += 1
                            logw.add(rule["id"], c["path"] + "（目录）", c["size"], "skipped",
                                     REASON_TEXT["fresh"])
                            bump(1)
                            continue
                    d = _delete_tree(c["path"], on_event)
                    cat["deleted"] += d["deleted"]
                    cat["skipped"] += d["skipped"]
                    cat["failed"] += d["failed"]
                    cat["freed_bytes"] += d["freed"]
                    for k, v in d["reasons"].items():
                        cat["reasons"][k] = cat["reasons"].get(k, 0) + v
                    with _state_lock:
                        totals["deleted"] += d["deleted"]
                        totals["skipped"] += d["skipped"]
                        totals["failed"] += d["failed"]
                        totals["freed_bytes"] += d["freed"]
                    logw.add(rule["id"], c["path"] + "（目录）", None,
                             "dir_partial" if d["cancelled"] else "dir_done",
                             "已清理 %d 个文件，释放 %s%s" % (
                                 d["deleted"], _hsize(d["freed"]),
                                 "（已取消）" if d["cancelled"] else ""))
                    bump(1)
                else:
                    status, info = _delete_file(c["path"])
                    if status == "deleted":
                        cat["deleted"] += 1
                        cat["freed_bytes"] += info
                        with _state_lock:
                            totals["deleted"] += 1
                            totals["freed_bytes"] += info
                        logw.add(rule["id"], c["path"], info, "deleted", None)
                    else:
                        code, text = info
                        cat[status] += 1
                        cat["reasons"][code] = cat["reasons"].get(code, 0) + 1
                        with _state_lock:
                            totals[status] += 1
                        logw.add(rule["id"], c["path"], None, status,
                                 REASON_TEXT.get(code, code) + "：" + text)
                    bump(1)

            processed = prog["n"]
            push_progress()

            for k, v in cat["reasons"].items():
                all_reasons[k] = all_reasons.get(k, 0) + v
            results.append(cat)
            logw.flush()
            with _state_lock:
                _state["results"] = list(results)
                _state["totals"] = dict(totals)

            # 空目录回收：删完内容后把规则根下已经为空的子目录收掉
            for root in roots:
                try:
                    with os.scandir(_long(root)) as it:
                        for e in list(it):
                            try:
                                if e.is_dir(follow_symlinks=False) and not os.listdir(e.path):
                                    os.rmdir(_long(e.path))
                            except OSError:
                                continue
                except OSError:
                    continue

        logw.flush()
        elapsed = time.time() - t0
        free_after_map = _disk_snapshot(roots_all)
        free_before = sum(free_before_map.values())
        free_after = sum(free_after_map.values())
        status = "cancelled" if _cancel_event.is_set() else "done"
        detail = {"results": results, "notes": notes, "reasons": all_reasons,
                  "reason_text": {k: REASON_TEXT.get(k, k) for k in all_reasons},
                  "free_before": free_before, "free_after": free_after,
                  "freed_bytes": totals["freed_bytes"]}
        with _state_lock:
            _state["phase"] = status
            _state["finished"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            _state["notes"] = notes
            _state["results"] = list(results)
            _state["totals"] = dict(totals)
            _state["progress"].update({"pct": 100, "processed": processed,
                                       "total": total_items, "eta_s": 0,
                                       "elapsed": round(elapsed, 1)})
        conn.execute(
            "UPDATE clean_runs SET finished=?, status=?, candidates=?, deleted=?, "
            "skipped=?, failed=?, freed_bytes=?, scanned_bytes=?, detail=?, "
            "duration_s=?, free_before=?, free_after=? WHERE id=?",
            (_state["finished"], status,
             totals["candidates"], totals["deleted"], totals["skipped"],
             totals["failed"], totals["freed_bytes"], totals["scanned_bytes"],
             json.dumps(detail, ensure_ascii=False), round(elapsed, 2),
             free_before, free_after, run_id))
        conn.commit()
    except Exception as e:
        try:
            logw.flush()
        except Exception:
            pass
        with _state_lock:
            _state["phase"] = "error"
            _state["error"] = "%s: %s" % (type(e).__name__, e)
            _state["finished"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        if run_id:
            try:
                conn.execute("UPDATE clean_runs SET status='error', finished=?, error=? "
                             "WHERE id=?",
                             (_state["finished"], _state["error"], run_id))
                conn.commit()
            except sqlite3.Error:
                pass
    finally:
        conn.close()


def cancel():
    _cancel_event.set()
    with _state_lock:
        _state["cancel"] = True
    return {"ok": True, "phase": "cancelling"}


def status():
    """轮询接口：纯内存读取，不碰数据库（v3 每次轮询要建两次连接、跑一次建表脚本）"""
    with _state_lock:
        s = dict(_state)
        s.pop("cancel", None)
        s["cancel_requested"] = _cancel_event.is_set()
    s["policy_accepted"] = get_policy()
    s["excludes_count"] = len(_load_excludes())
    return s


def list_categories():
    out = []
    for rule in _rules():
        roots = [os.path.expandvars(r) for r in rule["roots"]]
        exists = [os.path.isdir(r) for r in roots]
        out.append({"id": rule["id"], "name": rule["name"], "desc": rule["desc"],
                    "roots": roots, "min_age_days": rule.get("min_age_days", 0),
                    "group": rule.get("group", ""), "impact": rule.get("impact", ""),
                    "roots_exist": exists,
                    "in_default": rule["id"] in DEFAULT_CATEGORY_IDS})
    return out


def get_excludes_info():
    """排除名单现状（只读展示；新增条目只能编辑本地文件）"""
    path = EXCLUDES_PATH
    items = _load_excludes()
    return {"path": path, "exists": os.path.isfile(path), "count": len(items),
            "items": items[:200],
            "hint": "每行一个路径前缀，# 开头为注释。只能编辑该本地文件，网页端无权写入。"}


def _hsize(n):
    v = float(n)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if v < 1024 or unit == "TB":
            return ("%.0f %s" % (v, unit)) if unit == "B" else ("%.1f %s" % (v, unit))
        v /= 1024.0
    return str(n)
