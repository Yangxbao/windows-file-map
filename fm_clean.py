# -*- coding: utf-8 -*-
"""
本机文件地图与一键清理助手 · 安全清理引擎 (fm_clean.py)
=====================================================
设计原则（与第三方清理器对齐的部分见 THIRD_PARTY_NOTICES.md）：
  * 白名单驱动：只清理本文件中【明确列出】的规则目录与文件模式；
    前端只能传"规则 ID"，永远不能传路径或命令。
  * 与文件地图模块完全隔离：本模块独立维护路径校验与删除逻辑，
    不共享任何任意路径删除接口。
  * 不跟随符号链接/目录联接（reparse point 一律跳过，绝不进入）。
  * 每个被删除的文件都记录到 fmdata.db 的 clean_log（可追溯到规则）。
  * 被占用/只读/权限不足的对象一律跳过并记录原因，绝不扩大范围、
    绝不结束进程、绝不修改权限。
  * 取消安全：收到取消信号后不再开始任何新的删除。

安全边界（最高优先级）：
  * 永不触碰：个人目录（桌面/文档/下载/图片/视频）、任何项目与仓库、
    .git/.env/源代码、node_modules/target/build/dist、浏览器用户数据、
    回收站、Windows Installer、注册表、系统组件、分页/休眠文件。
  * 默认规则只有"明确安全且可重新生成"的临时文件与缓存，逐条人工核对过路径。
"""

import os
import fnmatch
import threading
import sqlite3
import time
import json
from datetime import datetime

import fm_scan  # 复用其 DB 路径与工具目录常量（只取常量，不共用删除逻辑）

DB_PATH = fm_scan.DB_PATH

F_REPARSE = 0x400
F_DIR = 0x10

# ---------------------------------------------------------------------------
# 白名单规则定义（唯一授权来源；新增规则必须经过人工核对）
# id 同时是前端可传的唯一合法参数
# ---------------------------------------------------------------------------
def _env(p):
    return os.path.expandvars(p) if p else p


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
            "mode": "children",          # 只清理 root 的子条目，不删 root 本身
            "include": None,             # 全部匹配（仍受时间/占用/链接保护约束）
            "min_age_days": 1,
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
        },
        {
            "id": "thumbcache",
            "name": "缩略图缓存",
            "desc": "资源管理器缩略图缓存（thumbcache_*.db），删除后浏览文件夹时会自动重建。"
                    "Explorer 正在运行时这些文件通常被占用，会被如实记为跳过。",
            "roots": [os.path.join(local, "Microsoft", "Windows", "Explorer")],
            "mode": "matches",
            "include": ["thumbcache_*.db"],
            "min_age_days": 0,
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
        },
        {
            "id": "wer_reports",
            "name": "Windows 错误报告队列",
            "desc": "Windows 错误报告（WER）的 ReportQueue/ReportArchive 中超过 7 天的旧报告，"
                    "与系统错误诊断系统相同，普通权限下无法删除的部分会跳过。",
            "roots": [os.path.join(programdata, "Microsoft", "Windows", "WER", "ReportQueue"),
                      os.path.join(programdata, "Microsoft", "Windows", "WER", "ReportArchive")],
            "mode": "children",
            "include": None,
            "min_age_days": 7,
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

_policy_lock = threading.Lock()
_state_lock = threading.Lock()
_state = {"phase": "idle", "mode": None, "categories": [], "started": None,
          "finished": None, "cancel": False, "results": [], "error": None,
          "run_id": None, "totals": {}}
_cancel_event = threading.Event()
_db_lock = threading.Lock()


# ---------------------------------------------------------------------------
# 数据库（独立读写连接；只写本工具目录内的 fmdata.db）
# ---------------------------------------------------------------------------
def _init_db(conn):
    conn.executescript("""
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
    """)
    conn.commit()


def _db():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False, timeout=15)
    conn.execute("PRAGMA busy_timeout=15000")
    _init_db(conn)
    return conn


def get_policy():
    with _db_lock:
        conn = _db()
        try:
            row = conn.execute("SELECT v FROM meta WHERE k='clean_policy_accepted'").fetchone()
            return bool(row and row[0] == "1")
        finally:
            conn.close()


def set_policy():
    with _db_lock:
        conn = _db()
        try:
            conn.execute("INSERT OR REPLACE INTO meta(k,v) VALUES('clean_policy_accepted','1')")
            conn.commit()
        finally:
            conn.close()


def get_history(limit=50):
    with _db_lock:
        conn = _db()
        try:
            rows = conn.execute(
                "SELECT * FROM clean_runs ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
            return [dict(r) for r in rows]
        finally:
            conn.close()


def get_run_log(run_id, limit=2000):
    with _db_lock:
        conn = _db()
        try:
            rows = conn.execute(
                "SELECT rule_id, path, size, status, reason, ts FROM clean_log "
                "WHERE run_id=? ORDER BY id LIMIT ?", (run_id, limit)).fetchall()
            return [dict(r) for r in rows]
        finally:
            conn.close()


# ---------------------------------------------------------------------------
# 路径与删除保护（核心安全层）
# ---------------------------------------------------------------------------
def _norm(p):
    return os.path.normcase(os.path.normpath(p))


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


def _delete_file(path):
    """删除单个文件；返回 (True, size) 或 (False, 原因)"""
    st = os.stat(path, follow_symlinks=False)
    if _is_reparse(st):
        return False, "符号链接/联接，跳过"
    size = st.st_size
    try:
        os.remove(path)
        return True, size
    except PermissionError:
        return False, "被占用或权限不足，已跳过"
    except FileNotFoundError:
        return False, "文件已不存在（跳过）"
    except OSError as e:
        return False, "删除失败：%s" % e


def _delete_tree(path, rule, on_event):
    """删除目录内容（不跟随任何 reparse point）。返回 (deleted, skipped, failed, freed)。"""
    deleted = skipped = failed = 0
    freed = 0
    stack = [path]
    while stack:
        if _cancel_event.is_set():
            return deleted, skipped, failed, freed, True
        cur = stack.pop()
        try:
            with os.scandir(cur) as it:
                entries = list(it)
        except PermissionError:
            failed += 1
            on_event(cur, "failed", "目录枚举被拒绝")
            continue
        except FileNotFoundError:
            continue
        except OSError as e:
            failed += 1
            on_event(cur, "failed", "目录枚举失败：%s" % e)
            continue
        removable = True
        for e in entries:
            if _cancel_event.is_set():
                return deleted, skipped, failed, freed, True
            try:
                st = e.stat(follow_symlinks=False)
            except OSError as ex:
                failed += 1
                on_event(e.path, "failed", "读取元数据失败：%s" % ex)
                continue
            if _is_reparse(st):
                skipped += 1
                on_event(e.path, "skipped", "符号链接/目录联接，不跟随")
                removable = False
                continue
            if st.st_file_attributes & F_DIR:
                stack.append(e.path)
            else:
                ok, info = _delete_file(e.path)
                if ok:
                    deleted += 1
                    freed += info
                    on_event(e.path, "deleted", info)
                else:
                    skipped += 1
                    on_event(e.path, "skipped", info)
                    removable = False
        if not removable:
            continue  # 内容未清空则不删目录本身
        try:
            os.rmdir(cur)
        except OSError:
            pass  # 目录非空或被占用：保留目录，不报为失败（内容级结果已记录）
    return deleted, skipped, failed, freed, False


# ---------------------------------------------------------------------------
# 扫描（只读预览）
# ---------------------------------------------------------------------------
def _iter_candidates(rule):
    """按规则枚举候选对象。返回 (candidates, notes)。不删除任何东西。"""
    candidates = []
    notes = []
    now = time.time()
    min_age = rule.get("min_age_days", 0) * 86400
    for root in rule["roots"]:
        root = os.path.expandvars(root)
        if not os.path.isdir(root):
            notes.append("目录不存在（%s）：本机可能没有该缓存，属正常" % root)
            continue
        try:
            with os.scandir(root) as it:
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
            if st.st_file_attributes & F_DIR:
                size = _dir_size_quick(e.path)
            else:
                size = st.st_size
            candidates.append({"path": e.path, "name": e.name,
                               "is_dir": bool(st.st_file_attributes & F_DIR),
                               "size": size, "mtime": int(st.st_mtime)})
    return candidates, notes


def _dir_size_quick(path):
    total = 0
    stack = [path]
    count = 0
    while stack and count < 20000:
        cur = stack.pop()
        try:
            with os.scandir(cur) as it:
                for e in it:
                    count += 1
                    if count >= 20000:
                        return total
                    st = e.stat(follow_symlinks=False)
                    if _is_reparse(st):
                        continue
                    if st.st_file_attributes & F_DIR:
                        stack.append(e.path)
                    else:
                        total += st.st_size
        except OSError:
            continue
    return total


def scan(rule_ids):
    results = []
    total_count = 0
    total_bytes = 0
    notes = []
    for rule in _rules():
        if rule["id"] not in rule_ids:
            continue
        cands, note = _iter_candidates(rule)
        notes.extend(["[%s] %s" % (rule["name"], n) for n in note])
        c_bytes = sum(c["size"] for c in cands)
        results.append({"id": rule["id"], "name": rule["name"], "desc": rule["desc"],
                        "candidates": len(cands), "bytes": c_bytes,
                        "items": cands[:50]})
        total_count += len(cands)
        total_bytes += c_bytes
    return {"ok": True, "phase": "scan_done", "results": results,
            "totals": {"candidates": total_count, "bytes": total_bytes}, "notes": notes}


# ---------------------------------------------------------------------------
# 执行清理（白名单 + 全程日志 + 可取消）
# ---------------------------------------------------------------------------
def run(rule_ids):
    with _state_lock:
        if _state["phase"] not in ("idle", "done", "cancelled", "error", "scan_done"):
            return {"ok": False, "error": "已有清理任务在执行中，请等待完成后再试"}
        _state.update({"phase": "running", "mode": "run", "categories": list(rule_ids),
                       "started": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                       "finished": None, "cancel": False, "results": [], "error": None,
                       "totals": {"candidates": 0, "deleted": 0, "skipped": 0,
                                  "failed": 0, "freed_bytes": 0, "scanned_bytes": 0}})
    _cancel_event.clear()
    t = threading.Thread(target=_run_impl, args=(rule_ids,), daemon=True)
    t.start()
    return {"ok": True, "phase": "running"}


def _run_impl(rule_ids):
    conn = _db()
    run_id = None
    try:
        cur = conn.execute(
            "INSERT INTO clean_runs(started, finished, mode, status, categories) "
            "VALUES(?,?,?,?,?)",
            (_state["started"], None, "run", "running", json.dumps(rule_ids)))
        conn.commit()
        run_id = cur.lastrowid
        with _state_lock:
            _state["run_id"] = run_id

        def log(rule_id, path, size, status, reason):
            with _db_lock:
                conn.execute(
                    "INSERT INTO clean_log(run_id, rule_id, path, size, status, reason, ts) "
                    "VALUES(?,?,?,?,?,?,?)",
                    (run_id, rule_id, path, size, status, reason, time.time()))
            conn.commit()

        for rule in _rules():
            if rule["id"] not in rule_ids:
                continue
            if _cancel_event.is_set():
                break
            with _state_lock:
                _state["phase"] = "running:" + rule["id"]
            cands, _notes = _iter_candidates(rule)
            with _state_lock:
                _state["totals"]["candidates"] += len(cands)
                _state["totals"]["scanned_bytes"] += sum(c["size"] for c in cands)
            cat_result = {"id": rule["id"], "name": rule["name"], "candidates": len(cands),
                          "deleted": 0, "skipped": 0, "failed": 0, "freed_bytes": 0}
            for c in cands:
                if _cancel_event.is_set():
                    break
                roots = [os.path.expandvars(r) for r in rule["roots"]]
                if not any(_in_root(c["path"], root) for root in roots):
                    # 双重校验：任何候选必须仍位于该规则的某个授权根目录内
                    cat_result["skipped"] += 1
                    log(rule["id"], c["path"], c["size"], "skipped", "路径校验未通过（安全保护）")
                    continue
                if c["is_dir"]:
                    d, s, f, freed, cancelled = _delete_tree(
                        c["path"], rule,
                        lambda p, st, info, rid=rule["id"]:
                            log(rid, p, info if st == "deleted" else None, st,
                                None if st == "deleted" else info))
                    cat_result["deleted"] += d
                    cat_result["skipped"] += s
                    cat_result["failed"] += f
                    cat_result["freed_bytes"] += freed
                    with _state_lock:
                        _state["totals"]["deleted"] += d
                        _state["totals"]["skipped"] += s
                        _state["totals"]["failed"] += f
                        _state["totals"]["freed_bytes"] += freed
                    log(rule["id"], c["path"] + "（目录）", None,
                        "dir_done" if not cancelled else "dir_partial",
                        "已清理 %d 个文件，释放 %s" % (d, _hsize(freed)))
                else:
                    ok, info = _delete_file(c["path"])
                    if ok:
                        cat_result["deleted"] += 1
                        cat_result["freed_bytes"] += info
                        with _state_lock:
                            _state["totals"]["deleted"] += 1
                            _state["totals"]["freed_bytes"] += info
                        log(rule["id"], c["path"], info, "deleted", None)
                    else:
                        cat_result["skipped"] += 1
                        with _state_lock:
                            _state["totals"]["skipped"] += 1
                        log(rule["id"], c["path"], None, "skipped", info)
            with _state_lock:
                _state["results"].append(cat_result)

        status = "cancelled" if _cancel_event.is_set() else "done"
        with _state_lock:
            _state["phase"] = status
            _state["finished"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        conn.execute(
            "UPDATE clean_runs SET finished=?, status=?, candidates=?, deleted=?, "
            "skipped=?, failed=?, freed_bytes=?, scanned_bytes=? WHERE id=?",
            (_state["finished"], status,
             _state["totals"]["candidates"], _state["totals"]["deleted"],
             _state["totals"]["skipped"], _state["totals"]["failed"],
             _state["totals"]["freed_bytes"], _state["totals"]["scanned_bytes"], run_id))
        conn.commit()
    except Exception as e:
        with _state_lock:
            _state["phase"] = "error"
            _state["error"] = str(e)
            _state["finished"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        if run_id:
            conn.execute("UPDATE clean_runs SET status='error', finished=? WHERE id=?",
                         (_state["finished"], run_id))
            conn.commit()
    finally:
        conn.close()


def cancel():
    _cancel_event.set()
    with _state_lock:
        _state["cancel"] = True
    return {"ok": True, "phase": "cancelling"}


def status():
    with _state_lock:
        s = dict(_state)
        s.pop("cancel", None)
        s["policy_accepted"] = get_policy()
        s["cancel_requested"] = _cancel_event.is_set()
    return s


def list_categories():
    out = []
    for rule in _rules():
        roots = [os.path.expandvars(r) for r in rule["roots"]]
        out.append({"id": rule["id"], "name": rule["name"], "desc": rule["desc"],
                    "roots": roots, "min_age_days": rule.get("min_age_days", 0),
                    "in_default": rule["id"] in DEFAULT_CATEGORY_IDS})
    return out


def _hsize(n):
    v = float(n)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if v < 1024 or unit == "TB":
            return ("%.0f %s" % (v, unit)) if unit == "B" else ("%.1f %s" % (v, unit))
        v /= 1024.0
    return str(n)
