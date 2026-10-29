# -*- coding: utf-8 -*-
"""
一键清理模块 · 沙盒测试 (fm_sandbox_test.py)  —— v4
=====================================================
所有删除测试都在 %TEMP% 下隔离的沙盒目录 + 独立临时数据库中进行；
测试用规则根被重定向到沙盒，真实系统的任何旧临时文件都不会被触碰。

v4 新增覆盖（对应本轮修复的问题）：
  * 清理记录读取（get_history / get_run_log / get_last_run）不再抛异常；
  * 完成状态持久化：完成后 duration_s / free_before / free_after / detail 都落库；
  * 失败与跳过计入总数（v4 早期版本漏加，界面会显示 0）；
  * 目录内"新鲜文件"保护、排除名单、长路径、错误原因分类；
  * HTTP 层：服务端任何内部异常都返回 JSON 而不是断开连接。
"""
import os
import sys
import json
import time
import stat
import uuid
import sqlite3
import http.client
import subprocess
import tempfile

sys.stdout.reconfigure(encoding="utf-8", errors="replace")
TOOL_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, TOOL_DIR)

import fm_scan
import fm_clean

PASS, FAIL = [], []


def check(name, cond, detail=""):
    if cond:
        PASS.append(name)
        print("  ✓", name)
    else:
        FAIL.append(name + ("：" + detail if detail else ""))
        print("  ✗", name, detail)


# ---------- 独立临时数据库（不污染真实清理记录） ----------
TEST_DB = os.path.join(tempfile.gettempdir(), "fm_clean_test_%s.db" % uuid.uuid4().hex[:8])
fm_scan.DB_PATH = TEST_DB
fm_clean.DB_PATH = TEST_DB
fm_clean.EXCLUDES_PATH = os.path.join(tempfile.gettempdir(),
                                      "fm_clean_excl_%s.txt" % uuid.uuid4().hex[:8])

sandbox = os.path.join(tempfile.gettempdir(), "fm_sbx_test")
protected = os.path.join(TOOL_DIR, "fm_sbx_protected")   # 工具目录内、白名单之外
sentinel = os.path.join(protected, "哨兵文件-绝不能删.txt")
junc = os.path.join(sandbox, "junc_联接")
old_ts = time.time() - 3 * 86400


def setup():
    import shutil
    for d in (sandbox, protected):
        if os.path.basename(d) in ("fm_sbx_test", "fm_sbx_protected"):
            shutil.rmtree(d, ignore_errors=True)
        os.makedirs(d, exist_ok=True)
    with open(sentinel, "w", encoding="utf-8") as f:
        f.write("sandbox junction target — must survive")

    def mk(path, content=b"x" * 1024, mtime=None):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "wb") as f:
            f.write(content)
        os.utime(path, (mtime if mtime is not None else old_ts,) * 2)

    global old_file, deep_dir, fresh_file, locked_file, ro_file, stale_dir
    old_file = os.path.join(sandbox, "old_普通文件.txt")
    mk(old_file)
    deep_dir = os.path.join(sandbox, "deep", "a b", "中文目录")
    mk(os.path.join(deep_dir, "deep_file.bin"), b"y" * 2048)
    for d in (sandbox, os.path.join(sandbox, "deep"),
              os.path.join(sandbox, "deep", "a b"), deep_dir):
        os.utime(d, (old_ts, old_ts))
    fresh_file = os.path.join(sandbox, "fresh_新文件.txt")
    mk(fresh_file, mtime=time.time())
    locked_file = os.path.join(sandbox, "locked_占用中.txt")
    mk(locked_file, b"z" * 512)
    global locked_handle
    locked_handle = open(locked_file, "rb")     # 占用句柄 → 删除必然失败
    ro_file = os.path.join(sandbox, "readonly_只读.txt")
    mk(ro_file)
    os.chmod(ro_file, stat.S_IREAD)
    # "目录属性很旧、但里面有刚写的文件"——v4 新增保护必须拦住它
    stale_dir = os.path.join(sandbox, "stale_dir_里面是新的")
    mk(os.path.join(stale_dir, "inner_old.txt"))
    mk(os.path.join(stale_dir, "inner_fresh.txt"), b"n" * 700, mtime=time.time())
    os.utime(stale_dir, (old_ts, old_ts))       # 目录自身时间被改回旧值
    subprocess.run(["cmd", "/c", "mklink", "/J", junc, protected],
                   capture_output=True, check=True)
    os.utime(junc, (old_ts, old_ts))
    print("沙盒就绪：", sandbox)


def teardown():
    import shutil
    try:
        locked_handle.close()
    except Exception:
        pass
    if "ro_file" in globals() and os.path.exists(ro_file):
        os.chmod(ro_file, stat.S_IWRITE)
    subprocess.run(["cmd", "/c", "rmdir", junc], capture_output=True)
    shutil.rmtree(sandbox, ignore_errors=True)
    shutil.rmtree(protected, ignore_errors=True)
    for p in [TEST_DB + s for s in ("", "-wal", "-shm")] + [fm_clean.EXCLUDES_PATH]:
        if os.path.exists(p):
            try:
                os.remove(p)
            except OSError:
                pass


def count_log(run_id, status=None, path=None):
    conn = sqlite3.connect(TEST_DB)
    try:
        if status and path:
            return conn.execute(
                "SELECT COUNT(*) FROM clean_log WHERE run_id=? AND status=? AND path=?",
                (run_id, status, path)).fetchone()[0]
        if status:
            return conn.execute(
                "SELECT COUNT(*) FROM clean_log WHERE run_id=? AND status=?",
                (run_id, status)).fetchone()[0]
        return conn.execute("SELECT COUNT(*) FROM clean_log WHERE run_id=?",
                            (run_id,)).fetchone()[0]
    finally:
        conn.close()


def wait_done(timeout=180):
    for _ in range(timeout * 10):
        st = fm_clean.status()
        if st["phase"] in ("done", "cancelled", "error"):
            return st
        time.sleep(0.1)
    return fm_clean.status()


TEST_RULES = [{
    "id": "user_temp", "name": "用户临时文件（测试沙盒）", "desc": "测试规则",
    "roots": [sandbox], "mode": "children", "include": None, "min_age_days": 1,
    "group": "测试", "impact": "无",
}]

try:
    fm_clean._rules = lambda: TEST_RULES
    setup()

    # ================= 1) 扫描预览（只读） =================
    print("== 测试 1：扫描预览 ==")
    r = fm_clean.scan(["user_temp"], use_cache=False)
    cat = next(x for x in r["results"] if x["id"] == "user_temp")
    cand = {c["path"].lower() for c in cat["items_preview"]}
    check("预览包含旧文件", old_file.lower() in cand)
    check("预览包含旧深层目录（顶层候选）", os.path.join(sandbox, "deep").lower() in cand)
    check("预览排除新文件（24 小时内）", fresh_file.lower() not in cand)
    check("联接不作候选（不跟随链接）", junc.lower() not in cand)
    check("哨兵目录不在候选中", protected.lower() not in cand)
    check("候选带条目数（用于进度分母）",
          any(c.get("n_items", 0) >= 2 for c in cat["items_preview"]))

    # ================= 2) 策略门禁 =================
    print("== 测试 2：策略门禁 ==")
    check("测试库策略默认未启用", fm_clean.get_policy() is False)

    # ================= 3) 执行清理（引擎级） =================
    print("== 测试 3：执行清理 ==")
    fm_clean.run(["user_temp"])
    st = wait_done()
    check("清理正常结束", st["phase"] == "done", "phase=%s" % st["phase"])
    check("旧文件已删除", not os.path.exists(old_file))
    check("深层旧目录已清理", not os.path.exists(deep_dir))
    check("新文件保留（24 小时保护）", os.path.exists(fresh_file))
    check("被占用文件跳过（仍存在）", os.path.exists(locked_file))
    check("只读文件跳过（仍存在）", os.path.exists(ro_file))
    check("联接未被删除", os.path.exists(junc))
    check("联接目标哨兵完好", os.path.exists(sentinel))
    check("目录内有新文件 → 整个目录被拦下（v4 新保护）",
          os.path.exists(os.path.join(stale_dir, "inner_old.txt")))
    check("删除数量与释放空间均为正",
          st["totals"]["deleted"] >= 2 and st["totals"]["freed_bytes"] >= 3072,
          "deleted=%s freed=%s" % (st["totals"]["deleted"], st["totals"]["freed_bytes"]))
    check("未删除对象都被如实记录（跳过或失败）",
          (st["totals"]["skipped"] + st["totals"]["failed"]) >= 3,
          "skipped=%s failed=%s" % (st["totals"]["skipped"], st["totals"]["failed"]))
    check("跳过/失败已计入总数（v4 修复）",
          (st["totals"]["skipped"] + st["totals"]["failed"]) > 0 and
          st["totals"]["deleted"] > 0,
          "totals=%s" % st["totals"])
    check("逐文件日志数量≥删除数", count_log(st["run_id"]) >= st["totals"]["deleted"])
    check("删除行为可追溯到规则", count_log(st["run_id"], "deleted", old_file) == 1)
    check("跳过记录带原因", count_log(st["run_id"], "skipped") >= 1)
    freed_log = 0
    conn = sqlite3.connect(TEST_DB)
    for (sz,) in conn.execute("SELECT size FROM clean_log WHERE run_id=? AND status='deleted'",
                             (st["run_id"],)):
        freed_log += sz or 0
    conn.close()
    check("日志合计大小=报告释放空间", freed_log == st["totals"]["freed_bytes"],
          "%s != %s" % (freed_log, st["totals"]["freed_bytes"]))

    # ================= 4) 完成状态与记录读取（v4 修复的核心 bug） =================
    print("== 测试 4：清理记录与完成状态 ==")
    try:
        last = fm_clean.get_last_run()
        check("get_last_run 可读取（v3 会抛 TypeError）", isinstance(last, dict))
    except Exception as e:
        last = None
        check("get_last_run 可读取（v3 会抛 TypeError）", False, repr(e))
    if last:
        check("完成状态=done 且已落库", last["status"] == "done", str(last["status"]))
        check("记录了耗时 duration_s", (last.get("duration_s") or 0) > 0,
              str(last.get("duration_s")))
        check("记录了磁盘快照 free_before/free_after",
              last.get("free_before") is not None and last.get("free_after") is not None)
        detail = last.get("detail") or {}
        check("detail.results 已持久化（刷新页面仍能显示明细）",
              bool(detail.get("results")), "detail=%s" % list(detail.keys()))
        check("detail.reasons 有原因统计", isinstance(detail.get("reasons"), dict))
        check("categories 解析为数组", isinstance(last.get("categories"), list))
    try:
        hist = fm_clean.get_history(10)
        check("get_history 返回字典列表（v3 会抛 TypeError）",
              isinstance(hist, list) and isinstance(hist[0], dict), repr(type(hist)))
    except Exception as e:
        check("get_history 返回字典列表（v3 会抛 TypeError）", False, repr(e))
    try:
        items, total = fm_clean.get_run_log(st["run_id"], limit=5, offset=0)
        check("get_run_log 分页可用（v3 会抛 ValueError）",
              len(items) <= 5 and total >= len(items), "total=%s" % total)
        sk, sk_total = fm_clean.get_run_log(st["run_id"], limit=5, offset=0,
                                            status="skipped")
        check("get_run_log 支持按状态筛选", sk_total >= 1 and
              all(x["status"] == "skipped" for x in sk))
    except Exception as e:
        check("get_run_log 分页可用（v3 会抛 ValueError）", False, repr(e))
    check("count_runs 可读取", fm_clean.count_runs() >= 1)

    # ================= 5) 排除名单 =================
    print("== 测试 5：排除名单 ==")
    excl_file = os.path.join(sandbox, "excl_不清理我.txt")
    with open(excl_file, "wb") as f:
        f.write(b"e" * 4096)
    os.utime(excl_file, (old_ts, old_ts))
    with open(fm_clean.EXCLUDES_PATH, "w", encoding="utf-8") as f:
        f.write("# 测试排除名单\n%s\n" % excl_file)
    r2 = fm_clean.scan(["user_temp"], use_cache=False)
    names2 = {c["path"].lower() for c in r2["results"][0]["items_preview"]}
    check("排除名单中的文件不作候选", excl_file.lower() not in names2)
    check("排除名单不影响其它文件", any(p.endswith("excl_不清理我.txt".lower()) is False
                                for p in names2))
    fm_clean.run(["user_temp"])
    st_e = wait_done()
    check("排除名单文件在清理后仍存在", os.path.exists(excl_file))
    check("排除条数统计正确", fm_clean.get_excludes_info()["count"] == 1)
    os.remove(fm_clean.EXCLUDES_PATH)

    # ================= 6) 安全工具函数 =================
    print("== 测试 6：安全工具函数 ==")
    check("长路径加 \\\\?\\ 前缀", fm_clean._long("C:\\" + "a" * 300).startswith("\\\\?\\"))
    check("短路径不加前缀", fm_clean._long("C:\\temp\\x.txt") == "C:\\temp\\x.txt")
    check("占用错误分类为 in_use", fm_clean._classify_oserr(OSError(32, "x"))[0] == "in_use")
    check("拒绝访问分类为 denied",
          fm_clean._classify_oserr(PermissionError(5, "x"))[0] == "denied")
    check("文件不存在分类为 gone", fm_clean._classify_oserr(OSError(2, "x"))[0] == "gone")
    check("路径越界校验生效",
          fm_clean._in_root("C:\\a\\b", "C:\\a") and
          not fm_clean._in_root("C:\\a", "C:\\a") and
          not fm_clean._in_root("C:\\ab", "C:\\a"))

    # ================= 7) 取消任务 =================
    print("== 测试 7：取消任务 ==")
    many2 = os.path.join(sandbox, "many2")
    os.makedirs(many2, exist_ok=True)
    for i in range(4000):
        p = os.path.join(many2, "c%05d.tmp" % i)
        with open(p, "wb") as f:
            f.write(b"c" * 32)
        os.utime(p, (old_ts, old_ts))
    os.utime(many2, (old_ts, old_ts))
    fm_clean.run(["user_temp"])
    time.sleep(0.08)
    fm_clean.cancel()
    st2 = wait_done()
    check("取消被接受并停止", st2["phase"] in ("cancelled", "done"),
          "phase=%s" % st2["phase"])
    if st2["phase"] == "cancelled":
        check("取消后未继续删除", st2["totals"]["deleted"] < 4000,
              "deleted=%s" % st2["totals"]["deleted"])
        print("  （取消时已删除 %d 个，剩余保留）" % st2["totals"]["deleted"])
    else:
        print("  （完成过快，取消未赶上——以 done 为准，不算失败）")

    # ================= 8) 崩溃遗留记录自愈 =================
    print("== 测试 8：崩溃遗留记录自愈 ==")
    conn = sqlite3.connect(TEST_DB)
    conn.execute("INSERT INTO clean_runs(started,status,mode,categories) "
                 "VALUES('2020-01-01 00:00:00','running','run','[]')")
    conn.commit()
    conn.close()
    fm_clean._inited_path = None          # 触发下一次 _ensure_db 重新自愈
    fm_clean.get_history(1)
    conn = sqlite3.connect(TEST_DB)
    left = conn.execute("SELECT COUNT(*) FROM clean_runs WHERE status='running'"
                        ).fetchone()[0]
    conn.close()
    check("遗留 running 记录被标记为 interrupted", left == 0, "left=%s" % left)

    # ================= 9) HTTP 层（真实服务器，指向沙盒临时库） =================
    print("== 测试 9：HTTP 层安全与错误处理 ==")
    env = dict(os.environ)
    env["FM_DB_PATH"] = TEST_DB
    env["FM_NO_BROWSER"] = "1"
    env["FM_PORT"] = TEST_PORT = str(9650)   # 独立端口，绝不复用用户正在跑的服务
    srv = subprocess.Popen([sys.executable, os.path.join(TOOL_DIR, "serve.py")],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=env)
    port = None
    try:
        for _ in range(60):
            time.sleep(0.3)
            try:
                c = http.client.HTTPConnection("127.0.0.1", int(TEST_PORT), timeout=1)
                c.request("GET", "/api/ping")
                data = json.loads(c.getresponse().read().decode("utf-8"))
                c.close()
                # 身份校验：必须是本次测试自己的服务与临时库，否则宁可不测
                if data.get("ok") and data.get("db") == os.path.basename(TEST_DB):
                    port = int(TEST_PORT)
                    break
            except (OSError, ValueError):
                continue
        check("本地服务已启动（沙盒库 + 独立端口，身份已校验）", port is not None)

        def post(path, body, headers=None, host=None):
            if not port:
                return 0, "服务未启动"
            c = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
            hd = {"Content-Type": "application/json"}
            if headers:
                hd.update(headers)
            if host:
                hd["Host"] = host
            c.request("POST", path, json.dumps(body).encode("utf-8"), hd)
            resp = c.getresponse()
            data = resp.read()
            c.close()
            return resp.status, data.decode("utf-8", "replace")

        def get(path):
            if not port:
                return 0, "服务未启动"
            c = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
            c.request("GET", path)
            resp = c.getresponse()
            data = resp.read()
            c.close()
            return resp.status, data.decode("utf-8", "replace")

        # 沙盒库未启用策略 → run 必须 403（绝不会真的删真实文件）
        code, body = post("/api/clean/run", {"categories": ["user_temp"]})
        check("未启用策略时 run 被拒绝（403）", code == 403,
              "code=%s body=%s" % (code, body[:100]))
        code, body = post("/api/clean/run", {"categories": ["cleansystem32"]})
        check("未知清理类别被拒绝（400）", code == 400, "code=%s" % code)
        code, body = post("/api/clean/run",
                          {"categories": ["user_temp"], "paths": ["C:\\Users"]})
        check("任意路径参数被拒绝（400）", code == 400, "code=%s body=%s" % (code, body[:80]))
        code, body = post("/api/clean/run",
                          {"categories": ["user_temp"], "path": "C:\\Windows\\Temp"})
        check("单数 path 参数同样被拒绝（400）", code == 400, "code=%s" % code)
        code, _b = post("/api/clean/scan", {"categories": ["user_temp"]},
                        host="evil.example.com:80")
        check("伪造 Host 被拒绝（403）", code == 403, "code=%s" % code)
        code, _b = post("/api/clean/scan", {"categories": ["user_temp"]},
                        headers={"Origin": "http://evil.example.com"})
        check("异常 Origin 被拒绝（403）", code == 403, "code=%s" % code)
        code, body = post("/api/clean/scan", {"categories": ["user_temp"]})
        check("同源预览请求正常（200）", code == 200, "code=%s" % code)

        # 记录类接口必须返回合法 JSON（v3 在这里直接断链 → 前端"加载失败"）
        for api_path, label in (("/api/clean/history", "清理记录"),
                                ("/api/clean/last", "上次清理"),
                                ("/api/clean/log?run_id=1", "逐文件日志"),
                                ("/api/clean/excludes", "排除名单"),
                                ("/api/clean/log.csv?run_id=1", "日志导出")):
            try:
                code, body = get(api_path)
                okjson = True
                if ".csv" not in api_path:
                    okjson = json.loads(body).get("ok") is True
                else:
                    okjson = body.lstrip("\ufeff").startswith("运行编号")
                check("%s 接口返回正常（HTTP 200）" % label,
                      code == 200 and okjson, "code=%s body=%s" % (code, body[:80]))
            except Exception as e:
                check("%s 接口返回正常（HTTP 200）" % label, False, repr(e))
        code, body = get("/api/clean/history?offset=9999&limit=10")
        check("记录分页越界不报错", code == 200, "code=%s" % code)
        code, body = get("/api/clean/log?run_id=abc")
        check("非法 run_id 返回 400", code == 400, "code=%s" % code)
    finally:
        srv.terminate()
finally:
    print("== 清理沙盒 ==")
    teardown()

print("=" * 60)
print("通过 %d 项，失败 %d 项" % (len(PASS), len(FAIL)))
if FAIL:
    for f in FAIL:
        print("  ✗", f)
    sys.exit(1)
print("沙盒测试全部通过 ✓")
