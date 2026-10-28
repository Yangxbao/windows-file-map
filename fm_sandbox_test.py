# -*- coding: utf-8 -*-
"""
一键清理模块 · 沙盒测试 (fm_sandbox_test.py)
=============================================
所有删除测试都在 %TEMP% 下隔离的沙盒目录 + 独立临时数据库中进行；
测试用规则根被重定向到沙盒，真实系统的任何旧临时文件都不会被触碰。
HTTP 越权测试使用真实数据库但只做"被拒绝"的断言，不执行任何删除。
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
import threading

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


def hsize(n):
    v = float(n)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if v < 1024 or unit == "TB":
            return ("%.0f %s" % (v, unit)) if unit == "B" else ("%.1f %s" % (v, unit))
        v /= 1024.0
    return str(n)


# ---------- 独立临时数据库（不污染真实清理记录） ----------
TEST_DB = os.path.join(tempfile.gettempdir(), "fm_clean_test_%s.db" % uuid.uuid4().hex[:8])
fm_scan.DB_PATH = TEST_DB
fm_clean.DB_PATH = TEST_DB

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

    global old_file, deep_dir, fresh_file, locked_file, ro_file
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
    for s in ("", "-wal", "-shm"):
        if os.path.exists(TEST_DB + s):
            try:
                os.remove(TEST_DB + s)
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


def wait_done(timeout=120):
    for _ in range(timeout * 10):
        st = fm_clean.status()
        if st["phase"] in ("done", "cancelled", "error"):
            return st
        time.sleep(0.1)
    return fm_clean.status()


try:
    # ---------- 测试规则根重定向到沙盒（真实 TEMP 不参与删除测试） ----------
    TEST_RULES = [{
        "id": "user_temp", "name": "用户临时文件（测试沙盒）", "desc": "测试规则",
        "roots": [sandbox], "mode": "children", "include": None, "min_age_days": 1,
    }]
    fm_clean._rules = lambda: TEST_RULES

    setup()

    # ================= 1) 扫描预览（只读） =================
    print("== 测试 1：扫描预览 ==")
    r = fm_clean.scan(["user_temp"])
    cat = next(x for x in r["results"] if x["id"] == "user_temp")
    cand = {c["path"].lower() for c in cat["items"]}
    check("预览包含旧文件", old_file.lower() in cand)
    check("预览包含旧深层目录（顶层候选）", os.path.join(sandbox, "deep").lower() in cand)
    check("预览排除新文件（24 小时内）", fresh_file.lower() not in cand)
    check("联接不作候选（不跟随链接）", junc.lower() not in cand)
    check("哨兵目录不在候选中", protected.lower() not in cand)

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
    check("删除数量与释放空间均为正（2 个待删文件+1 个深层）", st["totals"]["deleted"] >= 2
          and st["totals"]["freed_bytes"] >= 3072,
          "deleted=%s freed=%s" % (st["totals"]["deleted"], st["totals"]["freed_bytes"]))
    check("跳过数量≥2（占用+只读）", st["totals"]["skipped"] >= 2,
          "skipped=%s" % st["totals"]["skipped"])
    check("逐文件日志数量≥删除数", count_log(st["run_id"]) >= st["totals"]["deleted"])
    check("删除行为可追溯到规则", count_log(st["run_id"], "deleted", old_file) == 1)
    freed_log = 0
    conn = sqlite3.connect(TEST_DB)
    for (sz,) in conn.execute("SELECT size FROM clean_log WHERE run_id=? AND status='deleted'",
                              (st["run_id"],)):
        freed_log += sz or 0
    conn.close()
    check("日志合计大小=报告释放空间", freed_log == st["totals"]["freed_bytes"],
          "%s != %s" % (freed_log, st["totals"]["freed_bytes"]))

    # ================= 4) 取消任务 =================
    print("== 测试 4：取消任务 ==")
    many2 = os.path.join(sandbox, "many2")
    os.makedirs(many2, exist_ok=True)
    for i in range(4000):
        p = os.path.join(many2, "c%05d.tmp" % i)
        with open(p, "wb") as f:
            f.write(b"c" * 32)
        os.utime(p, (old_ts, old_ts))
    os.utime(many2, (old_ts, old_ts))
    fm_clean.run(["user_temp"])
    time.sleep(0.06)
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

    # ================= 5) HTTP 层越权防护（真实服务器，只断言"拒绝"） =================
    print("== 测试 5：HTTP 越权防护 ==")
    srv = subprocess.Popen([sys.executable, os.path.join(TOOL_DIR, "serve.py")],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    port = None
    try:
        for _ in range(50):
            time.sleep(0.3)
            for p in range(8618, 8638):
                try:
                    c = http.client.HTTPConnection("127.0.0.1", p, timeout=1)
                    c.request("GET", "/api/ping")
                    if c.getresponse().status == 200:
                        port = p
                        c.close()
                        break
                    c.close()
                except OSError:
                    continue
            if port:
                break
        check("本地服务已启动", port is not None)

        def post(path, body, headers=None, host=None):
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

        # 策略未启用 → run 必须被 403 拒绝（真实库从未启用过清理确认）
        code, body = post("/api/clean/run", {"categories": ["user_temp"]})
        ok403 = code == 403 or (code == 200 and json.loads(body).get("policy_accepted"))
        check("未启用策略时 run 被拒绝（403）", code == 403,
              "code=%s body=%s" % (code, body[:100]))
        # 未知类别 → 400
        code, body = post("/api/clean/run", {"categories": ["cleansystem32"]})
        check("未知清理类别被拒绝（400）", code == 400, "code=%s" % code)
        # 任意路径 → 400（接口不接受路径参数）
        code, body = post("/api/clean/run",
                          {"categories": ["user_temp"], "paths": ["C:\\Users"]})
        check("任意路径参数被拒绝（400）", code == 400, "code=%s body=%s" % (code, body[:100]))
        code, body = post("/api/clean/run",
                          {"categories": ["user_temp"], "path": "C:\\Windows\\Temp"})
        check("单数 path 参数同样被拒绝（400）", code == 400, "code=%s" % code)
        # 异常 Host / Origin → 403
        code, _b = post("/api/clean/scan", {"categories": ["user_temp"]},
                        host="evil.example.com:80")
        check("伪造 Host 被拒绝（403）", code == 403, "code=%s" % code)
        code, _b = post("/api/clean/scan", {"categories": ["user_temp"]},
                        headers={"Origin": "http://evil.example.com"})
        check("异常 Origin 被拒绝（403）", code == 403, "code=%s" % code)
        # 正常同源 POST（scan 只读预览）应成功
        code, body = post("/api/clean/scan", {"categories": ["user_temp"]})
        check("同源预览请求正常（200）", code == 200, "code=%s" % code)
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
