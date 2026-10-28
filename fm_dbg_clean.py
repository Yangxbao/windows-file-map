# -*- coding: utf-8 -*-
"""针对沙盒清理 run 的取证调试"""
import os
import sys
import json
import time
import uuid
import sqlite3
import tempfile

sys.stdout.reconfigure(encoding="utf-8", errors="replace")
TOOL_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, TOOL_DIR)
import fm_scan
import fm_clean

TEST_DB = os.path.join(tempfile.gettempdir(), "fm_dbg_%s.db" % uuid.uuid4().hex[:8])
fm_scan.DB_PATH = TEST_DB
fm_clean.DB_PATH = TEST_DB

sandbox = os.path.join(tempfile.gettempdir(), "fm_sbx_dbg")
import shutil
shutil.rmtree(sandbox, ignore_errors=True)
os.makedirs(sandbox, exist_ok=True)
old_ts = time.time() - 3 * 86400

old_file = os.path.join(sandbox, "old_普通文件.txt")
with open(old_file, "wb") as f:
    f.write(b"x" * 1024)
os.utime(old_file, (old_ts, old_ts))
deep = os.path.join(sandbox, "deep")
os.makedirs(deep, exist_ok=True)
df = os.path.join(deep, "deep_file.bin")
with open(df, "wb") as f:
    f.write(b"y" * 2048)
os.utime(df, (old_ts, old_ts))
os.utime(deep, (old_ts, old_ts))

RULES = [{"id": "user_temp", "name": "测试", "desc": "", "roots": [sandbox],
          "mode": "children", "include": None, "min_age_days": 1}]
fm_clean._rules = lambda: RULES

print("== scan ==")
r = fm_clean.scan(["user_temp"])
for c in r["results"][0]["items"]:
    print("  候选:", c["path"], c["size"])

print("== run ==")
fm_clean.run(["user_temp"])
for _ in range(100):
    st = fm_clean.status()
    if st["phase"] in ("done", "error", "cancelled"):
        break
    time.sleep(0.1)
st = fm_clean.status()
print("phase:", st["phase"], "error:", st.get("error"))
print("totals:", st["totals"])
print("results:", json.dumps(st["results"], ensure_ascii=False, indent=1))

conn = sqlite3.connect(TEST_DB)
print("== clean_log ==")
for row in conn.execute("SELECT rule_id, path, size, status, reason FROM clean_log"):
    print("  ", row)
conn.close()
print("old_file 存在:", os.path.exists(old_file))
shutil.rmtree(sandbox, ignore_errors=True)
for s in ("", "-wal", "-shm"):
    if os.path.exists(TEST_DB + s):
        os.remove(TEST_DB + s)
