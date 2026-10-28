# -*- coding: utf-8 -*-
"""fm_scan.py 的冒烟测试：扫描本工具目录（只读）到临时库，校验 parent 一致性与聚合守恒"""
import os
import sys
import sqlite3

sys.stdout.reconfigure(encoding="utf-8", errors="replace")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fm_scan as fs

TMP_DB = os.path.join(os.environ.get("TEMP", "."), "fm_smoke_test.db")
fs.DB_PATH = TMP_DB
for s in ("", "-wal", "-shm"):
    if os.path.exists(TMP_DB + s):
        os.remove(TMP_DB + s)

store = fs.Store(fresh=True)
try:
    store.insert(("D:\\", "", "D:", 1, 0, None, None, None, None, 0, 0,
                  None, None, None, "sys", "测试盘", "高"))
    store.conn.commit()
    fs.scan_dir(store, "D:\\文件地图助手", 1, False, False)
    store.flush()
    fs.aggregate(store)

    bad = store.conn.execute(
        "SELECT COUNT(*) FROM entries e WHERE e.parent!='' "
        "AND NOT EXISTS (SELECT 1 FROM entries d WHERE d.path=e.parent)").fetchone()[0]
    row = store.conn.execute(
        "SELECT size FROM entries WHERE path='D:\\'").fetchone()
    assert row is not None, "盘符行不存在"
    root_size = row[0]
    tool = store.conn.execute(
        "SELECT size FROM entries WHERE path='D:\\文件地图助手'").fetchone()
    assert tool is not None, "工具目录行不存在"
    tool_size = tool[0]
    dirs_with_children = store.conn.execute(
        "SELECT COUNT(*) FROM entries d WHERE d.is_dir=1 "
        "AND NOT EXISTS (SELECT 1 FROM entries c WHERE c.parent=d.path)").fetchone()[0]
    print("parent 不一致行数:", bad)
    print("盘符聚合大小:", root_size, "工具目录大小:", tool_size)
    print("叶子目录(空)数量:", dirs_with_children)
    assert bad == 0, "parent 存在不一致"
    assert root_size == tool_size, "聚合不守恒（%s != %s）" % (root_size, tool_size)
    assert root_size > 1000000, "聚合大小异常"
    print("冒烟测试通过 ✓（parent 一致、聚合守恒、大小合理）")
finally:
    store.close()
    for s in ("", "-wal", "-shm"):
        if os.path.exists(TMP_DB + s):
            try:
                os.remove(TMP_DB + s)
            except OSError:
                pass
