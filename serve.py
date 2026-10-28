# -*- coding: utf-8 -*-
"""
文件地图助手 · 本地服务 v2 (serve.py)
=====================================
在 127.0.0.1 上提供：
  1. index.html 网页与本目录静态文件；
  2. 基于 SQLite（fmdata.db，WAL 模式）的分页数据 API：
     /api/summary  总览统计       /api/children?path=&offset=  分页子目录清单
     /api/node?path= 单条详情     /api/search?q=&offset=       服务端搜索
     /api/projects /api/risk /api/events /api/progress
  3. /api/open —— 调用 Windows 资源管理器打开目录（白名单校验）。

安全说明：仅监听 127.0.0.1；/api/open 只允许打开数据库中记录过的路径；
数据库以只读方式打开；本服务不修改任何被扫描文件。
"""

import os
import sys
import json
import time
import sqlite3
import threading
import webbrowser
import subprocess
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fm_kb as kb
import fm_clean

TOOL_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(TOOL_DIR, "fmdata.db")
PROGRESS_PATH = os.path.join(TOOL_DIR, "scan_progress.json")
PORT_START = 8618
PORT = PORT_START  # main() 绑定成功后回写，用于 Host/Origin 校验

MIME = {
    ".html": "text/html; charset=utf-8", ".js": "text/javascript; charset=utf-8",
    ".css": "text/css; charset=utf-8", ".json": "application/json; charset=utf-8",
    ".csv": "text/csv; charset=utf-8", ".md": "text/plain; charset=utf-8",
    ".txt": "text/plain; charset=utf-8", ".db": "application/octet-stream",
}


def db_connect():
    conn = sqlite3.connect("file:%s?mode=ro" % DB_PATH.replace("\\", "/"), uri=True)
    conn.row_factory = sqlite3.Row
    return conn


def load_known_roots():
    try:
        conn = db_connect()
        rows = conn.execute("SELECT path FROM entries WHERE depth=0").fetchall()
        conn.close()
        return {os.path.normcase(r["path"].rstrip("\\")) + "\\" for r in rows}
    except sqlite3.Error:
        return set()


KNOWN_ROOTS = load_known_roots()


def q_escape(s):
    return s.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    # ---------------- 来源校验（防 DNS 重绑定 / 跨站调用） ----------------
    def _check_origin(self):
        """清理类等会改动本机状态的接口必须来自本机页面"""
        host = (self.headers.get("Host") or "").lower()
        if host not in ("127.0.0.1:%d" % PORT, "localhost:%d" % PORT):
            return "Host 头异常（%s），已拒绝" % host[:80]
        origin = self.headers.get("Origin")
        if origin and origin.lower() not in (
                "http://127.0.0.1:%d" % PORT, "http://localhost:%d" % PORT):
            return "Origin 来源异常（%s），已拒绝" % origin[:80]
        return None

    def _send(self, code, body, ctype="application/json; charset=utf-8"):
        b = body.encode("utf-8") if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(b)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        try:
            self.wfile.write(b)
        except OSError:
            pass

    def _json(self, obj, code=200):
        self._send(code, json.dumps(obj, ensure_ascii=False))

    # ---------------- API ----------------
    def api_summary(self):
        try:
            conn = db_connect()
        except sqlite3.Error as e:
            return self._json({"ok": False, "error": "数据库无法读取：%s" % e})
        try:
            meta = {}
            for r in conn.execute("SELECT k, v FROM meta"):
                meta[r["k"]] = json.loads(r["v"])
            risk = meta.pop("risk_json", {})
            meta["risk_top"] = (risk.get("bigdirs") or [])[:12]
            meta["cat_sizes"] = risk.get("cat_sizes") or []
            meta["ext_table"] = kb.EXT_TABLE
            meta["ok"] = True
            return self._json(meta)
        finally:
            conn.close()

    def api_children(self, qs):
        path = (qs.get("path") or [""])[0]
        try:
            offset = max(0, int((qs.get("offset") or ["0"])[0]))
            limit = min(500, max(1, int((qs.get("limit") or ["200"])[0])))
        except ValueError:
            offset, limit = 0, 200
        conn = db_connect()
        try:
            total = conn.execute("SELECT COUNT(*) FROM entries WHERE parent=?",
                                 (path,)).fetchone()[0]
            rows = conn.execute(
                "SELECT path,name,is_dir,size,mtime,ctime,attrs,flags,scanned,err,"
                "link_target,n_children,cat,zh,conf FROM entries WHERE parent=? "
                "ORDER BY is_dir DESC, name COLLATE NOCASE LIMIT ? OFFSET ?",
                (path, limit, offset)).fetchall()
            node = conn.execute(
                "SELECT path,name,is_dir,size,mtime,flags,scanned,err,n_children,cat,zh,conf "
                "FROM entries WHERE path=?", (path,)).fetchone()
            return self._json({
                "ok": True, "total": total, "offset": offset, "limit": limit,
                "node": dict(node) if node else None,
                "items": [dict(r) for r in rows]})
        finally:
            conn.close()

    def api_node(self, qs):
        path = (qs.get("path") or [""])[0]
        conn = db_connect()
        try:
            node = conn.execute(
                "SELECT * FROM entries WHERE path=?", (path,)).fetchone()
            if not node:
                return self._json({"ok": False, "error": "路径不在数据库中"}, 404)
            proj = conn.execute("SELECT * FROM projects WHERE path=?", (path,)).fetchone()
            return self._json({"ok": True, "node": dict(node),
                               "project": dict(proj) if proj else None})
        finally:
            conn.close()

    def api_search(self, qs):
        raw = (qs.get("q") or [""])[0].strip()
        try:
            offset = max(0, int((qs.get("offset") or ["0"])[0]))
        except ValueError:
            offset = 0
        limit = 200
        if not raw:
            return self._json({"ok": True, "total": 0, "items": []})
        like = "%" + q_escape(raw) + "%"
        conn = db_connect()
        try:
            total = conn.execute(
                "SELECT COUNT(*) FROM entries WHERE name LIKE ? ESCAPE '\\' "
                "OR zh LIKE ? ESCAPE '\\' OR path LIKE ? ESCAPE '\\'", (like, like, like)
            ).fetchone()[0]
            rows = conn.execute(
                "SELECT path,name,is_dir,size,mtime,flags,scanned,cat,zh,conf FROM entries "
                "WHERE name LIKE ? ESCAPE '\\' OR zh LIKE ? ESCAPE '\\' OR path LIKE ? ESCAPE '\\' "
                "ORDER BY is_dir DESC, length(path) LIMIT ? OFFSET ?",
                (like, like, like, limit, offset)).fetchall()
            return self._json({"ok": True, "total": total, "offset": offset,
                               "limit": limit, "items": [dict(r) for r in rows]})
        finally:
            conn.close()

    def api_projects(self, qs):
        kind = (qs.get("kind") or ["ok"])[0]
        conn = db_connect()
        try:
            if kind == "pending":
                rows = conn.execute("SELECT * FROM projects WHERE ptype='unknown' "
                                    "ORDER BY path").fetchall()
            else:
                rows = conn.execute("SELECT * FROM projects WHERE ptype!='unknown' "
                                    "ORDER BY size DESC").fetchall()
            return self._json({"ok": True, "items": [dict(r) for r in rows]})
        finally:
            conn.close()

    def api_risk(self):
        conn = db_connect()
        try:
            r = conn.execute("SELECT v FROM meta WHERE k='risk_json'").fetchone()
            if not r:
                return self._json({"ok": False, "error": "风险数据未生成，请重新运行扫描"}, 404)
            return self._json(dict(json.loads(r[0]), ok=True))
        finally:
            conn.close()

    def api_events(self, qs):
        kind = (qs.get("kind") or ["denied"])[0]
        conn = db_connect()
        try:
            rows = conn.execute("SELECT ts, path, detail FROM events WHERE kind=? "
                                "ORDER BY id LIMIT 300", (kind,)).fetchall()
            total = conn.execute("SELECT COUNT(*) FROM events WHERE kind=?",
                                 (kind,)).fetchone()[0]
            return self._json({"ok": True, "kind": kind, "total": total,
                               "items": [dict(r) for r in rows]})
        finally:
            conn.close()

    def api_progress(self):
        try:
            with open(PROGRESS_PATH, encoding="utf-8") as f:
                return self._json(dict(json.load(f), ok=True))
        except OSError:
            return self._json({"ok": False, "error": "没有进行中的扫描"})

    def api_open(self, qs):
        target = (qs.get("path") or [""])[0]
        if not target:
            return self._json({"ok": False, "error": "缺少 path 参数"}, 400)
        norm = urllib.parse.unquote(target)
        normc = os.path.normcase(os.path.normpath(norm))
        hit = any(normc == r or normc.startswith(r) for r in KNOWN_ROOTS)
        if not hit:
            conn = None
            try:
                conn = db_connect()
                row = conn.execute("SELECT 1 FROM entries WHERE path=? LIMIT 1",
                                   (normc,)).fetchone()
                hit = row is not None
            except sqlite3.Error:
                pass
            finally:
                if conn:
                    conn.close()
        if not hit:
            return self._json({"ok": False,
                               "error": "该路径不在本次扫描记录中，为安全起见拒绝打开"}, 403)
        if not os.path.exists(norm):
            return self._json({"ok": False, "error": "路径不存在（可能已被移动或删除）"}, 404)
        try:
            if os.path.isdir(norm):
                os.startfile(norm)
            else:
                subprocess.Popen(["explorer", "/select," + norm])
            return self._json({"ok": True})
        except Exception as e:
            return self._json({"ok": False, "error": str(e)}, 500)

    # ---------------- 路由 ----------------
    # ---------------- 清理模块 API（只接受规则 ID，绝不接受路径） ----------------
    def api_clean_categories(self):
        return self._json({"ok": True, "categories": fm_clean.list_categories(),
                           "default_ids": fm_clean.DEFAULT_CATEGORY_IDS,
                           "never_clean": fm_clean.NEVER_CLEAN_TEXT,
                           "policy_accepted": fm_clean.get_policy()})

    def api_clean_status(self):
        return self._json(fm_clean.status())

    def api_clean_history(self):
        return self._json({"ok": True, "items": fm_clean.get_history(50)})

    def api_clean_log(self, qs):
        try:
            run_id = int((qs.get("run_id") or ["0"])[0])
        except ValueError:
            return self._json({"ok": False, "error": "run_id 不合法"}, 400)
        return self._json({"ok": True, "items": fm_clean.get_run_log(run_id)})

    def do_POST(self):
        u = urllib.parse.urlparse(self.path)
        path = urllib.parse.unquote(u.path)
        bad = self._check_origin()
        if bad:
            return self._json({"ok": False, "error": bad}, 403)
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            length = 0
        if length > 64 * 1024:
            return self._json({"ok": False, "error": "请求体过大"}, 400)
        try:
            body = json.loads(self.rfile.read(length).decode("utf-8")) if length else {}
        except (ValueError, UnicodeDecodeError):
            return self._json({"ok": False, "error": "请求体不是合法 JSON"}, 400)
        if not isinstance(body, dict):
            return self._json({"ok": False, "error": "请求体必须是 JSON 对象"}, 400)

        if path == "/api/clean/enable":
            # 一次性确认：记录用户已知晓并启用安全清理范围
            fm_clean.set_policy()
            return self._json({"ok": True, "policy_accepted": True})

        if path in ("/api/clean/scan", "/api/clean/run"):
            if "paths" in body or "path" in body:
                return self._json(
                    {"ok": False, "error": "出于安全考虑，清理接口不接受任何路径参数，"
                                           "只能选择预定义的清理类别"}, 400)
            cats = body.get("categories")
            if cats is None:
                cats = fm_clean.DEFAULT_CATEGORY_IDS
            if not isinstance(cats, list) or not cats or \
                    not all(isinstance(c, str) for c in cats):
                return self._json({"ok": False, "error": "categories 必须是非空字符串数组"}, 400)
            known = {r["id"] for r in fm_clean._rules()}
            unknown = [c for c in cats if c not in known]
            if unknown:
                return self._json({"ok": False,
                                   "error": "未知的清理类别：%s" % "、".join(unknown)}, 400)
            if path == "/api/clean/scan":
                result = fm_clean.scan(cats)
                return self._json(result)
            # run 需要一次性确认已启用
            if not fm_clean.get_policy():
                return self._json(
                    {"ok": False, "error": "尚未确认启用安全清理。请先在页面上查看清理范围并"
                                           "点击「启用安全清理」（一次性确认）。"}, 403)
            return self._json(fm_clean.run(cats))

        if path == "/api/clean/cancel":
            return self._json(fm_clean.cancel())

        return self._json({"ok": False, "error": "未知接口"}, 404)

    def do_GET(self):
        u = urllib.parse.urlparse(self.path)
        path = urllib.parse.unquote(u.path)
        qs = urllib.parse.parse_qs(u.query)
        # 会改动本机状态的接口（打开资源管理器）同样做来源校验
        if path == "/api/open":
            bad = self._check_origin()
            if bad:
                return self._json({"ok": False, "error": bad}, 403)
        try:
            if path == "/api/summary":
                return self.api_summary()
            if path == "/api/children":
                return self.api_children(qs)
            if path == "/api/node":
                return self.api_node(qs)
            if path == "/api/search":
                return self.api_search(qs)
            if path == "/api/projects":
                return self.api_projects(qs)
            if path == "/api/risk":
                return self.api_risk()
            if path == "/api/events":
                return self.api_events(qs)
            if path == "/api/progress":
                return self.api_progress()
            if path == "/api/clean/categories":
                return self.api_clean_categories()
            if path == "/api/clean/status":
                return self.api_clean_status()
            if path == "/api/clean/history":
                return self.api_clean_history()
            if path == "/api/clean/log":
                return self.api_clean_log(qs)
            if path == "/api/open":
                return self.api_open(qs)
            if path == "/api/ping":
                return self._json({"ok": True, "helper": True})
            if path == "/server-mode.js":
                return self._send(200, "window.HAS_HELPER=true;",
                                  "text/javascript; charset=utf-8")
        except sqlite3.Error as e:
            return self._json({"ok": False, "error": "数据库错误：%s" % e}, 500)
        # ---- 静态文件 ----
        rel = path.lstrip("/") or "index.html"
        f = os.path.abspath(os.path.join(TOOL_DIR, rel))
        if not f.startswith(os.path.abspath(TOOL_DIR)) or not os.path.isfile(f):
            return self._send(404, "404 not found", "text/plain; charset=utf-8")
        ext = os.path.splitext(f)[1].lower()
        try:
            with open(f, "rb") as fp:
                body = fp.read()
        except OSError as e:
            return self._send(500, str(e), "text/plain; charset=utf-8")
        self.send_response(200)
        self.send_header("Content-Type", MIME.get(ext, "application/octet-stream"))
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        try:
            self.wfile.write(body)
        except OSError:
            pass


def main():
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    if not os.path.isfile(os.path.join(TOOL_DIR, "index.html")):
        print("未找到 index.html，请确认本脚本位于文件地图助手目录内。")
        return 1
    if not os.path.exists(DB_PATH):
        print("提示：尚未生成 fmdata.db，请先运行 fm_scan.py（或双击 重新扫描.bat）。"
              "网页将显示引导信息。")
    port = PORT_START
    srv = None
    for _ in range(20):
        try:
            srv = ThreadingHTTPServer(("127.0.0.1", port), Handler)
            break
        except OSError:
            port += 1
    if srv is None:
        print("无法绑定本地端口（8618-8637 均被占用）。")
        return 1
    global PORT
    PORT = port
    url = "http://127.0.0.1:%d/" % port
    print("=" * 54)
    print("  文件地图助手 · 本地服务已启动（只读）")
    print("  地址：%s" % url)
    print("  关闭此窗口即停止服务；扫描期间也可打开本页面实时查看进度。")
    print("=" * 54)
    threading.Timer(0.8, lambda: webbrowser.open(url)).start()
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    print("服务已停止。")
    return 0


if __name__ == "__main__":
    sys.exit(main())
