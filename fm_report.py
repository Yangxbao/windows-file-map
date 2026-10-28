# -*- coding: utf-8 -*-
"""
文件地图助手 · 报告生成器 v2 (fm_report.py)
=============================================
从 fmdata.db（SQLite）读取扫描结果，全部输出只写入本工具目录：
  * 目录总览_第N部分.csv —— 完整目录与文件清单（每 100 万行一卷，便于 Excel 分卷打开）
  * 扫描范围与遗漏.md    —— 三层完成度（目录枚举/元数据/用途分析）、排除清单、错误分类
  * 项目识别报告.md      —— 识别出的项目、判断依据、待识别项目
  * 安全与整理建议.md    —— 仅分析建议，不执行任何操作
  * meta 表 risk_json    —— 网页"空间与风险"页所需的分析数据
"""

import os
import csv
import sys
import json
import sqlite3
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fm_kb as kb

TOOL_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(TOOL_DIR, "fmdata.db")

CSV_ROWS_PER_PART = 1000000   # Excel 单表上限 1048576 行，按 100 万行分卷


def hsize(n):
    if n is None:
        return "未统计"
    v = float(n)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if v < 1024 or unit == "TB":
            return ("%.0f %s" % (v, unit)) if unit == "B" else ("%.1f %s" % (v, unit))
        v /= 1024.0
    return str(n)


def ftime(m):
    if not m:
        return ""
    try:
        return datetime.fromtimestamp(m).strftime("%Y-%m-%d %H:%M")
    except Exception:
        return ""


def flag_names(f, scanned):
    out = []
    if f & kb.F_DENIED:
        out.append("拒绝访问")
    if f & kb.F_LINK:
        out.append("链接未跟随")
    if f & kb.F_SENS:
        out.append("疑似敏感")
    if f & kb.F_EST:
        out.append("大小不完整")
    if f & kb.F_SKIP:
        out.append("规则排除")
    if scanned == kb.S_FAIL:
        out.append("枚举失败")
    elif scanned == kb.S_PART:
        out.append("部分扫描")
    elif scanned == kb.S_EXCL:
        out.append("未枚举内容")
    elif scanned == kb.S_GONE:
        out.append("已不存在")
    return "、".join(out)


SCANNED_LABEL = {kb.S_NONE: "未扫描", kb.S_DONE: "完成", kb.S_PART: "部分扫描",
                 kb.S_FAIL: "失败", kb.S_EXCL: "规则排除", kb.S_GONE: "已不存在"}


class DB:
    def __init__(self):
        self.conn = sqlite3.connect(DB_PATH)
        self.conn.row_factory = sqlite3.Row

    def q(self, sql, *a):
        if len(a) == 1 and isinstance(a[0], (tuple, list)):
            a = tuple(a[0])
        return self.conn.execute(sql, a).fetchall()

    def one(self, sql, *a):
        if len(a) == 1 and isinstance(a[0], (tuple, list)):
            a = tuple(a[0])
        return self.conn.execute(sql, a).fetchone()[0]

    def meta(self, key, default=None):
        r = self.conn.execute("SELECT v FROM meta WHERE k=?", (key,)).fetchone()
        return json.loads(r[0]) if r else default


def get_meta(db):
    return {
        "stats": db.meta("stats", {}),
        "drives": db.meta("drives", []),
        "scanned_at": db.meta("scanned_at", "?"),
        "duration_s": db.meta("duration_s", 0),
        "version": db.meta("version", kb.VERSION),
        "user": db.meta("user", ""),
        "admin_retry": db.meta("admin_retry"),
    }


# ---------------- CSV 分卷导出 ----------------

def export_csv(db):
    cur = db.conn.execute(
        "SELECT is_dir, name, zh, cat, path, substr(path,1,2), size, mtime, flags, scanned, "
        "err, link_target, n_children, attrs, conf FROM entries "
        "ORDER BY path COLLATE NOCASE")
    header = ["类型", "名称", "中文说明", "类别", "完整路径", "所在磁盘", "大小(字节)", "大小显示",
              "最后修改时间", "枚举状态", "扫描标记", "备注/错误", "链接目标", "子条目数", "用途置信度"]
    part = 1
    rows_in_part = 0
    total = 0
    wf = None
    writer = None
    path = None

    def new_writer():
        nonlocal part, rows_in_part, wf, writer, path
        path = os.path.join(TOOL_DIR, "目录总览_第%d部分.csv" % part)
        wf = open(path, "w", encoding="utf-8-sig", newline="")
        writer = csv.writer(wf)
        writer.writerow(header)
        rows_in_part = 0

    new_writer()
    for r in cur:
        if rows_in_part >= CSV_ROWS_PER_PART:
            wf.close()
            print("已生成 %s" % path)
            part += 1
            new_writer()
        size, mtime, flags, scanned = r[6], r[7], r[8], r[9]
        zh = r[2]
        if not zh and not r[0]:
            ext = kb.ext_of(r[1])
            zh = kb.EXT_TABLE.get(ext, ("", ""))[1] or ""
        note = r[10] or ""
        writer.writerow([
            "目录" if r[0] else "文件", r[1], zh, kb.CAT_LABELS.get(r[3], r[3] or ""),
            r[4], r[5], "" if size is None else size, hsize(size), ftime(mtime),
            SCANNED_LABEL.get(scanned, str(scanned)), flag_names(flags, scanned),
            note, r[11] or "", "" if r[12] is None else r[12], r[14] or "",
        ])
        rows_in_part += 1
        total += 1
    wf.close()
    print("已生成 %s（本卷 %d 行）" % (path, rows_in_part))
    print("CSV 导出完成：共 %d 行、%d 个分卷" % (total, part))
    return total, part


# ---------------- 项目/风险分析 ----------------

def analyze(db):
    stats = db.meta("stats", {})
    # 大目录 TOP（排除祖先包含关系）
    rows = db.q("SELECT path, size, flags FROM entries WHERE is_dir=1 AND depth>=1 "
                "AND size IS NOT NULL AND size>=209715200 ORDER BY size DESC LIMIT 400")
    big = []
    for r in rows:
        if any(r["path"].startswith(b["p"].rstrip("\\") + "\\") for b in big):
            continue
        big.append({"p": r["path"], "s": r["size"], "est": bool(r["flags"] & kb.F_EST)})
        if len(big) >= 40:
            break
    deps = [{"p": r["path"], "s": r["size"], "c": r["cat"]} for r in db.q(
        "SELECT path, size, cat FROM entries WHERE is_dir=1 AND depth>=1 AND size>=52428800 "
        "AND cat IN ('deps','build','cache','git') ORDER BY size DESC LIMIT 40")]
    dups = [{"name": n, "size": s, "count": c, "paths": json.loads(p)} for n, s, c, p in db.q(
        "SELECT lower(name) n, size s, COUNT(*) c, json_group_array(path) p FROM entries "
        "WHERE is_dir=0 AND size>=52428800 GROUP BY lower(name), size HAVING c>=2 "
        "ORDER BY s DESC LIMIT 200")]
    # 同级目录名称相似组（流式按 parent 分组）
    similar = []
    cur = db.conn.execute(
        "SELECT parent, name, path, size, flags, scanned FROM entries WHERE is_dir=1 "
        "AND scanned=? AND flags=0 ORDER BY parent, name COLLATE NOCASE", (kb.S_DONE,))
    cur_parent, bucket = None, []
    for r in cur:
        if r["parent"] != cur_parent:
            if cur_parent is not None and len(bucket) >= 2:
                groups = {}
                for b in bucket:
                    groups.setdefault(kb.norm_name(b["name"]), []).append(b)
                for k2, v in groups.items():
                    if len(v) >= 2 and len(similar) < 120:
                        similar.append({"kind": "同级目录名称相似", "norm": k2, "parent": cur_parent,
                                        "members": [{"name": m["name"], "path": m["path"],
                                                     "size": m["size"]} for m in v]})
            cur_parent = r["parent"]
            bucket = []
        bucket.append(r)
    if cur_parent is not None and len(bucket) >= 2:
        groups = {}
        for b in bucket:
            groups.setdefault(kb.norm_name(b["name"]), []).append(b)
        for k2, v in groups.items():
            if len(v) >= 2 and len(similar) < 120:
                similar.append({"kind": "同级目录名称相似", "norm": k2, "parent": cur_parent,
                                "members": [{"name": m["name"], "path": m["path"],
                                             "size": m["size"]} for m in v]})
    # 项目名称相似
    projs = db.q("SELECT name, path, size, ptype FROM projects")
    byname = {}
    for p in projs:
        byname.setdefault(kb.norm_name(p["name"]), []).append(p)
    for k2, v in byname.items():
        if len(v) >= 2 and len(similar) < 200:
            similar.append({"kind": "项目名称相似", "norm": k2,
                            "members": [{"name": x["name"], "path": x["path"],
                                         "size": x["size"]} for x in v]})
    unknown = [{"p": r["path"], "s": r["size"]} for r in db.q(
        "SELECT path, size FROM entries WHERE is_dir=1 AND cat='unknown' AND scanned=? "
        "AND depth>=1 AND depth<=4 ORDER BY size DESC LIMIT 60", (kb.S_DONE,))]
    sens = [r["path"] for r in db.q(
        "SELECT path FROM entries WHERE flags & ? ORDER BY path LIMIT 200", (kb.F_SENS,))]
    incomplete = [{"path": r["path"], "typezh": kb.TYPE_ZH.get(r["ptype"], r["ptype"])}
                  for r in db.q("SELECT path, ptype FROM projects "
                                "WHERE ptype NOT IN ('unknown') AND (srcs='[]' OR srcs IS NULL)")]
    cat_sizes = [{"c": r["c"], "s": r["s"]} for r in db.q(
        "SELECT cat c, SUM(size) s FROM entries WHERE depth=1 AND is_dir=1 "
        "AND size IS NOT NULL GROUP BY cat ORDER BY s DESC")]
    risk = {"bigdirs": big, "depdirs": deps, "dup_candidates": dups, "similar_groups": similar,
            "unknown_dirs": unknown, "sens_files": sens, "incomplete_projects": incomplete,
            "cat_sizes": cat_sizes}
    db.conn.execute("INSERT OR REPLACE INTO meta(k,v) VALUES('risk_json', ?)",
                    (json.dumps(risk, ensure_ascii=False),))
    db.conn.commit()
    return risk


# ---------------- Markdown 报告 ----------------

def write_scope_md(db, meta, risk):
    st = meta["stats"]
    lines = []
    a = lines.append
    a("# 扫描范围与遗漏说明")
    a("")
    a("> 本文件由文件地图助手 v%s 自动生成于 %s（扫描模式：%s，耗时 %.0f 秒）。"
      % (meta["version"], meta["scanned_at"], st.get("mode", "full"), meta["duration_s"]))
    a("")
    a("**三层完成度声明（请勿混为一谈）：**")
    a("")
    a("| 层级 | 含义 | 本次结果 |")
    a("|---|---|---|")
    a("| ① 目录枚举 | 列出目录下的全部子条目名称 | 完成枚举的目录 **%d** 个；枚举失败 **%d** 个；规则排除 **%d** 个 |"
      % (st.get("dirs_done", 0), st.get("dirs_fail", 0), st.get("dirs_excl", 0)))
    a("| ② 文件元数据 | 读取每个文件的大小/时间/属性 | 成功 **%d** 个文件；失败 **%d** 个 |"
      % (st.get("files_meta_ok", 0), st.get("files_meta_fail", 0)))
    a("| ③ 用途分析 | 依据标识文件/名称/结构推断用途 | 项目 **%d** 个 + 待识别 **%d** 个（不保证项目可运行） |"
      % (st.get("projects", 0), st.get("pending", 0)))
    a("")
    a("## 一、扫描方式")
    a("")
    a("- 对全部本地固定磁盘做**无上限递归枚举**：没有单目录条目上限、没有递归深度上限、没有全局条目上限；")
    a("- 系统目录（Windows、Program Files、ProgramData）、软件安装目录、`node_modules`/`.git`/`target` 等")
    a("  大型依赖目录**同样逐级枚举**其目录树与文件清单（只读元数据，不读取文件内容）；")
    a("- 每个目录记录：子条目数量、枚举状态（完成/失败/排除）；每个文件记录：大小、创建/修改时间、属性；")
    a("- 目录大小为**自底向上实测汇总**（非估算 API）；子树内存在无法访问部分时标记「大小不完整」，数值为已确认部分的下限。")
    a("")
    a("## 二、磁盘与覆盖情况")
    a("")
    a("| 磁盘 | 类型 | 总容量 | 可用 | 盘点数据量 | 目录数 | 文件数 |")
    a("|---|---|---|---|---|---|---|")
    for d in meta["drives"]:
        a("| %s: | %s | %s | %s | %s | %s | %s |" % (
            d["letter"], d["type"], hsize(d["total"]), hsize(d["free"]),
            hsize(d.get("bytes")) if d.get("scanned") else "未扫描",
            "{:,}".format(d.get("dirs", 0)) if d.get("scanned") else "—",
            "{:,}".format(d.get("files", 0)) if d.get("scanned") else "—"))
    a("")
    a("## 三、明确排除的目录（逐条列出，绝不笼统标注）")
    a("")
    a("| 排除规则 | 理由 | 本次命中 |")
    a("|---|---|---|")
    a("| 各盘 `$Recycle.Bin` | 回收站内容具有特殊删除语义，读取易产生误导 | 见 events 表 kind=excluded |")
    a("| 各盘 `System Volume Information` | 系统还原点/卷影副本，普通权限本就无法访问 | 同上 |")
    a("| 本工具自身目录 | 数据库与报告所在，避免自我扫描 | 同上 |")
    a("")
    a("## 四、访问失败与错误分类")
    a("")
    a("| 错误类别 | 次数 | 说明 |")
    a("|---|---|---|")
    for k in ("denied", "missing", "locked", "longpath", "readlink", "ioerror", "excluded"):
        cnt = st.get("events_by_kind", {}).get(k, 0)
        a("| %s | %d | %s |" % (k, cnt, kb.ERR_LABELS.get(k, "按规则排除")))
    a("")
    a("- 「denied（拒绝访问）」均为普通权限下的真实拒绝，未使用任何提权/改权限手段；")
    a("- 如需减少拒绝访问，可用**管理员终端**运行 `python fm_scan.py --admin-retry`，"
      "它只会对记录在案的失败目录做**只读**定向重试（建议先关闭本工具的网页服务）；")
    a("- 重试仍失败的目录将保留错误记录，本报告不会宣称其已扫描。")
    a("")
    a("## 五、数据规模与完整性")
    a("")
    a("| 指标 | 数值 |")
    a("|---|---|")
    a("| 数据库记录总行数 | {:,} |".format(st.get("rows", 0)))
    a("| 目录枚举完成 | {:,} |".format(st.get("dirs_done", 0)))
    a("| 枚举中断（可 --resume 续扫） | {:,} |".format(st.get("dirs_part", 0)))
    a("| 枚举失败 | {:,} |".format(st.get("dirs_fail", 0)))
    a("| 规则排除 | {:,} |".format(st.get("dirs_excl", 0)))
    a("| 文件元数据成功 | {:,} |".format(st.get("files_meta_ok", 0)))
    a("| 文件元数据失败 | {:,} |".format(st.get("files_meta_fail", 0)))
    a("| 大小不完整的目录（含无法访问子树） | {:,} |".format(st.get("flags_est", 0)))
    a("| 符号链接/联接（已记录目标，未跟随） | {:,} |".format(st.get("flags_link", 0)))
    a("| 疑似敏感文件（未读取内容） | {:,} |".format(st.get("flags_sens", 0)))
    a("")
    a("**本报告如实反映扫描结果：能访问的已全部枚举；不能访问的逐条记录原因；"
      "没有任何位置被「假装扫描过」。**")

    path = os.path.join(TOOL_DIR, "扫描范围与遗漏.md")
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    return path


def write_projects_md(db, meta):
    lines = []
    a = lines.append
    a("# 项目识别报告")
    a("")
    a("> 生成于 %s。识别只依据**目录结构、标识文件（pom.xml/package.json/go.mod 等）开头片段、"
      "README 摘要与 .git 存在性**，全程未运行任何项目代码，不保证任何项目可运行。"
      % meta["scanned_at"])
    a("")
    rows = db.q("SELECT * FROM projects WHERE ptype != 'unknown' ORDER BY "
                "CASE conf WHEN '高' THEN 0 WHEN '中' THEN 1 ELSE 2 END, size DESC")
    bytype = {}
    for p in rows:
        bytype.setdefault(kb.TYPE_ZH.get(p["ptype"], p["ptype"]), []).append(p)
    a("## 一、汇总（共 %d 个项目）" % len(rows))
    a("")
    a("| 项目类型 | 数量 |")
    a("|---|---|")
    for k in sorted(bytype, key=lambda x: -len(bytype[x])):
        a("| %s | %d |" % (k, len(bytype[k])))
    a("")
    a("## 二、项目明细")
    a("")
    order = {"springboot": 0, "maven": 1, "gradle": 2, "django": 3, "python": 4, "vue": 5,
             "react": 6, "electron": 7, "nodejs": 8, "go": 9, "rust": 10, "dotnet": 11,
             "php": 12, "static": 13, "gitrepo": 14}
    for p in sorted(rows, key=lambda x: (order.get(x["ptype"], 99), -(x["size"] or 0))):
        a("### %s —— %s" % (p["name"], kb.TYPE_ZH.get(p["ptype"], p["ptype"])))
        a("")
        a("- **完整路径**：`%s`" % p["path"])
        a("- **大小**：%s　**最后修改**：%s" % (hsize(p["size"]), ftime(p["mtime"])))
        a("- **Git 仓库**：%s　**置信度**：%s" % ("是" if p["git"] else "否", p["conf"]))
        if p["brief"]:
            a("- **项目说明**：%s" % p["brief"])
        for label, col in (("主要入口", "entry"), ("配置文件", "configs"), ("源代码目录", "srcs"),
                           ("文档目录", "docs"), ("依赖目录", "deps"), ("编译产物", "builds")):
            vals = json.loads(p[col] or "[]")
            if vals:
                a("- **%s**：%s" % (label, "、".join(vals)))
        a("- **识别依据**：%s" % "；".join(json.loads(p["basis"] or "[]")))
        a("")
    pend = db.q("SELECT * FROM projects WHERE ptype = 'unknown' ORDER BY path")
    a("## 三、待识别项目（疑似代码目录，用途需人工确认）")
    a("")
    if not pend:
        a("（无）")
    for p in pend:
        a("- `%s` —— %s" % (p["path"], "；".join(json.loads(p["basis"] or "[]"))))
    a("")
    risk = json.loads(db.conn.execute("SELECT v FROM meta WHERE k='risk_json'").fetchone()[0])
    a("## 四、名称相似 / 可能多版本的项目")
    a("")
    sim = [g for g in risk.get("similar_groups", []) if g["kind"] == "项目名称相似"]
    if not sim:
        a("（未发现）")
    for g in sim:
        a("- 相似名称「%s」：%s" % (g["norm"], "；".join("`%s`" % m["path"] for m in g["members"])))
    a("")
    path = os.path.join(TOOL_DIR, "项目识别报告.md")
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    return path


def write_advice_md(db, meta, risk):
    lines = []
    a = lines.append
    a("# 安全与整理建议")
    a("")
    a("> 生成于 %s。**本工具是只读盘点工具：以下只是观察与建议，没有执行、也不会执行任何"
      "删除/重命名/移动操作。**" % meta["scanned_at"])
    a("")
    a("## 一、占用空间最大的目录 TOP%d（实测汇总，≥200MB）" % len(risk["bigdirs"]))
    a("")
    for b in risk["bigdirs"]:
        a("- **%s** `%s`%s" % (hsize(b["s"]), b["p"], "（大小不完整，为下限）" if b["est"] else ""))
    a("")
    a("## 二、依赖与编译产物目录（可重建，删除前请确认项目不再使用）")
    a("")
    for d in risk["depdirs"]:
        a("- %s `%s`（%s）" % (hsize(d["s"]), d["p"], kb.CAT_LABELS.get(d["c"], d["c"])))
    a("")
    a("## 三、名称相似 / 可能多版本的目录组")
    a("")
    if not risk["similar_groups"]:
        a("（未发现）")
    for g in risk["similar_groups"][:80]:
        a("- **%s**（%s）：%s" % (g["norm"], g["kind"],
                                  "；".join("`%s`（%s）" % (m["path"], hsize(m["size"])) for m in g["members"])))
    a("")
    a("## 四、重复文件候选（名称+大小一致；未计算哈希，仅供参考）")
    a("")
    if not risk["dup_candidates"]:
        a("（未发现 50MB 以上同名同大小文件）")
    for d in risk["dup_candidates"][:50]:
        a("- `%s`（%s，共 %d 处）：%s" % (d["name"], hsize(d["size"]), d["count"],
                                          "；".join("`%s`" % p for p in d["paths"])))
    a("")
    a("## 五、用途待确认的目录（已检查名称/结构/标识文件，证据仍不足）")
    a("")
    if not risk["unknown_dirs"]:
        a("（无）")
    for u in risk["unknown_dirs"]:
        a("- `%s`（%s）" % (u["p"], hsize(u["s"])))
    a("")
    a("## 六、疑似不完整 / 失效的项目（未发现源代码目录）")
    a("")
    if not risk["incomplete_projects"]:
        a("（无）")
    for p in risk["incomplete_projects"]:
        a("- `%s`（%s）" % (p["path"], p["typezh"]))
    a("")
    a("## 七、疑似敏感文件位置（仅路径，内容未读取）")
    a("")
    for p in risk["sens_files"][:120]:
        a("- `%s`" % p)
    if len(risk["sens_files"]) > 120:
        a("- …（其余 %d 条见数据库 events/entries，网页可搜索「疑似敏感」）"
          % (len(risk["sens_files"]) - 120))
    a("")
    a("## 八、建议的下一步")
    a("")
    a("1. 在网页地图中逐个确认「用途待确认」目录；")
    a("2. 对相似目录确认新旧版本；")
    a("3. 确认后再决定是否进入实际整理阶段（届时仍会逐项征求确认）。")

    path = os.path.join(TOOL_DIR, "安全与整理建议.md")
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    return path


def generate():
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    db = DB()
    meta = get_meta(db)
    if not meta["stats"]:
        print("数据库为空，请先运行 fm_scan.py。")
        return
    print("… 生成风险分析数据 …", flush=True)
    risk = analyze(db)
    print("… 导出全量 CSV（分卷）…", flush=True)
    total, parts = export_csv(db)
    db.conn.execute("INSERT OR REPLACE INTO meta(k,v) VALUES('csv_parts', ?)",
                    (json.dumps({"parts": parts, "rows": total}),))
    db.conn.commit()
    p1 = write_scope_md(db, meta, risk)
    print("已生成 %s" % p1)
    p2 = write_projects_md(db, meta)
    print("已生成 %s" % p2)
    p3 = write_advice_md(db, meta, risk)
    print("已生成 %s" % p3)
    print("报告生成完毕。")


if __name__ == "__main__":
    generate()
