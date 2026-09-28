#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""update_rules.py — 更新 skill 自带的独立规则库（CVE / Exploit-DB / nuclei 模板）

安全约束：所有写入目标都必须位于 skill 的 data/ 目录内。脚本在启动时会校验，
任何指向 skill 之外的路径都会直接拒绝执行 —— 规则库只写自己的 data/，不碰机器上别的东西。

用法:
    python3 update_rules.py --status        # 只看三套规则库当前版本（不联网）
    python3 update_rules.py --all           # 全部更新
    python3 update_rules.py --cve           # NVD 增量更新（推荐，几分钟）
    python3 update_rules.py --cve --full    # NVD 全量重建（数小时）
    python3 update_rules.py --exploit-db    # git pull Exploit-DB
    python3 update_rules.py --nuclei        # nuclei -update-templates

NVD API Key 解析顺序:
    环境变量 NVD_API_KEY  >  <skill>/data/nvd_api_key.txt
无 Key 时 NVD 限速 5 请求/30 秒，增量更新会明显变慢但依然可用。
"""

import argparse
import json
import os
import sqlite3
import subprocess
import sys
import time
import urllib.parse
import urllib.request

_SCRIPTS_DIR = os.path.dirname(os.path.abspath(__file__))
if _SCRIPTS_DIR not in sys.path:
    sys.path.insert(0, _SCRIPTS_DIR)

import config  # noqa: E402

DATA_DIR = os.path.realpath(config.DATA_DIR)
CVE_DB = os.path.realpath(config.CVE_DB_PATH)
EXPLOIT_DB = os.path.realpath(config.EXPLOIT_DB_DIR or "")
NUCLEI_TEMPLATES = os.path.realpath(config.NUCLEI_TEMPLATES or "")
NVD_FEED = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# TODO nuclei 模板是逐个小文件铺开的（现有 1.37 万个），整个 data/ 加起来 6 万多个文件；
#      拷到某些文件系统、或者被上层工具做硬链接预检时会撞文件数上限。
#      想过把模板打包成 tar、用的时候再解到临时目录，一直在等这版先跑完再说。


def _guard(path, label):
    """确保写入目标位于 skill 自己的 data/ 目录内。"""
    if not path or not path.startswith(DATA_DIR + os.sep):
        raise SystemExit(
            f"[拒绝] {label} 指向 skill 目录之外: {path}\n"
            f"        所有写入必须位于 {DATA_DIR} 内。"
        )
    return path


def _api_key():
    key = os.environ.get("NVD_API_KEY") or config.NVD_API_KEY
    if key:
        return key.strip()
    keyfile = os.path.join(DATA_DIR, "nvd_api_key.txt")
    if os.path.exists(keyfile):
        with open(keyfile, encoding="utf-8") as fh:
            return fh.read().strip()
    return ""


def _nvd_page(params, start_index, page_size):
    query = dict(params)
    query["startIndex"] = start_index
    query["resultsPerPage"] = page_size
    url = NVD_FEED + "?" + urllib.parse.urlencode(query)
    headers = {"User-Agent": "sec-assessment-rule-updater", "Accept": "application/json"}
    key = _api_key()
    if key:
        headers["apiKey"] = key
    req = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(req, timeout=120) as resp:
        data = json.loads(resp.read().decode("utf-8"))
    return data.get("vulnerabilities", []), data.get("totalResults", 0)


def _cve_row(item):
    cve = item.get("cve", {})
    cve_id = cve.get("id", "")
    if not cve_id:
        return None, [], {}
    desc = ""
    for d in cve.get("descriptions", []):
        if d.get("lang") == "en":
            desc = d.get("value", "")
            break
    score, severity, vector = 0, "", ""
    metrics = cve.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if metrics.get(key):
            cd = metrics[key][0].get("cvssData", {})
            score = cd.get("baseScore", 0) or 0
            severity = cd.get("baseSeverity", "") or ""
            vector = cd.get("vectorString", "") or ""
            break
    products = []
    for node in cve.get("configurations", []):
        for match in node.get("nodes", []):
            for cpe in match.get("cpeMatch", []):
                parts = cpe.get("criteria", "").split(":")
                if len(parts) >= 5:
                    products.append((parts[3], parts[4]))
    products = list(dict.fromkeys(products))[:10]
    meta = {
        "source_identifier": cve.get("sourceIdentifier", ""),
        "published": cve.get("published", "") or "",
        "last_modified": cve.get("lastModified", "") or "",
        "vuln_status": cve.get("vulnStatus", "") or "",
    }
    row = (
        cve_id,
        meta["source_identifier"],
        meta["published"],
        meta["last_modified"],
        meta["vuln_status"],
        desc[:400],
        score,
        severity,
        vector,
        "; ".join(f"{v}/{p}" for v, p in products)[:400],
        json.dumps([r.get("url", "") for r in cve.get("references", [])[:5]])[:1000],
    )
    return row, products, meta


def _cve_meta(conn):
    try:
        cur = conn.execute(
            "SELECT key, value FROM db_meta WHERE key IN "
            "('total_cves','last_updated','mode')"
        )
        return dict(cur.fetchall())
    except sqlite3.Error:
        return {}


def _store(conn, pages_items, progress=None):
    inserted = 0
    total = len(pages_items)
    for item in pages_items:
        row, products, _ = _cve_row(item)
        if not row:
            continue
        conn.execute(
            """INSERT OR REPLACE INTO cve_items
               (id, source_identifier, published, last_modified, vuln_status,
                description, cvss_score, cvss_severity, cvss_vector,
                affected_products, reference_urls)
               VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
            row,
        )
        conn.execute("DELETE FROM cve_products WHERE cve_id = ?", (row[0],))
        for vendor, product in products:
            conn.execute(
                "INSERT INTO cve_products (cve_id, vendor, product) VALUES (?,?,?)",
                (row[0], vendor[:60], product[:60]),
            )
        inserted += 1
        if progress and inserted % 200 == 0:
            conn.commit()
            progress(f"    已写入 {inserted}/{total}")
    conn.commit()
    return inserted


def update_cve(full=False):
    _guard(CVE_DB, "CVE 库")
    if not os.path.exists(CVE_DB):
        print(f"[CVE] 本地库不存在，改为全量构建: {CVE_DB}")
        full = True

    conn = sqlite3.connect(CVE_DB)
    meta = _cve_meta(conn)
    mode = "全量重建" if full else "增量更新"
    print(f"[CVE] {mode} → {CVE_DB}")

    # NVD 对大时间区间（>3 天）的查询会长时间不返回，因此按天切片，每片 1-2 秒
    if not full:
        last = meta.get("last_updated", "")
        try:
            start_ts = time.mktime(time.strptime(last[:19], "%Y-%m-%d %H:%M:%S")) - 86400
        except ValueError:
            print("      [提示] 读不到 last_updated，按最近 30 天处理")
            start_ts = time.time() - 30 * 86400
    else:
        start_ts = None

    end_ts = time.time()
    windows = []
    if start_ts is None:
        windows.append((None, None))
    else:
        cur = start_ts
        while cur < end_ts:
            nxt = min(cur + 86400, end_ts)
            windows.append((
                time.strftime("%Y-%m-%dT%H:%M:%S.000", time.localtime(cur)),
                time.strftime("%Y-%m-%dT%H:%M:%S.000", time.localtime(nxt)),
            ))
            cur = nxt
        print(f"      窗口: {windows[0][0]} → {windows[-1][1]}（{len(windows)} 片）")

    page_size = 2000
    buffer = []
    for begin, end in windows:
        params = {}
        if begin:
            params["lastModStartDate"] = begin
            params["lastModEndDate"] = end
        label = (begin or "全量")[:10]
        start_index = 0
        while True:
            try:
                items, total_results = _nvd_page(params, start_index, page_size)
            except Exception as exc:
                print(f"    [警告] {label} 第 {start_index} 页失败: {str(exc)[:100]}")
                break
            if not items:
                break
            buffer.extend(items)
            start_index += page_size
            print(f"    {label}: 本片 {total_results} 条，累计 {len(buffer)} 条")
            sys.stdout.flush()
            if start_index >= min(total_results, page_size):
                break
            time.sleep(0.7 if _api_key() else 6)

    if not buffer:
        print("[CVE] 没有拉到新数据（可能已是最新，或网络不可达）")
        conn.close()
        return False

    inserted = _store(conn, buffer, progress=print)
    now = time.strftime("%Y-%m-%d %H:%M:%S")
    total = conn.execute("SELECT COUNT(*) FROM cve_items").fetchone()[0]
    for k, v in (
        ("total_cves", str(total)),
        ("last_updated", now),
        ("mode", "nvd_api_v2+fallback"),
        ("last_run", f"{mode}: +{inserted} @ {now}"),
    ):
        conn.execute("INSERT OR REPLACE INTO db_meta (key, value) VALUES (?,?)", (k, v))
    conn.commit()
    conn.close()
    print(f"[CVE] 完成：本次更新 {inserted} 条，库内共 {total} 条")
    return True


def _git(repo, args, timeout=900):
    """跑一条 git 命令，返回 CompletedProcess。"""
    return subprocess.run(["git", "-C", repo] + args, capture_output=True,
                          text=True, timeout=timeout)


def _git_head(repo):
    """当前 HEAD 的短提交号；取不到返回空串。"""
    try:
        out = _git(repo, ["rev-parse", "--short", "HEAD"], timeout=20)
        return out.stdout.strip() if out.returncode == 0 else ""
    except (OSError, subprocess.SubprocessError):
        return ""


def _git_pull(repo):
    """拉取更新，返回 (是否成功, 输出说明)。

    先试 `git pull --ff-only`；本地分支没配上游时它只会报
    "There is no tracking information for the current branch." 然后什么都不做 ——
    skill 自带的这份 exploit-db 克隆就是这样：浅克隆 + 本地 master + 远端分支叫
    main，规则库看着"更新过了"，其实一条没动。所以这里退回 fetch + merge --ff-only。
    """
    try:
        first = _git(repo, ["pull", "--ff-only"])
        if first.returncode == 0:
            return True, (first.stdout or "").strip()
        remotes = _git(repo, ["remote"], timeout=20).stdout.split()
        if not remotes:
            return False, (first.stderr or first.stdout or "").strip()
        remote = remotes[0]
        fetch = _git(repo, ["fetch", "--prune", remote])
        if fetch.returncode != 0:
            return False, (fetch.stderr or fetch.stdout or "").strip()
        merge = _git(repo, ["merge", "--ff-only", "FETCH_HEAD"])
        if merge.returncode != 0:
            return False, (merge.stderr or merge.stdout or "").strip()
        return True, ((fetch.stdout or "") + (merge.stdout or "")).strip()
    except subprocess.TimeoutExpired:
        return False, "git 操作超时（检查到 gitlab.com 的网络）"
    except (OSError, subprocess.SubprocessError) as exc:
        return False, f"git 调用失败: {exc}"


def update_exploit_db():
    _guard(EXPLOIT_DB, "Exploit-DB 目录")
    git_dir = os.path.join(EXPLOIT_DB, ".git")
    if os.path.isdir(git_dir):
        before = _git_head(EXPLOIT_DB)
        print(f"[Exploit-DB] 拉取更新 → {EXPLOIT_DB}")
        ok, message = _git_pull(EXPLOIT_DB)
        if message:
            print("    " + message.strip().replace("\n", "\n    "))
        after = _git_head(EXPLOIT_DB)
        # 必须明确说出"到底有没有换到新规则"，否则更新失败会和"已是最新"长得一样
        if not ok:
            print(f"    [警告] 更新失败，仍在用旧规则库（提交 {before or '未知'}）")
        elif before and before == after:
            print(f"    已是最新（提交 {after}）")
        else:
            print(f"    已更新：{before or '未知'} → {after or '未知'}")
    else:
        print(f"[Exploit-DB] 目录不是 git 仓库，跳过自动更新: {EXPLOIT_DB}")
        print("    手动更新: git clone --depth=1 "
              "https://gitlab.com/exploit-database/exploitdb.git " + EXPLOIT_DB)
    csv = os.path.join(EXPLOIT_DB, "files_exploits.csv")
    if os.path.exists(csv):
        with open(csv, "rb") as fh:
            lines = sum(1 for _ in fh)
        print(f"    files_exploits.csv: {lines - 1} 条记录")


def _count_templates(root):
    """统计模板目录下的 yaml/yml 数量（更新前后对比用）。"""
    total = 0
    for _dirpath, _dirs, files in os.walk(root or ""):
        total += sum(1 for name in files if name.endswith((".yaml", ".yml")))
    return total


def update_nuclei():
    _guard(NUCLEI_TEMPLATES, "nuclei 模板目录")
    binary = config.NUCLEI_BIN
    if not binary:
        print("[nuclei] 未找到 nuclei 可执行文件，跳过")
        return
    os.makedirs(NUCLEI_TEMPLATES, exist_ok=True)
    before = _count_templates(NUCLEI_TEMPLATES)
    print(f"[nuclei] 更新模板 → {NUCLEI_TEMPLATES}（当前 {before} 个）")
    try:
        r = subprocess.run(
            # 参数名必须是 -update-template-dir：nuclei 不认 -update-directory，
            # 写错只会让它报个未知参数然后退出，模板数一个不变。
            [binary, "-update-templates", "-update-template-dir", NUCLEI_TEMPLATES],
            capture_output=True, text=True, timeout=1800)
    except subprocess.TimeoutExpired:
        print("    [警告] 更新超时，仍在使用旧模板")
        return
    tail = (r.stdout or r.stderr or "").strip().splitlines()
    for line in tail[-6:]:
        print("    " + line)
    after = _count_templates(NUCLEI_TEMPLATES)
    if r.returncode != 0 and after == before:
        print(f"    [警告] 更新失败（退出码 {r.returncode}），模板数未变：{before}")
    else:
        print(f"    模板数：{before} → {after}")


def status():
    print("=" * 62)
    print("skill 自带规则库状态")
    print("=" * 62)
    for label, path in (("CVE 库", CVE_DB),
                        ("Exploit-DB", EXPLOIT_DB),
                        ("nuclei 模板", NUCLEI_TEMPLATES)):
        loc = "skill 内" if path.startswith(DATA_DIR) else "** skill 外部 **"
        print(f"\n{label}: {path}  [{loc}]")
        if not path or not os.path.exists(path):
            print("    不存在")
            continue
        if os.path.isdir(path):
            size = subprocess.run(["du", "-sh", path], capture_output=True,
                                  text=True).stdout.split()[0]
            print(f"    大小: {size}")
        else:
            print(f"    大小: {os.path.getsize(path) / 1048576:.0f} MB")
    if os.path.exists(CVE_DB):
        conn = sqlite3.connect(CVE_DB)
        meta = _cve_meta(conn)
        total = conn.execute("SELECT COUNT(*) FROM cve_items").fetchone()[0]
        print(f"    CVE 记录: {total}")
        print(f"    上次更新: {meta.get('last_updated', '未知')}")
        print(f"    构建方式: {meta.get('mode', '未知')}")
        conn.close()
    if EXPLOIT_DB and os.path.isdir(os.path.join(EXPLOIT_DB, ".git")):
        r = subprocess.run(["git", "-C", EXPLOIT_DB, "log", "-1",
                            "--format=%h %ad", "--date=short"],
                           capture_output=True, text=True)
        print(f"    Exploit-DB 提交: {r.stdout.strip()}")
    if NUCLEI_TEMPLATES and os.path.isdir(NUCLEI_TEMPLATES):
        n = subprocess.run(["bash", "-c",
                            f"find {NUCLEI_TEMPLATES} -name '*.yaml' | wc -l"],
                           capture_output=True, text=True)
        print(f"    模板数量: {n.stdout.strip()}")
    print(f"\nNVD API Key: {'已配置' if _api_key() else '未配置（限速 5 请求/30 秒）'}")


def main():
    ap = argparse.ArgumentParser(description="更新 skill 自带规则库")
    ap.add_argument("--status", action="store_true", help="只显示版本信息")
    ap.add_argument("--all", action="store_true", help="更新全部三套规则库")
    ap.add_argument("--cve", action="store_true", help="更新 CVE 库")
    ap.add_argument("--full", action="store_true", help="CVE 全量重建（数小时）")
    ap.add_argument("--exploit-db", action="store_true", help="更新 Exploit-DB")
    ap.add_argument("--nuclei", action="store_true", help="更新 nuclei 模板")
    args = ap.parse_args()

    if args.status or not any([args.all, args.cve, args.exploit_db, args.nuclei]):
        status()
        return
    if args.all or args.cve:
        update_cve(full=args.full)
    if args.all or args.exploit_db:
        update_exploit_db()
    if args.all or args.nuclei:
        update_nuclei()
    print()
    status()


if __name__ == "__main__":
    main()
