#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
三引擎结果归一化 + 统一报告生成 + P0安全门禁
================================================
输入：semgrep.json / gitleaks.json / trivy.json（三引擎原始输出）
输出：unified_report.csv（统一结果表）
      security_summary.md（汇总报告，可直接贴给领导）
门禁：发现P0问题 → 退出码1（CI流水线红灯 = 阻断上线）

用法：python3 scripts/normalize.py [扫描结果所在目录，默认当前目录]
依赖：仅Python3标准库，无需安装任何第三方包
"""
import csv
import json
import os
import sys
from collections import Counter

# ---------- 严重程度 → 问题等级映射（对齐《安全审核工作流程设计》P0~P3标准） ----------
SEV_TO_P = {
    "critical": "P0", "high": "P1", "medium": "P2", "low": "P3", "unknown": "P3",
    "error": "P1", "warning": "P2", "info": "P3",
}


def to_p(severity, is_secret=False):
    """统一等级换算；密钥泄露一律P0（可按企业标准调整）"""
    if is_secret:
        return "P0"
    return SEV_TO_P.get((severity or "").strip().lower(), "P3")


def load_json(path):
    if not os.path.exists(path):
        print(f"[提示] 未找到 {path}，跳过该引擎结果")
        return None
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def parse_semgrep(data):
    """Semgrep JSON → 统一格式"""
    out = []
    for r in data.get("results", []):
        extra = r.get("extra", {})
        out.append({
            "引擎": "Semgrep(代码)",
            "规则/编号": r.get("check_id", ""),
            "等级": to_p(extra.get("severity")),
            "文件": r.get("path", ""),
            "行号": r.get("start", {}).get("line", 0),
            "问题摘要": (extra.get("message") or "")[:100],
            "代码片段": (extra.get("lines") or "").strip().replace("\n", " ")[:80],
        })
    return out


def parse_gitleaks(data):
    """密钥扫描JSON → 统一格式（密钥泄露一律P0）"""
    out = []
    for r in data:
        commit = (r.get("Commit") or "")[:8]
        out.append({
            "引擎": "密钥扫描",
            "规则/编号": r.get("RuleID", ""),
            "等级": to_p(r.get("Severity"), is_secret=True),
            "文件": r.get("File", "") + (f" (commit {commit})" if commit else ""),
            "行号": r.get("StartLine", 0),
            "问题摘要": r.get("Description", "疑似密钥泄露"),
            "代码片段": (r.get("Secret") or r.get("Match") or "")[:80],
        })
    return out


def parse_trivy(data):
    """Trivy JSON → 统一格式"""
    out = []
    for res in data.get("Results", []):
        for v in res.get("Vulnerabilities") or []:
            pkg = f'{v.get("PkgName", "")} {v.get("InstalledVersion", "")}'
            fixed = v.get("FixedVersion") or "暂无修复版本"
            out.append({
                "引擎": "Trivy(依赖)",
                "规则/编号": v.get("VulnerabilityID", ""),
                "等级": to_p(v.get("Severity")),
                "文件": res.get("Target", ""),
                "行号": 0,
                "问题摘要": (v.get("Title") or v.get("Description") or "")[:100],
                "代码片段": f"{pkg} → 修复版本: {fixed}",
            })
    return out


def main():
    base = sys.argv[1] if len(sys.argv) > 1 else "."
    findings = []

    for fname, parser in [
        ("semgrep.json", parse_semgrep),
        ("gitleaks.json", parse_gitleaks),
        ("trivy.json", parse_trivy),
    ]:
        data = load_json(os.path.join(base, fname))
        if data:
            findings.extend(parser(data))

    # ---------- 去重：同引擎同文件同位置同规则只保留一条 ----------
    seen, uniq = set(), []
    for f in findings:
        key = (f["引擎"], f["文件"], f["行号"], f["规则/编号"])
        if key in seen:
            continue
        seen.add(key)
        uniq.append(f)
    # 按等级排序（P0在前）
    uniq.sort(key=lambda x: (x["等级"], x["引擎"], x["文件"]))

    # ---------- 输出CSV统一结果表 ----------
    csv_path = os.path.join(base, "unified_report.csv")
    if uniq:
        with open(csv_path, "w", newline="", encoding="utf-8-sig") as f:
            writer = csv.DictWriter(f, fieldnames=list(uniq[0].keys()))
            writer.writeheader()
            writer.writerows(uniq)

    # ---------- 汇总统计 ----------
    by_engine = Counter(f["引擎"] for f in uniq)
    by_level = Counter(f["等级"] for f in uniq)
    p0 = [f for f in uniq if f["等级"] == "P0"]

    lines = []
    lines.append("# 安全扫描统一报告\n")
    lines.append(f"**扫描对象**：虚拟工单系统 ticket-demo　**发现总数**：{len(uniq)} 个问题\n")
    lines.append("## 按问题等级分布\n")
    lines.append("| 等级 | 数量 | 说明 |")
    lines.append("|---|---|---|")
    desc = {"P0": "阻断上线", "P1": "本迭代内必须修复", "P2": "下迭代修复", "P3": "跟踪观察"}
    for lv in ["P0", "P1", "P2", "P3"]:
        lines.append(f"| {lv} | {by_level.get(lv, 0)} | {desc[lv]} |")
    lines.append("\n## 按引擎分布\n")
    lines.append("| 引擎 | 发现数 | 覆盖范围 |")
    lines.append("|---|---|---|")
    scope = {"Semgrep(代码)": "注入/XSS/硬编码等代码缺陷",
             "密钥扫描": "代码及Git历史中的密钥泄露",
             "Trivy(依赖)": "第三方依赖已知CVE"}
    for eng, n in by_engine.most_common():
        lines.append(f"| {eng} | {n} | {scope.get(eng, '')} |")
    lines.append("\n## 问题明细（按等级排序）\n")
    lines.append("| 等级 | 引擎 | 规则/编号 | 文件 | 行号 | 问题摘要 |")
    lines.append("|---|---|---|---|---|---|")
    for f in uniq:
        lines.append(f'| {f["等级"]} | {f["引擎"]} | {f["规则/编号"]} '
                     f'| {f["文件"]} | {f["行号"]} | {f["问题摘要"]} |')
    lines.append("\n## 安全门禁结论\n")
    if p0:
        lines.append(f"❌ **门禁不通过**：存在 {len(p0)} 个P0问题，阻断上线。")
    else:
        lines.append("✅ **门禁通过**：无P0问题。")
    lines.append("\n> ⚠️ 注意：工具扫描存在盲区（如越权/IDOR、业务逻辑漏洞），"
                 "P0门禁通过不代表可以跳过人工检查清单。")
    with open(os.path.join(base, "security_summary.md"), "w", encoding="utf-8") as f:
        f.write("\n".join(lines))

    # ---------- 控制台输出 ----------
    print("=" * 50)
    print(f"统一报告已生成：{csv_path}")
    print(f"汇总报告已生成：{os.path.join(base, 'security_summary.md')}")
    print(f"发现问题：{len(uniq)} 个（P0:{by_level.get('P0',0)} "
          f"P1:{by_level.get('P1',0)} P2:{by_level.get('P2',0)} P3:{by_level.get('P3',0)}）")
    for eng, n in by_engine.most_common():
        print(f"  - {eng}: {n} 个")
    print("=" * 50)
    # 门禁：P0存在则exit 1，CI失败（红灯=阻断上线）
    sys.exit(1 if p0 else 0)


if __name__ == "__main__":
    main()
