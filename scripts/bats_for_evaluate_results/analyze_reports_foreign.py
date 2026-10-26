#!/usr/bin/env python3
"""
analyze_reports_foreign.py — 国外 App 报告批量分析器（GDPR/CCPA/FTC 版）

从 report.html 或 audit_log.jsonl 中提取事件数据，
跨 App 整合分析，生成合规检测汇总报告。

与国内版 analyze_reports.py 的区别：
  1. 法规依据：违规标签与超范围判定改用 GDPR / CCPA(CPRA) / FTC Act §5，
     不再引用国信办14号文、《个人信息保护法》等中国法规。
  2. App 类别：不采用"39 类必要信息范围"机制，改用数据敏感性标签。
  3. 超范围判定融合隐私政策声明比对：设备标识符一律判超范围；
     GPS / 账号 Token 仅当该 App 隐私政策未声明时判超范围
     （读 output/policy_vs_audit_comparison_foreign.json，7 个政策受限
     App 的 GPS/Token 不判超范围，设备标识符仍判）。

用法：
    # 批量分析国外 App 的 JSONL 日志
    python analyze_reports_foreign.py 成果展示_外国/*/audit_log.jsonl -o 合规汇总报告_完整版_国外软件.html

    # 导出合规检测表 CSV
    python analyze_reports_foreign.py *.jsonl --csv compliance.csv

依赖：纯 Python 标准库
"""

import argparse
import csv
import json
import re
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path


# ──────────────────────────────────────────────
#  数据提取
# ──────────────────────────────────────────────

def extract_events_from_html(filepath: str) -> list:
    """从 report.html 中提取嵌入的 events JSON 数组"""
    text = Path(filepath).read_text(encoding="utf-8", errors="replace")

    # 匹配 const events=[...]; 或 const events={...};
    # gen_report.py 模板用 const events={events_json};
    patterns = [
        r'const\s+events\s*=\s*(\[.*?\])\s*;',       # 数组形式
        r"const\s+events\s*=\s*(\[.*?\])\s*;\s*\n",   # 带换行
    ]
    for pat in patterns:
        m = re.search(pat, text, re.DOTALL)
        if m:
            try:
                events = json.loads(m.group(1))
                return events
            except json.JSONDecodeError:
                pass

    # 备选：更宽松的匹配
    start = text.find('const events=')
    if start == -1:
        start = text.find('const events =')
    if start != -1:
        # 找到 = 号后面的 [ 或 {
        eq_pos = text.index('=', start) + 1
        while eq_pos < len(text) and text[eq_pos] in ' \n\r\t':
            eq_pos += 1
        if eq_pos < len(text) and text[eq_pos] == '[':
            # 找匹配的 ]
            depth = 0
            end = eq_pos
            for i in range(eq_pos, len(text)):
                if text[i] == '[':
                    depth += 1
                elif text[i] == ']':
                    depth -= 1
                    if depth == 0:
                        end = i + 1
                        break
            candidate = text[eq_pos:end]
            try:
                return json.loads(candidate)
            except json.JSONDecodeError:
                pass

    return []


def extract_events_from_jsonl(filepath: str) -> list:
    """从 audit_log.jsonl 中逐行解析事件"""
    events = []
    with open(filepath, encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                ev = json.loads(line)
                ev.setdefault("sdk", None)
                ev.setdefault("sdk_label", None)
                ev.setdefault("endpoint_type", "unknown")
                events.append(ev)
            except json.JSONDecodeError:
                pass
    return events


def load_events(filepath: str) -> tuple:
    """自动判断文件类型并加载事件，返回 (events, source_label)"""
    p = Path(filepath)
    if not p.exists():
        print(f"[警告] 文件不存在：{filepath}", file=sys.stderr)
        return [], filepath

    suffix = p.suffix.lower()

    def _derive_label(path: Path) -> str:
        stem = path.stem
        if stem.lower() in ('report', 'audit_log', 'crypto_log'):
            parent = path.parent.name
            m = re.match(r'^(.+?)(?:：|$)', parent)
            return m.group(1) if m else parent
        return stem

    if suffix in ('.html', '.htm'):
        events = extract_events_from_html(filepath)
        label = _derive_label(p)
        return events, label

    elif suffix in ('.jsonl', '.json', '.log'):
        events = extract_events_from_jsonl(filepath)
        label = _derive_label(p)
        return events, label

    else:
        events = extract_events_from_html(filepath)
        if not events:
            events = extract_events_from_jsonl(filepath)
        return events, _derive_label(p)


# ──────────────────────────────────────────────
#  分析逻辑
# ──────────────────────────────────────────────

SEV_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}

# ── 超范围规则集（依据 GDPR / CCPA / FTC）────────────────────────

# 设备标识符类字段：任何广告 SDK 业务均非必要，一律判超范围（数据最小化）
# 覆盖国外数据实际出现的 13 个 rule 键中的设备标识类
ALWAYS_OVERCOLLECTION = {
    "imei":             "采集 IMEI/MEID 超出数据最小化原则，广告业务非必要（GDPR Art.5(1)(c)）",
    "mac_address":      "采集 MAC 地址超出数据最小化原则，非必要（GDPR Art.5(1)(c)）",
    "android_id":       "采集 Android ID 超出数据最小化原则，非必要（GDPR Art.5(1)(c)）",
    "oaid":             "采集 OAID 超出数据最小化原则，非必要（GDPR Art.5(1)(c)）",
    "serial_number":    "采集设备序列号超出数据最小化原则，非必要（GDPR Art.5(1)(c)）",
    "sim_info":         "采集 SIM/IMSI/ICCID 超出数据最小化原则，非必要（GDPR Art.5(1)(c)）",
    "build_fingerprint":"采集系统/设备指纹超出数据最小化原则，非必要（GDPR Art.5(1)(c)）",
    "clipboard":        "采集剪贴板内容超出数据最小化原则，非必要（GDPR Art.5(1)(c)）",
    "installed_apps":   "采集已安装应用列表超出数据最小化原则，非必要（GDPR Art.5(1)(c)）",
    "contact_list":     "采集通讯录超出数据最小化原则，非必要（GDPR Art.5(1)(c)）",
    "call_log":         "采集通话记录超出数据最小化原则，非必要（GDPR Art.5(1)(c)）",
    "sms_content":      "采集短信内容属特殊类别数据，超出数据最小化原则（GDPR Art.5(1)(c)+Art.9）",
}

# 位置 / 账号 Token 类：仅当政策已声明或政策无法核对时豁免，否则判超范围
# 豁免逻辑在 analyze_app() 里按 policy_declared / policy_uncheckable 判断
CONDITIONAL_OVERCOLLECTION = {
    "gps_coords":       "位置信息仅政策已声明且属基本功能时允许；未声明则违反数据最小化原则（GDPR Art.5(1)(c)）",
    "cell_location":    "位置信息仅政策已声明时允许；未声明则违反数据最小化原则（GDPR Art.5(1)(c)）",
    "wifi_location":    "位置信息仅政策已声明时允许；未声明则违反数据最小化原则（GDPR Art.5(1)(c)）",
    "account_token":    "账号 Token/Session 仅政策声明时允许；未声明则超范围（GDPR Art.5(1)(c)）",
}

# 合并：全部超范围规则（用于合规检测表法规回填兜底）
ALL_OVERCOLLECTION = {**ALWAYS_OVERCOLLECTION, **CONDITIONAL_OVERCOLLECTION}

# 手机号 / 真实姓名 / 邮箱：可凭合法基础采集，不判超范围（由同意类违规覆盖）
# （对应国外数据里的 phone_number / real_name / email，未纳入超范围规则集）

# ── 隐私政策声明比对 ──────────────────────────────────────────
# 政策字段名（中文，来自 privacy_policy_fields_foreign.json）→ 审计 rule 键
POLICY_FIELD_TO_RULE = {
    "GPS 经纬度": "gps_coords",
    "账号 Token / Session": "account_token",
    "SIM 卡信息": "sim_info",
    "Android ID": "android_id",
    "IMEI": "imei",
    "MAC 地址": "mac_address",
    "应用列表": "installed_apps",
    "OAID": "oaid",
}

# 政策抓取受限的应用（来自 compare_foreign_policy_vs_audit.py 的 POLICY_ISSUE）：
# 政策无法核对，GPS/Token 不判超范围，但设备标识符仍判
POLICY_ISSUE_PKGS = {
    "com.contextlogic.wish", "com.vive.riderleague", "com.aniplex.fategrandorder",
    "jp.pxv.android", "jp.konami.masterduel", "com.naver.labs.translator",
    "kr.co.tf.starwars",
}

# 政策比对数据文件
POLICY_COMPARISON_PATH = (
    Path(__file__).resolve().parents[2] / "output" / "policy_vs_audit_comparison_foreign.json"
)

# 法规条款映射（违规标签 → 国外法规），键与实际事件里的违规标签一致
VIOLATION_LAWS = {
    "超范围采集":               "违反 GDPR Art.5(1)(c) 数据最小化原则；CCPA §1798.100(b) 合理必要限制",
    "未经同意采集（同意前）":  "违反 GDPR Art.6(1)(a)+Art.7 同意合法基础，未经有效同意即处理",
    "超频次采集":               "违反 GDPR Art.5(1)(c) 数据最小化（超出必要频率）/ Art.6 合法基础缺失",
    "后台静默采集（应用在后台）":"违反 GDPR Art.5(1)(a) 合法公平透明 + Art.13 告知义务",
    "静默采集（响应含敏感数据）":"违反 GDPR Art.13/14 数据主体告知义务",
}

# 已知 SDK 上报端点（归因类）——带 SDK 后缀，前缀匹配
SDK_ENDPOINT_LAW = "第三方共享未充分告知，违反 GDPR Art.13(1)(e)+Art.6(1)(f) 合法利益平衡"
SDK_ENDPOINT_PREFIX = "已知 SDK 上报端点（"

# 超范围判定的统一兜底法规（规则在规则集内且无专门条款时）
GDPR_MINIMIZATION_LAW = "违反 GDPR Art.5(1)(c) 数据最小化原则"


def max_severity(hits: list) -> str:
    if not hits:
        return "low"
    return max(hits, key=lambda h: SEV_ORDER.get(h.get("severity", "low"), 0))["severity"]


@dataclass
class AppReport:
    source: str              # 文件名
    events: list             # 原始事件列表
    total_events: int
    critical_count: int
    high_count: int
    sdks: dict               # sdk_label → event_count
    endpoints: dict          # endpoint_type → count
    rules_hit: dict          # rule_name → count
    hosts: dict              # host → count
    violations: dict         # violation_tag → count
    startup_events: int      # 启动阶段事件
    overcollection: list     # 超范围采集事件
    compliance_rows: list    # 合规检测表行


def analyze_app(events: list, source: str,
                policy_declared: set = None, policy_uncheckable: bool = False) -> AppReport:
    """分析单个 App 的事件列表。

    policy_declared: 该 App 隐私政策已声明的采集字段（rule 键集合），
                     命中时 GPS/账号 Token 类字段豁免超范围判定。
    policy_uncheckable: 该 App 隐私政策无法核对（policy_issue），
                      GPS/账号 Token 类字段豁免超范围判定。
    """

    oc_rules = dict(ALL_OVERCOLLECTION)   # ALWAYS + CONDITIONAL（GPS/Token 走政策豁免）
    policy_declared = policy_declared or set()

    total = len(events)
    critical = 0
    high = 0
    sdks = Counter()
    endpoints = Counter()
    rules_hit = Counter()
    hosts = Counter()
    violations_counter = Counter()
    startup = 0
    overcollection = []
    compliance_rows = []

    # 已生成的合规行去重
    seen_compliance = set()

    for ev in events:
        hits = ev.get("hits", [])
        sev = max_severity(hits)
        if sev == "critical":
            critical += 1
        elif sev == "high":
            high += 1

        sdk = ev.get("sdk_label") or "未识别"
        sdks[sdk] += 1
        endpoints[ev.get("endpoint_type", "unknown")] += 1
        hosts[ev.get("host", "")] += 1

        if ev.get("is_startup"):
            startup += 1

        # 国外版：事件自带的「超范围采集」标签按国内规则判定，
        # 需按国外规则集 + 政策豁免重新判定后再计违规
        # is_oc_hit: rule 在 oc_rules 且未因政策豁免
        ev_violations = []
        for v in ev.get("violations", []):
            if v == "超范围采集":
                continue   # 由下面 hit 循环按国外规则重新判定
            ev_violations.append(v)

        for h in hits:
            rule = h.get("rule", "")
            rules_hit[rule] += 1

            # 超范围判定（政策比对融合）
            # 设备标识符一律判超范围；GPS/位置/账号 Token 仅当政策已声明
            # 或政策无法核对（policy_issue）时豁免
            conditional = rule in ("gps_coords", "cell_location", "wifi_location", "account_token")
            is_oc = rule in oc_rules and not (conditional and (policy_uncheckable or rule in policy_declared))

            if is_oc:
                overcollection.append({
                    "rule": rule,
                    "label": h.get("label", ""),
                    "reason": oc_rules[rule],
                    "key": h.get("key", ""),
                    "value": h.get("value_snippet", ""),
                    "sdk": sdk,
                    "host": ev.get("host", ""),
                    "ts": ev.get("ts", ""),
                })

            # 合规检测表行：国外重新判定的违规集合
            row_violations = list(ev_violations)
            if is_oc:
                row_violations.append("超范围采集")
            for v in row_violations:
                row_key = (sdk, rule, v)
                if row_key not in seen_compliance:
                    seen_compliance.add(row_key)
                    law = VIOLATION_LAWS.get(v, "")
                    # 归因类违规带 SDK 后缀，前缀匹配
                    if not law and v.startswith(SDK_ENDPOINT_PREFIX):
                        law = SDK_ENDPOINT_LAW
                    # 超范围规则集内且无专门条款 → GDPR 数据最小化兜底
                    if is_oc and not law:
                        law = GDPR_MINIMIZATION_LAW
                    compliance_rows.append({
                        "sdk": sdk,
                        "rule": rule,
                        "rule_label": h.get("label", rule),
                        "severity": h.get("severity", "medium"),
                        "violation": v,
                        "law": law,
                        "overcollection_reason": oc_rules.get(rule, ""),
                        "key": h.get("key", ""),
                        "value": h.get("value_snippet", ""),
                        "host": ev.get("host", ""),
                        "endpoint": ev.get("endpoint_type", ""),
                        "ts": ev.get("ts", ""),
                        "is_startup": ev.get("is_startup", False),
                    })

        # 违规计数：超范围标签按重新判定后的结果计
        violations_counter["超范围采集"] += sum(
            1 for h in hits
            if h.get("rule", "") in oc_rules
            and not (h.get("rule", "") in ("gps_coords", "cell_location", "wifi_location", "account_token")
                     and (policy_uncheckable or h.get("rule", "") in policy_declared))
        )
        for v in ev_violations:
            violations_counter[v] += 1

    return AppReport(
        source=source,
        events=events,
        total_events=total,
        critical_count=critical,
        high_count=high,
        sdks=dict(sdks.most_common(20)),
        endpoints=dict(endpoints),
        rules_hit=dict(rules_hit.most_common(20)),
        hosts=dict(Counter(hosts).most_common(15)),
        violations=dict(violations_counter),
        startup_events=startup,
        overcollection=overcollection,
        compliance_rows=compliance_rows,
    )


# ──────────────────────────────────────────────
#  终端输出
# ──────────────────────────────────────────────

C = {
    "R": "\033[91m", "Y": "\033[93m", "G": "\033[92m", "C": "\033[96m",
    "M": "\033[95m", "B": "\033[1m", "D": "\033[90m", "W": "\033[97m",
    "0": "\033[0m",
}


def sensitivity_label(r: AppReport) -> str:
    """按实际命中的敏感字段生成数据敏感性标签"""
    tags = []
    if r.rules_hit.get("gps_coords"):
        tags.append("GPS")
    if r.rules_hit.get("account_token"):
        tags.append("账号Token")
    device_ids = [k for k in ("imei", "mac_address", "android_id", "oaid", "sim_info")
                  if r.rules_hit.get(k)]
    if device_ids:
        tags.append("设备标识")
    if r.rules_hit.get("sms_content"):
        tags.append("短信")
    if r.rules_hit.get("phone_number"):
        tags.append("手机号")
    return "含" + "/".join(tags) if tags else "未检出敏感字段"


def print_app_summary(r: AppReport):
    cat_str = sensitivity_label(r)
    print(f"\n{C['B']}{C['C']}{'─' * 55}{C['0']}")
    print(f"{C['B']}📁 {r.source}{C['0']}  ({r.total_events} 条告警)  {C['D']}[{cat_str}]{C['0']}")
    print(f"{C['B']}{C['C']}{'─' * 55}{C['0']}")

    print(f"  {C['R']}Critical: {r.critical_count}{C['0']}  "
          f"{C['Y']}High: {r.high_count}{C['0']}  "
          f"启动阶段: {r.startup_events}  "
          f"超范围(含GPS): {len(r.overcollection)}")

    if r.sdks:
        print(f"\n  {C['B']}SDK 分布:{C['0']}")
        for sdk, cnt in list(r.sdks.items())[:8]:
            bar = "█" * min(cnt, 40)
            print(f"    {C['M']}{sdk:25s}{C['0']} {cnt:4d}  {C['D']}{bar}{C['0']}")

    if r.violations:
        print(f"\n  {C['B']}违规标签:{C['0']}")
        for v, cnt in sorted(r.violations.items(), key=lambda x: -x[1]):
            print(f"    {C['R']}{v:35s}{C['0']} × {cnt}")

    if r.rules_hit:
        top5 = list(r.rules_hit.items())[:5]
        print(f"\n  {C['B']}命中规则 Top 5:{C['0']}")
        for rule, cnt in top5:
            print(f"    {C['Y']}{rule:25s}{C['0']} × {cnt}")


def print_cross_summary(reports: list):
    print(f"\n{C['B']}{C['W']}{'═' * 55}{C['0']}")
    print(f"{C['B']}📊 跨 App 整合分析（共 {len(reports)} 个 App）{C['0']}")
    print(f"{C['B']}{C['W']}{'═' * 55}{C['0']}")

    # SDK 风险排名
    sdk_risk = Counter()
    sdk_apps = defaultdict(set)
    for r in reports:
        for row in r.compliance_rows:
            sdk = row["sdk"]
            sev_score = SEV_ORDER.get(row["severity"], 0) + 1
            sdk_risk[sdk] += sev_score
            sdk_apps[sdk].add(r.source)

    if sdk_risk:
        print(f"\n  {C['B']}🏴 SDK 风险排名（加权得分）:{C['0']}")
        for sdk, score in sdk_risk.most_common(10):
            apps = ", ".join(sorted(sdk_apps[sdk]))
            print(f"    {C['R']}{score:4d}{C['0']}  {C['M']}{sdk:25s}{C['0']}  {C['D']}出现于: {apps}{C['0']}")

    # 违规类型统计
    all_violations = Counter()
    for r in reports:
        for v, cnt in r.violations.items():
            all_violations[v] += cnt
    if all_violations:
        print(f"\n  {C['B']}⚠ 违规类型汇总:{C['0']}")
        for v, cnt in all_violations.most_common():
            law = VIOLATION_LAWS.get(v, "")
            print(f"    {C['R']}{v:35s}{C['0']} × {cnt:4d}  {C['D']}{law}{C['0']}")

    # 合规检测表预览
    all_rows = []
    for r in reports:
        for row in r.compliance_rows:
            row["app"] = r.source
            all_rows.append(row)

    if all_rows:
        print(f"\n  {C['B']}📋 合规检测表（{len(all_rows)} 条，前 15 条）:{C['0']}")
        print(f"    {'App':12s} {'SDK':20s} {'检测项':18s} {'违规':22s} {'证据':30s}")
        print(f"    {'─'*12} {'─'*20} {'─'*18} {'─'*22} {'─'*30}")
        for row in all_rows[:15]:
            evidence = f"{row['key']}={row['value'][:15]}"
            print(f"    {row['app'][:12]:12s} {row['sdk'][:20]:20s} "
                  f"{row['rule_label'][:18]:18s} {row['violation'][:22]:22s} "
                  f"{evidence[:30]:30s}")
        if len(all_rows) > 15:
            print(f"    {C['D']}... 另有 {len(all_rows)-15} 条，详见 HTML 报告{C['0']}")


# ──────────────────────────────────────────────
#  CSV 导出
# ──────────────────────────────────────────────

def export_csv(reports: list, out_path: Path):
    """导出为合规检测表 CSV"""
    rows = []
    for r in reports:
        sens = sensitivity_label(r)
        for row in r.compliance_rows:
            rows.append({
                "APP": r.source,
                "数据敏感性": sens,
                "SDK": row["sdk"],
                "端点类型": row["endpoint"],
                "检测项": row["rule_label"],
                "结果": "违规",
                "违规类型": row["violation"],
                "超范围判定依据": row.get("overcollection_reason", ""),
                "严重度": row["severity"],
                "证据字段": row["key"],
                "证据值": row["value"],
                "域名": row["host"],
                "时间戳": row["ts"],
                "启动阶段": "是" if row["is_startup"] else "否",
                "违反法规": row["law"],
            })

    with out_path.open("w", encoding="utf-8-sig", newline="") as f:
        if rows:
            writer = csv.DictWriter(f, fieldnames=rows[0].keys())
            writer.writeheader()
            writer.writerows(rows)

    print(f"[✓] CSV 导出：{out_path}（{len(rows)} 条）")


# ──────────────────────────────────────────────
#  HTML 报告
# ──────────────────────────────────────────────

def generate_html(reports: list, out_path: Path):
    """生成跨 App 整合分析 HTML 报告"""

    # ── 汇总数据 ──
    total_events = sum(r.total_events for r in reports)
    total_critical = sum(r.critical_count for r in reports)
    total_high = sum(r.high_count for r in reports)
    total_startup = sum(r.startup_events for r in reports)
    total_overcollection = sum(len(r.overcollection) for r in reports)

    all_sdks = Counter()
    all_rules = Counter()
    all_violations = Counter()
    all_hosts = Counter()
    for r in reports:
        for k, v in r.sdks.items(): all_sdks[k] += v
        for k, v in r.rules_hit.items(): all_rules[k] += v
        for k, v in r.violations.items(): all_violations[k] += v
        for k, v in r.hosts.items(): all_hosts[k] += v

    # ── 合规检测表行 ──
    all_compliance = []
    for r in reports:
        for row in r.compliance_rows:
            row["app"] = r.source
            all_compliance.append(row)

    # 按严重度排序
    all_compliance.sort(key=lambda x: -SEV_ORDER.get(x["severity"], 0))

    # ── 各 App 概览卡片 ──
    app_cards = ""
    for r in reports:
        sens = sensitivity_label(r)
        sens_badge_cls = "critical" if ("设备标识" in sens or "短信" in sens) else "medium"
        top_sdks = ", ".join(list(r.sdks.keys())[:4])
        top_violations = ", ".join(list(r.violations.keys())[:3]) or "无"
        app_cards += f"""<div class="app-card">
            <div class="app-name">{esc(r.source)} <span class="tag {sens_badge_cls}" style="font-size:10px">{esc(sens)}</span></div>
            <div class="app-stats">
                <span class="n critical">{r.critical_count}</span> Critical
                <span class="n high">{r.high_count}</span> High
                <span class="n">{r.total_events}</span> 总告警
                <span class="n startup">{r.startup_events}</span> 启动采集
                <span class="n" style="color:#e94560">{len(r.overcollection)}</span> 超范围
            </div>
            <div class="app-detail">SDK: {esc(top_sdks)}</div>
            <div class="app-detail">违规: {esc(top_violations)}</div>
        </div>"""

    # ── 合规检测表 HTML ──
    compliance_rows_html = ""
    for row in all_compliance:
        sev = row["severity"]
        startup_tag = ' <span class="tag startup">启动阶段</span>' if row["is_startup"] else ""
        compliance_rows_html += f"""<tr>
            <td>{esc(row['app'])}</td>
            <td><span class="tag sdk">{esc(row['sdk'])}</span></td>
            <td><span class="tag ep-{row['endpoint']}">{esc(row['endpoint'])}</span></td>
            <td>{esc(row['rule_label'])}</td>
            <td><span class="tag {sev}">{sev.upper()}</span></td>
            <td><span class="tag viol">{esc(row['violation'])}</span>{startup_tag}</td>
            <td><code>{esc(row['key'])}={esc(row['value'])}</code></td>
            <td style="max-width:140px" title="{esc(row['host'])}">{esc(row['host'][:35])}</td>
            <td>{esc(row.get('law',''))}</td>
        </tr>"""

    # ── SDK 风险排名 ──
    sdk_risk = Counter()
    sdk_apps = defaultdict(set)
    sdk_violations = defaultdict(Counter)
    for row in all_compliance:
        sdk = row["sdk"]
        sdk_risk[sdk] += SEV_ORDER.get(row["severity"], 0) + 1
        sdk_apps[sdk].add(row["app"])
        sdk_violations[sdk][row["violation"]] += 1

    sdk_ranking_html = ""
    for i, (sdk, score) in enumerate(sdk_risk.most_common(15), 1):
        apps = ", ".join(sorted(sdk_apps[sdk]))
        viols = ", ".join(f"{v}×{c}" for v, c in sdk_violations[sdk].most_common(3))
        sdk_ranking_html += f"""<tr>
            <td>{i}</td>
            <td><span class="tag sdk">{esc(sdk)}</span></td>
            <td class="score">{score}</td>
            <td>{esc(apps)}</td>
            <td style="font-size:11px">{esc(viols)}</td>
        </tr>"""

    # ── 图表数据 ──
    chart_sdks = json.dumps(all_sdks.most_common(10), ensure_ascii=False)
    chart_rules = json.dumps(all_rules.most_common(12), ensure_ascii=False)
    chart_violations = json.dumps(all_violations.most_common(8), ensure_ascii=False)

    html = HTML_TEMPLATE.format(
        now=datetime.now().strftime('%Y-%m-%d %H:%M'),
        app_count=len(reports),
        total_events=total_events,
        total_critical=total_critical,
        total_high=total_high,
        total_startup=total_startup,
        total_overcollection=total_overcollection,
        total_sdks=len(all_sdks),
        total_compliance=len(all_compliance),
        app_cards=app_cards,
        compliance_rows=compliance_rows_html,
        sdk_ranking=sdk_ranking_html,
        chart_sdks=chart_sdks,
        chart_rules=chart_rules,
        chart_violations=chart_violations,
    )
    out_path.write_text(html, encoding="utf-8")


def esc(s):
    return str(s).replace("&","&amp;").replace("<","&lt;").replace(">","&gt;").replace('"',"&quot;")


# ──────────────────────────────────────────────
#  HTML 模板
# ──────────────────────────────────────────────

HTML_TEMPLATE = r"""<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>隐私审计整合报告（国外 App · GDPR/CCPA/FTC）— {now}</title>
<script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.1/chart.umd.min.js"></script>
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:-apple-system,'PingFang SC','Microsoft YaHei',sans-serif;background:#f5f6fa;color:#2d2d2d;font-size:14px}}
code{{font-family:'JetBrains Mono',Consolas,monospace;font-size:11px;background:#f0f0f0;padding:1px 4px;border-radius:3px}}
.header{{background:linear-gradient(135deg,#1a1a2e,#16213e,#0f3460);color:#fff;padding:28px 32px}}
.header h1{{font-size:22px;font-weight:600;margin-bottom:6px}}
.header .meta{{color:#9ab;font-size:13px}}
.container{{max-width:1360px;margin:0 auto;padding:20px 16px}}
h2{{font-size:16px;font-weight:600;margin:28px 0 14px;padding-bottom:6px;border-bottom:2px solid #e94560;color:#1a1a2e}}
.stats{{display:grid;grid-template-columns:repeat(auto-fit,minmax(120px,1fr));gap:10px;margin:16px 0}}
.stat{{background:#fff;border-radius:8px;padding:14px;text-align:center;box-shadow:0 1px 3px rgba(0,0,0,.08)}}
.stat .n{{font-size:26px;font-weight:700;color:#e94560}}
.stat .l{{font-size:11px;color:#888;margin-top:4px}}
.app-grid{{display:grid;grid-template-columns:repeat(auto-fill,minmax(280px,1fr));gap:12px;margin:14px 0}}
.app-card{{background:#fff;border-radius:8px;padding:16px;box-shadow:0 1px 3px rgba(0,0,0,.08);border-left:4px solid #e94560}}
.app-name{{font-weight:600;font-size:15px;margin-bottom:8px;color:#1a1a2e}}
.app-stats .n{{font-weight:700;margin-right:2px}}
.app-stats .n.critical{{color:#e74c3c}} .app-stats .n.high{{color:#e67e22}} .app-stats .n.startup{{color:#8e44ad}}
.app-detail{{font-size:12px;color:#888;margin-top:4px}}
.charts{{display:grid;grid-template-columns:1fr 1fr 1fr;gap:14px;margin:14px 0}}
.chart-box{{background:#fff;border-radius:8px;padding:14px;box-shadow:0 1px 3px rgba(0,0,0,.08)}}
.chart-box h3{{font-size:13px;font-weight:500;margin-bottom:8px;color:#555}}
table{{width:100%;border-collapse:collapse;background:#fff;border-radius:8px;overflow:hidden;box-shadow:0 1px 3px rgba(0,0,0,.08)}}
th{{background:#f8f9fa;font-weight:600;text-align:left;padding:10px;font-size:12px;color:#555;border-bottom:1px solid #eee;position:sticky;top:0;z-index:1}}
td{{padding:8px 10px;font-size:12px;border-top:1px solid #f5f5f5;vertical-align:top;word-break:break-all}}
tr:hover td{{background:#fafbfc}}
.score{{font-weight:700;font-size:16px;color:#e94560}}
.tag{{display:inline-block;padding:2px 7px;border-radius:4px;font-size:10px;font-weight:600;margin:1px;white-space:nowrap}}
.critical{{background:#fde8e8;color:#c0392b}}
.high{{background:#fef3cd;color:#856404}}
.medium{{background:#d1ecf1;color:#0c5460}}
.low{{background:#e8f5e9;color:#2e7d32}}
.viol{{background:#e8eaf6;color:#3949ab}}
.sdk{{background:#f3e5f5;color:#6a1b9a}}
.startup{{background:#fce4ec;color:#ad1457}}
.ep-telemetry{{background:#fde8e8;color:#c0392b}}
.ep-ad_api{{background:#fef3cd;color:#856404}}
.ep-service{{background:#d1ecf1;color:#0c5460}}
.ep-cdn,.ep-unknown{{background:#eee;color:#666}}
.filter-bar{{padding:10px 16px;display:flex;gap:8px;flex-wrap:wrap;border-bottom:1px solid #f0f0f0;background:#fff;border-radius:8px 8px 0 0}}
.filter-bar select,.filter-bar input{{padding:5px 8px;border:1px solid #ddd;border-radius:5px;font-size:12px}}
.filter-bar label{{font-size:12px;color:#666;align-self:center}}
.count-tip{{font-size:12px;color:#888;align-self:center;margin-left:auto}}
@media(max-width:900px){{.charts{{grid-template-columns:1fr}}.app-grid{{grid-template-columns:1fr}}}}
</style></head><body>
<div class="header">
  <h1>📋 隐私审计整合分析报告（国外 App）</h1>
  <div class="meta">生成时间：{now} · 共 {app_count} 个 App · {total_events} 条告警事件 · 依据 GDPR / CCPA(CPRA) / FTC Act §5</div>
</div>
<div class="container">

<div class="stats">
  <div class="stat"><div class="n">{app_count}</div><div class="l">App 数量</div></div>
  <div class="stat"><div class="n">{total_events}</div><div class="l">告警事件</div></div>
  <div class="stat"><div class="n">{total_critical}</div><div class="l">Critical</div></div>
  <div class="stat"><div class="n">{total_high}</div><div class="l">High</div></div>
  <div class="stat"><div class="n">{total_startup}</div><div class="l">启动即采集</div></div>
  <div class="stat"><div class="n">{total_overcollection}</div><div class="l">超范围采集</div></div>
  <div class="stat"><div class="n">{total_sdks}</div><div class="l">涉及 SDK</div></div>
  <div class="stat"><div class="n">{total_compliance}</div><div class="l">合规违规条目</div></div>
</div>

<h2>📱 各 App 概览</h2>
<div class="app-grid">{app_cards}</div>

<div class="charts">
  <div class="chart-box"><h3>📦 SDK 事件分布</h3><canvas id="cSdk" height="240"></canvas></div>
  <div class="chart-box"><h3>🎯 命中规则分布</h3><canvas id="cRule" height="240"></canvas></div>
  <div class="chart-box"><h3>⚠ 违规类型分布</h3><canvas id="cViol" height="240"></canvas></div>
</div>

<h2>🏴 SDK 风险排名</h2>
<table>
<thead><tr><th>#</th><th>SDK</th><th>风险分</th><th>涉及 App</th><th>主要违规</th></tr></thead>
<tbody>{sdk_ranking}</tbody>
</table>

<h2>📋 合规检测表</h2>
<div class="filter-bar">
  <label>严重度</label><select id="fSev" onchange="ft()"><option value="">全部</option><option>critical</option><option>high</option><option>medium</option></select>
  <label>App</label><select id="fApp" onchange="ft()"><option value="">全部</option></select>
  <label>SDK</label><select id="fSdk" onchange="ft()"><option value="">全部</option></select>
  <label>违规</label><select id="fViol" onchange="ft()"><option value="">全部</option></select>
  <input id="fHost" placeholder="域名..." oninput="ft()" style="flex:1;min-width:100px">
  <span class="count-tip" id="tip"></span>
</div>
<div style="overflow-x:auto">
<table id="ctable">
<thead><tr><th>App</th><th>SDK</th><th>端点</th><th>检测项</th><th>严重度</th><th>违规类型</th><th>证据</th><th>域名</th><th>法规条款</th></tr></thead>
<tbody id="ctbody">{compliance_rows}</tbody>
</table>
</div>

</div>
<script>
const cs={chart_sdks},cr={chart_rules},cv={chart_violations};
const cl=['#e74c3c','#e67e22','#f1c40f','#2ecc71','#3498db','#9b59b6','#1abc9c','#e91e63','#ff5722','#607d8b','#795548','#4caf50'];
if(cs.length)new Chart(document.getElementById('cSdk'),{{type:'doughnut',data:{{labels:cs.map(x=>x[0]),datasets:[{{data:cs.map(x=>x[1]),backgroundColor:cl}}]}},options:{{plugins:{{legend:{{position:'right',labels:{{font:{{size:10}},boxWidth:8}}}}}}}}}});
if(cr.length)new Chart(document.getElementById('cRule'),{{type:'bar',data:{{labels:cr.map(x=>x[0]),datasets:[{{data:cr.map(x=>x[1]),backgroundColor:cl,borderRadius:3}}]}},options:{{plugins:{{legend:{{display:false}}}},scales:{{y:{{beginAtZero:true}},x:{{ticks:{{font:{{size:9}}}}}}}}}}}});
if(cv.length)new Chart(document.getElementById('cViol'),{{type:'bar',data:{{labels:cv.map(x=>x[0].slice(0,12)),datasets:[{{data:cv.map(x=>x[1]),backgroundColor:cl,borderRadius:3}}]}},options:{{indexAxis:'y',plugins:{{legend:{{display:false}}}},scales:{{x:{{beginAtZero:true}}}}}}}});

// 填充过滤器
const trs=[...document.querySelectorAll('#ctbody tr')];
const getCol=(tr,i)=>(tr.children[i]||{{}}).textContent||'';
const uniq=(arr)=>[...new Set(arr)].sort();
const fillSel=(id,vals)=>{{const s=document.getElementById(id);vals.forEach(v=>{{const o=document.createElement('option');o.value=v;o.textContent=v;s.appendChild(o);}});}};
fillSel('fApp',uniq(trs.map(t=>getCol(t,0).trim())));
fillSel('fSdk',uniq(trs.map(t=>getCol(t,1).trim())));
fillSel('fViol',uniq(trs.map(t=>getCol(t,5).trim().replace('启动阶段','').trim())));

function ft(){{
  const sv=document.getElementById('fSev').value;
  const ap=document.getElementById('fApp').value;
  const sk=document.getElementById('fSdk').value;
  const vi=document.getElementById('fViol').value;
  const ho=document.getElementById('fHost').value.toLowerCase();
  let shown=0;
  trs.forEach(tr=>{{
    const ok=(!sv||getCol(tr,4).toLowerCase().includes(sv))
      &&(!ap||getCol(tr,0).includes(ap))
      &&(!sk||getCol(tr,1).includes(sk))
      &&(!vi||getCol(tr,5).includes(vi))
      &&(!ho||getCol(tr,7).toLowerCase().includes(ho));
    tr.style.display=ok?'':'none';
    if(ok)shown++;
  }});
  document.getElementById('tip').textContent=`${{shown}} / ${{trs.length}} 条`;
}}
ft();
</script></body></html>"""


# ──────────────────────────────────────────────
#  入口
# ──────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="privacy_auditor 报告批量分析器 — 跨 App 整合分析",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument("files", nargs="+", help="report.html 或 audit_log.jsonl 文件（支持多个）")
    parser.add_argument("-o", "--out", default="合规汇总报告.html", help="输出 HTML 路径（默认：合规汇总报告.html）")
    parser.add_argument("--no-html", action="store_true", help="不生成 HTML，只打印终端摘要")
    parser.add_argument("--csv", help="导出合规检测表 CSV（可粘贴到 Word）")
    args = parser.parse_args()

    # 加载政策比对数据（国外），按包名建索引
    policy_by_pkg = {}
    if POLICY_COMPARISON_PATH.exists():
        try:
            with POLICY_COMPARISON_PATH.open(encoding="utf-8") as f:
                for item in json.load(f):
                    pkg = item.get("pkg", "")
                    if not pkg:
                        continue
                    declared = {POLICY_FIELD_TO_RULE.get(f, "")
                                for f in item.get("declared_fields", []) if POLICY_FIELD_TO_RULE.get(f)}
                    declared.discard("")
                    uncheckable = bool(item.get("policy_issue")) or pkg in POLICY_ISSUE_PKGS
                    policy_by_pkg[pkg] = (declared, uncheckable)
            print(f"[✓] 政策比对：加载 {len(policy_by_pkg)} 个 App 的声明字段")
        except Exception as e:
            print(f"[警告] 政策比对数据解析失败：{e}", file=sys.stderr)

    def _pkg_of_path(fp: str) -> str:
        """从完整文件路径的父目录名「显示名：包名」提取包名末段。
        load_events 返回的 label 会截断掉包名，这里直接用父目录名，
        兼容目录名含 +、-、：等特殊字符的情况。
        """
        parent = Path(fp).parent.name
        if "：" in parent:
            return parent.split("：", 1)[1].strip()
        if ":" in parent:
            return parent.split(":", 1)[1].strip()
        return parent

    reports = []
    for fp in args.files:
        # 支持通配符展开后的多文件
        events, label = load_events(fp)
        if not events:
            print(f"[警告] {fp}: 未提取到事件数据，跳过", file=sys.stderr)
            continue
        print(f"[✓] {fp}: 加载 {len(events)} 条事件")
        pkg = _pkg_of_path(fp)
        policy_declared, policy_uncheckable = policy_by_pkg.get(pkg, (set(), False))
        if policy_declared:
            print(f"    [政策比对] {pkg}: 声明字段 {sorted(policy_declared)}"
                  f"{'（政策受限，GPS/Token 豁免）' if policy_uncheckable else ''}")
        report = analyze_app(events, label,
                             policy_declared=policy_declared,
                             policy_uncheckable=policy_uncheckable)
        reports.append(report)
        print_app_summary(report)

    if not reports:
        print("[错误] 没有成功加载任何数据", file=sys.stderr)
        sys.exit(1)

    if len(reports) > 1:
        print_cross_summary(reports)

    if not args.no_html:
        out = Path(args.out)
        generate_html(reports, out)
        print(f"\n[✓] HTML 整合报告：{out}")

    if args.csv:
        export_csv(reports, Path(args.csv))


if __name__ == "__main__":
    main()
