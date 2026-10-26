#!/usr/bin/env python3
"""
analyze_reports.py — privacy_auditor 报告批量分析器

从 report.html 或 audit_log.jsonl 中提取事件数据，
跨 App 整合分析，生成合规检测汇总报告。

支持输入：
  1. report.html（privacy_auditor / gen_report.py 生成的 HTML）
  2. audit_log.jsonl（原始 JSONL 日志）
  3. 混合输入（同时传 HTML 和 JSONL）

用法：
    # 分析单个报告
    python analyze_reports.py 转转_report.html

    # 批量分析多个 App 的报告
    python analyze_reports.py 转转_report.html 贴吧_report.html 抖音_report.html

    # 直接分析 JSONL 日志
    python analyze_reports.py audit_log_zhuanzhuan.jsonl audit_log_tieba.jsonl

    # 混合输入
    python analyze_reports.py reports/*.html logs/*.jsonl

    # 指定输出
    python analyze_reports.py *.html -o 合规汇总.html

    # 只看终端摘要
    python analyze_reports.py *.html --no-html

    # 导出为合规检测表 CSV（可直接粘贴到 Word 表格）
    python analyze_reports.py *.html --csv compliance.csv

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

# ── 超范围规则集（依据国信办14号文）──────────────────────────

# 所有39类App均不允许采集的信息
ALWAYS_OVERCOLLECTION = {
    "imei":             "IMEI 在 39 类 App 中均非必要信息",
    "mac_address":      "MAC 地址在 39 类 App 中均非必要信息",
    "android_id":       "Android ID 在 39 类 App 中均非必要信息",
    "oaid":             "OAID 在 39 类 App 中均非必要信息",
    "serial_number":    "设备序列号在 39 类 App 中均非必要信息",
    "sim_info":         "SIM 信息（IMSI/ICCID）在 39 类 App 中均非必要信息",
    "build_fingerprint":"系统指纹/设备指纹在 39 类 App 中均非必要信息",
    "clipboard":        "剪切板内容在 39 类 App 中均非必要信息",
    "installed_apps":   "已安装应用列表在 39 类 App 中均非必要信息",
    "contact_list":     "通讯录仅即时通信类（第3类）需要，其余均属超范围",
    "call_log":         "通话记录在 39 类 App 中均非必要信息",
    "sms_content":      "短信内容在 39 类 App 中均非必要信息",
    # GPS：仅第1类（地图导航）、第2类（网约车）、第22类（用车服务）可采集
    "gps_coords":       "GPS 经纬度仅地图导航/网约车/用车服务类可采集，其余均属超范围（14号文附表）",
    "cell_location":    "基站位置仅地图导航/网约车/用车服务类可采集",
    "wifi_location":    "WiFi 位置信息仅地图导航/网约车/用车服务类可采集",
}

# 无须个人信息类（第21、27-38类）额外禁止：任何个人信息均属超范围
NO_INFO_EXTRA_OVERCOLLECTION = {
    "phone_number":  "该类 App（短视频/直播/影音/资讯）无需采集任何个人信息，手机号亦属超范围",
    "real_name":     "该类 App 无需采集任何个人信息，真实姓名亦属超范围",
    "email":         "该类 App 无需采集任何个人信息，电子邮箱亦属超范围",
    "id_card":       "该类 App 无需采集任何个人信息，证件号亦属超范围",
    "account_token": "该类 App 无需采集任何个人信息，Token/Session 亦属超范围",
}

# ── App 类别映射（依据国信办14号文分类）────────────────────────
# need_phone=False → 无须任何个人信息（超范围最严格）
APP_CATEGORIES = {
    # 无须个人信息类（第27-30类）—— 任何个人信息采集均属超范围
    "抖音":         {"type_id": 29, "type_name": "短视频类",   "need_phone": False},
    "快手":         {"type_id": 27, "type_name": "网络直播类",  "need_phone": False},
    "腾讯视频":     {"type_id": 28, "type_name": "在线影音类",  "need_phone": False},
    "红果免费短剧": {"type_id": 30, "type_name": "新闻资讯类",  "need_phone": False},
    # 仅需手机号类（第4、18、20类）
    "百度贴吧":     {"type_id": 4,  "type_name": "网络社区类",  "need_phone": True},
    "知乎":         {"type_id": 4,  "type_name": "网络社区类",  "need_phone": True},
    "lofter":       {"type_id": 4,  "type_name": "网络社区类",  "need_phone": True},
    "soul":         {"type_id": 4,  "type_name": "网络社区类",  "need_phone": True},
    "小红书":       {"type_id": 4,  "type_name": "网络社区类",  "need_phone": True},
    "米游社":       {"type_id": 18, "type_name": "网络游戏类",  "need_phone": True},
    "转转":         {"type_id": 20, "type_name": "本地生活类",  "need_phone": True},
    # 网上购物类（第6类）—— 手机号+收货人信息+支付信息，不含设备标识符/GPS
    "淘宝":         {"type_id": 6,  "type_name": "网上购物类",  "need_phone": True},
    "得物":         {"type_id": 6,  "type_name": "网上购物类",  "need_phone": True},
    "唯品会":       {"type_id": 6,  "type_name": "网上购物类",  "need_phone": True},
    "咸鱼":         {"type_id": 6,  "type_name": "网上购物类",  "need_phone": True},
    "Amazon":       {"type_id": 6,  "type_name": "网上购物类",  "need_phone": True},
    "Aliexpress":   {"type_id": 6,  "type_name": "网上购物类",  "need_phone": True},
    "1688":         {"type_id": 6,  "type_name": "网上购物类",  "need_phone": True},
    "vivo商城":     {"type_id": 6,  "type_name": "网上购物类",  "need_phone": True},
    # 婚恋相亲类（第10类）—— 手机号+性别+年龄+婚姻状况
    "meetme":       {"type_id": 10, "type_name": "婚恋相亲类",  "need_phone": True},
}

# 法规条款映射
VIOLATION_LAWS = {
    "超范围采集":               "《常见类型移动互联网应用程序必要个人信息范围规定》(国信办14号文)",
    "未经同意采集（启动阶段）":  "《个人信息保护法》第13条",
    "超频次采集":               "工信部164号文",
    "静默采集（响应含敏感数据）":"《个人信息保护法》第17条",
}


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


def analyze_app(events: list, source: str, cat_info: dict = None) -> AppReport:
    """分析单个 App 的事件列表"""

    # 依据 App 类别构建超范围规则集
    oc_rules = dict(ALWAYS_OVERCOLLECTION)
    if cat_info and not cat_info.get("need_phone", True):
        # 无须个人信息类（短视频/直播/影音/资讯）：手机号等个人信息也属超范围
        oc_rules.update(NO_INFO_EXTRA_OVERCOLLECTION)

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

        for v in ev.get("violations", []):
            violations_counter[v] += 1

        for h in hits:
            rule = h.get("rule", "")
            rules_hit[rule] += 1

            # 超范围判定（基于App类别的规则集）
            if rule in oc_rules:
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

            # 合规检测表行
            for v in ev.get("violations", []):
                row_key = (sdk, rule, v)
                if row_key not in seen_compliance:
                    seen_compliance.add(row_key)
                    law = VIOLATION_LAWS.get(v, "")
                    if rule in oc_rules and not law:
                        law = "《常见类型移动互联网应用程序必要个人信息范围规定》(国信办14号文)"
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


def print_app_summary(r: AppReport):
    cat = APP_CATEGORIES.get(r.source)
    cat_str = f"第{cat['type_id']}类·{cat['type_name']}" if cat else "类别未识别"
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
        cat = APP_CATEGORIES.get(r.source)
        cat_str = f"第{cat['type_id']}类·{cat['type_name']}" if cat else "未识别"
        for row in r.compliance_rows:
            rows.append({
                "APP": r.source,
                "App类别(国信办14号文)": cat_str,
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
        cat = APP_CATEGORIES.get(r.source)
        cat_str = f"第{cat['type_id']}类·{cat['type_name']}" if cat else "类别未识别"
        no_info = cat and not cat.get("need_phone", True)
        cat_badge_cls = "critical" if no_info else "medium"
        top_sdks = ", ".join(list(r.sdks.keys())[:4])
        top_violations = ", ".join(list(r.violations.keys())[:3]) or "无"
        app_cards += f"""<div class="app-card">
            <div class="app-name">{esc(r.source)} <span class="tag {cat_badge_cls}" style="font-size:10px">{esc(cat_str)}</span></div>
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
<title>隐私审计整合报告 — {now}</title>
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
  <h1>📋 隐私审计整合分析报告</h1>
  <div class="meta">生成时间：{now} · 共 {app_count} 个 App · {total_events} 条告警事件</div>
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

    reports = []
    for fp in args.files:
        # 支持通配符展开后的多文件
        events, label = load_events(fp)
        if not events:
            print(f"[警告] {fp}: 未提取到事件数据，跳过", file=sys.stderr)
            continue
        print(f"[✓] {fp}: 加载 {len(events)} 条事件")
        # 查找 App 类别（精确匹配优先，再尝试包含匹配）
        cat_info = APP_CATEGORIES.get(label)
        if not cat_info:
            for k, v in APP_CATEGORIES.items():
                if k in label or label in k:
                    cat_info = v
                    break
        report = analyze_app(events, label, cat_info=cat_info)
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
