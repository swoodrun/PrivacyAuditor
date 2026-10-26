#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
analyze_reports_miit.py — 工信部第二批通报违规 App 审计整合分析（违规版本）

从 APP_set_miit/datarecord_miit/<pkg>/audit_log.jsonl 提取事件，
按国信办14号文39类必要信息清单判定超范围采集，生成：
  APP_set_miit/合规汇总报告_违规版本.html

特点：
  - 类别查找用包名 → App 中文名 → MIIT_APP_CATEGORIES，不复用文件名匹配
  - 违规汇总表：8 个 App 对照工信部通报类型，标注「动态审计印证/证据不足」
  - SDK API 常量搜索节：3 个被通报 SDK 域名在全项目检测结果中的命中情况
  - txt-only App（小鱼出行/泊安飞停车）单列证据不足档
"""
import argparse
import csv
import json
import re
import sys
import glob
import os
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

# 共享数据（包名/类别/通报/SDK 常量）
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'report'))
from miit_apps import (
    MIIT_APP_CATEGORIES, MIIT_NOTIFICATION, PKG_TO_APP, TXT_ONLY_APPS,
    MIIT_SDK_DOMAINS, MIIT_SDK_SOURCES, MIIT_DIR, EXCLUDE_SDKS,
    MIIT_APP_DETAIL, APP_BATCH,
)

SEV_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}

# rule 键 → 中文说明（政策对比节展示用）
RULE_LABELS = {
    "imei": "IMEI 设备识别码",
    "sim_info": "SIM 卡信息（IMSI/ICCID）",
    "android_id": "Android ID",
    "oaid": "OAID",
    "mac_address": "MAC 地址",
    "gps_coords": "GPS 经纬度",
    "ip_address": "IP 地址",
    "wifi_location": "WiFi 位置（SSID/BSSID）",
    "build_fingerprint": "设备/系统指纹",
    "installed_apps": "已安装应用列表",
    "contact_list": "通讯录",
    "clipboard": "剪贴板",
    "account_token": "账号 Token / Session",
    "phone_number": "手机号码",
    "real_name": "真实姓名",
    "email": "电子邮箱",
    "id_card": "证件号",
    "storage": "相册 / 存储",
    "sensor": "传感器数据",
    "camera": "摄像头 / 麦克风",
}

# ── 超范围规则集（依据国信办14号文，与 analyze_reports.py 一致）──
ALWAYS_OVERCOLLECTION = {
    "imei": "IMEI 在 39 类 App 中均非必要信息",
    "mac_address": "MAC 地址在 39 类 App 中均非必要信息",
    "android_id": "Android ID 在 39 类 App 中均非必要信息",
    "oaid": "OAID 在 39 类 App 中均非必要信息",
    "serial_number": "设备序列号在 39 类 App 中均非必要信息",
    "sim_info": "SIM 信息（IMSI/ICCID）在 39 类 App 中均非必要信息",
    "build_fingerprint": "系统指纹/设备指纹在 39 类 App 中均非必要信息",
    "clipboard": "剪切板内容在 39 类 App 中均非必要信息",
    "installed_apps": "已安装应用列表在 39 类 App 中均非必要信息",
    "contact_list": "通讯录仅即时通信类（第3类）需要，其余均属超范围",
    "call_log": "通话记录在 39 类 App 中均非必要信息",
    "sms_content": "短信内容在 39 类 App 中均非必要信息",
    "gps_coords": "GPS 经纬度仅地图导航/网约车/用车服务类可采集，其余均属超范围（14号文附表）",
    "cell_location": "基站位置仅地图导航/网约车/用车服务类可采集",
    "wifi_location": "WiFi 位置信息仅地图导航/网约车/用车服务类可采集",
}
# 无须个人信息类额外禁止
NO_INFO_EXTRA_OVERCOLLECTION = {
    "phone_number": "工具类无需采集任何个人信息，手机号亦属超范围",
    "real_name": "工具类无需采集任何个人信息，真实姓名亦属超范围",
    "email": "工具类无需采集任何个人信息，电子邮箱亦属超范围",
    "id_card": "工具类无需采集任何个人信息，证件号亦属超范围",
    "account_token": "工具类无需采集任何个人信息，Token/Session 亦属超范围",
}

VIOLATION_LAWS = {
    "超范围采集": "《常见类型移动互联网应用程序必要个人信息范围规定》(国信办14号文)",
    "超频次采集": "工信部164号文",
    "静默采集（响应含敏感数据）": "《个人信息保护法》第17条",
    "后台静默采集（应用在后台）": "《个人信息保护法》第13条",
    "已知 SDK 上报端点": "《个人信息保护法》第22条（委托处理）",
    "高风险 SDK 上报": "《个人信息保护法》第22条（委托处理）",
}


def max_severity(hits: list) -> str:
    if not hits:
        return "low"
    return max(hits, key=lambda h: SEV_ORDER.get(h.get("severity", "low"), 0))["severity"]


def extract_events_from_jsonl(filepath) -> list:
    events = []
    with open(filepath, encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                ev = json.loads(line)
                ev.setdefault("sdk_label", None)
                ev.setdefault("endpoint_type", "unknown")
                events.append(ev)
            except json.JSONDecodeError:
                pass
    return events


@dataclass
class AppReport:
    source: str
    app_name: str
    events: list
    total_events: int
    critical_count: int
    high_count: int
    sdks: dict
    endpoints: dict
    rules_hit: dict
    hosts: dict
    violations: dict
    startup_events: int
    overcollection: list
    compliance_rows: list


def build_oc_rules(app_name: str) -> dict:
    """按 App 类别构建超范围规则集。返回 (oc_rules, note)"""
    cat = MIIT_APP_CATEGORIES.get(app_name)
    oc_rules = dict(ALWAYS_OVERCOLLECTION)
    note = cat['note'] if cat else ''
    if cat:
        # 类别允许采集的字段（如地图导航类允许 GPS）从超范围集移除
        for allowed in cat.get('allowed', set()):
            oc_rules.pop(allowed, None)
        # 额外禁止的字段
        oc_rules.update(cat.get('extra_oc', {}))
        if not cat.get('need_phone', True):
            oc_rules.update(NO_INFO_EXTRA_OVERCOLLECTION)
    return oc_rules, note


def analyze_app(events: list, source: str, app_name: str) -> AppReport:
    oc_rules, cat_note = build_oc_rules(app_name)

    total = 0
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
    seen_compliance = set()

    for ev in events:
        sdk = ev.get("sdk_label") or "未识别"
        # 独立能力（如中国移动一键登录认证）不参与违规分析，跳过
        if sdk in EXCLUDE_SDKS:
            continue
        total += 1
        hits = ev.get("hits", [])
        sev = max_severity(hits)
        if sev == "critical":
            critical += 1
        elif sev == "high":
            high += 1

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

            # 超范围判定（14号文 39 类必要信息清单重判）
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
        source=source, app_name=app_name, events=events,
        total_events=total, critical_count=critical, high_count=high,
        sdks=dict(sdks.most_common(20)), endpoints=dict(endpoints),
        rules_hit=dict(rules_hit.most_common(20)),
        hosts=dict(Counter(hosts).most_common(15)),
        violations=dict(violations_counter),
        startup_events=startup, overcollection=overcollection,
        compliance_rows=compliance_rows,
    )


# ── crypto_log 敏感明文检测 ─────────────────────────────
_SENS_RE = re.compile(
    r'(?i)(?:imei|android[_\-]?id|oaid|imsi|iccid|lat(?:itude)?[=:]|lon(?:itude)?[=:]'
    r'|lng[=:]|phone[=:]|mobile[=:]|mac[_\-]?addr|ssid|bssid|serial|installed_app'
    r'|clipboard|getDeviceId|getLastKnownLocation|gps|idfa)')
_HOOK_RE = re.compile(
    r'(?i)(?:已hook|已替换|hook\s+完成|hook\s+已启动|已启动|已加载|正在启动|安装完成|'
    r'ssl.?pin|TrustManager|HostnameVerifier|CertificatePinner|Conscrypt|Apache|WebViewClient|'
    r'hook Activity|hook ClipboardManager|hook LocationManager|hook TelephonyManager|'
    r'Cipher 已 hook|SecretKeySpec 已 hook|IvParameterSpec 已 hook|JSONObject 已 hook|'
    r'HttpURLConnection 已 hook|Protobuf|等待 App|tip|init\]|anti\]|sensitive\])')


def _has_sensitive_evidence(app_name: str) -> bool:
    """判断 App 是否有敏感明文证据（crypto_log.txt 非 hook 初始化内容）。"""
    pkg = next((p for p, a in PKG_TO_APP.items() if a == app_name), None)
    if not pkg:
        return False
    txt = MIIT_DIR / 'datarecord_miit' / pkg / f'{pkg}.txt'
    if not txt.exists():
        return False
    try:
        raw = txt.read_text(encoding='utf-8', errors='replace')
    except Exception:
        return False
    for line in raw.splitlines():
        clean = re.sub(r'\x1b\[[0-9;]*m', '', line)
        if _HOOK_RE.search(clean):
            continue
        if _SENS_RE.search(clean):
            return True
    return False


# ── SDK API 常量全项目搜索 ─────────────────────────────
def search_sdk_domains() -> dict:
    """在项目所有检测结果中搜索 3 个被通报 SDK 的域名。
    数据源：datarecord/datarecord_foreign/datarecord_miit/datarecord_miit_another/证据收集/output/*。
    返回 {sdk: {'domains': [...], 'hit_files': [...], 'found': bool}}"""
    root = MIIT_DIR.parent  # 项目根
    data_dirs = ['datarecord', 'datarecord_foreign', 'datarecord_miit', 'datarecord_miit_another',
                 '证据收集', 'output/_evidence_build', 'output/_evidence_build_foreign']
    files = set()
    for d in data_dirs:
        p = root / d
        if p.is_dir():
            for f in p.glob('**/*'):
                if f.is_file():
                    files.add(f)
    # 两批通报数据目录都纳入搜索
    for base in ('datarecord_miit', 'datarecord_miit_another'):
        for f in (root / 'APP_set_miit' / base).glob('**/*'):
            if f.is_file():
                files.add(f)

    result = {}
    for sdk, domains in MIIT_SDK_DOMAINS.items():
        hit_files = []
        for dom in domains:
            pat = re.compile(re.escape(dom), re.IGNORECASE)
            for f in sorted(files):
                try:
                    t = f.read_text(encoding='utf-8', errors='replace')
                except Exception:
                    continue
                if pat.search(t):
                    rel = os.path.relpath(f, root)
                    if rel not in hit_files:
                        hit_files.append(rel)
        result[sdk] = {
            'source': MIIT_SDK_SOURCES[sdk],
            'domains': domains,
            'hit_files': hit_files,
            'found': bool(hit_files),
        }
    return result


# ── 终端输出 ─────────────────────────────
C = {"R": "\033[91m", "Y": "\033[93m", "G": "\033[92m", "C": "\033[96m",
     "M": "\033[95m", "B": "\033[1m", "D": "\033[90m", "W": "\033[97m", "0": "\033[0m"}


def print_app_summary(r: AppReport):
    cat = MIIT_APP_CATEGORIES.get(r.app_name)
    cat_str = f"第{cat['type_id']}类·{cat['type_name']}" if cat else "类别未识别"
    print(f"\n{C['B']}{C['C']}{'─' * 55}{C['0']}")
    print(f"{C['B']}📁 {r.app_name} ({r.source})  {C['0']}  ({r.total_events} 条告警)  {C['D']}[{cat_str}]{C['0']}")
    print(f"{C['B']}{C['C']}{'─' * 55}{C['0']}")
    print(f"  {C['R']}Critical: {r.critical_count}{C['0']}  {C['Y']}High: {r.high_count}{C['0']}  "
          f"启动阶段: {r.startup_events}  超范围(按14号文): {len(r.overcollection)}")
    if r.sdks:
        print(f"\n  {C['B']}SDK 分布:{C['0']}")
        for sdk, cnt in list(r.sdks.items())[:8]:
            print(f"    {C['M']}{sdk:25s}{C['0']} {cnt:4d}")
    if r.violations:
        print(f"\n  {C['B']}违规标签:{C['0']}")
        for v, cnt in sorted(r.violations.items(), key=lambda x: -x[1]):
            print(f"    {C['R']}{v:35s}{C['0']} × {cnt}")
    if r.rules_hit:
        print(f"\n  {C['B']}命中规则 Top 5:{C['0']}")
        for rule, cnt in list(r.rules_hit.items())[:5]:
            print(f"    {C['Y']}{rule:25s}{C['0']} × {cnt}")


def esc(s):
    return str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")


def _load_policy_comparison():
    """加载政策 vs 实际采集对比 JSON（compare_miit_policy_vs_audit.py 产物）"""
    p = MIIT_DIR / 'policy_vs_audit_miit.json'
    if not p.exists():
        return []
    try:
        return json.loads(p.read_text(encoding='utf-8'))
    except Exception:
        return []


def generate_html(reports: list, out_path: Path, sdk_search: dict):
    policy_comp = _load_policy_comparison()
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

    all_compliance = []
    for r in reports:
        for row in r.compliance_rows:
            row["app"] = r.app_name
            all_compliance.append(row)
    all_compliance.sort(key=lambda x: -SEV_ORDER.get(x["severity"], 0))

    # ── 各 App 概览卡片 ──
    app_cards = ""
    for r in reports:
        cat = MIIT_APP_CATEGORIES.get(r.app_name)
        cat_str = f"第{cat['type_id']}类·{cat['type_name']}" if cat else "类别未识别"
        no_info = cat and not cat.get("need_phone", True)
        cat_badge_cls = "critical" if no_info else "medium"
        top_sdks = ", ".join(list(r.sdks.keys())[:4]) or "无"
        top_violations = ", ".join(list(r.violations.keys())[:3]) or "无"
        batch_tag = f'<span class="tag sdk" style="font-size:10px">第{APP_BATCH.get(r.app_name, 2)}批</span>'
        app_cards += f"""<div class="app-card">
            <div class="app-name">{esc(r.app_name)} {batch_tag} <span class="tag {cat_badge_cls}" style="font-size:10px">{esc(cat_str)}</span></div>
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

    # ── 工信部通报 vs 审计印证表（按批次分段）──
    notif_rows_html = ""
    # 已分析的 App 名
    analyzed_apps = {r.app_name for r in reports}
    # App → 实际违规命中（动态审计命中类型 → 次数）
    app_actual_viols = {}
    for r in reports:
        app_actual_viols[r.app_name] = "、".join(
            f"{v}×{c}" for v, c in
            sorted(r.violations.items(), key=lambda x: -x[1])) or "无"
    batch_meta = {1: ('第一批', '2026 年第 1 批通报（总第 54 批）'),
                  2: ('第二批', '2026 年第 2 批通报（总第 55 批）')}
    for batch in (1, 2):
        batch_apps = [a for a in MIIT_NOTIFICATION if APP_BATCH.get(a) == batch]
        if not batch_apps:
            continue
        title, sub = batch_meta[batch]
        notif_rows_html += f'''<tr class="batch-hdr"><td colspan="4">
            <strong>📌 {title} · {sub}</strong></td></tr>'''
        for app_name in batch_apps:
            notice_str = "、".join(MIIT_NOTIFICATION[app_name])
            det = MIIT_APP_DETAIL.get(app_name, {})
            det_str = (f"{det.get('developer','')} · {det.get('source','')} · v{det.get('version','')}"
                       f" · MD5 {det.get('md5','')[:12]}…")
            # 印证判定：有 jsonl 动态审计，或有 crypto_log 敏感明文证据
            if app_name in analyzed_apps or _has_sensitive_evidence(app_name):
                verdict = '<span class="tag critical">动态审计印证</span>'
            else:
                verdict = '<span class="tag low">证据不足（未捕获敏感明文）</span>'
            actual = app_actual_viols.get(app_name, '<span style="color:#bbb">未纳入动态审计</span>')
            notif_rows_html += f"""<tr>
                <td><strong>{esc(app_name)}</strong><br><span style="font-size:10px;color:#888">{esc(det_str)}</span></td>
                <td>{esc(notice_str)}</td>
                <td>{verdict}</td>
                <td style="font-size:11px">{actual}</td>
            </tr>"""

    # ── SDK API 常量搜索节 ──
    sdk_search_html = ""
    for sdk, info in sdk_search.items():
        dom_str = "、".join(f"<code>{esc(d)}</code>" for d in info['domains'])
        if info['found']:
            status = f'<span class="tag critical">发现 {len(info["hit_files"])} 处</span>'
            hits = "、".join(esc(h) for h in info['hit_files'][:5])
        else:
            status = '<span class="tag medium">0 命中</span>'
            hits = '全项目检测结果中未出现'
        sdk_search_html += f"""<tr>
            <td>{esc(sdk)}</td>
            <td style="font-size:11px">{esc(info['source'])}</td>
            <td>{dom_str}</td>
            <td>{status}</td>
            <td style="font-size:11px">{esc(hits)}</td>
        </tr>"""

    # ── 政策 vs 实际采集对比节 ──
    policy_rows_html = ""
    for pc in policy_comp:
        app_name = pc.get('name', '')
        batch = pc.get('batch', 2)
        declared = pc.get('declared_fields', [])
        actual_counts = pc.get('actual_counts', {})
        undeclared = pc.get('undeclared', [])
        src = pc.get('policy_source', '')

        # 实际采集（rule → 中文）
        actual_str = "、".join(
            f"{RULE_LABELS.get(r, r)}×{c}" for r, c in
            sorted(actual_counts.items(), key=lambda x: -x[1])) or "无"
        # 未声明却采集
        if batch == 1:
            # 第一批政策未获取，不判未声明
            und_str = "—"
            und_badge = '<span class="tag medium">政策未获取</span>'
        elif undeclared:
            und_str = "、".join(RULE_LABELS.get(r, r) for r in undeclared)
            und_badge = f'<span class="tag critical">未声明却采集 {len(undeclared)}</span>'
        else:
            und_str = "—"
            und_badge = '<span class="tag pass">均在政策范围内</span>'

        batch_tag = f'<span class="tag sdk" style="font-size:9px">第{batch}批</span> '
        policy_rows_html += f"""<tr>
            <td><strong>{batch_tag}{esc(app_name)}</strong></td>
            <td style="font-size:11px">{esc(src)}</td>
            <td style="font-size:11px;max-width:240px">{esc('、'.join(declared) or '(未声明具体字段)')}</td>
            <td style="font-size:11px">{esc(actual_str)}</td>
            <td>{und_badge}</td>
            <td style="font-size:11px;color:#c0392b">{esc(und_str)}</td>
        </tr>"""

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
            <td>{esc(row.get('law', ''))}</td>
        </tr>"""

    chart_sdks = json.dumps(all_sdks.most_common(10), ensure_ascii=False)
    chart_rules = json.dumps(all_rules.most_common(12), ensure_ascii=False)
    chart_violations = json.dumps(all_violations.most_common(8), ensure_ascii=False)

    html = HTML_TEMPLATE.format(
        now=datetime.now().strftime('%Y-%m-%d %H:%M'),
        app_count=len(MIIT_NOTIFICATION), analyzed_count=len(reports),
        total_events=total_events, total_critical=total_critical,
        total_high=total_high, total_startup=total_startup,
        total_overcollection=total_overcollection,
        total_sdks=len(all_sdks), total_compliance=len(all_compliance),
        app_cards=app_cards, notif_rows=notif_rows_html,
        sdk_search_rows=sdk_search_html,
        policy_rows=policy_rows_html,
        compliance_rows=compliance_rows_html,
        chart_sdks=chart_sdks, chart_rules=chart_rules,
        chart_violations=chart_violations,
    )
    out_path.write_text(html, encoding="utf-8")


HTML_TEMPLATE = r"""<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>工信部第二批通报违规App审计 — 合规汇总报告（违规版本）— {now}</title>
<script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.1/chart.umd.min.js"></script>
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:-apple-system,'PingFang SC','Microsoft YaHei',sans-serif;background:#f5f6fa;color:#2d2d2d;font-size:14px}}
code{{font-family:'JetBrains Mono',Consolas,monospace;font-size:11px;background:#f0f0f0;padding:1px 4px;border-radius:3px}}
.header{{background:linear-gradient(135deg,#5a1220,#7a1f2b,#a32f3e);color:#fff;padding:28px 32px}}
.header h1{{font-size:22px;font-weight:600;margin-bottom:6px}}
.header .meta{{color:#ecc;font-size:13px}}
.container{{max-width:1360px;margin:0 auto;padding:20px 16px}}
h2{{font-size:16px;font-weight:600;margin:28px 0 14px;padding-bottom:6px;border-bottom:2px solid #a32f3e;color:#5a1220}}
.stats{{display:grid;grid-template-columns:repeat(auto-fit,minmax(120px,1fr));gap:10px;margin:16px 0}}
.stat{{background:#fff;border-radius:8px;padding:14px;text-align:center;box-shadow:0 1px 3px rgba(0,0,0,.08)}}
.stat .n{{font-size:26px;font-weight:700;color:#a32f3e}}
.stat .l{{font-size:11px;color:#888;margin-top:4px}}
.app-grid{{display:grid;grid-template-columns:repeat(auto-fill,minmax(280px,1fr));gap:12px;margin:14px 0}}
.app-card{{background:#fff;border-radius:8px;padding:16px;box-shadow:0 1px 3px rgba(0,0,0,.08);border-left:4px solid #a32f3e}}
.app-name{{font-weight:600;font-size:15px;margin-bottom:8px;color:#5a1220}}
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
tr.batch-hdr td{{background:#f3e8f7;color:#6a1b9a;font-weight:700;padding:8px 10px;border-top:2px solid #e1bee7;font-size:13px}}
.tag{{display:inline-block;padding:2px 7px;border-radius:4px;font-size:10px;font-weight:600;margin:1px;white-space:nowrap}}
.critical{{background:#fde8e8;color:#c0392b}}
.high{{background:#fef3cd;color:#856404}}
.medium{{background:#d1ecf1;color:#0c5460}}
.low{{background:#e8f5e9;color:#2e7d32}}
.pass{{background:#e8f5e9;color:#2e7d32}}
.viol{{background:#e8eaf6;color:#3949ab}}
.sdk{{background:#f3e5f5;color:#6a1b9a}}
.startup{{background:#fce4ec;color:#ad1457}}
.ep-telemetry{{background:#fde8e8;color:#c0392b}}
.ep-ad_api{{background:#fef3cd;color:#856404}}
.ep-service{{background:#d1ecf1;color:#0c5460}}
.ep-cdn,.ep-unknown{{background:#eee;color:#666}}
.legend-note{{background:#fff8f0;border:1px solid #f5d9b0;border-radius:8px;padding:14px 16px;margin:14px 0;font-size:12px;color:#6b4f2a;line-height:1.7}}
.filter-bar{{padding:10px 16px;display:flex;gap:8px;flex-wrap:wrap;border-bottom:1px solid #f0f0f0;background:#fff;border-radius:8px 8px 0 0}}
.filter-bar select,.filter-bar input{{padding:5px 8px;border:1px solid #ddd;border-radius:5px;font-size:12px}}
.filter-bar label{{font-size:12px;color:#666;align-self:center}}
.count-tip{{font-size:12px;color:#888;align-self:center;margin-left:auto}}
@media(max-width:900px){{.charts{{grid-template-columns:1fr}}.app-grid{{grid-template-columns:1fr}}}}
</style></head><body>
<div class="header">
  <h1>⚠ 工信部通报违规 App 审计 · 合规汇总报告（违规版本·完整版）</h1>
  <div class="meta">生成时间：{now} · 通报 App 数 {app_count} · 动态审计 {analyzed_count} 个 · {total_events} 条告警事件<br>
  判定依据：《常见类型移动互联网应用程序必要个人信息范围规定》(国信办14号文) · 《个人信息保护法》 · 工信部164号文</div>
</div>
<div class="container">

<div class="stats">
  <div class="stat"><div class="n">{app_count}</div><div class="l">通报 App</div></div>
  <div class="stat"><div class="n">{analyzed_count}</div><div class="l">动态审计印证</div></div>
  <div class="stat"><div class="n">{total_events}</div><div class="l">告警事件</div></div>
  <div class="stat"><div class="n">{total_critical}</div><div class="l">Critical</div></div>
  <div class="stat"><div class="n">{total_high}</div><div class="l">High</div></div>
  <div class="stat"><div class="n">{total_startup}</div><div class="l">启动即采集</div></div>
  <div class="stat"><div class="n">{total_overcollection}</div><div class="l">超范围采集</div></div>
  <div class="stat"><div class="n">{total_compliance}</div><div class="l">合规违规条目</div></div>
</div>

<div class="legend-note">
<strong>本报告说明：</strong>工信部于 2026 年第 1 批（总第 54 批）、第 2 批（总第 55 批）先后通报上述 App 存在侵害用户权益行为。
本报告基于对两批共 {app_count} 个 App 的动态审计（mitmproxy 流量采集 + Frida 加密穿透），用实测流量中的敏感字段采集与
14 号文 39 类必要信息清单比对，逐项印证或补充通报内容。
其中动态审计捕获到明文/敏感命中的 App 标注「动态审计印证」；审计会话未捕获敏感明文的 App 标注「证据不足」，单列一档。
</div>

<h2>📱 各 App 概览</h2>
<div class="app-grid">{app_cards}</div>

<div class="charts">
  <div class="chart-box"><h3>📦 SDK 事件分布</h3><canvas id="cSdk" height="240"></canvas></div>
  <div class="chart-box"><h3>🎯 命中规则分布</h3><canvas id="cRule" height="240"></canvas></div>
  <div class="chart-box"><h3>⚠ 违规类型分布</h3><canvas id="cViol" height="240"></canvas></div>
</div>

<h2>🏛 工信部通报与审计印证对照</h2>
<table>
<thead><tr><th>App（开发者 · 来源 · 版本 · MD5）</th><th>工信部通报问题</th><th>审计印证</th><th>动态审计实际命中</th></tr></thead>
<tbody>{notif_rows}</tbody>
</table>

<h2>🔍 被通报 SDK API 常量全项目搜索结果</h2>
<div class="legend-note">
<strong>说明：</strong>工信部第 2 批通报的 SDK（大树游戏SDK、游戏Fan SDK、0.1折游戏SDK）经 ADScope 静态分析提取出 API 常量域名，
已在本项目全部审计结果（datarecord / datarecord_foreign / datarecord_miit / datarecord_miit_another / 证据收集 / output 等文件）中检索。
检索结果表明这些 SDK 未集成在本次两批审计的 13 个 App 中，属独立通报的 SDK 包。
</div>
<table>
<thead><tr><th>被通报 SDK</th><th>来源包</th><th>API 常量域名</th><th>搜索结果</th><th>命中位置</th></tr></thead>
<tbody>{sdk_search_rows}</tbody>
</table>

<h2>📜 隐私政策 vs 实际采集对比</h2>
<div class="legend-note">
<strong>说明：</strong>以下为各 App 官方隐私政策声明字段与实际动态审计采集字段的比对。「未声明却采集」指
实际采集但政策未声明的字段——从告知义务看属违规收集。设备标识符等即使政策已声明，按 14 号文仍可能超范围
（政策比对管「是否告知」，14 号文管「是否必要」）。
</div>
<table>
<thead><tr><th>App</th><th>政策来源</th><th>政策声明字段</th><th>实际采集</th><th>比对结果</th><th>未声明却采集</th></tr></thead>
<tbody>{policy_rows}</tbody>
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


def export_csv(reports: list, out_path: Path):
    rows = []
    for r in reports:
        cat = MIIT_APP_CATEGORIES.get(r.app_name)
        cat_str = f"第{cat['type_id']}类·{cat['type_name']}" if cat else "未识别"
        for row in r.compliance_rows:
            rows.append({
                "APP": r.app_name,
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
                "违反法规": row["law"],
            })
    with out_path.open("w", encoding="utf-8-sig", newline="") as f:
        if rows:
            writer = csv.DictWriter(f, fieldnames=rows[0].keys())
            writer.writeheader()
            writer.writerows(rows)
    print(f"[✓] CSV 导出：{out_path}（{len(rows)} 条）")


def main():
    parser = argparse.ArgumentParser(
        description="工信部第二批通报违规App审计 — 违规汇总报告",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument("files", nargs="+", help="audit_log.jsonl 文件")
    parser.add_argument("-o", "--out", default=str(MIIT_DIR / '合规汇总报告_违规版本.html'),
                        help="输出 HTML 路径")
    parser.add_argument("--csv", help="导出合规检测表 CSV")
    parser.add_argument("--no-html", action="store_true", help="只打印终端摘要")
    args = parser.parse_args()

    # SDK API 常量搜索（全项目）
    sdk_search = search_sdk_domains()
    for sdk, info in sdk_search.items():
        st = "命中" if info['found'] else "0 命中"
        print(f"[SDK搜索] {sdk}: {st} ({len(info['domains'])} 域名)")

    reports = []
    for fp in args.files:
        events = extract_events_from_jsonl(fp)
        if not events:
            print(f"[警告] {fp}: 未提取到事件数据，跳过", file=sys.stderr)
            continue
        # 从目录名取包名 → App 中文名
        parent = Path(fp).parent.name
        pkg = None
        if '：' in parent:
            pkg = parent.split('：')[-1]
        else:
            pkg = parent
        app_name = PKG_TO_APP.get(pkg, pkg)
        print(f"[✓] {fp}: {app_name} ({pkg}) {len(events)} 条事件")
        report = analyze_app(events, fp, app_name)
        reports.append(report)
        print_app_summary(report)

    if not reports:
        print("[错误] 没有成功加载任何数据", file=sys.stderr)
        sys.exit(1)

    if not args.no_html:
        out = Path(args.out)
        generate_html(reports, out, sdk_search)
        print(f"\n[✓] HTML 违规汇总报告：{out}")

    if args.csv:
        export_csv(reports, Path(args.csv))


if __name__ == "__main__":
    main()
