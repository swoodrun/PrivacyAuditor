# -*- coding: utf-8 -*-
"""
compare_miit_policy_vs_audit.py — 工信部第二批通报 App：隐私政策 vs 实际采集对比

数据源：
  - 政策：APP_set_miit/policies/*.html（已抓取）+ 官方声明（小学英语同步学 App Store 不收集）
  - 实际：APP_set_miit/datarecord_miit/<pkg>/<pkg>.jsonl（动态审计 rule 键）

输出：
  - APP_set_miit/policy_vs_audit_miit.json（每 App：declared / actual / undeclared / over_scope_count）
  - 终端摘要（undeclared = 实际采集但政策未声明的字段）

判定模型与 compare_policy_vs_audit.py 一致：declared 政策字段名 → rule 键归一；
undeclared = actual_rule_keys - declared_rule_keys（实际采集超过政策声明 = 超范围）。
"""
import json
import os
import re
import sys
import glob
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'report'))
from miit_apps import (
    MIIT_DIR, EVIDENCE_DIR, EVIDENCE_DIR_ANOTHER, POLICY_DIR, OUT_JSON,
    PKG_TO_APP, EXCLUDE_SDKS, MIIT_APP_DETAIL,
)

# ── 政策关键词 → 中文字段名（复用 fetch_privacy_policy.py 的 KNOWN_DATA_KEYWORDS）──
KNOWN_DATA_KEYWORDS = {
    "IMEI": ["IMEI", "imei", "设备识别码", "国际移动设备识别码"],
    "IMSI": ["IMSI", "imsi", "国际移动用户识别码"],
    "Android ID": ["Android ID", "AndroidID", "android_id", "安卓ID"],
    "OAID": ["OAID", "oaid", "匿名设备标识"],
    "MAC 地址": ["MAC地址", "MAC 地址", "mac地址", "网卡地址", "WLAN地址"],
    "GPS 经纬度": ["GPS", "gps", "经纬度", "地理位置", "位置信息", "精确位置", "地理位置信息"],
    "IP 地址": ["IP地址", "IP 地址", "ip地址", "网络地址"],
    "SSID / BSSID": ["SSID", "WiFi名称", "WiFi信息", "WLAN", "无线网络"],
    "SIM 卡信息": ["SIM", "sim卡", "SIM卡", "运营商", "手机号", "电话号码", "手机号码"],
    "设备型号": ["设备型号", "手机型号", "设备信息", "设备类型", "硬件信息"],
    "操作系统版本": ["操作系统", "系统版本", "Android版本"],
    "应用列表": ["应用列表", "安装列表", "已安装应用", "应用安装"],
    "通讯录": ["通讯录", "联系人", "通信录"],
    "相册 / 存储": ["相册", "存储", "文件", "照片", "媒体"],
    "剪贴板": ["剪贴板", "粘贴板", "剪切板"],
    "账号 Token / Session": ["token", "Token", "session", "Session", "登录凭证", "会话"],
    "广告标识": ["广告标识", "广告ID", "IDFA", "GAID"],
    "传感器数据": ["传感器", "加速度", "陀螺仪", "sensor"],
    "摄像头 / 麦克风": ["摄像头", "相机", "麦克风", "录音"],
}

# 中文政策字段名 → rule 键（归一映射，反向）
FIELD_TO_RULE = {
    "IMEI": "imei",
    "IMSI": "sim_info",
    "Android ID": "android_id",
    "OAID": "oaid",
    "MAC 地址": "mac_address",
    "GPS 经纬度": "gps_coords",
    "IP 地址": "ip_address",
    "SSID / BSSID": "wifi_location",
    "SIM 卡信息": "sim_info",
    "设备型号": "build_fingerprint",
    "操作系统版本": "build_fingerprint",
    "应用列表": "installed_apps",
    "通讯录": "contact_list",
    "相册 / 存储": "storage",
    "剪贴板": "clipboard",
    "账号 Token / Session": "account_token",
    "广告标识": "oaid",
    "传感器数据": "sensor",
    "摄像头 / 麦克风": "camera",
}

# rule 键 → 中文说明（用于报告展示）
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

# 政策 HTML 文件 → App 名（文件名前缀 → App）
POLICY_FILE_TO_APP = {
    'xiaoyu_xiaoyuchuxing': '小鱼出行',
    'huidou_qiyijiu': '汇投北斗伴',
    'dengshan_fingersoft': '登山赛车',
    'chuxing365': '出行365',
    'dingdang_qq_policy': '叮当同学',
    'boaifei_qq_policy': '泊安飞停车',
}

# 官方声明：App Store 标注"不收集任何数据"（无政策文件）
DECLARES_NOTHING = {'小学英语同步学'}
# 政策来源不可得的 App（经下载站政策六原则确认收集，但无完整字段清单）
POLICY_PARTIAL = {'智雨云图'}


def strip_tags(text: str) -> str:
    # 部分政策页把整段正文以 HTML 实体形式嵌入 script/textarea 变量里
    # （双重转义 &amp;lt;b&amp;gt;...）。反转义后正文才变成真实标签，
    # 且正文内部可能含 </script>，因此不能按标签块删除——只删 script/style
    # 的开闭标记，保留内容（正文），再由通用 <[^>]+> 规则剥掉正文内标签。
    import html as _html
    for _ in range(3):
        unescaped = _html.unescape(text)
        if unescaped == text:
            break
        text = unescaped
    text = re.sub(r'<script[^>]*>', ' ', text, flags=re.I)
    text = re.sub(r'</script[^>]*>', ' ', text, flags=re.I)
    text = re.sub(r'<style[^>]*>', ' ', text, flags=re.I)
    text = re.sub(r'</style[^>]*>', ' ', text, flags=re.I)
    text = re.sub(r'<[^>]+>', ' ', text)
    text = re.sub(r'\s+', ' ', text)
    return text


def extract_declared_fields(app_name: str) -> list:
    """从政策 HTML / 官方声明提取政策声明字段（返回中文字段名列表）"""
    if app_name in DECLARES_NOTHING:
        return []  # 声明不收集任何数据
    if app_name in POLICY_PARTIAL:
        return []  # 仅有六原则，无字段清单 → 视为未声明具体字段

    # 找到对应政策文件
    policy_file = None
    for prefix, name in POLICY_FILE_TO_APP.items():
        if name == app_name:
            cand = POLICY_DIR / f'{prefix}.html'
            if cand.exists():
                policy_file = cand
                break
    if not policy_file:
        return []

    try:
        text = policy_file.read_text(encoding='utf-8', errors='replace')
    except Exception:
        return []
    text = strip_tags(text)

    declared = []
    for field, kws in KNOWN_DATA_KEYWORDS.items():
        if any(kw in text for kw in kws):
            declared.append(field)
    return declared


# hook 初始化/框架加载行（非实际采集，排除）
_HOOK_LINE_RE = re.compile(
    r'(?i)(?:已hook|已替换|hook\s+完成|hook\s+已启动|已启动|已加载|正在启动|安装完成|'
    r'ssl.?pin|TrustManager|HostnameVerifier|CertificatePinner|Conscrypt|Apache|WebViewClient|'
    r'hook Activity|hook ClipboardManager|hook LocationManager|hook TelephonyManager|'
    r'Cipher 已 hook|SecretKeySpec 已 hook|IvParameterSpec 已 hook|JSONObject 已 hook|'
    r'HttpURLConnection 已 hook|Protobuf|等待 App|tip|init\]|anti\]|sensitive\])')
# crypto txt 里的敏感字段 → rule 键
_TXT_RULE = [
    (re.compile(r'(?i)\bimei\b|设备识别码|getDeviceId'), 'imei'),
    (re.compile(r'(?i)\bimsi\b|\biccid\b|sim卡|sim_info'), 'sim_info'),
    (re.compile(r'(?i)android[_\-]?id'), 'android_id'),
    (re.compile(r'(?i)\boaid\b|匿名设备标识'), 'oaid'),
    (re.compile(r'(?i)\bidfa\b|广告标识'), 'oaid'),
    (re.compile(r'(?i)mac[_\-]?addr|网卡'), 'mac_address'),
    (re.compile(r'(?i)lat(?:itude)?[=:]|lon(?:itude)?[=:]|lng[=:]|getLastKnownLocation|gps|经纬度'), 'gps_coords'),
    (re.compile(r'(?i)phone[=:]|mobile[=:]|手机号'), 'phone_number'),
    # 不用裸 session：友盟 analytics 的 sessions/SessionTracker 是会话追踪，非账号 Token
    (re.compile(r'(?i)atoken|account_token|登录凭证'), 'account_token'),
    (re.compile(r'(?i)serial[_=:]|序列号'), 'serial_number'),
    (re.compile(r'(?i)installed_app|应用列表'), 'installed_apps'),
]


def load_actual_rule_keys(pkg: str) -> Counter:
    """从动态审计 jsonl + crypto txt 提取实际采集字段（rule 键）。
    在第二批（datarecord_miit）和第一批（datarecord_miit_another）两个证据目录中查找。"""
    counts = Counter()
    # jsonl：规则命中
    for base in (EVIDENCE_DIR, EVIDENCE_DIR_ANOTHER):
        log_files = glob.glob(str(base / pkg / f'{pkg}.jsonl'))
        for lf in log_files:
            try:
                with open(lf, encoding='utf-8', errors='replace') as f:
                    for line in f:
                        try:
                            ev = json.loads(line)
                        except json.JSONDecodeError:
                            continue
                        # 独立能力（如中国移动一键登录认证）不参与实际采集统计
                        if (ev.get('sdk_label') or '未识别') in EXCLUDE_SDKS:
                            continue
                        for h in ev.get('hits', []):
                            rule = h.get('rule', '')
                            if rule:
                                counts[rule] += 1
            except Exception:
                continue

    # crypto txt：非 hook 初始化的敏感明文（泊安飞等 txt-only App）
    txt_path = next((base / pkg / f'{pkg}.txt' for base in (EVIDENCE_DIR, EVIDENCE_DIR_ANOTHER)
                     if (base / pkg / f'{pkg}.txt').exists()), None)
    if txt_path and txt_path.exists():
        try:
            for line in txt_path.read_text(encoding='utf-8', errors='replace').splitlines():
                clean = re.sub(r'\x1b\[[0-9;]*m', '', line)
                if _HOOK_LINE_RE.search(clean):
                    continue
                for rx, rule in _TXT_RULE:
                    if rx.search(clean):
                        counts[rule] += 1
        except Exception:
            pass
    return counts


def field_to_rules(fields: list) -> set:
    """中文字段名 → rule 键集合"""
    rules = set()
    for f in fields:
        r = FIELD_TO_RULE.get(f)
        if r:
            rules.add(r)
    return rules


def main():
    results = []
    print(f"{'=' * 80}")
    print("工信部第 1、2 批通报 App：隐私政策 vs 实际采集对比")
    print(f"{'=' * 80}\n")

    for pkg, app_name in sorted(PKG_TO_APP.items()):
        batch = MIIT_APP_DETAIL.get(app_name, {}).get('batch', 2)
        declared_fields = extract_declared_fields(app_name)
        declared_rules = field_to_rules(declared_fields)

        actual_counts = load_actual_rule_keys(pkg)
        actual_rules = set(actual_counts.keys())

        undeclared = actual_rules - declared_rules
        declared_not_detected = declared_rules - actual_rules

        if app_name in DECLARES_NOTHING:
            policy_source = '官方声明不收集'
        elif batch == 1:
            # 第一批：未抓取政策，政策声明未知 → 只列实际采集，不做未声明判定
            policy_source = '政策未获取（第一批）'
        else:
            policy_source = ('政策已抓取' if declared_fields or app_name not in POLICY_PARTIAL
                             else '政策仅有六原则无字段清单' if app_name in POLICY_PARTIAL
                             else '政策不可得')

        results.append({
            "pkg": pkg,
            "name": app_name,
            "batch": batch,
            "policy_source": policy_source,
            "declared_fields": sorted(declared_fields),
            "declared_rules": sorted(declared_rules),
            "actual_rules": sorted(actual_rules),
            "actual_counts": dict(actual_counts),
            "undeclared": (sorted(undeclared) if batch == 2 else []),
            "declared_not_detected": sorted(declared_not_detected),
            "over_scope_count": (len(undeclared) if batch == 2 else 0),
        })

        print(f"{'─' * 60}")
        print(f"  {app_name} ({pkg})")
        src = results[-1]['policy_source']
        print(f"  政策来源: {src}")
        if declared_fields:
            print(f"  政策声明字段 ({len(declared_fields)}): {', '.join(declared_fields)}")
        else:
            print("  政策声明字段: (未声明具体字段)")
        actual_str = "、".join(f"{RULE_LABELS.get(r, r)}×{c}" for r, c in actual_counts.most_common())
        print(f"  实际采集 ({len(actual_rules)}): {actual_str or '(无)'}")
        if batch == 1:
            print("  (第一批：政策未获取，未做政策-采集对比)")
        elif undeclared:
            und_str = "、".join(RULE_LABELS.get(r, r) for r in sorted(undeclared))
            print(f"  ⚠ 政策未声明但实际采集 ({len(undeclared)}): {und_str}")
        else:
            print("  ✓ 实际采集均在政策声明范围内")
        if declared_not_detected:
            print(f"  (政策声明但未检测到: {', '.join(RULE_LABELS.get(r, r) for r in sorted(declared_not_detected))})")

    results.sort(key=lambda x: -x["over_scope_count"])

    with open(OUT_JSON, 'w', encoding='utf-8') as f:
        json.dump(results, f, ensure_ascii=False, indent=2)
    print(f"\n[✓] 结果保存: {OUT_JSON}")

    total_over = sum(r["over_scope_count"] for r in results)
    apps_over = sum(1 for r in results if r["over_scope_count"] > 0)
    print(f"\n总计: {len(results)} 个 App，{apps_over} 个存在政策未声明采集，{total_over} 个字段实例")


if __name__ == '__main__':
    main()
