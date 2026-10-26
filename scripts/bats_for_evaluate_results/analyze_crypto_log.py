#!/usr/bin/env python3
"""
analyze_crypto_log.py — crypto_log.txt 自动化分析器

自动从 crypto_tracer.js 产出的日志中提取：
  1. 隐私同意时间线（弹窗展示 → 用户同意 → 各 SDK 采集时间）
  2. 敏感数据字段清单（Android ID / IMEI / GPS / IP / MAC 等）
  3. 加密事件汇总（算法、密钥、IV、明文/密文对照）
  4. SDK 归属识别
  5. 违规行为自动判定
  6. 生成 HTML 可视化报告

用法：
    python analyze_crypto_log.py crypto_log.txt
    python analyze_crypto_log.py crypto_log.txt -o report.html
    python analyze_crypto_log.py crypto_log.txt --audit audit_log.jsonl
    python analyze_crypto_log.py *.txt              # 批量分析

依赖：纯 Python 标准库，无需 pip install
"""

import argparse
import json
import os
import re
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path


# 地区开关：'cn' 用国内法规（默认，国内版行为不变）；'foreign' 用 GDPR/CCPA/FTC
# 由命令行 --region 覆盖（subprocess 调用）或脚本内直接赋值
REGION = 'cn'


# ──────────────────────────────────────────────
#  ANSI 清理
# ──────────────────────────────────────────────

ANSI_RE = re.compile(r'\x1b\[[0-9;]*m')

def strip_ansi(text: str) -> str:
    return ANSI_RE.sub('', text)


# ──────────────────────────────────────────────
#  时间戳提取
# ──────────────────────────────────────────────

TS_RE = re.compile(r'\[(\d{2}:\d{2}:\d{2}\.\d+)\]')

def extract_ts(line: str):
    m = TS_RE.search(line)
    return m.group(1) if m else None


# ──────────────────────────────────────────────
#  JSON 提取
# ──────────────────────────────────────────────

def extract_json_objects(text: str) -> list:
    """从一行文本中提取所有 JSON 对象"""
    results = []
    depth = 0
    start = None
    for i, ch in enumerate(text):
        if ch == '{':
            if depth == 0:
                start = i
            depth += 1
        elif ch == '}':
            depth -= 1
            if depth == 0 and start is not None:
                candidate = text[start:i+1]
                try:
                    obj = json.loads(candidate)
                    results.append(obj)
                except json.JSONDecodeError:
                    pass
                start = None
    return results


# ──────────────────────────────────────────────
#  敏感数据规则
# ──────────────────────────────────────────────

@dataclass
class SensitiveHit:
    rule: str
    label: str
    severity: str       # critical / high / medium
    key: str
    value: str
    timestamp: str
    source_sdk: str
    line_no: int


SENSITIVE_RULES = [
    # (rule_name, label, severity, key_patterns, value_patterns)
    ("imei",         "IMEI / MEID",          "critical", [r"(?i)\bimei\b", r"(?i)\bmeid\b", r"(?i)not_get_imei"],
                                                          [r"\b\d{15,16}\b"]),
    ("android_id",   "Android ID",           "critical", [r"(?i)android[_\-]?id", r"(?i)BEACON_ANDROID_ID"],
                                                          [r"\b[0-9a-f]{16}\b"]),
    ("oaid",         "OAID",                 "high",     [r"(?i)\boaid\b"], []),
    ("mac_address",  "MAC 地址",             "critical", [r"(?i)mac[_\-]?addr", r"(?i)wifi[_\-]?mac"],
                                                          [r"(?:[0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}"]),
    ("gps",          "GPS 经纬度",           "critical", [r"(?i)(?<![a-z])(lat|lng|lon|latitude|longitude|gps_lat|gps_lng)(?![a-z])",
                                                           r"(?i)(?<![a-z])latlon(?![a-z])", r"(?i)report_latlon"],
                                                          [r"^-?\d{1,3}\.\d{4,8}$"]),
    ("ip_address",   "IP 地址",              "high",     [r"(?i)\bipv[46]\b"],
                                                          [r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b"]),
    ("phone",        "手机号",               "critical", [r"(?i)\b(phone|mobile|tel)\b"],
                                                          [r"(?<!\d)1[3-9]\d{9}(?!\d)"]),
    ("device_id",    "设备追踪 ID",          "high",     [r"(?i)(devid|device_id|dev_id|lego_devid|guid)"], []),
    ("installed_apps","已安装应用列表",       "high",     [r"(?i)(installed_app|pkg_list|app_list|applist|packages)"], []),
    ("clipboard",    "剪切板",               "high",     [r"(?i)(clipboard|clip_data)"], []),
    ("ssid_bssid",   "WiFi SSID/BSSID",      "high",     [r"(?i)(ssid|bssid|wifi_info|wifi_list|ap_mac)"], []),
    ("sim_info",     "SIM 卡信息",           "critical", [r"(?i)(imsi|iccid)"], [r"\b\d{15,20}\b"]),
    ("serial",       "设备序列号",           "high",     [r"(?i)\bserial\b", r"(?i)device_serial"], []),
    ("ua_fingerprint","UserAgent 指纹",      "medium",   [r"(?i)\bua\b"], []),
    ("build_info",   "设备/系统信息",        "medium",   [r"(?i)(build_fp|fingerprint|model|cpu|arch|G0[0-9]_00|G[12][0-9]_00)"],
                                                          []),
    ("contact",      "通讯录",               "critical", [r"(?i)(contacts|contact_list|addressbook)"], []),
    ("sms",          "短信内容",             "critical", [r"(?i)\bsms\b", r"(?i)short_message"], []),
    ("call_log",     "通话记录",             "critical", [r"(?i)(call_log|calllog|call_history)"], []),
]

# 编译正则
_COMPILED_RULES = []
for name, label, sev, key_pats, val_pats in SENSITIVE_RULES:
    _COMPILED_RULES.append((
        name, label, sev,
        [re.compile(p) for p in key_pats],
        [re.compile(p) for p in val_pats],
    ))


# ──────────────────────────────────────────────
#  超范围规则集（依据国信办14号文）
# ──────────────────────────────────────────────

# 所有39类App均不允许采集（包括 GPS：仅第1/2/22类可采集）
ALWAYS_OVERCOLLECTION_RULES = {
    "imei":          "IMEI 在 39 类 App 中均非必要信息",
    "android_id":    "Android ID 在 39 类 App 中均非必要信息",
    "oaid":          "OAID 在 39 类 App 中均非必要信息",
    "mac_address":   "MAC 地址在 39 类 App 中均非必要信息",
    "device_id":     "设备追踪 ID 在 39 类 App 中均非必要信息",
    "sim_info":      "SIM 信息（IMSI/ICCID）在 39 类 App 中均非必要信息",
    "serial":        "设备序列号在 39 类 App 中均非必要信息",
    "build_info":    "系统/设备指纹在 39 类 App 中均非必要信息",
    "installed_apps":"已安装应用列表在 39 类 App 中均非必要信息",
    "clipboard":     "剪切板内容在 39 类 App 中均非必要信息",
    "contact":       "通讯录仅即时通信类（第3类）需要，其余均属超范围",
    "sms":           "短信内容在 39 类 App 中均非必要信息",
    "call_log":      "通话记录在 39 类 App 中均非必要信息",
    # GPS 及位置信息：仅第1类（地图导航）、第2类（网约车）、第22类（用车服务）可采集
    "gps":           "GPS 经纬度仅地图导航/网约车/用车服务类可采集，其余均属超范围（14号文附表）",
    "ssid_bssid":    "WiFi SSID/BSSID 位置信息仅地图导航/网约车/用车服务类可采集",
}

# ── 国外版超范围规则集（依据 GDPR/CCPA/FTC）────────────────────
# 设备标识符类：一律判超范围（数据最小化）；位置/IP 类由合规汇总按政策比对处理，
# crypto 整合层仅标记为"含位置信息"，不重复判超范围（避免与合规汇总口径冲突）
ALWAYS_OVERCOLLECTION_RULES_FOREIGN = {
    "imei":          "采集 IMEI/MEID 超出数据最小化原则，广告业务非必要（GDPR Art.5(1)(c)）",
    "android_id":    "采集 Android ID 超出数据最小化原则，非必要（GDPR Art.5(1)(c)）",
    "oaid":          "采集 OAID 超出数据最小化原则，非必要（GDPR Art.5(1)(c)）",
    "mac_address":   "采集 MAC 地址超出数据最小化原则，非必要（GDPR Art.5(1)(c)）",
    "device_id":     "采集设备追踪 ID 超出数据最小化原则，非必要（GDPR Art.5(1)(c)）",
    "sim_info":      "采集 SIM/IMSI/ICCID 超出数据最小化原则，非必要（GDPR Art.5(1)(c)）",
    "serial":        "采集设备序列号超出数据最小化原则，非必要（GDPR Art.5(1)(c)）",
    "build_info":    "采集系统/设备指纹超出数据最小化原则，非必要（GDPR Art.5(1)(c)）",
    "installed_apps":"采集已安装应用列表超出数据最小化原则，非必要（GDPR Art.5(1)(c)）",
    "clipboard":     "采集剪贴板内容超出数据最小化原则，非必要（GDPR Art.5(1)(c)）",
    "contact":       "采集通讯录超出数据最小化原则，非必要（GDPR Art.5(1)(c)）",
    "sms":           "采集短信内容属特殊类别数据，超出数据最小化原则（GDPR Art.5(1)(c)+Art.9）",
    "call_log":      "采集通话记录超出数据最小化原则，非必要（GDPR Art.5(1)(c)）",
}

# 国外版：位置 / 网络信息类不判超范围（政策比对在合规汇总层完成）
# （gps / ssid_bssid / phone / ua_fingerprint / ip_address 仍出现在敏感数据清单，但不进超范围）

# 无须个人信息类（第21、27-38类）额外禁止：任何个人信息均属超范围
NO_INFO_EXTRA_OVERCOLLECTION = {
    "phone":         "该类 App（短视频/直播/影音/资讯）无需采集任何个人信息，手机号亦属超范围",
    "ua_fingerprint":"该类 App 无需采集任何个人信息，UserAgent 指纹亦属超范围",
    "ip_address":    "该类 App 无需采集任何个人信息，IP 地址亦属超范围",
}

# App 类别映射（依据国信办14号文）
APP_CATEGORIES = {
    # 无须个人信息类（第27-30类）—— 任何个人信息采集均属超范围
    "抖音":         {"type_id": 29, "type_name": "短视频类",   "need_phone": False},
    "快手":         {"type_id": 27, "type_name": "网络直播类",  "need_phone": False},
    "腾讯视频":     {"type_id": 28, "type_name": "在线影音类",  "need_phone": False},
    "红果免费短剧": {"type_id": 30, "type_name": "新闻资讯类",  "need_phone": False},
    # 仅需手机号类
    "百度贴吧":     {"type_id": 4,  "type_name": "网络社区类",  "need_phone": True},
    "知乎":         {"type_id": 4,  "type_name": "网络社区类",  "need_phone": True},
    "lofter":       {"type_id": 4,  "type_name": "网络社区类",  "need_phone": True},
    "soul":         {"type_id": 4,  "type_name": "网络社区类",  "need_phone": True},
    "小红书":       {"type_id": 4,  "type_name": "网络社区类",  "need_phone": True},
    "米游社":       {"type_id": 18, "type_name": "网络游戏类",  "need_phone": True},
    "转转":         {"type_id": 20, "type_name": "本地生活类",  "need_phone": True},
    # 网上购物类（手机号+收货人信息+支付信息）
    "淘宝":         {"type_id": 6,  "type_name": "网上购物类",  "need_phone": True},
    "得物":         {"type_id": 6,  "type_name": "网上购物类",  "need_phone": True},
    "唯品会":       {"type_id": 6,  "type_name": "网上购物类",  "need_phone": True},
    "咸鱼":         {"type_id": 6,  "type_name": "网上购物类",  "need_phone": True},
    "Amazon":       {"type_id": 6,  "type_name": "网上购物类",  "need_phone": True},
    "Aliexpress":   {"type_id": 6,  "type_name": "网上购物类",  "need_phone": True},
    "1688":         {"type_id": 6,  "type_name": "网上购物类",  "need_phone": True},
    "vivo商城":     {"type_id": 6,  "type_name": "网上购物类",  "need_phone": True},
    # 婚恋相亲类（手机号+性别+年龄+婚姻状况）
    "meetme":       {"type_id": 10, "type_name": "婚恋相亲类",  "need_phone": True},
    # 文件名与 App 名不一致的特殊映射
    "bilibili":     {"type_id": 28, "type_name": "在线影音类",  "need_phone": False},  # B站
    "美团":         {"type_id": 7,  "type_name": "餐饮外卖类",  "need_phone": True},
}

# 文件名 → 显示名称（用于文件名与 App 名不一致时）
DISPLAY_NAME_MAP = {
    "bilibili":   "B站",
}


def match_sensitive(kv_pairs: list, timestamp: str, sdk: str, line_no: int) -> list:
    hits = []
    seen_rules = set()
    for key, value in kv_pairs:
        for name, label, sev, key_rxs, val_rxs in _COMPILED_RULES:
            if name in seen_rules:
                continue
            matched = False
            for rx in key_rxs:
                if rx.search(str(key)):
                    matched = True
                    break
            if not matched:
                for rx in val_rxs:
                    if rx.search(str(value)):
                        matched = True
                        break
            if matched:
                seen_rules.add(name)
                val_preview = str(value)[:80]
                hits.append(SensitiveHit(name, label, sev, str(key)[:60], val_preview,
                                         timestamp, sdk, line_no))
    return hits


# ──────────────────────────────────────────────
#  SDK 识别
# ──────────────────────────────────────────────

SDK_PATTERNS = [
    (r"com\.tencent\.tmsbeacon",          "腾讯灯塔 tmsbeacon"),
    (r"com\.tencent\.gaya",               "腾讯地图 SDK"),
    (r"com\.tencent\.liteav",             "腾讯 LiteAV"),
    (r"com\.tencent\.mm",                 "微信 SDK"),
    (r"com\.tencent\.open",               "腾讯开放平台"),
    (r"com\.bytedance",                   "字节跳动 SDK"),
    (r"com\.pangle\b|pangle",            "穿山甲 Pangle"),
    (r"com\.umeng|umengcloud",            "友盟+ Umeng"),
    (r"com\.baidu\.mobads",               "百度 MobAds"),
    (r"com\.qq\.e\.|gdt\.qq\.com",        "优量汇 GDT"),
    (r"com\.xiaomi\b|\.mi\.com",          "小米 SDK"),
    (r"com\.alibaba|alicdn",              "阿里系 SDK"),
    (r"com\.huawei",                      "华为 SDK"),
    (r"com\.google\.android\.gms",        "Google Play Services"),
    (r"com\.facebook",                    "Facebook SDK"),
    (r"SignInterceptor|SignResponse",      "App 自有签名"),
]

_SDK_RXS = [(re.compile(p, re.IGNORECASE), name) for p, name in SDK_PATTERNS]


def identify_sdk(text: str) -> str:
    for rx, name in _SDK_RXS:
        if rx.search(text):
            return name
    return "未识别"


# ──────────────────────────────────────────────
#  主分析器
# ──────────────────────────────────────────────

@dataclass
class CipherEvent:
    timestamp: str
    algorithm: str
    mode: str           # ENCRYPT / DECRYPT
    key_hex: str
    iv_hex: str
    plaintext: str
    ciphertext: str
    sdk: str
    line_no: int


@dataclass
class ConsentEvent:
    show_ts: str        # 隐私弹窗展示时间
    agree_ts: str       # 用户点击同意时间


@dataclass
class EncryptionEvasionHit:
    """加密规避：敏感数据出现在 Cipher.doFinal ENCRYPT 明文中，意图绕过网络层（mitmproxy）检测"""
    rule: str
    label: str
    severity: str
    key: str
    value: str
    timestamp: str
    sdk: str
    line_no: int
    algorithm: str


@dataclass
class BgCollectionHit:
    """后台静默采集：距上次 JSON 事件超过空闲阈值后仍检测到敏感数据采集"""
    rule: str
    label: str
    severity: str
    key: str
    value: str
    timestamp: str
    sdk: str
    line_no: int
    gap_seconds: float


@dataclass
class FrequentCollectionHit:
    """超频次采集：同一敏感字段类型在短时窗内被多次采集"""
    rule: str
    label: str
    count: int
    window_start: str
    window_end: str
    threshold: int


@dataclass
class AnalysisResult:
    app_name: str
    file_path: str
    total_lines: int
    time_range: tuple

    consent: ConsentEvent
    sensitive_hits: list
    cipher_events: list
    sdk_set: set
    json_count: int
    cipher_count: int

    # 违规判定
    pre_consent_hits: list        # 同意前采集的敏感数据
    overcollection_hits: list     # 超范围采集（含判定依据）
    cat_info: dict = None         # App 类别信息（国信办14号文）
    encryption_evasion_hits: list = None   # 加密规避行为
    bg_collection_hits: list = None        # 后台静默采集
    frequent_collection_hits: list = None  # 超频次采集


def ts_to_sec(ts: str) -> float:
    """将 HH:MM:SS.mmm 时间戳转换为秒数，用于时间差计算"""
    try:
        parts = ts.split(':')
        return int(parts[0]) * 3600 + int(parts[1]) * 60 + float(parts[2])
    except Exception:
        return -1.0


_BG_IDLE_SEC    = 30.0  # 后台判定：距上次 JSON 事件超过此秒数视为进入后台
_FREQ_WINDOW    = 60.0  # 超频次判定：滑动时间窗口（秒）
_FREQ_THRESHOLD = 5     # 超频次判定：窗口内同规则出现次数阈值


def parse_crypto_log(filepath: str, app_label: str = "") -> AnalysisResult:
    """解析 crypto_log.txt，返回分析结果"""

    path = Path(filepath)
    raw_lines = path.read_text(encoding='utf-8', errors='replace').splitlines()
    lines = [strip_ansi(l) for l in raw_lines]

    total_lines = len(lines)
    all_timestamps = []
    json_events = []
    cipher_events = []
    sensitive_hits = []
    cipher_plaintext_hits = []   # (SensitiveHit, algo) 来自 ENCRYPT 明文，用于加密规避检测
    sdk_set = set()

    consent_show_ts = None
    consent_agree_ts = None

    # 上下文缓存
    current_key_hex = ""
    current_iv_hex = ""
    current_algo = ""
    current_mode = ""
    pending_stack_lines = []

    json_count = 0
    cipher_count = 0

    i = 0
    while i < total_lines:
        line = lines[i]
        ts = extract_ts(line)
        if ts:
            all_timestamps.append(ts)

        # ── 隐私弹窗检测（JSON 可能在上一行或下一行）──
        combined = line
        if i > 0:
            combined = lines[i-1] + " " + line
        if i + 1 < total_lines:
            combined += " " + lines[i+1]

        if 'privacyPolicyAlertShow' in combined:
            found_ts = ts
            if not found_ts and i > 0:
                found_ts = extract_ts(lines[i-1])
            if not found_ts and i + 1 < total_lines:
                found_ts = extract_ts(lines[i+1])
            consent_show_ts = found_ts or consent_show_ts

        if 'privacyPolicyAlertBtnClick' in combined and '同意' in combined:
            found_ts = ts
            if not found_ts and i > 0:
                found_ts = extract_ts(lines[i-1])
            if not found_ts and i + 1 < total_lines:
                found_ts = extract_ts(lines[i+1])
            consent_agree_ts = found_ts or consent_agree_ts

        # ── JSON 事件 ──
        if 'JSONObject.toString()' in line or line.strip().startswith('{'):
            json_count += 1
            # 找 JSON 内容（可能在本行或下一行）
            json_text = line
            if i + 1 < total_lines and lines[i+1].strip().startswith('{'):
                json_text = lines[i+1]

            objs = extract_json_objects(json_text)

            # 收集调用栈判断 SDK
            stack_text = ""
            j = i + 1
            while j < total_lines and j < i + 12:
                if lines[j].strip().startswith('at '):
                    stack_text += lines[j] + "\n"
                elif lines[j].strip().startswith('['):
                    break
                j += 1

            sdk = identify_sdk(stack_text) if stack_text else "未识别"
            if sdk != "未识别":
                sdk_set.add(sdk)

            for obj in objs:
                kv = []
                _flatten_to_kv(obj, "", kv)
                hits = match_sensitive(kv, ts or "", sdk, i + 1)
                sensitive_hits.extend(hits)

                json_events.append({
                    "ts": ts,
                    "data": obj,
                    "sdk": sdk,
                    "line": i + 1,
                })

        # ── SecretKeySpec ──
        if 'SecretKeySpec' in line and '密钥:' in line:
            m = re.search(r'密钥:\s*(.+)', line)
            if m:
                current_key_hex = m.group(1).strip()
            # SDK from stack
            stack = _collect_stack(lines, i + 1)
            sdk = identify_sdk(stack)
            if sdk != "未识别":
                sdk_set.add(sdk)

        if line.strip().startswith('密钥:'):
            m = re.search(r'密钥:\s*(.+)', line)
            if m:
                current_key_hex = m.group(1).strip()

        # ── IV ──
        if 'IvParameterSpec' in line or line.strip().startswith('IV:'):
            m = re.search(r'IV:\s*(.+)', line)
            if not m and i + 1 < total_lines:
                m = re.search(r'IV:\s*(.+)', lines[i+1])
            if m:
                current_iv_hex = m.group(1).strip()

        # ── Cipher.getInstance ──
        if 'getInstance(' in line and 'Cipher' in line:
            m = re.search(r'getInstance\("([^"]+)"\)', line)
            if m:
                current_algo = m.group(1)

        # ── Cipher.init ──
        if 'Cipher' in line and 'init(' in line:
            if 'ENCRYPT' in line:
                current_mode = 'ENCRYPT'
            elif 'DECRYPT' in line:
                current_mode = 'DECRYPT'
            # 密钥可能在下面几行
            for j in range(i+1, min(i+4, total_lines)):
                if '密钥:' in lines[j]:
                    m = re.search(r'密钥:\s*(.+)', lines[j])
                    if m:
                        current_key_hex = m.group(1).strip()
                if 'IV:' in lines[j]:
                    m = re.search(r'IV:\s*(.+)', lines[j])
                    if m:
                        current_iv_hex = m.group(1).strip()

        # ── Cipher.doFinal ──
        if 'Cipher.doFinal' in line:
            cipher_count += 1
            plaintext = ""
            ciphertext = ""
            algo = current_algo

            # 算法可能在本行
            m_algo = re.search(r'Cipher\.doFinal\s*—\s*(\S+)', line)
            if m_algo:
                algo = m_algo.group(1)

            # 扫描接下来的行找输入/输出
            for j in range(i+1, min(i+8, total_lines)):
                l = lines[j]
                if '输入' in l and ('TEXT' in l or 'HEX' in l):
                    m = re.search(r'(?:TEXT\]|HEX\])\s*(.+)', l)
                    if m:
                        plaintext = m.group(1).strip()[:200]
                if '输出' in l and ('TEXT' in l or 'HEX' in l):
                    m = re.search(r'(?:TEXT\]|HEX\])\s*(.+)', l)
                    if m:
                        ciphertext = m.group(1).strip()[:200]

            stack = _collect_stack(lines, i + 1)
            sdk = identify_sdk(stack)
            if sdk != "未识别":
                sdk_set.add(sdk)

            ev = CipherEvent(
                timestamp=ts or "",
                algorithm=algo,
                mode=current_mode,
                key_hex=current_key_hex[:100],
                iv_hex=current_iv_hex[:100],
                plaintext=plaintext,
                ciphertext=ciphertext,
                sdk=sdk,
                line_no=i + 1,
            )
            cipher_events.append(ev)

            # 检查明文中的敏感数据；ENCRYPT 模式下单独记录用于加密规避检测
            if plaintext:
                objs = extract_json_objects(plaintext)
                for obj in objs:
                    kv = []
                    _flatten_to_kv(obj, "", kv)
                    hits = match_sensitive(kv, ts or "", sdk, i + 1)
                    sensitive_hits.extend(hits)
                    if ev.mode == 'ENCRYPT':
                        for h in hits:
                            cipher_plaintext_hits.append((h, algo))

        i += 1

    # ── 去重 ──
    seen = set()
    unique_hits = []
    for h in sensitive_hits:
        key = (h.rule, h.key, h.value[:30])
        if key not in seen:
            seen.add(key)
            unique_hits.append(h)
    sensitive_hits = unique_hits

    # ── App 类别查找 ──
    # 优先用传入的 app_label，其次尝试从包名推断
    cat_info = APP_CATEGORIES.get(app_label)
    if not cat_info and app_label:
        for k, v in APP_CATEGORIES.items():
            if k in app_label or app_label in k:
                cat_info = v
                break

    # ── 依据类别构建超范围规则集 ──
    if REGION == 'foreign':
        # 国外版：设备标识符判超范围，位置/IP 类交给合规汇总的政策比对层
        oc_rules = dict(ALWAYS_OVERCOLLECTION_RULES_FOREIGN)
        # 位置/IP 类仅标记敏感性，不判超范围
        for h in sensitive_hits:
            if h.rule in ("gps", "ssid_bssid", "phone", "ua_fingerprint", "ip_address"):
                h.overcollection_reason = "位置/网络信息：是否超范围由隐私政策比对判定（GDPR Art.5(1)(c)）"
        cat_info = None   # 国外版无 App 类别概念，徽章走数据敏感性标签
    else:
        oc_rules = dict(ALWAYS_OVERCOLLECTION_RULES)
        if cat_info and not cat_info.get("need_phone", True):
            # 无须个人信息类（短视频/直播/影音/资讯）：手机号等也属超范围
            oc_rules.update(NO_INFO_EXTRA_OVERCOLLECTION)

    # ── 违规判定 ──
    pre_consent_hits = []
    overcollection_hits = []

    if consent_agree_ts:
        for h in sensitive_hits:
            if h.timestamp and h.timestamp < consent_agree_ts:
                pre_consent_hits.append(h)

    for h in sensitive_hits:
        if h.rule in oc_rules:
            # 把判定依据附加到 hit 对象上，供报告展示
            h.overcollection_reason = oc_rules[h.rule]
            overcollection_hits.append(h)

    # ── 加密规避行为检测 ──
    # 敏感数据出现在 ENCRYPT 操作的明文中 → 数据在上传前被加密，绕过网络层监测
    encryption_evasion_hits = []
    seen_ee = set()
    for h, algo in cipher_plaintext_hits:
        if h.rule in oc_rules:
            key = (h.rule, h.key, h.value[:30])
            if key not in seen_ee:
                seen_ee.add(key)
                encryption_evasion_hits.append(EncryptionEvasionHit(
                    rule=h.rule, label=h.label, severity=h.severity,
                    key=h.key, value=h.value, timestamp=h.timestamp,
                    sdk=h.source_sdk, line_no=h.line_no, algorithm=algo,
                ))

    # ── 后台静默采集检测 ──
    # 找出相邻 JSON 事件之间超过 _BG_IDLE_SEC 的空闲间隔，间隔后 10 秒内的采集视为后台采集
    json_timed = sorted(
        [(ts_to_sec(ev['ts']), ev) for ev in json_events
         if ev.get('ts') and ts_to_sec(ev['ts']) >= 0],
        key=lambda x: x[0],
    )
    bg_gap_starts = []
    for j in range(1, len(json_timed)):
        gap = json_timed[j][0] - json_timed[j-1][0]
        if gap >= _BG_IDLE_SEC:
            bg_gap_starts.append((json_timed[j][0], gap))

    bg_collection_hits = []
    seen_bg = set()
    for h in sensitive_hits:
        if h.timestamp:
            sec = ts_to_sec(h.timestamp)
            for gap_ts, gap_sec in bg_gap_starts:
                if 0.0 <= sec - gap_ts <= 10.0:
                    key = (h.rule, h.key)
                    if key not in seen_bg:
                        seen_bg.add(key)
                        bg_collection_hits.append(BgCollectionHit(
                            rule=h.rule, label=h.label, severity=h.severity,
                            key=h.key, value=h.value, timestamp=h.timestamp,
                            sdk=h.source_sdk, line_no=h.line_no,
                            gap_seconds=round(gap_sec, 1),
                        ))
                    break

    # ── 超频次采集检测 ──
    # 同一规则在 _FREQ_WINDOW 秒内出现 >= _FREQ_THRESHOLD 次视为超频次
    rule_timed = defaultdict(list)
    for h in sensitive_hits:
        if h.timestamp:
            sec = ts_to_sec(h.timestamp)
            if sec >= 0:
                rule_timed[h.rule].append((sec, h))

    frequent_collection_hits = []
    seen_freq = set()
    for rule, timed in rule_timed.items():
        timed.sort(key=lambda x: x[0])
        for start_idx in range(len(timed)):
            s0 = timed[start_idx][0]
            window = [(s, h) for s, h in timed[start_idx:] if s - s0 <= _FREQ_WINDOW]
            if len(window) >= _FREQ_THRESHOLD and rule not in seen_freq:
                seen_freq.add(rule)
                frequent_collection_hits.append(FrequentCollectionHit(
                    rule=rule,
                    label=window[0][1].label,
                    count=len(window),
                    window_start=window[0][1].timestamp,
                    window_end=window[-1][1].timestamp,
                    threshold=_FREQ_THRESHOLD,
                ))
                break

    # ── 推断 App 名 ──
    app_name = "未知"
    for ev in json_events:
        data = ev.get("data", {})
        # 直接字段
        pkg = data.get("packageName") or data.get("bundle_id") or data.get("bundleId") or ""
        if pkg and "." in pkg and len(pkg) > 5:
            app_name = pkg
            break
    # 备选：从 lego_devid / CertificatePinner 域名推断
    if app_name == "未知":
        for l in lines[:200]:
            m = re.search(r'CertificatePinner\.check\("([^"]+)"\)', l)
            if m:
                app_name = m.group(1)
                break

    time_range = (all_timestamps[0] if all_timestamps else "?",
                  all_timestamps[-1] if all_timestamps else "?")

    return AnalysisResult(
        app_name=app_name,
        file_path=str(filepath),
        total_lines=total_lines,
        time_range=time_range,
        consent=ConsentEvent(consent_show_ts or "未检测到", consent_agree_ts or "未检测到"),
        sensitive_hits=sensitive_hits,
        cipher_events=cipher_events,
        sdk_set=sdk_set,
        json_count=json_count,
        cipher_count=cipher_count,
        pre_consent_hits=pre_consent_hits,
        overcollection_hits=overcollection_hits,
        cat_info=cat_info,
        encryption_evasion_hits=encryption_evasion_hits,
        bg_collection_hits=bg_collection_hits,
        frequent_collection_hits=frequent_collection_hits,
    )


def _flatten_to_kv(obj, prefix, result):
    if isinstance(obj, dict):
        for k, v in obj.items():
            full_key = f"{prefix}.{k}" if prefix else k
            if isinstance(v, (dict, list)):
                _flatten_to_kv(v, full_key, result)
            else:
                result.append((full_key, str(v)))
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            _flatten_to_kv(v, f"{prefix}[{i}]", result)


def _collect_stack(lines, start, max_lines=10):
    parts = []
    for j in range(start, min(start + max_lines, len(lines))):
        l = lines[j].strip()
        if l.startswith('at '):
            parts.append(l)
        elif l.startswith('[') and 'at ' not in l:
            break
    return "\n".join(parts)


# ──────────────────────────────────────────────
#  终端输出
# ──────────────────────────────────────────────

C_RED = "\033[91m"
C_YEL = "\033[93m"
C_GRN = "\033[92m"
C_CYA = "\033[96m"
C_MAG = "\033[95m"
C_BOLD = "\033[1m"
C_DIM = "\033[90m"
C_RST = "\033[0m"

SEV_COLOR = {"critical": C_RED, "high": C_YEL, "medium": C_CYA, "low": C_DIM}


def print_summary(r: AnalysisResult):
    print(f"\n{C_BOLD}{C_CYA}{'═' * 60}{C_RST}")
    print(f"{C_BOLD} 📊 crypto_log 自动分析结果{C_RST}")
    print(f"{C_BOLD}{C_CYA}{'═' * 60}{C_RST}")

    cat = r.cat_info
    cat_str = f"第{cat['type_id']}类·{cat['type_name']}" if cat else "类别未识别（按最严格规则判定）"
    no_info = cat and not cat.get("need_phone", True)
    print(f"\n{C_BOLD}📱 App 信息{C_RST}")
    print(f"  包名：{r.app_name}")
    print(f"  文件：{r.file_path}（{r.total_lines} 行）")
    print(f"  时间：{r.time_range[0]} → {r.time_range[1]}")
    if REGION == 'foreign':
        print(f"  判定依据：GDPR / CCPA(CPRA) / FTC Act §5")
    elif no_info:
        print(f"  {C_RED}类别：{cat_str} — 任何个人信息采集均属超范围{C_RST}")
    else:
        print(f"  类别：{cat_str}")

    print(f"\n{C_BOLD}📈 统计{C_RST}")
    print(f"  JSON 事件：{r.json_count}")
    print(f"  加密调用：{r.cipher_count}")
    print(f"  涉及 SDK：{len(r.sdk_set)} 个 — {', '.join(r.sdk_set) if r.sdk_set else '无'}")

    print(f"\n{C_BOLD}⏱  隐私同意时间线{C_RST}")
    print(f"  弹窗显示：{r.consent.show_ts}")
    print(f"  用户同意：{r.consent.agree_ts}")
    if r.consent.show_ts != "未检测到" and r.consent.agree_ts != "未检测到":
        print(f"  {C_RED}同意前采集事件：{len(r.pre_consent_hits)} 条{C_RST}")

    if r.sensitive_hits:
        print(f"\n{C_BOLD}🔍 敏感数据采集清单（{len(r.sensitive_hits)} 项）{C_RST}")
        for h in r.sensitive_hits:
            c = SEV_COLOR.get(h.severity, "")
            pre = " ⚠同意前" if (r.consent.agree_ts != "未检测到" and h.timestamp and h.timestamp < r.consent.agree_ts) else ""
            print(f"  {c}[{h.severity.upper():8s}]{C_RST} {h.label:20s} "
                  f"{C_DIM}key={C_RST}{h.key:30s} {C_DIM}val={C_RST}{h.value[:40]}"
                  f"{C_RED}{pre}{C_RST}"
                  f"  {C_DIM}@ {h.timestamp} L{h.line_no} ({h.source_sdk}){C_RST}")

    if r.cipher_events:
        print(f"\n{C_BOLD}🔐 加密事件摘要（{len(r.cipher_events)} 次 doFinal）{C_RST}")
        # 只打印有明文的
        shown = 0
        for ev in r.cipher_events:
            if ev.plaintext and shown < 10:
                shown += 1
                print(f"  {C_MAG}[{ev.algorithm}]{C_RST} {ev.mode} @ {ev.timestamp} L{ev.line_no}")
                print(f"    {C_DIM}密钥:{C_RST} {ev.key_hex[:60]}")
                if ev.iv_hex:
                    print(f"    {C_DIM}IV:  {C_RST} {ev.iv_hex[:60]}")
                print(f"    {C_GRN}明文:{C_RST} {ev.plaintext[:120]}")
                print(f"    {C_DIM}SDK: {ev.sdk}{C_RST}")
        if len(r.cipher_events) > shown:
            print(f"  {C_DIM}... 另有 {len(r.cipher_events) - shown} 条无明文 / 已省略{C_RST}")

    ee  = r.encryption_evasion_hits or []
    bg  = r.bg_collection_hits or []
    frq = r.frequent_collection_hits or []

    if r.pre_consent_hits or r.overcollection_hits or ee or bg or frq:
        print(f"\n{C_BOLD}{C_RED}⚠ 违规行为判定{C_RST}")
        if r.pre_consent_hits:
            law_str = "违反 GDPR Art.6(1)(a)+Art.7 同意合法基础" if REGION == 'foreign' else "违反 PIPL 第13条"
            print(f"  {C_RED}🔴 未经同意采集（{len(r.pre_consent_hits)} 项）— {law_str}{C_RST}")
            for h in r.pre_consent_hits:
                print(f"     {h.label}: {h.key}={h.value[:40]} @ {h.timestamp}")
        if r.overcollection_hits:
            cat = r.cat_info
            cat_str = f"第{cat['type_id']}类·{cat['type_name']}" if cat else "未识别类别"
            oc_law = "违反 GDPR Art.5(1)(c) 数据最小化原则" if REGION == 'foreign' else "违反国信办14号文"
            print(f"  {C_RED}🔴 超范围采集（{len(r.overcollection_hits)} 项）— {oc_law} [{cat_str}]{C_RST}")
            for h in r.overcollection_hits:
                reason = getattr(h, "overcollection_reason", "")
                reason_str = f"  {C_DIM}← {reason}{C_RST}" if reason else ""
                print(f"     {h.label}: {h.key}={h.value[:40]}{reason_str}")
        if ee:
            print(f"  {C_MAG}🔐 加密规避行为（{len(ee)} 项）— 敏感数据加密后上传，绕过网络层检测{C_RST}")
            for h in ee:
                print(f"     [{h.algorithm}] {h.label}: {h.key}={h.value[:40]} @ {h.timestamp}")
        if bg:
            print(f"  {C_YEL}🌙 后台静默采集（{len(bg)} 项）— 用户切换后台后仍采集敏感数据{C_RST}")
            for h in bg:
                print(f"     {h.label}: {h.key}={h.value[:40]} @ {h.timestamp}  {C_DIM}← 距上次活动 {h.gap_seconds}s{C_RST}")
        if frq:
            print(f"  {C_YEL}🔄 超频次采集（{len(frq)} 类）— {_FREQ_WINDOW}s 内超过 {_FREQ_THRESHOLD} 次{C_RST}")
            for h in frq:
                print(f"     {h.label}: {h.count} 次 / {_FREQ_WINDOW}s  [{h.window_start} → {h.window_end}]")

    print(f"\n{C_BOLD}{C_CYA}{'═' * 60}{C_RST}\n")


# ──────────────────────────────────────────────
#  HTML 报告生成
# ──────────────────────────────────────────────

def generate_html_report(r: AnalysisResult, out_path: Path):
    """生成 HTML 分析报告"""

    sensitive_rows = ""
    for h in r.sensitive_hits:
        pre = "⚠ 同意前" if (r.consent.agree_ts != "未检测到" and h.timestamp and h.timestamp < r.consent.agree_ts) else ""
        sev_cls = h.severity
        sensitive_rows += f"""<tr>
            <td><span class="badge {sev_cls}">{h.severity.upper()}</span></td>
            <td>{_esc(h.label)}</td>
            <td><code>{_esc(h.key)}</code></td>
            <td><code>{_esc(h.value)}</code></td>
            <td>{_esc(h.source_sdk)}</td>
            <td>{_esc(h.timestamp)}{' <span class="pre-consent">'+pre+'</span>' if pre else ''}</td>
            <td>L{h.line_no}</td>
        </tr>"""

    cipher_rows = ""
    for ev in r.cipher_events:
        if ev.plaintext:
            cipher_rows += f"""<tr>
                <td>{_esc(ev.timestamp)}</td>
                <td><code>{_esc(ev.algorithm)}</code></td>
                <td>{ev.mode}</td>
                <td><code style="font-size:10px">{_esc(ev.key_hex[:48])}</code></td>
                <td style="max-width:300px;overflow:hidden;text-overflow:ellipsis">{_esc(ev.plaintext[:150])}</td>
                <td>{_esc(ev.sdk)}</td>
            </tr>"""

    violation_items = ""
    if r.pre_consent_hits:
        items = "".join(f"<li>{_esc(h.label)}: <code>{_esc(h.key)}={_esc(h.value[:40])}</code> @ {h.timestamp}</li>"
                        for h in r.pre_consent_hits)
        pre_consent_law = ("违反 GDPR Art.6(1)(a)+Art.7 同意合法基础，未经有效同意即处理"
                           if REGION == 'foreign' else "违反：《个人信息保护法》第13条")
        violation_items += f"""<div class="violation critical">
            <h3>🔴 未经同意采集（{len(r.pre_consent_hits)} 项）</h3>
            <p>隐私弹窗 {r.consent.show_ts}，同意 {r.consent.agree_ts}，以下数据在同意前已采集：</p>
            <ul>{items}</ul>
            <p class="law">{_esc(pre_consent_law)}</p>
        </div>"""
    if r.overcollection_hits:
        cat = r.cat_info
        cat_str = f"第{cat['type_id']}类·{cat['type_name']}" if cat else "未识别类别"
        no_info_tip = "（该类 App 无需采集任何个人信息，所有采集均属超范围）" if (cat and not cat.get("need_phone", True)) else ""
        items = "".join(
            f"<li>{_esc(h.label)}: <code>{_esc(h.key)}={_esc(h.value[:40])}</code>"
            f"<span class='law' style='margin-left:8px'>{_esc(getattr(h,'overcollection_reason',''))}</span></li>"
            for h in r.overcollection_hits
        )
        if REGION == 'foreign':
            oc_head = f"<h3>🔴 超范围采集（{len(r.overcollection_hits)} 项）— 设备标识符类</h3>"
            oc_intro = "以下设备标识符采集超出数据最小化原则，广告业务非必要："
            oc_law = "违反：GDPR Art.5(1)(c) 数据最小化原则；CCPA §1798.100(b) 合理必要限制"
        else:
            oc_head = f"<h3>🔴 超范围采集（{len(r.overcollection_hits)} 项）— App 类别：{_esc(cat_str)}{_esc(no_info_tip)}</h3>"
            oc_intro = "以下采集行为超出国信办14号文规定的必要信息范围："
            oc_law = "违反：《常见类型移动互联网应用程序必要个人信息范围规定》（国信办秘字〔2021〕14号）"
        violation_items += f"""<div class="violation high">
            {oc_head}
            <p>{_esc(oc_intro)}</p>
            <ul>{items}</ul>
            <p class="law">{_esc(oc_law)}</p>
        </div>"""

    ee_hits = r.encryption_evasion_hits or []
    if ee_hits:
        items = "".join(
            f"<li>[{_esc(h.algorithm)}] {_esc(h.label)}: <code>{_esc(h.key)}={_esc(h.value[:40])}</code>"
            f" @ {_esc(h.timestamp)} — {_esc(h.sdk)}</li>"
            for h in ee_hits
        )
        violation_items += f"""<div class="violation critical" style="border-left-color:#8e44ad">
            <h3>🔐 加密规避行为（{len(ee_hits)} 项）</h3>
            <p>以下敏感数据出现在 <code>Cipher.doFinal</code> ENCRYPT 操作的明文中，说明 App 在上传前对其加密，意图绕过网络层（mitmproxy）监测：</p>
            <ul>{items}</ul>
            <p class="law">参考：《个人信息保护法》第51条（技术措施不得用于规避监管）</p>
        </div>"""

    bg_hits = r.bg_collection_hits or []
    if bg_hits:
        items = "".join(
            f"<li>{_esc(h.label)}: <code>{_esc(h.key)}={_esc(h.value[:40])}</code>"
            f" @ {_esc(h.timestamp)} <span class='law'>← 距上次活动 {h.gap_seconds}s 后采集</span></li>"
            for h in bg_hits
        )
        bg_law = ("违反 GDPR Art.5(1)(a) 合法公平透明 + Art.13 告知义务"
                  if REGION == 'foreign' else "违反：《个人信息保护法》第17条（知情同意原则）")
        violation_items += f"""<div class="violation high" style="border-left-color:#e67e22">
            <h3>🌙 后台静默采集（{len(bg_hits)} 项）</h3>
            <p>以下敏感数据在用户疑似切换后台（距上次 JSON 事件超过 {_BG_IDLE_SEC:.0f} 秒）后仍被采集：</p>
            <ul>{items}</ul>
            <p class="law">{_esc(bg_law)}</p>
        </div>"""

    frq_hits = r.frequent_collection_hits or []
    if frq_hits:
        items = "".join(
            f"<li>{_esc(h.label)}：{h.count} 次 / {_FREQ_WINDOW:.0f}s"
            f"（{_esc(h.window_start)} → {_esc(h.window_end)}）</li>"
            for h in frq_hits
        )
        frq_law = ("违反 GDPR Art.5(1)(c) 数据最小化（超出必要频率）/ Art.6 合法基础缺失"
                   if REGION == 'foreign' else "违反：《个人信息保护法》第6条（最小必要原则）")
        violation_items += f"""<div class="violation high" style="border-left-color:#f39c12">
            <h3>🔄 超频次采集（{len(frq_hits)} 类字段）</h3>
            <p>以下敏感字段在 {_FREQ_WINDOW:.0f} 秒滑动窗口内被采集 ≥ {_FREQ_THRESHOLD} 次，存在持续轮询行为：</p>
            <ul>{items}</ul>
            <p class="law">{_esc(frq_law)}</p>
        </div>"""

    sdk_list = "".join(f"<span class='badge sdk'>{_esc(s)}</span> " for s in sorted(r.sdk_set))

    html = f"""<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>crypto_log 分析报告 — {_esc(r.app_name)}</title>
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:-apple-system,'PingFang SC','Microsoft YaHei',sans-serif;background:#f8f9fa;color:#333;font-size:14px;line-height:1.6}}
code{{font-family:'JetBrains Mono',Consolas,monospace;font-size:12px;background:#e9ecef;padding:1px 4px;border-radius:3px}}
.header{{background:#1a1a2e;color:#fff;padding:28px 32px}}
.header h1{{font-size:20px;margin-bottom:6px}}
.header .meta{{color:#aab;font-size:13px}}
.container{{max-width:1200px;margin:0 auto;padding:20px 16px}}
h2{{font-size:16px;margin:24px 0 12px;padding-bottom:6px;border-bottom:2px solid #e94560;color:#1a1a2e}}
.stats{{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:10px;margin:16px 0}}
.stat{{background:#fff;border-radius:8px;padding:14px;text-align:center;box-shadow:0 1px 3px rgba(0,0,0,.1)}}
.stat .n{{font-size:24px;font-weight:700;color:#e94560}}
.stat .l{{font-size:11px;color:#888;margin-top:4px}}
table{{width:100%;border-collapse:collapse;background:#fff;border-radius:8px;overflow:hidden;box-shadow:0 1px 3px rgba(0,0,0,.1)}}
th{{background:#f1f3f5;font-weight:600;text-align:left;padding:10px;font-size:12px;color:#555}}
td{{padding:8px 10px;font-size:12px;border-top:1px solid #f1f3f5;vertical-align:top;word-break:break-all}}
tr:hover td{{background:#f8f9fa}}
.badge{{display:inline-block;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:600}}
.critical{{background:#fde8e8;color:#c0392b}}
.high{{background:#fef3cd;color:#856404}}
.medium{{background:#d1ecf1;color:#0c5460}}
.sdk{{background:#f3e5f5;color:#6a1b9a}}
.pre-consent{{color:#c0392b;font-weight:600;font-size:11px}}
.violation{{background:#fff;border-left:4px solid #c0392b;padding:16px 20px;margin:12px 0;border-radius:0 8px 8px 0;box-shadow:0 1px 3px rgba(0,0,0,.1)}}
.violation.high{{border-left-color:#e67e22}}
.violation h3{{margin-bottom:8px;font-size:15px}}
.violation ul{{margin:8px 0 8px 20px}}
.violation li{{margin:4px 0;font-size:13px}}
.law{{color:#888;font-size:12px;margin-top:8px;font-style:italic}}
.timeline{{background:#fff;border-radius:8px;padding:16px 20px;box-shadow:0 1px 3px rgba(0,0,0,.1)}}
.tl-item{{padding:8px 0 8px 20px;border-left:2px solid #dee2e6;position:relative}}
.tl-item::before{{content:'';position:absolute;left:-5px;top:12px;width:8px;height:8px;border-radius:50%;background:#e94560}}
.tl-item.consent::before{{background:#27ae60}}
.tl-ts{{font-family:monospace;font-size:12px;color:#888}}
</style></head><body>
<div class="header">
  <h1>📊 crypto_log 自动分析报告</h1>
  <div class="meta">{_esc(r.app_name)} · {_esc(r.file_path)} · 生成于 {datetime.now().strftime('%Y-%m-%d %H:%M')}</div>
</div>
<div class="container">

<div class="stats">
  <div class="stat"><div class="n">{r.total_lines}</div><div class="l">日志行数</div></div>
  <div class="stat"><div class="n">{r.json_count}</div><div class="l">JSON 事件</div></div>
  <div class="stat"><div class="n">{r.cipher_count}</div><div class="l">加密调用</div></div>
  <div class="stat"><div class="n">{len(r.sensitive_hits)}</div><div class="l">敏感数据项</div></div>
  <div class="stat"><div class="n">{len(r.pre_consent_hits)}</div><div class="l">同意前采集</div></div>
  <div class="stat"><div class="n">{len(r.overcollection_hits)}</div><div class="l">超范围采集</div></div>
  <div class="stat"><div class="n">{len(r.encryption_evasion_hits or [])}</div><div class="l">加密规避</div></div>
  <div class="stat"><div class="n">{len(r.bg_collection_hits or [])}</div><div class="l">后台采集</div></div>
  <div class="stat"><div class="n">{len(r.frequent_collection_hits or [])}</div><div class="l">超频次采集</div></div>
  <div class="stat"><div class="n">{len(r.sdk_set)}</div><div class="l">SDK 数量</div></div>
</div>

<h2>⏱ 隐私同意时间线</h2>
<div class="timeline">
  <div class="tl-item"><span class="tl-ts">{r.consent.show_ts}</span> — 隐私弹窗显示</div>
  {"".join(f'<div class="tl-item"><span class="tl-ts">{h.timestamp}</span> — <span class="pre-consent">⚠ {_esc(h.label)}: {_esc(h.key)}</span> ({_esc(h.source_sdk)})</div>' for h in r.pre_consent_hits)}
  <div class="tl-item consent"><span class="tl-ts">{r.consent.agree_ts}</span> — ✅ 用户点击同意</div>
</div>

<h2>🛡 SDK 识别</h2>
<p>{sdk_list or '未识别到已知 SDK'}</p>

{"<h2>⚠ 违规行为判定</h2>" + violation_items if violation_items else ""}

<h2>🔍 敏感数据采集清单</h2>
<table>
<thead><tr><th>严重度</th><th>类型</th><th>字段名</th><th>值</th><th>SDK</th><th>时间</th><th>行号</th></tr></thead>
<tbody>{sensitive_rows or '<tr><td colspan="7" style="text-align:center;color:#888">未检测到敏感数据</td></tr>'}</tbody>
</table>

<h2>🔐 加密事件（含明文）</h2>
<table>
<thead><tr><th>时间</th><th>算法</th><th>模式</th><th>密钥</th><th>明文</th><th>SDK</th></tr></thead>
<tbody>{cipher_rows or '<tr><td colspan="6" style="text-align:center;color:#888">无含明文的加密事件</td></tr>'}</tbody>
</table>

</div></body></html>"""

    out_path.write_text(html, encoding="utf-8")


def _esc(s):
    return str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")


# ──────────────────────────────────────────────
#  整合报告生成
# ──────────────────────────────────────────────

def generate_combined_html_report(results: list, out_path: Path):
    """生成跨 App 整合分析 HTML 报告（基于 crypto_log）"""
    from collections import Counter as _Counter

    def _display(r):
        p = Path(r.file_path)
        parent = p.parent.name
        m = re.match(r'^(.+?)(?:：|$)', parent)
        if m and m.group(1):
            return m.group(1)
        stem = p.stem
        return DISPLAY_NAME_MAP.get(stem, stem)

    # ── 汇总数 ──
    total_oc   = sum(len(r.overcollection_hits) for r in results)
    total_sens = sum(len(r.sensitive_hits) for r in results)
    total_pre  = sum(len(r.pre_consent_hits) for r in results)
    total_ciph = sum(r.cipher_count for r in results)
    total_sdks = len({s for r in results for s in r.sdk_set})
    total_ee   = sum(len(r.encryption_evasion_hits or []) for r in results)
    total_bg   = sum(len(r.bg_collection_hits or []) for r in results)
    total_frq  = sum(len(r.frequent_collection_hits or []) for r in results)

    # ── 各 App 卡片 ──
    sev_order = {"critical": 3, "high": 2, "medium": 1, "low": 0}
    app_cards = ""
    for r in results:
        name = _display(r)
        cat  = r.cat_info
        cat_str  = f"第{cat['type_id']}类·{cat['type_name']}" if cat else "未识别"
        no_info  = cat and not cat.get("need_phone", True)
        badge_cls = "critical" if no_info else "medium"
        if REGION == 'foreign':
            # 国外版：按命中字段给数据敏感性标签
            has_dev = any(h.rule in ("imei", "android_id", "oaid", "mac_address", "device_id",
                                     "sim_info", "serial", "build_info") for h in r.sensitive_hits)
            has_loc = any(h.rule in ("gps", "ssid_bssid") for h in r.sensitive_hits)
            sens_parts = []
            if has_dev: sens_parts.append("设备标识")
            if has_loc: sens_parts.append("位置")
            if any(h.rule == "sms" for h in r.sensitive_hits): sens_parts.append("短信")
            cat_str = "含" + "/".join(sens_parts) if sens_parts else "未检出敏感字段"
            badge_cls = "critical" if has_dev else "medium"
        sdks_str  = ", ".join(sorted(r.sdk_set)) or "未识别"
        top3 = _Counter(h.label for h in r.overcollection_hits).most_common(3)
        top3_str = " / ".join(f"{lb}×{c}" for lb, c in top3) or "无"
        consent_str = r.consent.agree_ts if r.consent.agree_ts != "未检测到" else "—"
        ee_cnt  = len(r.encryption_evasion_hits or [])
        bg_cnt  = len(r.bg_collection_hits or [])
        frq_cnt = len(r.frequent_collection_hits or [])
        app_cards += f"""<div class="app-card">
  <div class="app-name">{_esc(name)} <span class="tag {badge_cls}">{_esc(cat_str)}</span></div>
  <div class="app-stats">
    <span class="n red">{len(r.overcollection_hits)}</span>超范围 &nbsp;
    <span class="n yel">{len(r.sensitive_hits)}</span>敏感项 &nbsp;
    <span class="n pur">{len(r.pre_consent_hits)}</span>同意前 &nbsp;
    <span class="n">{r.cipher_count}</span>加密次
  </div>
  <div class="app-stats" style="margin-top:4px">
    <span class="n" style="color:#8e44ad">{ee_cnt}</span>加密规避 &nbsp;
    <span class="n" style="color:#e67e22">{bg_cnt}</span>后台采集 &nbsp;
    <span class="n" style="color:#f39c12">{frq_cnt}</span>超频次
  </div>
  <div class="app-detail">SDK：{_esc(sdks_str[:60])}</div>
  <div class="app-detail">主要违规：{_esc(top3_str[:80])}</div>
  <div class="app-detail">同意时间：{_esc(consent_str)}</div>
</div>"""

    # ── 超范围明细表 ──
    oc_rows = ""
    for r in results:
        name = _display(r)
        cat  = r.cat_info
        cat_str = f"第{cat['type_id']}类·{cat['type_name']}" if cat else "未识别"
        if REGION == 'foreign':
            has_dev = any(h.rule in ("imei", "android_id", "oaid", "mac_address", "device_id",
                                     "sim_info", "serial", "build_info") for h in r.sensitive_hits)
            has_loc = any(h.rule in ("gps", "ssid_bssid") for h in r.sensitive_hits)
            cat_str = ("含设备标识/位置" if has_dev and has_loc
                       else "含设备标识" if has_dev
                       else "含位置" if has_loc else "未检出")
        for h in sorted(r.overcollection_hits,
                        key=lambda x: -sev_order.get(x.severity, 0)):
            reason = getattr(h, "overcollection_reason", "")
            pre_tag = '<span class="tag pre">同意前</span>' if (
                r.consent.agree_ts != "未检测到" and h.timestamp
                and h.timestamp < r.consent.agree_ts) else ""
            oc_rows += f"""<tr>
  <td>{_esc(name)}</td>
  <td><span class="tag {h.severity}">{h.severity.upper()}</span>{pre_tag}</td>
  <td>{_esc(h.label)}</td>
  <td><code>{_esc(h.key[:50])}</code></td>
  <td><code>{_esc(h.value[:60])}</code></td>
  <td>{_esc(h.source_sdk)}</td>
  <td>{_esc(h.timestamp)}</td>
  <td style="font-size:11px;color:#888">{_esc(reason[:60])}</td>
  <td style="font-size:11px">{_esc(cat_str)}</td>
</tr>"""

    # ── 图表数据 ──
    rule_cnt  = _Counter(h.label for r in results for h in r.overcollection_hits)
    sdk_cnt   = _Counter(h.source_sdk for r in results for h in r.overcollection_hits)
    app_oc    = [[_display(r), len(r.overcollection_hits)] for r in results]
    app_oc.sort(key=lambda x: -x[1])

    html = f"""<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>crypto_log 整合审计报告{ '（国外 App · GDPR/CCPA/FTC）' if REGION == 'foreign' else '' } — {datetime.now().strftime('%Y-%m-%d %H:%M')}</title>
<script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.1/chart.umd.min.js"></script>
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:-apple-system,'PingFang SC','Microsoft YaHei',sans-serif;background:#f5f6fa;color:#2d2d2d;font-size:14px}}
code{{font-family:'JetBrains Mono',Consolas,monospace;font-size:11px;background:#eee;padding:1px 4px;border-radius:3px}}
.header{{background:linear-gradient(135deg,#1a1a2e,#16213e,#0f3460);color:#fff;padding:28px 32px}}
.header h1{{font-size:22px;font-weight:600;margin-bottom:6px}}
.header .meta{{color:#9ab;font-size:13px}}
.container{{max-width:1400px;margin:0 auto;padding:20px 16px}}
h2{{font-size:16px;font-weight:600;margin:28px 0 14px;padding-bottom:6px;border-bottom:2px solid #e94560;color:#1a1a2e}}
.stats{{display:grid;grid-template-columns:repeat(auto-fit,minmax(110px,1fr));gap:10px;margin:16px 0}}
.stat{{background:#fff;border-radius:8px;padding:14px;text-align:center;box-shadow:0 1px 3px rgba(0,0,0,.08)}}
.stat .n{{font-size:26px;font-weight:700;color:#e94560}}
.stat .l{{font-size:11px;color:#888;margin-top:4px}}
.app-grid{{display:grid;grid-template-columns:repeat(auto-fill,minmax(260px,1fr));gap:12px;margin:14px 0}}
.app-card{{background:#fff;border-radius:8px;padding:14px 16px;box-shadow:0 1px 3px rgba(0,0,0,.08);border-left:4px solid #e94560}}
.app-name{{font-weight:600;font-size:14px;margin-bottom:8px}}
.app-stats{{margin:6px 0;font-size:12px}}
.app-stats .n{{font-weight:700;margin-right:2px}}
.n.red{{color:#e74c3c}} .n.yel{{color:#e67e22}} .n.pur{{color:#8e44ad}}
.app-detail{{font-size:11px;color:#888;margin-top:3px}}
.charts{{display:grid;grid-template-columns:1fr 1fr 1fr;gap:14px;margin:14px 0}}
.chart-box{{background:#fff;border-radius:8px;padding:14px 16px;box-shadow:0 1px 3px rgba(0,0,0,.08)}}
.chart-box h3{{font-size:13px;font-weight:500;margin-bottom:10px;color:#555}}
table{{width:100%;border-collapse:collapse;background:#fff;border-radius:8px;overflow:hidden;box-shadow:0 1px 3px rgba(0,0,0,.08)}}
th{{background:#f8f9fa;font-weight:600;text-align:left;padding:10px;font-size:12px;color:#555;border-bottom:1px solid #eee;position:sticky;top:0;z-index:1}}
td{{padding:7px 10px;font-size:12px;border-top:1px solid #f2f2f2;vertical-align:top;word-break:break-all}}
tr:hover td{{background:#fafbfc}}
.tag{{display:inline-block;padding:2px 7px;border-radius:4px;font-size:10px;font-weight:600;margin:1px;white-space:nowrap}}
.critical{{background:#fde8e8;color:#c0392b}} .high{{background:#fef3cd;color:#856404}}
.medium{{background:#d1ecf1;color:#0c5460}}  .low{{background:#e8f5e9;color:#2e7d32}}
.pre{{background:#fce4ec;color:#ad1457}}
.filter-bar{{padding:10px 14px;display:flex;gap:8px;flex-wrap:wrap;border-bottom:1px solid #f0f0f0;background:#fff;border-radius:8px 8px 0 0}}
.filter-bar select,.filter-bar input{{padding:5px 8px;border:1px solid #ddd;border-radius:5px;font-size:12px}}
.count-tip{{font-size:12px;color:#888;align-self:center;margin-left:auto}}
@media(max-width:900px){{.charts{{grid-template-columns:1fr}}.app-grid{{grid-template-columns:1fr}}}}
</style></head><body>
<div class="header">
  <h1>📊 crypto_log 整合审计报告{ '（国外 App）' if REGION == 'foreign' else '' }</h1>
  <div class="meta">生成时间：{datetime.now().strftime('%Y-%m-%d %H:%M')} · 共 {len(results)} 个 App · 依据：{ 'GDPR / CCPA(CPRA) / FTC Act §5' if REGION == 'foreign' else '《常见类型移动互联网应用程序必要个人信息范围规定》（国信办14号文）' }</div>
</div>
<div class="container">

<div class="stats">
  <div class="stat"><div class="n">{len(results)}</div><div class="l">App 数量</div></div>
  <div class="stat"><div class="n">{total_oc}</div><div class="l">超范围采集项</div></div>
  <div class="stat"><div class="n">{total_sens}</div><div class="l">敏感数据项</div></div>
  <div class="stat"><div class="n">{total_pre}</div><div class="l">同意前采集</div></div>
  <div class="stat"><div class="n">{total_ee}</div><div class="l">加密规避</div></div>
  <div class="stat"><div class="n">{total_bg}</div><div class="l">后台采集</div></div>
  <div class="stat"><div class="n">{total_frq}</div><div class="l">超频次采集类</div></div>
  <div class="stat"><div class="n">{total_ciph}</div><div class="l">加密调用</div></div>
  <div class="stat"><div class="n">{total_sdks}</div><div class="l">涉及 SDK</div></div>
</div>

<h2>📱 各 App 概览</h2>
<div class="app-grid">{app_cards}</div>

<div class="charts">
  <div class="chart-box"><h3>📊 各 App 超范围采集数量</h3><canvas id="cApp" height="260"></canvas></div>
  <div class="chart-box"><h3>🎯 超范围规则分布 Top 12</h3><canvas id="cRule" height="260"></canvas></div>
  <div class="chart-box"><h3>📦 SDK 分布</h3><canvas id="cSdk" height="260"></canvas></div>
</div>

<h2>⚠ 超范围采集明细（{total_oc} 项）</h2>
<div class="filter-bar">
  <select id="fApp" onchange="ft()"><option value="">全部 App</option></select>
  <select id="fSev" onchange="ft()"><option value="">全部严重度</option><option>CRITICAL</option><option>HIGH</option><option>MEDIUM</option></select>
  <select id="fRule" onchange="ft()"><option value="">全部规则</option></select>
  <input id="fKey" placeholder="字段名过滤..." oninput="ft()" style="min-width:120px">
  <span class="count-tip" id="tip"></span>
</div>
<div style="overflow-x:auto">
<table id="oc_table">
<thead><tr>
  <th>App</th><th>严重度</th><th>类型</th><th>字段名</th><th>字段值</th>
  <th>SDK</th><th>时间</th><th>判定依据</th><th>{ '数据敏感性' if REGION == 'foreign' else 'App类别' }</th>
</tr></thead>
<tbody id="oc_tbody">{oc_rows}</tbody>
</table>
</div>

</div>
<script>
const appOc={json.dumps(app_oc, ensure_ascii=False)};
const ruleOc={json.dumps(rule_cnt.most_common(12), ensure_ascii=False)};
const sdkOc={json.dumps(sdk_cnt.most_common(10), ensure_ascii=False)};
const cl=['#e74c3c','#e67e22','#f1c40f','#2ecc71','#3498db','#9b59b6','#1abc9c','#e91e63','#ff5722','#607d8b','#795548','#4caf50'];

new Chart(document.getElementById('cApp'),{{
  type:'bar',
  data:{{labels:appOc.map(x=>x[0]),datasets:[{{data:appOc.map(x=>x[1]),backgroundColor:cl,borderRadius:4}}]}},
  options:{{indexAxis:'y',plugins:{{legend:{{display:false}}}},scales:{{x:{{beginAtZero:true}},y:{{ticks:{{font:{{size:10}}}}}}}}}}
}});
new Chart(document.getElementById('cRule'),{{
  type:'bar',
  data:{{labels:ruleOc.map(x=>x[0].slice(0,14)),datasets:[{{data:ruleOc.map(x=>x[1]),backgroundColor:cl,borderRadius:4}}]}},
  options:{{plugins:{{legend:{{display:false}}}},scales:{{y:{{beginAtZero:true}},x:{{ticks:{{font:{{size:9}}}}}}}}}}
}});
new Chart(document.getElementById('cSdk'),{{
  type:'doughnut',
  data:{{labels:sdkOc.map(x=>x[0]),datasets:[{{data:sdkOc.map(x=>x[1]),backgroundColor:cl,borderWidth:1}}]}},
  options:{{plugins:{{legend:{{position:'right',labels:{{font:{{size:10}},boxWidth:10}}}}}}}}
}});

const trs=[...document.querySelectorAll('#oc_tbody tr')];
const gc=(tr,i)=>(tr.children[i]||{{}}).textContent||'';
const uniq=a=>[...new Set(a)].sort();
const fill=(id,vals)=>{{const s=document.getElementById(id);vals.forEach(v=>{{const o=document.createElement('option');o.value=v;o.textContent=v;s.appendChild(o);}});}};
fill('fApp',uniq(trs.map(t=>gc(t,0).trim())));
fill('fRule',uniq(trs.map(t=>gc(t,2).trim())));

function ft(){{
  const app=document.getElementById('fApp').value;
  const sev=document.getElementById('fSev').value;
  const rule=document.getElementById('fRule').value;
  const key=document.getElementById('fKey').value.toLowerCase();
  let n=0;
  trs.forEach(tr=>{{
    const ok=(!app||gc(tr,0).includes(app))
      &&(!sev||gc(tr,1).toUpperCase().includes(sev))
      &&(!rule||gc(tr,2).includes(rule))
      &&(!key||gc(tr,3).toLowerCase().includes(key));
    tr.style.display=ok?'':'none';
    if(ok)n++;
  }});
  document.getElementById('tip').textContent=n+' / '+trs.length+' 条';
}}
ft();
</script></body></html>"""

    out_path.write_text(html, encoding="utf-8")


# ──────────────────────────────────────────────
#  入口
# ──────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="crypto_log.txt 自动分析器 — 提取敏感数据、加密事件、违规判定",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument("files", nargs="+", help="crypto_log.txt 文件路径（支持多个）")
    parser.add_argument("-o", "--out", help="单个文件时的 HTML 报告路径")
    parser.add_argument("-c", "--combined", metavar="PATH",
                        help="生成跨 App 整合报告（如 combined_report.html）")
    parser.add_argument("--no-html", action="store_true", help="不生成单个 HTML，只打印终端摘要")
    parser.add_argument("--json", action="store_true", help="输出 JSON 格式的分析结果")
    parser.add_argument("--region", choices=["cn", "foreign"], default="cn",
                        help="法规依据：cn=国内（默认），foreign=GDPR/CCPA/FTC")
    args = parser.parse_args()

    global REGION
    REGION = args.region

    all_results = []

    for filepath in args.files:
        if not Path(filepath).exists():
            print(f"[错误] 文件不存在：{filepath}", file=sys.stderr)
            continue

        print(f"\n[*] 分析中：{filepath} ...")
        p = Path(filepath)
        stem = p.stem
        if stem.lower() in ('crypto_log', 'report', 'audit_log'):
            parent = p.parent.name
            m_parent = re.match(r'^(.+?)(?:：|$)', parent)
            app_label = m_parent.group(1) if m_parent else parent
        else:
            app_label = DISPLAY_NAME_MAP.get(stem, stem)
        result = parse_crypto_log(filepath, app_label=app_label)
        all_results.append(result)
        print_summary(result)

        if args.json:
            json_out = {
                "app": result.app_name,
                "file": result.file_path,
                "lines": result.total_lines,
                "consent_show": result.consent.show_ts,
                "consent_agree": result.consent.agree_ts,
                "sdks": list(result.sdk_set),
                "json_count": result.json_count,
                "cipher_count": result.cipher_count,
                "sensitive_hits": [
                    {"rule": h.rule, "label": h.label, "severity": h.severity,
                     "key": h.key, "value": h.value, "ts": h.timestamp,
                     "sdk": h.source_sdk, "line": h.line_no}
                    for h in result.sensitive_hits
                ],
                "violations": {
                    "pre_consent": len(result.pre_consent_hits),
                    "overcollection": len(result.overcollection_hits),
                },
            }
            json_path = Path(filepath).stem + "_analysis.json"
            Path(json_path).write_text(json.dumps(json_out, ensure_ascii=False, indent=2), encoding="utf-8")
            print(f"[✓] JSON 结果：{json_path}")

        if not args.no_html:
            if args.out:
                out = Path(args.out)
            else:
                out = Path(filepath).with_name(Path(filepath).stem + "_analysis.html")
            generate_html_report(result, out)
            print(f"[✓] HTML 报告：{out}")

    # 整合报告
    if args.combined and all_results:
        combined_path = Path(args.combined)
        generate_combined_html_report(all_results, combined_path)
        print(f"\n[✓] 整合报告：{combined_path}（{len(all_results)} 个 App，"
              f"共 {sum(len(r.overcollection_hits) for r in all_results)} 条超范围采集）")


if __name__ == "__main__":
    main()
