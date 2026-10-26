"""
privacy_auditor.py — mitmproxy 隐私审计插件（v3：sdk_summary.csv 同步扩展）
"""

import json
import re
import time
import gzip
import zlib
import urllib.parse
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Optional

from mitmproxy import http, ctx

# SDK 注册表
try:
    import sdk_registry
except ImportError:
    import sys, os
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import sdk_registry

#  配置

# Push/Analytics SDK — 设备注册接口本身即属于敏感数据上报，我们直接创建高风险SDK字段集合
# 命中telemetry端点时额外追加"高风险SDK上报"违规标记。
_HIGH_RISK_PUSH_SDKS = {
    "jpush", "getui", "vivo_push", "oppo",
    "rangers_applog", "apmplus", "ali_emas",
}

# 审计配置文件
class AuditConfig:
    LOG_PATH = Path("audit_log.jsonl")
    REPORT_PATH = Path("report.html")

    FREQ_WINDOW_SECONDS = 60
    FREQ_MAX_REQUESTS = 20

    LOG_ALL = False

    # 跳过已知CDN域名
    SKIP_KNOWN_CDN = True

    # 敏感数据流向telemetry端点时，最低严重度升级为critical
    TELEMETRY_SEVERITY_BOOST = "critical"

    # 同意事件锚定
    # 点击隐私弹窗“同意”的瞬间创建此文件，之后不再判定为“同意前采集”。
    CONSENT_MARKER = Path("consent.marker")
    # 后台状态锚定：操作员按Home切后台时创建，返回前台前删除→据此标记后台静默采集。
    BACKGROUND_MARKER = Path("background.marker")
    # 同意前观察窗口上限（秒）：仅在 consent.marker出现前作兜底；设置为45s
    STARTUP_WINDOW_SECONDS = 45

    # 额外忽略的域名后缀，可以设置
    EXTRA_IGNORE_HOSTS = set()

#  敏感数据规则

@dataclass
class Rule:
    name: str
    label: str
    category: str
    severity: str
    patterns: list = field(default_factory=list)
    key_patterns: list = field(default_factory=list)
    value_patterns: list = field(default_factory=list)


RULES: list = [
    # 检测IMEI/MEID：匹配字段名或 15～16 位数字设备标识。
    Rule("imei", "IMEI / MEID", "device", "critical",
         key_patterns=[r"(?i)\bimei\b", r"(?i)\bmeid\b"],
         value_patterns=[r"\b\d{15,16}\b"]),
    # 检测MAC地址：匹配 MAC 字段名或标准冒号/短横线格式。
    Rule("mac_address", "MAC 地址", "device", "critical",
         patterns=[r"(?i)\bmac[_\-]?addr", r"(?i)\bwifi[_\-]?mac\b"],
         value_patterns=[r"(?:[0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}"]),
    # 检测Android ID：匹配 android_id 字段名或 16 位十六进制值。
    Rule("android_id", "Android ID", "device", "high",
         key_patterns=[r"(?i)\bandroid[_\-]?id\b"],
         value_patterns=[r"\b[0-9a-f]{16}\b"]),
    # 检测OAID：匹配开放匿名设备标识符字段。
    Rule("oaid", "OAID（开放匿名标识符）", "device", "high",
         key_patterns=[r"(?i)\boaid\b"]),
    # 检测设备序列号：匹配 serial/device_serial 等字段名。
    Rule("serial_number", "设备序列号", "device", "high",
         key_patterns=[r"(?i)\bserial\b", r"(?i)\bdevice[_\-]?serial\b"]),
    # 检测 SIM 卡标识：匹配 IMSI/ICCID 字段名或 15～20 位数字。
    Rule("sim_info", "SIM 卡信息", "device", "critical",
         key_patterns=[r"(?i)\bimsi\b", r"(?i)\biccid\b"],
         value_patterns=[r"\b\d{15,20}\b"]),
    # 检测系统指纹和ROM版本：匹配fingerprint、build_fp等字段名。
    Rule("build_fingerprint", "系统指纹（Build.FINGERPRINT 等）", "device", "medium",
         key_patterns=[r"(?i)\b(build_fp|fingerprint|build_fingerprint|rom_version)\b"]),

    # 检测 GPS 经纬度：匹配经纬度字段名或带小数的坐标值。
    Rule("gps_coords", "GPS 经纬度", "location", "critical",
         key_patterns=[r"(?i)\b(lat|lng|lon|latitude|longitude|gps_lat|gps_lng)\b"],
         value_patterns=[r"-?\d{1,2}\.\d{4,}", r"-?\d{2,3}\.\d{4,}"]),
    # 检测基站位置：匹配 cellid、lac、bsid 等字段名。
    Rule("cell_location", "基站位置", "location", "high",
         key_patterns=[r"(?i)\b(cellid|cell_id|lac|bsid|cellinfo)\b"]),
    # 检测 Wi-Fi 位置线索：匹配 BSSID、SSID、Wi-Fi 列表等字段名。
    Rule("wifi_location", "WiFi 位置信息（BSSID/SSID/列表）", "location", "high",
         key_patterns=[r"(?i)\b(bssid|ssid|wifi_info|wifi_list|ap_mac)\b"]),

    # 检测手机号码：匹配手机号字段名或中国大陆 11 位手机号格式。
    Rule("phone_number", "手机号码", "personal", "critical",
         key_patterns=[r"(?i)\b(phone|mobile|tel|cellphone|phone_num)\b"],
         value_patterns=[r"(?<!\d)1[3-9]\d{9}(?!\d)"]),
    # 检测身份证号：匹配身份证字段名或居民身份证格式。
    Rule("id_card", "身份证号", "personal", "critical",
         key_patterns=[r"(?i)\b(idcard|id_card|sfzh|id_no)\b"],
         value_patterns=[r"\b[1-9]\d{5}(19|20)\d{2}(0[1-9]|1[0-2])\d{2}\d{3}[\dXx]\b"]),
    # 检测真实姓名、用户名或昵称字段。
    Rule("real_name", "真实姓名", "personal", "high",
         key_patterns=[r"(?i)\b(realname|real_name|username|nick_?name|uname)\b"]),
    # 检测电子邮箱：匹配 email 字段名或常见邮箱地址格式。
    Rule("email", "电子邮箱", "personal", "medium",
         key_patterns=[r"(?i)\bemail\b"],
         value_patterns=[r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}"]),

    # 检测账号认证凭据：匹配 token、session、refresh_token 等字段名。
    Rule("account_token", "账号 Token / Session", "account", "medium",
         key_patterns=[r"(?i)\b(access_token|token|session_id|sessionid|auth_token|refresh_token)\b"]),

    # 检测剪切板内容：匹配 clipboard、clip_data 等字段名。
    Rule("clipboard", "剪切板内容", "behavior", "high",
         key_patterns=[r"(?i)\b(clipboard|clip_data|clipboard_text)\b"]),
    # 检测已安装应用列表：匹配 installed_apps、pkg_list、packages 等字段名。
    Rule("installed_apps", "已安装应用列表", "behavior", "high",
         key_patterns=[r"(?i)\b(installed_apps|pkg_list|app_list|applist|packages)\b"]),
    # 检测通讯录：匹配 contacts、contact_list、addressbook 等字段名。
    Rule("contact_list", "通讯录", "behavior", "critical",
         key_patterns=[r"(?i)\b(contacts|contact_list|addressbook)\b"]),
    # 检测通话记录：匹配 call_log、calllog、call_history 等字段名。
    Rule("call_log", "通话记录", "behavior", "critical",
         key_patterns=[r"(?i)\b(call_log|calllog|call_history)\b"]),
    # 检测短信内容：匹配 sms、messages、short_message 等字段名。
    Rule("sms_content", "短信内容", "behavior", "critical",
         key_patterns=[r"(?i)\b(sms|messages|short_message)\b"]),

    # 可疑系统路径
    # 检测疑似设备指纹或 Root 检测路径：模式来自 SDK 注册表。
    Rule("suspicious_path", "可疑系统路径（设备指纹/Root 检测）", "behavior", "high",
         value_patterns=[p for p, _ in sdk_registry.SUSPICIOUS_PATH_PATTERNS]),
]

for r in RULES:
    r.patterns = [re.compile(p) for p in r.patterns]
    r.key_patterns = [re.compile(p) for p in r.key_patterns]
    r.value_patterns = [re.compile(p) for p in r.value_patterns]

# 生成报告展示页面工具函数
SEVERITY_COLOR = {"critical": "\033[91m", "high": "\033[93m",
                  "medium":   "\033[96m", "low":  "\033[37m"}
SDK_COLOR   = "\033[95m"
EP_COLOR    = {"telemetry": "\033[91m", "ad_api": "\033[93m",
               "cdn":       "\033[37m", "service": "\033[96m"}
RESET, BOLD = "\033[0m", "\033[1m"
SEV_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}

# 将请求体和响应体转化为可分析的文本
def decode_body(flow, is_response=False):
    try:
        content = flow.response.content if is_response else flow.request.content
        if not content:
            return None
        hdr = flow.response.headers if is_response else flow.request.headers
        encoding = hdr.get("content-encoding", "").lower()
        if "gzip" in encoding:
            content = gzip.decompress(content)
        elif "deflate" in encoding:
            content = zlib.decompress(content)
        elif "br" in encoding:
            try:
                import brotli
                content = brotli.decompress(content)
            except ImportError:
                pass
        return content.decode("utf-8", errors="replace")
    except Exception:
        return None


# 文本类Content-Type关键字（匹配到才解析，否则跳过）
_TEXT_CT_KEYWORDS = ("json", "text", "xml", "html", "form", "javascript", "urlencoded")

# 检查是否为文本函数
def _is_text_content(content_type: str) -> bool:
    """
    对于 protobuf / octet-stream / image / video 等二进制类型返回 False，
    避免强行 UTF-8 解码后产生乱码误报。
    """
    if not content_type:
        return True  # 无 Content-Type 时保守处理，仍然解析
    ct = content_type.lower()
    return any(kw in ct for kw in _TEXT_CT_KEYWORDS)

# 将获取的json请求展平
def _flatten_json(obj, prefix=""):
    result = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            full_key = f"{prefix}.{k}" if prefix else k
            if isinstance(v, (dict, list)):
                result.extend(_flatten_json(v, full_key))
            else:
                result.append((full_key, str(v)))
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            result.extend(_flatten_json(v, f"{prefix}[{i}]"))
    else:
        if prefix:
            result.append((prefix, str(obj)))
    return result

# 提取键值对，我们会将请求内容解析为一个键值对，这样就能完成匹配
def extract_kv_pairs(text, content_type):
    pairs = []
    if not text:
        return pairs
    ct = (content_type or "").lower()

    if "json" in ct or text.lstrip().startswith(("{", "[")):
        try:
            pairs.extend(_flatten_json(json.loads(text)))
        except json.JSONDecodeError:
            pass

    if "x-www-form-urlencoded" in ct or not pairs:
        try:
            pairs.extend(urllib.parse.parse_qsl(text, keep_blank_values=True))
        except Exception:
            pass

    if not pairs:
        pairs.extend(re.findall(r"([a-zA-Z_][a-zA-Z0-9_]{1,40})=([^&\s]{1,200})", text))
    return pairs


def _redact(value):
    if len(value) <= 6:
        return "***"
    return value[:2] + "***" + value[-2:]

# 匹配上文所述的规则
def match_rules(kv_pairs):
    hits = []
    for rule in RULES:
        for key, value in kv_pairs:
            matched_key = False
            matched_val = False
            for pat in rule.key_patterns:
                if pat.search(key):
                    matched_key = True
                    break
            for pat in rule.patterns:
                if pat.search(key):
                    matched_key = True
                    break
            for pat in rule.value_patterns:
                if pat.search(value):
                    matched_val = True
                    break
            if matched_key or matched_val:
                hits.append({
                    "rule": rule.name,
                    "label": rule.label,
                    "category": rule.category,
                    "severity": rule.severity,
                    "key": str(key)[:80],
                    "value_snippet": _redact(str(value)),
                    "match_type": "key" if matched_key else "value",
                })
                break
    return hits

# 匹配可疑的URL
def match_url_suspicious_paths(url):
    hits = []
    for pattern, description in sdk_registry.SUSPICIOUS_PATH_PATTERNS:
        m = re.search(pattern, url, re.IGNORECASE)
        if m:
            hits.append({
                "rule": "url_suspicious_path",
                "label": f"URL 含可疑路径：{description}",
                "category": "behavior",
                "severity": "high",
                "key": "url",
                "value_snippet": m.group(0)[:60],
                "match_type": "url",
            })
    return hits

# 设置严重度
def max_severity(hits):
    if not hits:
        return "low"
    return max(hits, key=lambda h: SEV_ORDER.get(h.get("severity", "low"), 0))["severity"]

# 严重度增长规则
def boost_severity(hits, min_sev):
    target = SEV_ORDER[min_sev]
    for h in hits:
        if SEV_ORDER.get(h["severity"], 0) < target:
            h["severity"] = min_sev
            h["severity_boosted"] = True

#  主插件
class PrivacyAuditor:
    def __init__(self):
        self.log_file = AuditConfig.LOG_PATH.open("a", encoding="utf-8")
        self.start_time = time.time()
        self.startup_end = self.start_time + AuditConfig.STARTUP_WINDOW_SECONDS

        # 同意事件锁存：一旦检测到 consent.marker 即置 True，不再回退
        self._consent_seen = False
        self._consent_time = None

        # 清理上一次会话残留的 marker，保证每个 App 从“同意前 + 前台”干净状态开始
        for mk in (AuditConfig.CONSENT_MARKER, AuditConfig.BACKGROUND_MARKER):
            try:
                mk.unlink()
            except FileNotFoundError:
                pass

        self.freq_map = defaultdict(deque)
        self.total_requests = 0
        self.flagged_requests = 0
        self.skipped_cdn = 0
        self.events = []

    def load(self, loader):
        """addon 加载完成后由 mitmproxy 回调（此时ctx已绑定，可安全使用ctx.log）。"""
        ctx.log.info(
            f"{BOLD}[PrivacyAuditor v4] 已启动{RESET}\n"
            f"  日志: {AuditConfig.LOG_PATH}\n"
            f"  已加载 SDK 指纹: {len(sdk_registry.SDK_REGISTRY)} 个\n"
            f"  同意锚定: 点“同意”时创建 {AuditConfig.CONSENT_MARKER}"
            f"（未创建则按 {AuditConfig.STARTUP_WINDOW_SECONDS}s 窗口近似）\n"
            f"  后台锚定: 切后台时创建 {AuditConfig.BACKGROUND_MARKER}，回前台前删除"
        )

    def request(self, flow):
        host = flow.request.pretty_host
        path = flow.request.path
        url = flow.request.pretty_url

        if AuditConfig.EXTRA_IGNORE_HOSTS and host.endswith(tuple(AuditConfig.EXTRA_IGNORE_HOSTS)):
            return

        self.total_requests += 1
        now = time.time()

        sdk_key, sdk_label, endpoint_type = sdk_registry.classify(host, path)

        if AuditConfig.SKIP_KNOWN_CDN and endpoint_type == sdk_registry.EP_CDN:
            self.skipped_cdn += 1
            return

        freq_q = self.freq_map[host]
        freq_q.append(now)
        while freq_q and freq_q[0] < now - AuditConfig.FREQ_WINDOW_SECONDS:
            freq_q.popleft()
        is_high_freq = len(freq_q) > AuditConfig.FREQ_MAX_REQUESTS

        # 同意前判定
        if not self._consent_seen and AuditConfig.CONSENT_MARKER.exists():
            self._consent_seen = True
            self._consent_time = now
            ctx.log.info(
                f"{BOLD}[PrivacyAuditor] 已检测到 consent.marker"
                f" → 后续请求不再判定为“同意前采集”{RESET}"
            )
        if self._consent_seen:
            is_pre_consent = False
            consent_basis = "marker"            # 锚定真实同意事件，可信
        else:
            is_pre_consent = now <= self.startup_end
            consent_basis = "marker_pending" if is_pre_consent else "window_expired"
        is_startup = is_pre_consent              # 兼容旧字段/HTML 报告

        # 前后台状态锚定
        in_background = AuditConfig.BACKGROUND_MARKER.exists()

        body_text = decode_body(flow, is_response=False)
        content_type = flow.request.headers.get("content-type", "")
        # 对请求体也做文本类型过滤，避免 protobuf和加密body的误报
        if _is_text_content(content_type):
            kv_pairs = extract_kv_pairs(body_text, content_type)
        else:
            kv_pairs = []
        # URL query参数始终解析（明文）
        kv_pairs.extend(flow.request.query.items())

        hits = match_rules(kv_pairs)
        hits.extend(match_url_suspicious_paths(url))

        # Telemetry端点严重度升级
        if hits and endpoint_type == sdk_registry.EP_TELEMETRY:
            boost_severity(hits, AuditConfig.TELEMETRY_SEVERITY_BOOST)

        is_high_risk_push = (
            sdk_key in _HIGH_RISK_PUSH_SDKS
            and endpoint_type == sdk_registry.EP_TELEMETRY
        )
        if not (hits or is_high_freq or is_high_risk_push):
            return

        self.flagged_requests += 1

        violations = []
        if hits:
            violations.append("超范围采集")
            if endpoint_type == sdk_registry.EP_TELEMETRY:
                violations.append(f"已知 SDK 上报端点（{sdk_label}）")
            if is_pre_consent:
                violations.append("未经同意采集（同意前）")
            if in_background:
                violations.append("后台静默采集（应用在后台）")
        if is_high_freq:
            violations.append("超频次采集")
        # 高风险 Push/Analytics SDK 的 telemetry 请求即使无规则命中也追加标记
        if (sdk_key in _HIGH_RISK_PUSH_SDKS
                and endpoint_type == sdk_registry.EP_TELEMETRY
                and f"已知 SDK 上报端点（{sdk_label}）" not in violations):
            violations.append(f"高风险 SDK 上报（{sdk_label}）")

        event = {
            "ts": datetime.utcnow().isoformat(),
            "host": host,
            "path": path[:200],
            "method": flow.request.method,
            "phase": "request",
            "sdk": sdk_key,
            "sdk_label": sdk_label,
            "endpoint_type": endpoint_type,
            "violations": violations,
            "hits": hits,
            "freq_per_min": len(freq_q),
            "is_startup": is_startup,
            "consent_basis": consent_basis,
            "app_state": "background" if in_background else "foreground",
            "url": url[:300],
        }
        self._record(event)

    def response(self, flow):
        if not flow.response:
            return
        host = flow.request.pretty_host

        sdk_key, sdk_label, endpoint_type = sdk_registry.classify(host, flow.request.path)
        if endpoint_type == sdk_registry.EP_CDN:
            return

        in_background = AuditConfig.BACKGROUND_MARKER.exists()

        # 跳过非文本类响应，避免二进制数据误报
        content_type = flow.response.headers.get("content-type", "").lower()
        if not _is_text_content(content_type):
            return

        body_text = decode_body(flow, is_response=True)
        kv_pairs = extract_kv_pairs(body_text, content_type)

        hits = match_rules(kv_pairs)
        if not hits:
            return

        for h in hits:
            h["label"] = f"[响应体] {h['label']}"

        event = {
            "ts": datetime.utcnow().isoformat(),
            "host": host,
            "path": flow.request.path[:200],
            "method": flow.request.method,
            "phase": "response",
            "sdk": sdk_key,
            "sdk_label": sdk_label,
            "endpoint_type": endpoint_type,
            "violations": ["静默采集（响应含敏感数据）"]
                          + (["后台静默采集（应用在后台）"] if in_background else []),
            "hits": hits,
            "freq_per_min": 0,
            "is_startup": False,
            "consent_basis": "n/a",
            "app_state": "background" if in_background else "foreground",
            "url": flow.request.pretty_url[:300],
        }
        self._record(event)

    def done(self):
        self.log_file.close()
        self._generate_html_report()
        ctx.log.info(
            f"\n{BOLD}[PrivacyAuditor] 会话结束{RESET}\n"
            f"  总请求数：{self.total_requests}\n"
            f"  命中告警：{self.flagged_requests}\n"
            f"  CDN 静默：{self.skipped_cdn}\n"
            f"  报告生成：{AuditConfig.REPORT_PATH}"
        )

    def _record(self, event):
        self.events.append(event)
        self.log_file.write(json.dumps(event, ensure_ascii=False) + "\n")
        self.log_file.flush()
        self._print_event(event)

    def _print_event(self, event):
        max_sev = max_severity(event["hits"])
        color = SEVERITY_COLOR.get(max_sev, "")
        ep_color = EP_COLOR.get(event["endpoint_type"], "")
        ts = event["ts"][11:19]
        sdk = f"{SDK_COLOR}[{event['sdk_label'] or '未知'}]{RESET}"
        ep = f"{ep_color}<{event['endpoint_type']}>{RESET}"

        print(f"\n{color}{BOLD}[{ts}] ⚠ {' | '.join(event['violations'])}{RESET}")
        print(f"  {sdk} {ep}  {event['method']} {event['host']}{event['path'][:80]}")
        if event["freq_per_min"] > AuditConfig.FREQ_MAX_REQUESTS:
            print(f"  {SEVERITY_COLOR['high']}频次：{event['freq_per_min']} 次/分钟{RESET}")
        for h in event["hits"]:
            sev_c = SEVERITY_COLOR.get(h["severity"], "")
            boosted = " [↑]" if h.get("severity_boosted") else ""
            print(f"  {sev_c}[{h['severity'].upper()}{boosted}] {h['label']}  "
                  f"key={h['key']}  val={h['value_snippet']}{RESET}")

    def _generate_html_report(self):
        from collections import Counter

        sdk_counts = Counter(e["sdk_label"] or "未识别" for e in self.events)
        ep_counts = Counter(e["endpoint_type"] for e in self.events)
        rule_counts = Counter(h["rule"] for e in self.events for h in e["hits"])
        host_counts = Counter(e["host"] for e in self.events)

        rule_labels = {r.name: r.label for r in RULES}

        html = _HTML_TEMPLATE.format(
            now=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            log_path=AuditConfig.LOG_PATH,
            events_json=json.dumps(self.events, ensure_ascii=False),
            top_sdks_json=json.dumps(sdk_counts.most_common(10), ensure_ascii=False),
            top_rules_json=json.dumps(rule_counts.most_common(15), ensure_ascii=False),
            top_hosts_json=json.dumps(host_counts.most_common(10), ensure_ascii=False),
            ep_counts_json=json.dumps(dict(ep_counts), ensure_ascii=False),
            rule_labels_json=json.dumps(rule_labels, ensure_ascii=False),
        )
        AuditConfig.REPORT_PATH.write_text(html, encoding="utf-8")

#  HTML 报告模板

_HTML_TEMPLATE = r"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>隐私审计报告 — {now}</title>
<script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.1/chart.umd.min.js"></script>
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:'PingFang SC','Microsoft YaHei',sans-serif;background:#f5f6fa;color:#2d2d2d;font-size:14px}}
.header{{background:#1a1a2e;color:#fff;padding:24px 32px}}
.header h1{{font-size:22px;font-weight:500}}
.header .meta{{color:#aaa;margin-top:6px;font-size:13px}}
.container{{max-width:1280px;margin:0 auto;padding:24px 16px}}
.stats{{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:12px;margin-bottom:20px}}
.stat-card{{background:#fff;border-radius:10px;padding:14px 18px;box-shadow:0 1px 4px rgba(0,0,0,.08)}}
.stat-card .num{{font-size:26px;font-weight:500}}
.stat-card .lbl{{color:#888;font-size:12px;margin-top:4px}}
.charts{{display:grid;grid-template-columns:1fr 1fr 1fr;gap:14px;margin-bottom:24px}}
.chart-card{{background:#fff;border-radius:10px;padding:14px 18px;box-shadow:0 1px 4px rgba(0,0,0,.08)}}
.chart-card h2{{font-size:14px;font-weight:500;margin-bottom:10px;color:#444}}
.event-table{{background:#fff;border-radius:10px;overflow:hidden;box-shadow:0 1px 4px rgba(0,0,0,.08)}}
.event-table h2{{font-size:14px;font-weight:500;padding:14px 16px;border-bottom:1px solid #eee}}
table{{width:100%;border-collapse:collapse}}
th{{background:#f9fafb;font-weight:500;text-align:left;padding:10px 10px;font-size:12px;color:#666;border-bottom:1px solid #eee}}
td{{padding:8px 10px;font-size:12px;border-bottom:1px solid #f5f5f5;vertical-align:top;word-break:break-all}}
tr:hover td{{background:#fafafa}}
.badge{{display:inline-block;padding:2px 7px;border-radius:4px;font-size:11px;font-weight:500;margin:1px}}
.critical{{background:#fde8e8;color:#c0392b}}
.high{{background:#fef3cd;color:#856404}}
.medium{{background:#d1ecf1;color:#0c5460}}
.low{{background:#e8f5e9;color:#2e7d32}}
.viol{{background:#e8eaf6;color:#3949ab;font-size:10px}}
.sdk{{background:#f3e5f5;color:#6a1b9a}}
.ep-telemetry{{background:#fde8e8;color:#c0392b;font-size:10px}}
.ep-ad_api{{background:#fef3cd;color:#856404;font-size:10px}}
.ep-service{{background:#d1ecf1;color:#0c5460;font-size:10px}}
.ep-cdn,.ep-unknown{{background:#eee;color:#666;font-size:10px}}
.filter-bar{{padding:12px 16px;display:flex;gap:10px;flex-wrap:wrap}}
.filter-bar select,.filter-bar input{{padding:6px 10px;border:1px solid #ddd;border-radius:6px;font-size:13px}}
@media(max-width:900px){{.charts{{grid-template-columns:1fr}}}}
</style>
</head>
<body>
<div class="header">
  <h1>📋 Android App 隐私审计报告 <span style="font-size:12px;opacity:.7">v4 · 同意锚定 · 后台态</span></h1>
  <div class="meta">生成时间：{now} &nbsp;|&nbsp; 日志：{log_path}</div>
</div>
<div class="container">

  <div class="stats" id="stats"></div>

  <div class="charts">
    <div class="chart-card"><h2>📦 按 SDK 分布</h2><canvas id="sdkChart" height="220"></canvas></div>
    <div class="chart-card"><h2>🎯 命中规则 Top 15</h2><canvas id="ruleChart" height="220"></canvas></div>
    <div class="chart-card"><h2>🌐 Top 10 可疑域名</h2><canvas id="hostChart" height="220"></canvas></div>
  </div>

  <div class="event-table">
    <h2>⚠ 告警事件列表</h2>
    <div class="filter-bar">
      <select id="sevFilter" onchange="renderTable()">
        <option value="">全部严重度</option><option>critical</option><option>high</option><option>medium</option><option>low</option>
      </select>
      <select id="sdkFilter" onchange="renderTable()"><option value="">全部 SDK</option></select>
      <select id="epFilter" onchange="renderTable()">
        <option value="">全部端点类型</option>
        <option value="telemetry">telemetry (上报)</option>
        <option value="ad_api">ad_api (广告)</option>
        <option value="service">service (业务)</option>
        <option value="unknown">unknown (未识别)</option>
      </select>
      <input id="hostFilter" placeholder="域名过滤..." oninput="renderTable()" style="flex:1;min-width:160px">
    </div>
    <div style="overflow-x:auto">
    <table>
      <thead><tr>
        <th>时间</th><th>SDK</th><th>端点</th><th>域名</th>
        <th>路径</th><th>违规</th><th>命中规则</th><th>阶段</th>
      </tr></thead>
      <tbody id="tbody"></tbody>
    </table>
    </div>
  </div>

</div>
<script>
const events={events_json};
const topSdks={top_sdks_json};
const topRules={top_rules_json};
const topHosts={top_hosts_json};
const epCounts={ep_counts_json};
const ruleLabels={rule_labels_json};
const sevOrder={{'low':0,'medium':1,'high':2,'critical':3}};

function maxSev(hits){{if(!hits||!hits.length)return'low';return hits.reduce((a,b)=>sevOrder[b.severity]>sevOrder[a.severity]?b:a).severity;}}

document.getElementById('stats').innerHTML=[
  [events.length,'告警事件总数'],
  [events.filter(e=>maxSev(e.hits)==='critical').length,'Critical 级别'],
  [new Set(events.map(e=>e.sdk_label).filter(Boolean)).size,'涉及 SDK'],
  [epCounts.telemetry||0,'Telemetry 端点'],
  [events.filter(e=>e.violations.includes('超频次采集')).length,'超频次告警'],
  [events.filter(e=>e.is_startup).length,'同意前采集'],
  [events.filter(e=>e.app_state==='background').length,'后台时段采集'],
].map(([n,l])=>`<div class="stat-card"><div class="num">${{n}}</div><div class="lbl">${{l}}</div></div>`).join('');

const colors=['#e74c3c','#e67e22','#f1c40f','#2ecc71','#3498db','#9b59b6','#1abc9c','#e91e63','#ff5722','#607d8b','#795548','#4caf50','#00bcd4','#673ab7','#ff9800'];
new Chart(document.getElementById('sdkChart'),{{type:'doughnut',data:{{labels:topSdks.map(([k])=>k),datasets:[{{data:topSdks.map(([,v])=>v),backgroundColor:colors,borderWidth:1}}]}},options:{{plugins:{{legend:{{position:'right',labels:{{font:{{size:11}},boxWidth:10}}}}}}}}}});
new Chart(document.getElementById('ruleChart'),{{type:'bar',data:{{labels:topRules.map(([k])=>ruleLabels[k]||k),datasets:[{{data:topRules.map(([,v])=>v),backgroundColor:colors,borderRadius:4}}]}},options:{{plugins:{{legend:{{display:false}}}},scales:{{y:{{beginAtZero:true}},x:{{ticks:{{font:{{size:10}}}}}}}}}}}});
new Chart(document.getElementById('hostChart'),{{type:'bar',data:{{labels:topHosts.map(([k])=>k.length>28?k.slice(0,26)+'...':k),datasets:[{{data:topHosts.map(([,v])=>v),backgroundColor:colors,borderRadius:4}}]}},options:{{indexAxis:'y',plugins:{{legend:{{display:false}}}},scales:{{x:{{beginAtZero:true}},y:{{ticks:{{font:{{size:10}}}}}}}}}}}});

const sdkSet=[...new Set(events.map(e=>e.sdk_label).filter(Boolean))].sort();
const sdkFilter=document.getElementById('sdkFilter');
sdkSet.forEach(s=>{{const o=document.createElement('option');o.value=s;o.textContent=s;sdkFilter.appendChild(o);}});

function renderTable(){{
  const sev=document.getElementById('sevFilter').value;
  const sdk=document.getElementById('sdkFilter').value;
  const ep=document.getElementById('epFilter').value;
  const hostQ=document.getElementById('hostFilter').value.toLowerCase();
  const rows=events.filter(e=>{{
    if(sev&&maxSev(e.hits)!==sev)return false;
    if(sdk&&e.sdk_label!==sdk)return false;
    if(ep&&e.endpoint_type!==ep)return false;
    if(hostQ&&!e.host.toLowerCase().includes(hostQ))return false;
    return true;
  }});
  document.getElementById('tbody').innerHTML=rows.map(e=>{{
    const s=maxSev(e.hits);
    const viols=(e.violations||[]).map(v=>`<span class="badge viol">${{v}}</span>`).join('');
    const hits=(e.hits||[]).map(h=>{{
      const b=h.severity_boosted?' <small style="color:#c0392b">↑</small>':'';
      return `<span class="badge ${{h.severity}}">${{h.label}}${{b}}</span><small style="color:#888"> ${{h.key}}=${{h.value_snippet}}</small>`;
    }}).join('<br>');
    return `<tr>
      <td>${{e.ts.slice(11,19)}}</td>
      <td>${{e.sdk_label?`<span class="badge sdk">${{e.sdk_label}}</span>`:'—'}}</td>
      <td><span class="badge ep-${{e.endpoint_type}}">${{e.endpoint_type}}</span></td>
      <td>${{e.host}}</td>
      <td style="max-width:180px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${{e.path}}">${{e.path.slice(0,50)}}</td>
      <td>${{viols||'—'}}</td>
      <td>${{hits||'—'}}</td>
      <td><span class="badge ${{s}}">${{e.phase}}</span></td>
    </tr>`;
  }}).join('');
}}
renderTable();
</script>
</body>
</html>"""


addons = [PrivacyAuditor()]
