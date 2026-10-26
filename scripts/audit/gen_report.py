"""
gen_report.py — 离线报告生成器 v2
从已有的 audit_log.jsonl 重新生成 report.html，无需重启 mitmproxy
兼容 v1（无 sdk 字段）和 v2（有 sdk_label / endpoint_type 字段）日志

用法：
    python gen_report.py
    python gen_report.py --log audit_log.jsonl --out report.html
    python gen_report.py --severity critical
    python gen_report.py --sdk 友盟+ Umeng
    python gen_report.py --endpoint telemetry
    python gen_report.py --host snssdk.com
"""

import argparse
import json
import sys
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path


# ──────────────────────────────────────────────
#  规则标签映射（不依赖 mitmproxy，直接硬编码）
# ──────────────────────────────────────────────

RULE_LABELS = {
    "imei":              "IMEI / MEID",
    "mac_address":       "MAC 地址",
    "android_id":        "Android ID",
    "oaid":              "OAID（开放匿名标识符）",
    "serial_number":     "设备序列号",
    "sim_info":          "SIM 卡信息",
    "build_fingerprint": "系统指纹",
    "gps_coords":        "GPS 经纬度",
    "cell_location":     "基站位置",
    "wifi_location":     "WiFi 位置信息",
    "phone_number":      "手机号码",
    "id_card":           "身份证号",
    "real_name":         "真实姓名",
    "email":             "电子邮箱",
    "account_token":     "账号 Token / Session",
    "clipboard":         "剪切板内容",
    "installed_apps":    "已安装应用列表",
    "contact_list":      "通讯录",
    "call_log":          "通话记录",
    "sms_content":       "短信内容",
    "suspicious_path":   "可疑系统路径",
    "url_suspicious_path": "URL 含可疑路径",
}

SEV_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}


def max_severity(hits: list) -> str:
    if not hits:
        return "low"
    return max(hits, key=lambda h: SEV_ORDER.get(h.get("severity", "low"), 0))["severity"]


# ──────────────────────────────────────────────
#  加载 & 过滤
# ──────────────────────────────────────────────

def load_events(log_path: Path) -> list:
    events = []
    with log_path.open(encoding="utf-8") as f:
        for i, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                ev = json.loads(line)
                # v1 兼容：补全 v2 新字段
                ev.setdefault("sdk", None)
                ev.setdefault("sdk_label", None)
                ev.setdefault("endpoint_type", "unknown")
                events.append(ev)
            except json.JSONDecodeError as e:
                print(f"[警告] 第 {i} 行 JSON 解析失败，已跳过：{e}", file=sys.stderr)
    return events


def filter_events(events: list, args) -> list:
    result = events
    if args.severity:
        min_sev = SEV_ORDER.get(args.severity, 0)
        result = [e for e in result if SEV_ORDER.get(max_severity(e.get("hits", [])), 0) >= min_sev]
    if args.sdk:
        result = [e for e in result if args.sdk in (e.get("sdk_label") or "")]
    if args.endpoint:
        result = [e for e in result if e.get("endpoint_type") == args.endpoint]
    if args.host:
        result = [e for e in result if args.host.lower() in e.get("host", "").lower()]
    return result


# ──────────────────────────────────────────────
#  HTML 报告
# ──────────────────────────────────────────────

def generate_html(events: list, log_path: str, out_path: Path, args):
    sdk_counts   = Counter(e["sdk_label"] or "未识别" for e in events)
    ep_counts    = Counter(e["endpoint_type"] for e in events)
    rule_counts  = Counter(h["rule"] for e in events for h in e.get("hits", []))
    host_counts  = Counter(e["host"] for e in events)

    top_sdks  = sdk_counts.most_common(10)
    top_rules = rule_counts.most_common(15)
    top_hosts = host_counts.most_common(10)

    # 过滤条件说明
    filter_desc_parts = []
    if args.severity:
        filter_desc_parts.append(f"严重度 ≥ {args.severity}")
    if args.sdk:
        filter_desc_parts.append(f"SDK = {args.sdk}")
    if args.endpoint:
        filter_desc_parts.append(f"端点类型 = {args.endpoint}")
    if args.host:
        filter_desc_parts.append(f"域名含 {args.host}")
    filter_desc = "（过滤：" + " | ".join(filter_desc_parts) + "）" if filter_desc_parts else ""

    html = _TEMPLATE.format(
        now=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        log_path=log_path,
        filter_desc=filter_desc,
        events_json=json.dumps(events, ensure_ascii=False),
        top_sdks_json=json.dumps(top_sdks, ensure_ascii=False),
        top_rules_json=json.dumps(top_rules, ensure_ascii=False),
        top_hosts_json=json.dumps(top_hosts, ensure_ascii=False),
        ep_counts_json=json.dumps(dict(ep_counts), ensure_ascii=False),
        rule_labels_json=json.dumps(RULE_LABELS, ensure_ascii=False),
    )
    out_path.write_text(html, encoding="utf-8")


# ──────────────────────────────────────────────
#  HTML 模板
# ──────────────────────────────────────────────

_TEMPLATE = r"""<!DOCTYPE html>
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
.header h1{{font-size:22px;font-weight:500;margin-bottom:6px}}
.header .meta{{color:#aaa;font-size:13px;line-height:1.7}}
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
th{{background:#f9fafb;font-weight:500;text-align:left;padding:10px;font-size:12px;color:#666;border-bottom:1px solid #eee}}
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
.boosted{{color:#c0392b;font-size:10px;margin-left:2px}}
.filter-bar{{padding:12px 16px;display:flex;gap:10px;flex-wrap:wrap;border-bottom:1px solid #f0f0f0}}
.filter-bar select,.filter-bar input{{padding:6px 10px;border:1px solid #ddd;border-radius:6px;font-size:13px}}
.filter-bar label{{font-size:13px;color:#555;align-self:center}}
.count-tip{{font-size:12px;color:#888;align-self:center;margin-left:auto}}
@media(max-width:900px){{.charts{{grid-template-columns:1fr}}}}
</style>
</head>
<body>
<div class="header">
  <h1>📋 Android App 隐私审计报告 <span style="font-size:12px;opacity:.6">v2 · 离线版</span></h1>
  <div class="meta">
    生成时间：{now} &nbsp;|&nbsp; 来源：{log_path}
    <span style="color:#f9ca74">{filter_desc}</span>
  </div>
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
      <label>严重度</label>
      <select id="sevFilter" onchange="renderTable()">
        <option value="">全部</option><option>critical</option><option>high</option><option>medium</option><option>low</option>
      </select>
      <label>SDK</label>
      <select id="sdkFilter" onchange="renderTable()"><option value="">全部</option></select>
      <label>端点</label>
      <select id="epFilter" onchange="renderTable()">
        <option value="">全部</option>
        <option value="telemetry">telemetry（上报）</option>
        <option value="ad_api">ad_api（广告）</option>
        <option value="service">service（业务）</option>
        <option value="unknown">unknown（未识别）</option>
      </select>
      <label>阶段</label>
      <select id="phaseFilter" onchange="renderTable()">
        <option value="">全部</option><option value="request">request</option><option value="response">response</option>
      </select>
      <input id="hostFilter" placeholder="域名关键词..." oninput="renderTable()" style="flex:1;min-width:140px">
      <span class="count-tip" id="countTip"></span>
    </div>
    <div style="overflow-x:auto">
    <table>
      <thead><tr>
        <th>时间</th><th>SDK</th><th>端点类型</th><th>域名</th>
        <th>路径</th><th>违规标签</th><th>命中规则</th><th>阶段</th>
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

function maxSev(hits){{
  if(!hits||!hits.length)return'low';
  return hits.reduce((a,b)=>sevOrder[b.severity]>sevOrder[a.severity]?b:a).severity;
}}

// 统计卡片
document.getElementById('stats').innerHTML=[
  [events.length,'告警事件总数'],
  [events.filter(e=>maxSev(e.hits)==='critical').length,'Critical 级别'],
  [new Set(events.map(e=>e.sdk_label).filter(Boolean)).size,'涉及 SDK 数'],
  [epCounts.telemetry||0,'Telemetry 端点'],
  [events.filter(e=>(e.violations||[]).some(v=>v.includes('超频次'))).length,'超频次告警'],
  [events.filter(e=>e.is_startup).length,'启动即采集'],
].map(([n,l])=>`<div class="stat-card"><div class="num">${{n}}</div><div class="lbl">${{l}}</div></div>`).join('');

// 图表颜色
const colors=['#e74c3c','#e67e22','#f1c40f','#2ecc71','#3498db','#9b59b6','#1abc9c','#e91e63','#ff5722','#607d8b','#795548','#4caf50','#00bcd4','#673ab7','#ff9800'];

// SDK 饼图
if(topSdks.length){{
  new Chart(document.getElementById('sdkChart'),{{
    type:'doughnut',
    data:{{labels:topSdks.map(([k])=>k),datasets:[{{data:topSdks.map(([,v])=>v),backgroundColor:colors,borderWidth:1}}]}},
    options:{{plugins:{{legend:{{position:'right',labels:{{font:{{size:11}},boxWidth:10}}}}}}}}
  }});
}}else{{
  document.getElementById('sdkChart').parentElement.innerHTML+='<p style="color:#aaa;font-size:12px">无数据（v1 日志不含 SDK 字段）</p>';
}}

// 规则柱状图
new Chart(document.getElementById('ruleChart'),{{
  type:'bar',
  data:{{
    labels:topRules.map(([k])=>ruleLabels[k]||k),
    datasets:[{{data:topRules.map(([,v])=>v),backgroundColor:colors,borderRadius:4}}]
  }},
  options:{{plugins:{{legend:{{display:false}}}},scales:{{y:{{beginAtZero:true}},x:{{ticks:{{font:{{size:10}}}}}}}}}}
}});

// 域名横向柱状图
new Chart(document.getElementById('hostChart'),{{
  type:'bar',
  data:{{
    labels:topHosts.map(([k])=>k.length>28?k.slice(0,26)+'…':k),
    datasets:[{{data:topHosts.map(([,v])=>v),backgroundColor:colors,borderRadius:4}}]
  }},
  options:{{indexAxis:'y',plugins:{{legend:{{display:false}}}},scales:{{x:{{beginAtZero:true}},y:{{ticks:{{font:{{size:10}}}}}}}}}}
}});

// 填充 SDK 下拉
const sdkSet=[...new Set(events.map(e=>e.sdk_label).filter(Boolean))].sort();
const sdkSel=document.getElementById('sdkFilter');
sdkSet.forEach(s=>{{const o=document.createElement('option');o.value=s;o.textContent=s;sdkSel.appendChild(o);}});

// 渲染表格
function renderTable(){{
  const sev=document.getElementById('sevFilter').value;
  const sdk=document.getElementById('sdkFilter').value;
  const ep=document.getElementById('epFilter').value;
  const phase=document.getElementById('phaseFilter').value;
  const hostQ=document.getElementById('hostFilter').value.toLowerCase();

  const rows=events.filter(e=>{{
    if(sev&&maxSev(e.hits)!==sev)return false;
    if(sdk&&e.sdk_label!==sdk)return false;
    if(ep&&e.endpoint_type!==ep)return false;
    if(phase&&e.phase!==phase)return false;
    if(hostQ&&!e.host.toLowerCase().includes(hostQ))return false;
    return true;
  }});

  document.getElementById('countTip').textContent=`显示 ${{rows.length}} / ${{events.length}} 条`;

  document.getElementById('tbody').innerHTML=rows.map(e=>{{
    const s=maxSev(e.hits);
    const viols=(e.violations||[]).map(v=>`<span class="badge viol">${{v}}</span>`).join(' ');
    const hits=(e.hits||[]).map(h=>{{
      const b=h.severity_boosted?'<span class="boosted">↑升级</span>':'';
      return `<span class="badge ${{h.severity}}">${{h.label}}${{b}}</span>`
           + `<small style="color:#888;margin-left:3px">${{h.key}}=${{h.value_snippet}}</small>`;
    }}).join('<br>');
    const sdkBadge=e.sdk_label?`<span class="badge sdk">${{e.sdk_label}}</span>`:'<span style="color:#bbb">—</span>';
    const epBadge=`<span class="badge ep-${{e.endpoint_type}}">${{e.endpoint_type}}</span>`;
    return `<tr>
      <td style="white-space:nowrap">${{e.ts.slice(0,19).replace('T',' ')}}</td>
      <td>${{sdkBadge}}</td>
      <td>${{epBadge}}</td>
      <td style="max-width:160px">${{e.host}}</td>
      <td style="max-width:180px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${{e.path}}">${{e.path.slice(0,55)}}</td>
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


# ──────────────────────────────────────────────
#  入口
# ──────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="从 audit_log.jsonl 生成隐私审计 HTML 报告（v2）",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument("--log",      default="audit_log.jsonl", help="输入日志文件（默认：audit_log.jsonl）")
    parser.add_argument("--out",      default="report.html",     help="输出 HTML 文件（默认：report.html）")
    parser.add_argument("--severity", choices=["critical","high","medium","low"],
                        help="只保留不低于此级别的事件")
    parser.add_argument("--sdk",      help="只保留指定 SDK 的事件，例如：友盟+ Umeng")
    parser.add_argument("--endpoint", choices=["telemetry","ad_api","service","cdn","unknown"],
                        help="只保留指定端点类型的事件")
    parser.add_argument("--host",     help="只保留域名含此字符串的事件")
    args = parser.parse_args()

    log_path = Path(args.log)
    out_path = Path(args.out)

    if not log_path.exists():
        print(f"[错误] 找不到日志文件：{log_path}", file=sys.stderr)
        print("       请先运行 mitmweb -s privacy_auditor.py 生成日志", file=sys.stderr)
        sys.exit(1)

    print(f"[gen_report] 读取日志：{log_path}")
    all_events = load_events(log_path)
    print(f"[gen_report] 共 {len(all_events)} 条事件")

    events = filter_events(all_events, args)
    if len(events) < len(all_events):
        print(f"[gen_report] 过滤后剩余：{len(events)} 条")

    if not events:
        print("[警告] 过滤后无数据，报告将为空", file=sys.stderr)

    generate_html(events, str(log_path), out_path, args)
    print(f"[gen_report] ✓ 报告已生成：{out_path}")


if __name__ == "__main__":
    main()
