# PrivacyAuditor — Android 广告 SDK 数据安全风险分析工具链

> 2025 信安大赛参赛作品  
> 面向 Android 广告 SDK 的静态识别 + 动态取证 + 加密穿透 + 合规审计全链路系统

---

## 项目简介

本项目由两个协同工具组成：

**ADScope**（`ADScope-master/`）— SDK 域名知识库构建工具。基于 Soot 静态分析框架，解析 SDK AAR/JAR 文件的 class 常量池，提取所有 HTTP/HTTPS 端点域名，输出结构化的 `domains.json`。这些域名构成 PrivacyAuditor `sdk_registry.py` 的知识基础，使动态审计能够将网络请求准确归属到具体 SDK。

**PrivacyAuditor**（`scripts/`）— 动态审计与合规分析主系统。针对 Android App 中内嵌的广告/统计 SDK，构建了从"APK 静态扫描"到"运行时明文取证"再到"隐私合规判定"的自动化分析链路。

### 两者的关系

```
ADScope（离线预处理）
    输入: SDK 官方 AAR/JAR 文件
    处理: 常量池解析 → HTTP/HTTPS 域名提取
    输出: domains.json（每个 SDK 的端点列表）
        ↓
sdk_registry.py（知识库）
    将 ADScope 结果整合为"域名 → SDK 名称 + 端点类型"的映射表
        ↓
privacy_auditor.py（实时审计）
    拦截 App 网络流量，查表归属 SDK，触发合规规则
```

### PrivacyAuditor 核心能力

- **SDK 域名提取**（ADScope）：从 AAR/JAR 常量池静态提取 HTTP 端点，对代码混淆鲁棒，准确率 >95%
- **静态识别**：扫描 APK DEX，匹配包名/域名/版本常量，识别集成的 SDK 及版本
- **动态审计**：通过 mitmproxy 代理抓包，实时检测敏感字段上报
- **加密穿透**：Frida 注入 SSL Pinning 绕过 + Cipher/JSON Hook，捕获加密前明文
- **合规判定**：五维规则矩阵（采集阶段 × 字段类型 × 端点类型 × 频次 × 采集范围）
- **隐私政策对比**：自动抓取各 App 官网隐私政策，与实际 SDK 采集行为交叉比对

**测试规模**：53 个 APK 静态扫描 + 55 个 App 动态审计，覆盖社交、电商、金融、视频、游戏等类别。  
**产出数据**：553 条 SDK 识别记录、19961 条动态告警事件、1789 条加密明文样本。

---

## 目录结构

```
privacyauditor/
│
├── APP_set/                        # 待分析的 APK 样本集（53 个）
│
├── jadx/                           # JADX 反编译工具（jadx-gui-1.5.3）
│   └── jadx-gui-1.5.3-win/
│       ├── jadx-gui-1.5.3.exe
│       └── platform-tools/         # ADB 工具集（adb.exe、fastboot.exe）
│
├── docs/                           # 参考文档
│   ├── 【信安大赛科创选题】Android广告SDK数据安全风险分析.docx   # 赛题原文
│   └── 必要个人信息范围对照表.md                                  # 各类 App 必要信息规定
│
├── scripts/
│   │
│   ├── audit/                      # 动态审计核心脚本
│   │   ├── privacy_auditor.py      # mitmproxy 插件：主审计引擎，实时告警
│   │   ├── sdk_registry.py         # SDK 域名注册表 + 端点语义分类（telemetry/ad_api/cdn/service）
│   │   ├── ssl_bypass.js           # Frida 脚本：SSL Pinning 全覆盖绕过
│   │   ├── crypto_tracer.js        # Frida 脚本：Cipher.doFinal / JSONObject Hook，捕获加密前明文
│   │   ├── sensitive_api_tracer.js # Frida 脚本：定位/剪贴板敏感 API 调用频次 + 前台/后台状态取证
│   │   ├── audit_panel.py          # 审计标记悬浮面板：按钮一键打"同意/后台"标记，免手敲命令
│   │   └── dashboard.py            # 一体化仪表盘（编排器）：输包名→开始→标记→结束，一键完成全流程
│   │
│   ├── extract/                    # 数据提取与比对脚本
│   │   ├── extract_sdk_versions_jadx.py    # 从 JADX 反编译结果中提取 SDK 版本号
│   │   ├── fetch_privacy_policy.py         # HTTP 方式批量抓取各 App 隐私政策页面
│   │   ├── fetch_privacy_spa.py            # Playwright 无头浏览器抓取 SPA 隐私政策页面
│   │   └── compare_policy_vs_audit.py      # 隐私政策声明字段 vs SDK 实际采集权限对比分析
│   │
│   ├── report/                     # 报告生成与优化脚本（按执行顺序）
│   │   ├── gen_report.py                   # 生成 HTML 合规检测表
│   │   ├── gen_fingerprint_report.py       # 生成 HTML 数字指纹画像报告
│   │   ├── gen_evidence_report.py          # 生成 HTML 解密证据报告
│   │   ├── rewrite_award_style_report.py   # 原始 docx → 获奖风格重写（基础版）
│   │   ├── expand_report.py                # 早期扩充脚本
│   │   ├── p2_expand.py                    # P2 阶段扩充
│   │   ├── p3_expand.py                    # P3 阶段扩充
│   │   ├── final_optimize.py               # 高价值优化（摘要重写、TOC 重建、3.7 典型案例深化）
│   │   ├── medium_optimize.py              # 中等价值优化（章末小结、5.3 未来工作扩充、参考文献）
│   │   ├── extra_optimize.py               # 额外优化（1.2 背景案例、2.1 开发方法论、测试环境表、模块贡献分析）
│   │   ├── policy_comparison_optimize.py   # 新增 3.8 节：隐私政策与实际采集对比
│   │   └── fix_heading_and_toc.py          # 修复标题样式与目录条目
│   │
│   └── bats_for_evaluate_results/  # 批量结果分析辅助脚本
│       ├── analyze_reports.py              # 汇总多个 App 的 HTML 报告数据
│       └── analyze_crypto_log.py           # 分析 crypto_log.txt 加密日志
│
├── 证据收集/                       # 各 App 动态审计原始证据
│   ├── jj斗地主/
│   │   ├── audit_log.jsonl         # mitmproxy 告警流水（每行一条 JSON 事件）
│   │   ├── crypto_log.txt          # Frida crypto hook 明文截获日志
│   │   └── report.html             # 该 App 的合规检测 HTML 报告
│   ├── 哔哩哔哩：tv.danmaku.bili/
│   ├── 腾讯自选股：com.tencent.portfolio/
│   ├── 微信：com.tencent.mm/
│   ├── 美团：com.sankuai.meituan/
│   ├── 同花顺：com.hexin.plat.android/
│   ├── 快手极速版：com.kuaishou.nebula/
│   ├── ... （共约 55 个 App 子目录）
│   └── audit_log_整合_0517前.jsonl # 0517 前所有 App 的告警日志合并文件
│
└── output/                         # 分析结果输出
    ├── sdk_complete.csv                    # SDK 识别总表（553 条记录：App、SDK、版本、权限、证据数）
    ├── privacy_policy_fields.json          # 17 个 App 隐私政策解析结果（声明的数据字段及上下文）
    ├── policy_vs_audit_comparison.json     # 隐私政策 vs SDK 审计的字段对比结果（14/17 App 存在未声明采集）
    └── 作品报告_Android广告SDK数据安全风险分析_policy.docx   # 最终版作品报告
```

---

## 各脚本运行说明

> 运行环境：Python 3.10+，Windows，PowerShell。  
> 中文路径下请加 `-X utf8` 参数。

### 1. 动态审计（需要模拟器 + Frida）

```powershell
# 启动 mitmproxy 代理（监听 8080 端口，加载审计插件）
mitmproxy -s scripts\audit\privacy_auditor.py --listen-port 8080

# 在另一个终端注入 Frida 脚本（模拟器运行 frida-server）
frida -U -f <package_name> -l scripts\audit\ssl_bypass.js --no-pause
frida -U -f <package_name> -l scripts\audit\crypto_tracer.js --no-pause
```

### 2. 提取 SDK 版本（需要先用 JADX 反编译 APK）

```powershell
python -X utf8 scripts\extract\extract_sdk_versions_jadx.py
```

### 3. 抓取隐私政策

```powershell
# 普通 HTTP 页面
python -X utf8 scripts\extract\fetch_privacy_policy.py

# SPA/JS 渲染页面（需安装 playwright）
python -X utf8 scripts\extract\fetch_privacy_spa.py
```

### 4. 隐私政策 vs 实际采集对比

```powershell
python -X utf8 scripts\extract\compare_policy_vs_audit.py
# 输出：output\policy_vs_audit_comparison.json
```

### 5. 生成报告（按优化顺序执行）

```powershell
python -X utf8 scripts\report\final_optimize.py          # _final.docx
python -X utf8 scripts\report\medium_optimize.py         # _medium.docx
python -X utf8 scripts\report\extra_optimize.py          # _extra.docx
python -X utf8 scripts\report\policy_comparison_optimize.py  # _policy.docx（最终版）
python -X utf8 scripts\report\fix_heading_and_toc.py     # 修复标题样式
```

---

## 核心数据产出

| 数据文件 | 说明 |
|---|---|
| `output/sdk_complete.csv` | 89 个 App × SDK 识别记录（553 条），含版本号、证据数、权限列表 |
| `output/privacy_policy_fields.json` | 17 个 App 的隐私政策解析，含声明字段及原文上下文片段 |
| `output/policy_vs_audit_comparison.json` | 字段级比对结果：17 个 App 中 14 个（82%）存在未声明采集，累计 78 个未声明字段实例 |
| `证据收集/*/audit_log.jsonl` | 原始动态告警流水，每行含时间戳、域名、字段命中、SDK 归属、违规类型 |
| `证据收集/*/crypto_log.txt` | Frida Hook 截获的加密前明文，含算法类型、参数内容、调用栈 |

---

## 关键发现

1. **静态识别**：53 个 APK 中共检出 553 条 SDK 记录，200 条提取到版本号，覆盖腾讯优量汇 GDT、穿山甲 Pangolin、Google AdMob、友盟+等主流广告 SDK。

2. **动态审计**：55 个 App 产生 19961 条告警事件，超范围采集 3774 次，超频次采集 17615 次。启用 SSL Pinning 的 App 占 78%（43 个），全部被 ssl_bypass.js 绕过。

3. **隐私政策对比**：17 个 App 中 14 个（82%）存在实际采集但未在隐私政策中声明的数据字段。MAC 地址和 SSID/BSSID 是最常见的未声明字段，美团（10 项）、腾讯自选股（10 项）问题最突出；小红书、抖音、哔哩哔哩隐私政策覆盖完整（未声明字段数为 0）。

4. **加密穿透**：32 个 App 成功截获加密前明文，产出 1789 条样本，涉及 AES、RSA、DES、HmacSHA256 等 12 类算法。

---

## 依赖环境

```
python >= 3.10
mitmproxy >= 10.0
frida >= 16.0
playwright (chromium)
beautifulsoup4
requests
python-docx
jadx-gui-1.5.3（已内置于 jadx/ 目录）
```

安装 Python 依赖：
```powershell
pip install mitmproxy frida frida-tools playwright beautifulsoup4 requests python-docx
playwright install chromium
```
