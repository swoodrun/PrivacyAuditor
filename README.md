# PrivacyAuditor — Android 广告 SDK 数据安全风险分析工具链

> 2025 信安大赛参赛作品  
> 面向 Android 广告 SDK 的静态识别 + 动态取证 + 加密穿透 + 合规审计全链路系统

---

## 项目简介

**PrivacyAuditor**（`scripts/`）— 动态审计与合规分析主系统。针对 Android App 中内嵌的广告/统计 SDK，构建了从"APK 静态扫描"到"运行时明文取证"再到"隐私合规判定"的自动化分析链路。

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
