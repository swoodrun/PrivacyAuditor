# 如何使用这些脚本？
- 这是给我们生成的审计日志 report.html 和 crypto_log.txt 做分析的脚本，运行方法如下：

## 一、利用**analyze_reports.py** 对 privacy_auditor.py 生成的 report.html 进行分析

    bash
    # 分析多个 App 的 report.html，生成整合报告
    python analyze_reports.py 转转_report.html 贴吧_report.html 抖音_report.html

    # 也支持直接传 audit_log.jsonl
    python analyze_reports.py audit_log_*.jsonl

    # 混合输入也行
    python analyze_reports.py reports/*.html logs/*.jsonl

    # 同时导出 CSV（可直接粘到 Word 的合规检测表里）
    python analyze_reports.py *.html --csv 合规检测表.csv


## 二、利用**analyze_crypto_log.py** 对 crypto_tracer.js 生成的 crypto_log.txt 进行分析

    bash   
    # 单个 App
    python analyze_crypto_log.py 转转_crypto.txt
    # 批量
    python analyze_crypto_log.py 转转_crypto.txt 贴吧_crypto.txt 抖音_crypto.txt


## 三、我们目前可以进行的工作
- 每个 App 审计完成后：
  ├── crypto_log.txt    → python analyze_crypto_log.py xxx_crypto.txt
  └── audit_log.jsonl   → (已被 gen_report.py 生成 report.html)

- 所有 App 审计完后：
  └── python analyze_reports.py *_report.html --csv 合规检测表.csv -o 整合报告.html