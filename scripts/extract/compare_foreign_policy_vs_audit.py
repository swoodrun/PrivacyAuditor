# -*- coding: utf-8 -*-
"""国外应用：隐私政策声明字段 vs 实际动态审计检测字段 对比。

实际收集：datarecord_foreign/*/audit_log.jsonl 里 hits[].label（真实检测到的敏感字段）
政策声明：output/privacy_policy_fields_foreign.json 的 field_names
输出：output/policy_vs_audit_comparison_foreign.json
"""
import json
import re
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DATA = ROOT / "datarecord_foreign"
POLICY_PATH = ROOT / "output" / "privacy_policy_fields_foreign.json"
OUT_PATH = ROOT / "output" / "policy_vs_audit_comparison_foreign.json"

# 审计 label → 政策字段名 归一化映射
LABEL_NORM = {
    "IMEI / MEID": "IMEI",
    "OAID（开放匿名标识符）": "OAID",
    "已安装应用列表": "应用列表",
    "手机号码": "SIM 卡信息",
    "电子邮箱": "SIM 卡信息",
    "真实姓名": "SIM 卡信息",
    "[响应体] IMEI / MEID": "IMEI",
    "[响应体] Android ID": "Android ID",
    "[响应体] GPS 经纬度": "GPS 经纬度",
    "[响应体] MAC 地址": "MAC 地址",
    "[响应体] SIM 卡信息": "SIM 卡信息",
    "[响应体] 手机号码": "SIM 卡信息",
    "[响应体] 电子邮箱": "SIM 卡信息",
    "[响应体] 真实姓名": "SIM 卡信息",
    "[响应体] 账号 Token / Session": "账号 Token / Session",
    "[响应体] 系统指纹（Build.FINGERPRINT 等）": "系统指纹",
    "系统指纹（Build.FINGERPRINT 等）": "系统指纹",
}
# 政策字段"Android ID等设备标识"是泛称，涵盖以下具体设备标识
DEVICE_IDENTIFIER_GROUP = {"Android ID", "IMEI", "OAID", "MAC 地址"}
# 政策字段里没有、不参与对比的类型
IGNORE_LABELS = {"短信内容", "系统指纹"}

# 政策抓取受限的应用（非英文政策 / 壳页 / 无URL）——单独标注，不误判为超范围
POLICY_ISSUE = {
    "com.contextlogic.wish": "政策为JS壳页，正文无法抓取",
    "com.vive.riderleague": "无政策URL",
    "com.aniplex.fategrandorder": "政策为日文通用条款，关键词无法匹配",
    "jp.pxv.android": "政策为日文，关键词匹配受限",
    "jp.konami.masterduel": "政策为日文，关键词匹配受限",
    "com.naver.labs.translator": "政策为韩文，关键词匹配受限",
    "kr.co.tf.starwars": "政策为韩文，关键词匹配受限",
}


def norm_label(label):
    return LABEL_NORM.get(label, label)


def load_actual_fields():
    """pkg -> Counter(政策字段名 -> 命中次数)"""
    actual = {}
    for sub in DATA.iterdir():
        if not sub.is_dir():
            continue
        pkg = sub.name
        jf = sub / f"{pkg}.jsonl"
        if not jf.exists():
            continue
        c = Counter()
        for line in jf.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                e = json.loads(line)
            except Exception:
                continue
            for h in e.get("hits", []):
                lab = norm_label(h.get("label", ""))
                if lab and lab not in IGNORE_LABELS:
                    c[lab] += 1
        actual[pkg] = c
    return actual


def load_policy_fields():
    d = json.loads(POLICY_PATH.read_text(encoding="utf-8"))
    result = {}
    for pkg, info in d.items():
        fields = set(info.get("field_names", []))
        # 泛称"Android ID等设备标识"展开为具体设备标识，与审计字段对齐
        if "Android ID等设备标识" in fields:
            fields |= DEVICE_IDENTIFIER_GROUP
        result[pkg] = {"name": info.get("name", pkg), "fields": fields,
                       "url": info.get("url"), "char_count": info.get("char_count", 0)}
    return result


def main():
    actual = load_actual_fields()
    policy = load_policy_fields()

    all_pkgs = sorted(set(actual.keys()) | set(policy.keys()))
    results = []

    for pkg in all_pkgs:
        act = actual.get(pkg, Counter())
        pol = policy.get(pkg, {"fields": set(), "name": pkg})
        name = pol["name"] or pkg

        actual_fields = set(act.keys())
        declared = pol["fields"]

        undeclared = actual_fields - declared          # 实际检测到、政策未声明 → 超范围
        declared_not_detected = declared - actual_fields  # 政策声明、实际未检测到

        issue = POLICY_ISSUE.get(pkg)
        # 政策抓取受限的应用：不参与超范围判定，单独标注
        if issue:
            undeclared = []
            declared_not_detected = []
            over_scope = 0
        else:
            over_scope = len(undeclared)

        results.append({
            "pkg": pkg,
            "name": name,
            "policy_url": pol.get("url"),
            "policy_char_count": pol.get("char_count", 0),
            "policy_issue": issue,
            "actual_field_count": len(actual_fields),
            "actual_hits": sum(act.values()),
            "actual_fields": sorted(actual_fields),
            "declared_fields": sorted(declared),
            "undeclared": sorted(undeclared),
            "declared_not_detected": sorted(declared_not_detected),
            "over_scope_count": over_scope,
        })

    results.sort(key=lambda x: -x["over_scope_count"])

    # ── 控制台摘要 ──
    total_over = 0
    apps_over = 0
    print(f"{'App':<30s} {'实际':>4s} {'声明':>4s} {'超范围':>5s}  超范围类型")
    print("-" * 100)
    for r in results:
        und = "、".join(r["undeclared"]) if r["undeclared"] else "-"
        if r["undeclared"]:
            total_over += len(r["undeclared"])
            apps_over += 1
        mark = f"  [{r['policy_issue']}]" if r.get("policy_issue") else ""
        print(f"{r['name'][:28]:<30s} {r['actual_field_count']:>4d} {len(r['declared_fields']):>4d} "
              f"{r['over_scope_count']:>5d}  {und}{mark}")

    issues = sum(1 for r in results if r.get("policy_issue"))
    print(f"\n应用总数: {len(results)}")
    print(f"有超范围采集: {apps_over} ({apps_over * 100 // (len(results) - issues) if (len(results) - issues) else 0}%)")
    print(f"超范围字段实例总数: {total_over}")
    print(f"政策受限未判定: {issues}")

    OUT_PATH.write_text(json.dumps(results, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"\n详细结果: {OUT_PATH}")


if __name__ == "__main__":
    main()
