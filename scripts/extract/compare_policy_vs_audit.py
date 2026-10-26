"""
Compare declared privacy policy fields vs actual SDK audit findings.
Identifies "超范围采集" (over-scope collection) where actual collection exceeds declared scope.
"""
import csv, json, os

PERM_TO_POLICY = {
    "设备标识(IMEI等)": ["IMEI", "IMSI", "Android ID", "OAID", "广告标识"],
    "WiFi信息": ["MAC 地址", "SSID / BSSID"],
    "粗略位置": ["GPS 经纬度"],
    "精确位置": ["GPS 经纬度"],
    "相机": ["摄像头 / 麦克风"],
    "麦克风": ["摄像头 / 麦克风"],
    "存储写入": ["相册 / 存储"],
    "存储读取": ["相册 / 存储"],
    "通讯录": ["通讯录"],
    "运行任务列表": ["应用列表"],
    "通话记录": ["SIM 卡信息"],
    "短信": ["SIM 卡信息"],
    "应用使用统计": ["应用列表"],
}

POLICY_TO_PERMS = {}
for perm, fields in PERM_TO_POLICY.items():
    for f in fields:
        if f not in POLICY_TO_PERMS:
            POLICY_TO_PERMS[f] = set()
        POLICY_TO_PERMS[f].add(perm)


def load_sdk_audit(csv_path):
    apps = {}
    with open(csv_path, encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            pkg = row["应用包名"]
            name = row["应用名称"]
            if pkg not in apps:
                apps[pkg] = {"name": name, "perms": set(), "sdks": set(), "sdk_count": 0}
            perms = [p.strip() for p in row["关联敏感权限"].split(",") if p.strip()]
            apps[pkg]["perms"].update(perms)
            apps[pkg]["sdks"].add(row["SDK名称"])
        for pkg in apps:
            apps[pkg]["sdk_count"] = len(apps[pkg]["sdks"])
    return apps


def load_policy_fields(json_path):
    with open(json_path, encoding="utf-8") as f:
        data = json.load(f)
    result = {}
    for pkg, info in data.items():
        if "error" in info and info.get("fields", {}) == {}:
            continue
        fields = set(info.get("field_names", []))
        if not fields and info.get("fields"):
            fields = set(info["fields"].keys())
        result[pkg] = {"name": info["name"], "fields": fields}
    return result


def compare(audit, policy):
    results = []
    both = set(audit.keys()) & set(policy.keys())
    for pkg in sorted(both):
        a = audit[pkg]
        p = policy[pkg]
        name = a["name"]
        declared = p["fields"]
        actual_perms = a["perms"]

        actual_policy_fields = set()
        for perm in actual_perms:
            if perm in PERM_TO_POLICY:
                actual_policy_fields.update(PERM_TO_POLICY[perm])

        undeclared = actual_policy_fields - declared
        declared_not_detected = declared - actual_policy_fields

        results.append({
            "pkg": pkg,
            "name": name,
            "sdk_count": a["sdk_count"],
            "actual_perms": sorted(actual_perms),
            "actual_fields": sorted(actual_policy_fields),
            "declared_fields": sorted(declared),
            "undeclared": sorted(undeclared),
            "declared_not_detected": sorted(declared_not_detected),
            "over_scope_count": len(undeclared),
        })

    results.sort(key=lambda x: -x["over_scope_count"])
    return results


def main():
    base = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
    csv_path = os.path.join(base, "output", "sdk_complete.csv")
    json_path = os.path.join(base, "output", "privacy_policy_fields.json")

    audit = load_sdk_audit(csv_path)
    policy = load_policy_fields(json_path)

    both_keys = set(audit.keys()) & set(policy.keys())
    print(f"SDK audit apps: {len(audit)}")
    print(f"Policy fetched apps: {len(policy)}")
    print(f"Overlap (both have data): {len(both_keys)}")

    results = compare(audit, policy)

    print(f"\n{'='*80}")
    print("PRIVACY POLICY vs ACTUAL SDK AUDIT COMPARISON")
    print(f"{'='*80}\n")

    total_over = 0
    apps_with_over = 0

    for r in results:
        name = r["name"]
        pkg = r["pkg"]
        print(f"\n{'─'*60}")
        print(f"  {name} ({pkg})")
        print(f"  SDKs detected: {r['sdk_count']}")
        print(f"  Declared fields ({len(r['declared_fields'])}): {', '.join(r['declared_fields']) or '(none)'}")
        print(f"  Actual collection ({len(r['actual_fields'])}): {', '.join(r['actual_fields'])}")

        if r["undeclared"]:
            print(f"  ⚠ UNDECLARED collection ({len(r['undeclared'])}): {', '.join(r['undeclared'])}")
            total_over += len(r["undeclared"])
            apps_with_over += 1
        else:
            print(f"  ✓ All actual collection is declared")

        if r["declared_not_detected"]:
            print(f"  (Declared but not detected by SDK audit: {', '.join(r['declared_not_detected'])})")

    print(f"\n\n{'='*80}")
    print("SUMMARY")
    print(f"{'='*80}")
    print(f"Apps analyzed: {len(results)}")
    print(f"Apps with undeclared collection: {apps_with_over} ({apps_with_over*100//len(results) if results else 0}%)")
    print(f"Total undeclared field instances: {total_over}")

    print(f"\n{'App':<16s} {'SDKs':>5s} {'Declared':>8s} {'Actual':>8s} {'Undeclared':>10s}  Undeclared types")
    print("-" * 90)
    for r in results:
        und = ", ".join(r["undeclared"]) if r["undeclared"] else "-"
        print(f"{r['name']:<16s} {r['sdk_count']:>5d} {len(r['declared_fields']):>8d} {len(r['actual_fields']):>8d} {r['over_scope_count']:>10d}  {und}")

    out_path = os.path.join(base, "output", "policy_vs_audit_comparison.json")
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(results, f, ensure_ascii=False, indent=2)
    print(f"\nDetailed results saved to: {out_path}")


if __name__ == "__main__":
    main()
