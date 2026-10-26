# -*- coding: utf-8 -*-
"""
analyze_re_sdks.py — 对 APPs/APP_set_re 下 11 个国内 APK 做静态 SDK 分析
输出对齐 output/sdk_complete.csv 的 16 列格式，供合并进 sdk_complete.csv。

流程:
  1. aapt dump badging 提取包名/版本/应用名；aapt dump permissions 提取敏感权限（映射中文）
  2. jadx 反编译每个 APK（缓存到 _jadx_cache_re，可复用）
  3. 对每个 SDK 规则（sdk_rules_cn.SDK_RULES，42 种）检查包目录是否存在
  4. 提取版本号（BuildConfig / manifest / 版本常量）
  5. 提取初始化位置（引用 SDK 的 Application/Activity 文件）
  6. 汇总为 sdk_complete.csv 同款 16 列，输出到 output/sdk_re_analysis.csv

用法:
  python -X utf8 scripts/extract/analyze_re_sdks.py
  python -X utf8 scripts/extract/analyze_re_sdks.py --only Hello
  python -X utf8 scripts/extract/analyze_re_sdks.py --no-decompile   # 用已有缓存
"""
import argparse
import csv
import os
import re
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from sdk_rules_cn import SDK_RULES, map_manifest_permissions

ROOT = Path(r"D:\.vscode\pythonsss\privacyauditor")
APK_DIR = ROOT / "APPs" / "APP_set_re"
JADX_JAR = ROOT / "jadx" / "jadx-gui-1.5.3-win" / "lib" / "jadx-gui-1.5.3-all.jar"
AAPT = Path(r"D:\leidian\LDPlayer9\aapt.exe")
CACHE_DIR = ROOT / "_jadx_cache_re"
OUTPUT_CSV = ROOT / "output" / "sdk_re_analysis.csv"

COLS = ["应用文件", "应用名称", "应用包名", "应用版本", "APK大小(MB)",
        "SDK名称", "SDK厂商", "SDK版本", "SDK包名", "置信度", "证据数",
        "初始化位置", "后台Service", "后台Receiver", "关联敏感权限", "版本来源"]

VERSION_VALID_RE = re.compile(r"^\d+\.\d+[\.\d]*(?:[-_.][a-zA-Z0-9]+)*$")


def is_valid_version(ver):
    if not ver or ver == "None":
        return False
    if re.match(r"^[0-9a-fA-F]{12,}$", ver):
        return False
    if len(ver) > 15 and not re.match(r"^[\d.]+", ver):
        return False
    parts = ver.split(".")
    if len(parts) == 4 and all(p.isdigit() for p in parts):
        nums = [int(p) for p in parts]
        if all(0 <= n <= 255 for n in nums) and nums[0] >= 10:
            return False
    for p in parts:
        if p.isdigit() and len(p) > 6:
            return False
    return True


def aapt_info(apk_path):
    """aapt 提取包名/版本/应用名 + 敏感权限"""
    info = {"pkg": "", "ver": "", "label": "", "permissions": []}
    if not AAPT.exists():
        return info
    try:
        badging = subprocess.run([str(AAPT), "dump", "badging", str(apk_path)],
                                 capture_output=True, text=True, timeout=60).stdout
        m = re.search(r"package: name='([^']+)' versionCode='\d+' versionName='([^']*)'", badging)
        if m:
            info["pkg"], info["ver"] = m.group(1), m.group(2)
        ml = re.search(r"application-label:'([^']*)'", badging)
        if ml:
            info["label"] = ml.group(1)
    except Exception:
        pass
    try:
        perm_out = subprocess.run([str(AAPT), "dump", "permissions", str(apk_path)],
                                  capture_output=True, text=True, timeout=60).stdout
        perms = re.findall(r"uses-permission: name='([^']+)'", perm_out)
        info["permissions"] = map_manifest_permissions(perms)
    except Exception:
        pass
    return info


def decompile(apk_path, out_dir):
    if not JADX_JAR.exists():
        return False
    cmd = ["java", "-Xmx4g", "-cp", str(JADX_JAR), "jadx.cli.JadxCLI",
           "--threads-count", "4", "--output-dir", str(out_dir), str(apk_path)]
    try:
        subprocess.run(cmd, capture_output=True, text=True, timeout=1800,
                       encoding="utf-8", errors="replace")
    except Exception:
        return False
    src = out_dir / "sources"
    return src.exists() and any(src.rglob("*.java"))


def _pkg_dir(sources, pkg_path):
    d = sources / pkg_path
    if d.exists():
        return d
    d2 = sources / pkg_path.replace("/", os.sep)
    if d2.exists():
        return d2
    return None


def sdk_exists(sources, rule):
    return any(_pkg_dir(sources, p) for p in rule["packages"])


def extract_version(sources, rule):
    """返回 (version, source_desc)；source_desc 留空 = 未提取到版本证据"""
    # BuildConfig.VERSION_NAME
    if rule.get("buildconfig"):
        for p in rule["packages"]:
            pd = _pkg_dir(sources, p)
            if not pd:
                continue
            for bc in pd.rglob("BuildConfig.java"):
                try:
                    text = bc.read_text(encoding="utf-8", errors="replace")
                except Exception:
                    continue
                m = re.search(r'VERSION_NAME\s*=\s*"([^"]+)"', text)
                if m and VERSION_VALID_RE.match(m.group(1)):
                    return m.group(1), "BuildConfig"
    # manifest meta-data
    mf = sources.parent / "resources" / "AndroidManifest.xml"
    if mf and mf.exists():
        try:
            mtext = mf.read_text(encoding="utf-8", errors="replace")
            for key in rule.get("manifest_keys", []):
                for pat in [r'name="' + re.escape(key) + r'"\s*value="([^"]+)"',
                            r'value="([^"]+)"\s*name="' + re.escape(key) + r'"']:
                    m2 = re.search(pat, mtext)
                    if m2 and is_valid_version(m2.group(1)):
                        return m2.group(1), "manifest"
        except Exception:
            pass
    # 源码版本常量
    for p in rule["packages"]:
        pd = _pkg_dir(sources, p)
        if not pd:
            continue
        for jf in list(pd.rglob("*.java"))[:200]:
            try:
                text = jf.read_text(encoding="utf-8", errors="replace")
            except Exception:
                continue
            for pat in rule.get("version_patterns", []):
                m = re.search(pat, text)
                if m and is_valid_version(m.group(1)):
                    return m.group(1), "source"
    return "", ""


def find_init_locations(sources, rule):
    """找 SDK 包内引用/初始化位置，输出 `路径.java:行号` 格式（对齐 sdk_complete.csv）"""
    hits = []
    for p in rule["packages"]:
        pd = _pkg_dir(sources, p)
        if not pd:
            continue
        for jf in list(pd.rglob("*.java"))[:200]:
            try:
                text = jf.read_text(encoding="utf-8", errors="replace")
            except Exception:
                continue
            # 版本常量 / 初始化入口引用 → 记录 文件:行号
            for pat in rule.get("version_patterns", []):
                m = re.search(pat, text)
                if m:
                    ln = text[:m.start()].count("\n") + 1
                    rel = str(jf.relative_to(sources)).replace(os.sep, "/")
                    hits.append(f"{rel}:{ln}")
                    break
            if len(hits) >= 3:
                break
        if len(hits) >= 3:
            break
    if hits:
        return "; ".join(list(dict.fromkeys(hits))[:3])
    # 无版本常量 → 找 Application/初始化类引用
    for p in rule["packages"]:
        pd = _pkg_dir(sources, p)
        if not pd:
            continue
        for jf in list(pd.rglob("*.java"))[:50]:
            try:
                text = jf.read_text(encoding="utf-8", errors="replace")
            except Exception:
                continue
            m = re.search(r"class\s+\w*(Application|Init)\w*", text)
            if m:
                ln = text[:m.start()].count("\n") + 1
                rel = str(jf.relative_to(sources)).replace(os.sep, "/")
                hits.append(f"{rel}:{ln}")
                if len(hits) >= 3:
                    break
        if len(hits) >= 3:
            break
    return "; ".join(list(dict.fromkeys(hits))[:3]) if hits else "未定位"


def count_evidence(sources, rule):
    """证据数 = 匹配到 SDK 包名下文件数（SDK 自身引用点计数）"""
    n = 0
    for p in rule["packages"]:
        pd = _pkg_dir(sources, p)
        if not pd:
            continue
        # 对每个 java 文件计分：含版本常量/初始化引用 各算一点
        for jf in list(pd.rglob("*.java"))[:100]:
            try:
                text = jf.read_text(encoding="utf-8", errors="replace")
            except Exception:
                continue
            score = 0
            if rule.get("version_patterns"):
                if any(re.search(pat, text) for pat in rule["version_patterns"]):
                    score += 1
            if "Application" in text:
                score += 1
            n += score
    return str(n) if n else "1"


def process_apk(apk_path):
    """处理单个 APK，返回 16 列行列表"""
    ainfo = aapt_info(apk_path)
    pkg = ainfo["pkg"]
    ver = ainfo["ver"]
    label = ainfo["label"]
    app_name = label or apk_path.stem
    print(f"\n== {app_name} ({pkg} {ver}) ==")

    cache_dir = CACHE_DIR / apk_path.stem
    if not (cache_dir / "sources").exists():
        print("  [jadx] 反编译中...")
        cache_dir.mkdir(parents=True, exist_ok=True)
        if not decompile(apk_path, cache_dir):
            print("  [!] 反编译失败")
            return []
    sources = cache_dir / "sources"

    size_mb = apk_path.stat().st_size / 1e6
    results = []
    for rule in SDK_RULES:
        if not sdk_exists(sources, rule):
            continue
        ver_sdk, ver_src = extract_version(sources, rule)
        init_loc = find_init_locations(sources, rule)
        ev_cnt = count_evidence(sources, rule)
        # 置信度：有版本证据 high；仅源码/权限 evidence medium；否则 low
        if ver_sdk:
            conf = "high"
        else:
            conf = "high" if int(ev_cnt or 0) >= 3 else ("medium" if int(ev_cnt or 0) >= 2 else "low")
        sdk_pkg = ", ".join(rule["packages"]).replace("/", ".")
        results.append({
            "应用文件": f"{pkg}_{ver}.apk",
            "应用名称": app_name,
            "应用包名": pkg,
            "应用版本": ver,
            "APK大小(MB)": f"{size_mb:.1f}",
            "SDK名称": rule["name"],
            "SDK厂商": rule["vendor"],
            "SDK版本": ver_sdk or "未提取",
            "SDK包名": sdk_pkg,
            "置信度": conf,
            "证据数": ev_cnt,
            "初始化位置": init_loc,
            "后台Service": "",
            "后台Receiver": "",
            "关联敏感权限": ", ".join(ainfo["permissions"]) if ainfo["permissions"] else ", ".join(rule["permissions"]),
            "版本来源": "静态扫描" if ver_src else "",
        })
        print(f"  [{rule['name']}] {ver_sdk or '未提取'} ({conf})")
    return results


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--only", default="", help="只处理包含该关键字的 APK")
    parser.add_argument("--no-decompile", action="store_true", help="仅用已缓存反编译结果")
    args = parser.parse_args()

    if not APK_DIR.exists():
        print(f"[!] APK 目录不存在: {APK_DIR}")
        sys.exit(1)
    apks = sorted(f for f in APK_DIR.iterdir()
                  if f.is_file() and f.suffix.lower() in (".apk", ".apkm", ".xapk"))
    if args.only:
        apks = [f for f in apks if args.only in f.name]
    print(f"待处理 APK: {len(apks)} 个")
    if not apks:
        sys.exit(0)

    all_results = []
    for apk in apks:
        try:
            all_results.extend(process_apk(apk))
        except Exception as e:
            print(f"  [!] {apk.name}: {e}")

    if all_results:
        OUTPUT_CSV.parent.mkdir(parents=True, exist_ok=True)
        with open(OUTPUT_CSV, "w", encoding="utf-8-sig", newline="") as f:
            w = csv.DictWriter(f, fieldnames=COLS)
            w.writeheader()
            w.writerows(all_results)
        print(f"\n已写入: {OUTPUT_CSV} ({len(all_results)} 条)")
    else:
        print("\n无结果")


if __name__ == "__main__":
    main()
