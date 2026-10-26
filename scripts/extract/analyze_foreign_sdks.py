# -*- coding: utf-8 -*-
"""
analyze_foreign_sdks.py — 对 APP_set_foreign 下国外 APK 做静态 SDK 分析
输出对齐 output/sdk_complete.csv 的 16 列格式。

流程:
  1. 用 jadx 反编译每个 APK（可缓存复用已反编译结果）
  2. 对每个 SDK 规则检查包目录是否存在于反编译源码
  3. 提取版本号（BuildConfig / manifest / 版本常量）
  4. 提取初始化位置 / 后台 Service / Receiver / 关联权限
  5. 汇总为 sdk_complete.csv 同款 16 列 CSV

用法:
  python -X utf8 scripts/extract/analyze_foreign_sdks.py
  python -X utf8 scripts/extract/analyze_foreign_sdks.py --only slither
  python -X utf8 scripts/extract/analyze_foreign_sdks.py --no-decompile
"""
import argparse
import csv
import json
import os
import re
import sys
import time
import shutil
import tempfile
import zipfile
import subprocess
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

ROOT = Path(r"D:\.vscode\pythonsss\privacyauditor")
APK_DIR = ROOT / "APP_set_foreign"
JADX_JAR = ROOT / "jadx" / "jadx-gui-1.5.3-win" / "lib" / "jadx-gui-1.5.3-all.jar"
AAPT = Path(r"D:\leidian\LDPlayer9\aapt.exe")
CACHE_DIR = ROOT / "_jadx_cache_foreign"
BUNDLE_TMP = ROOT / "_jadx_tmp" / "bundle_base"
OUTPUT_CSV = ROOT / "output" / "sdk_foreign_analysis.csv"


def aapt_pkg_info(apk_path: Path):
    """用 aapt 提取 APK 的包名/版本/应用名；失败返回 None"""
    if not AAPT.exists():
        return None
    try:
        out = subprocess.run([str(AAPT), "dump", "badging", str(apk_path)],
                             capture_output=True, text=True, timeout=60).stdout
        m = re.search(r"package: name='([^']+)' versionCode='\d+' versionName='([^']*)'", out)
        if not m:
            return None
        pkg, ver = m.group(1), m.group(2)
        ml = re.search(r"application-label:'([^']*)'", out)
        label = ml.group(1) if ml else ""
        return pkg, ver, label
    except Exception:
        return None

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


# ──────────────────────────────────────────────
#  SDK 规则表：合并中国 + 海外 SDK
#  字段: name, vendor, packages(源码包路径), manifest_keys, version_patterns,
#        services, receivers, permissions
# ──────────────────────────────────────────────

SDK_RULES = [
    # ── 广告 / 变现 ──
    {"name": "Google AdMob", "vendor": "Google",
     "packages": ["com/google/android/gms/ads", "com/google/ads"],
     "version_patterns": [r'VERSION\s*=\s*"([^"]+)"', r'SDK_VERSION\s*=\s*"([^"]+)"'],
     "buildconfig": True,
     "services": [], "receivers": [],
     "permissions": ["广告标识", "网络状态"]},
    {"name": "Facebook Audience Network", "vendor": "Meta",
     "packages": ["com/facebook/ads"],
     "version_patterns": [r'VERSION\s*=\s*"([^"]+)"', r'SDK_VERSION\s*=\s*"([^"]+)"'],
     "buildconfig": True, "services": [], "receivers": [],
     "permissions": ["广告标识"]},
    {"name": "Unity Ads", "vendor": "Unity Technologies",
     "packages": ["com/unity3d/ads", "com/unity3d/services"],
     "version_patterns": [r'VERSION\s*=\s*"([^"]+)"', r'SDK_VERSION\s*=\s*"([^"]+)"'],
     "buildconfig": True, "services": [], "receivers": [],
     "permissions": ["广告标识"]},
    {"name": "IronSource (Unity LevelPlay)", "vendor": "Unity / IronSource",
     "packages": ["com/ironsource", "com/unity3d/mediation"],
     "version_patterns": [r'VERSION\s*=\s*"([^"]+)"', r'SDK_VERSION\s*=\s*"([^"]+)"'],
     "buildconfig": True, "services": [], "receivers": [],
     "permissions": ["广告标识"]},
    {"name": "AppLovin MAX", "vendor": "AppLovin",
     "packages": ["com/applovin"],
     "version_patterns": [r'VERSION\s*=\s*"([^"]+)"', r'SDK_VERSION\s*=\s*"([^"]+)"'],
     "buildconfig": True, "services": [], "receivers": [],
     "permissions": ["广告标识"]},
    {"name": "AdColony", "vendor": "AdColony",
     "packages": ["com/jirbo/adcolony", "com/adcolony"],
     "version_patterns": [r'VERSION\s*=\s*"([^"]+)"', r'SDK_VERSION\s*=\s*"([^"]+)"'],
     "buildconfig": True, "services": [], "receivers": [],
     "permissions": ["广告标识"]},
    {"name": "Vungle 广告", "vendor": "Vungle",
     "packages": ["com/vungle"],
     "version_patterns": [r'VERSION\s*=\s*"([^"]+)"', r'SDK_VERSION\s*=\s*"([^"]+)"'],
     "buildconfig": True, "services": [], "receivers": [],
     "permissions": ["广告标识"]},
    {"name": "Tapjoy", "vendor": "Tapjoy",
     "packages": ["com/tapjoy"],
     "version_patterns": [r'VERSION\s*=\s*"([^"]+)"', r'SDK_VERSION\s*=\s*"([^"]+)"'],
     "buildconfig": True, "services": [], "receivers": [],
     "permissions": ["广告标识"]},
    {"name": "InMobi 广告", "vendor": "InMobi",
     "packages": ["com/inmobi"],
     "version_patterns": [r'VERSION\s*=\s*"([^"]+)"', r'SDK_VERSION\s*=\s*"([^"]+)"'],
     "buildconfig": True, "services": [], "receivers": [],
     "permissions": ["广告标识"]},
    {"name": "Mintegral 广告", "vendor": "Mintegral",
     "packages": ["com/mbridge"],
     "version_patterns": [r'VERSION\s*=\s*"([^"]+)"', r'SDK_VERSION\s*=\s*"([^"]+)"'],
     "buildconfig": True, "services": [], "receivers": [],
     "permissions": ["广告标识"]},
    {"name": "Mobvista / Mintegral", "vendor": "汇量科技",
     "packages": ["com/mobvista", "com/mintegral"],
     "version_patterns": [r'VERSION\s*=\s*"([^"]+)"', r'SDK_VERSION\s*=\s*"([^"]+)"'],
     "buildconfig": True, "services": [], "receivers": [],
     "permissions": ["广告标识"]},

    # ── 归因 / 数据分析 ──
    {"name": "AppsFlyer / OneLink 归因", "vendor": "AppsFlyer",
     "packages": ["com/appsflyer"],
     "version_patterns": [r'VERSION\s*=\s*"([^"]+)"', r'SDK_VERSION\s*=\s*"([^"]+)"'],
     "buildconfig": True, "services": [], "receivers": [],
     "permissions": ["广告标识", "网络状态"]},
    {"name": "Adjust 归因", "vendor": "Adjust",
     "packages": ["com/adjust/sdk", "com/adjust"],
     "version_patterns": [r'VERSION\s*=\s*"([^"]+)"', r'SDK_VERSION\s*=\s*"([^"]+)"'],
     "buildconfig": True, "services": [], "receivers": [],
     "permissions": ["广告标识"]},
    {"name": "Firebase Analytics", "vendor": "Google",
     "packages": ["com/google/firebase/analytics"],
     "version_patterns": [r'VERSION\s*=\s*"([^"]+)"', r'SDK_VERSION\s*=\s*"([^"]+)"'],
     "buildconfig": True, "services": [], "receivers": [],
     "permissions": ["广告标识", "网络状态"]},
    {"name": "TalkingData 数据分析", "vendor": "TalkingData",
     "packages": ["com/tendcloud/tenddata", "com/talkingdata"],
     "version_patterns": [r'VERSION\s*=\s*"([^"]+)"', r'SDK_VERSION\s*=\s*"([^"]+)"'],
     "buildconfig": True, "services": [], "receivers": [],
     "permissions": ["网络状态"]},
    {"name": "神策数据 Sensors Analytics", "vendor": "神策",
     "packages": ["com/sensorsdata", "cn/sensorsdata"],
     "version_patterns": [r'VERSION\s*=\s*"([^"]+)"', r'SDK_VERSION\s*=\s*"([^"]+)"'],
     "buildconfig": True, "services": [], "receivers": [],
     "permissions": ["网络状态"]},
    {"name": "腾讯 Bugly 崩溃监控", "vendor": "腾讯",
     "packages": ["com/tencent/bugly"],
     "version_patterns": [r'VERSION\s*=\s*"([^"]+)"', r'SDK_VERSION\s*=\s*"([^"]+)"'],
     "buildconfig": True, "services": [], "receivers": [],
     "permissions": ["网络状态"]},

    # ── 工具 / 系统 SDK ──
    {"name": "七牛云 SDK", "vendor": "七牛",
     "packages": ["com/qiniu"],
     "version_patterns": [r'VERSION\s*=\s*"([^"]+)"', r'SDK_VERSION\s*=\s*"([^"]+)"'],
     "buildconfig": True, "services": [], "receivers": [],
     "permissions": ["存储读取", "存储写入"]},
    {"name": "Google Firebase Messaging (FCM)", "vendor": "Google",
     "packages": ["com/google/firebase/messaging", "com/google/firebase/iid"],
     "version_patterns": [r'VERSION\s*=\s*"([^"]+)"', r'SDK_VERSION\s*=\s*"([^"]+)"'],
     "buildconfig": True,
     "services": ["com.google.firebase.messaging.FirebaseMessagingService"],
     "receivers": [], "permissions": ["网络状态"]},
]


def decompile(apk_path, out_dir):
    """jadx 反编译，返回是否成功"""
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


def sdk_exists(sources, rule):
    for p in rule["packages"]:
        d = sources / p
        if d.exists():
            return True
        d2 = sources / p.replace("/", os.sep)
        if d2.exists():
            return True
    return False


def extract_version(sources, rule):
    """返回 (version, source_desc)"""
    # BuildConfig.VERSION_NAME
    if rule.get("buildconfig"):
        for p in rule["packages"]:
            pd = sources / p
            if not pd.exists():
                pd = sources / p.replace("/", os.sep)
            if not pd.exists():
                continue
            for bc in pd.rglob("BuildConfig.java"):
                try:
                    text = bc.read_text(encoding="utf-8", errors="replace")
                except Exception:
                    continue
                m = re.search(r'VERSION_NAME\s*=\s*"([^"]+)"', text)
                if m and VERSION_VALID_RE.match(m.group(1)):
                    return m.group(1), f"BuildConfig:{bc.relative_to(sources)}"
    # version constants in source
    for p in rule["packages"]:
        pd = sources / p
        if not pd.exists():
            pd = sources / p.replace("/", os.sep)
        if not pd.exists():
            continue
        for jf in list(pd.rglob("*.java"))[:200]:
            try:
                text = jf.read_text(encoding="utf-8", errors="replace")
            except Exception:
                continue
            for pat in rule.get("version_patterns", []):
                m = re.search(pat, text)
                if m and VERSION_VALID_RE.match(m.group(1)):
                    return m.group(1), f"source:{jf.relative_to(sources)}"
    return "", ""


def find_init_locations(sources, rule):
    """查找 SDK 初始化位置（Application 或 Activity 中的引用）"""
    hits = []
    for p in rule["packages"]:
        pd = sources / p
        if not pd.exists():
            pd = sources / p.replace("/", os.sep)
        if not pd.exists():
            continue
        # find Application class or init methods referencing the SDK
        for jf in list(pd.rglob("*.java"))[:50]:
            try:
                text = jf.read_text(encoding="utf-8", errors="replace")
            except Exception:
                continue
            if re.search(r"class\s+\w*Application", text):
                hits.append(str(jf.relative_to(sources)))
    return "; ".join(hits[:3])


def extract_manifest_info(sources, rule):
    """从反编译的 AndroidManifest.xml 提取 Service / Receiver"""
    services, receivers = [], []
    mf = sources.parent / "resources" / "AndroidManifest.xml"
    if mf and mf.exists():
        try:
            text = mf.read_text(encoding="utf-8", errors="replace")
            for svc in rule.get("services", []):
                if svc in text:
                    services.append(svc)
        except Exception:
            pass
    return "; ".join(services), "; ".join(receivers)


def get_apk_meta(apk_path):
    """提取 APK 自身信息（包名、版本、大小）"""
    size_mb = apk_path.stat().st_size / 1e6
    stem = apk_path.stem
    # filename pattern: pkg_version_rest
    m = re.match(r"([a-zA-Z0-9_.]+)_([0-9][0-9.]*)", stem)
    pkg = m.group(1) if m else stem
    ver = m.group(2) if m else ""
    return stem, pkg, ver, size_mb


def process_apk(apk_path, app_name, no_decompile=False):
    stem, pkg, ver, size_mb = get_apk_meta(apk_path)
    # 单 APK（非捆绑包）：用 aapt 拿真实包名/版本（APKPure 单 apk 文件名不含包名）
    if apk_path.suffix.lower() in (".apk",):
        ainfo = aapt_pkg_info(apk_path)
        if ainfo:
            pkg, ver, label = ainfo
            if label:
                app_name = label
    print(f"\n== {app_name} ({pkg}) ==")

    cache_dir = CACHE_DIR / stem
    target_apk = apk_path
    # 捆绑包（.apkm/.xapk/.apks）：先读 manifest/info 拿真实包名/版本
    if apk_path.suffix.lower() in (".apkm", ".xapk", ".apks"):
        try:
            z = zipfile.ZipFile(apk_path)
            names = z.namelist()
            try:
                if "manifest.json" in names:      # APKPure 格式
                    info = json.loads(z.read("manifest.json"))
                    pkg = info.get("package_name", pkg)
                    ver = info.get("version_name", ver)
                elif "info.json" in names:         # APKMirror 格式
                    info = json.loads(z.read("info.json"))
                    pkg = info.get("pname", pkg)
                    ver = info.get("release_version", ver)
            except Exception:
                pass
            # 主 APK：优先 base.apk（APKMirror），否则取包名同名 apk（APKPure），否则第一个 apk
            main_apk = [n for n in names if n.endswith("base.apk")]
            if not main_apk:
                main_apk = [n for n in names if n.endswith(f"{pkg}.apk")]
            if not main_apk:
                apks = [n for n in names if n.endswith(".apk")]
                main_apk = [apks[0]] if apks else []
            if not main_apk:
                print(f"  [!] 捆绑包内无 apk: {apk_path.name}")
                return []
            safe_stem = re.sub(r"[^A-Za-z0-9_.-]", "_", stem)
            BUNDLE_TMP.mkdir(parents=True, exist_ok=True)
            base_file = BUNDLE_TMP / f"{safe_stem}.base.apk"
            base_file.write_bytes(z.read(main_apk[0]))
            target_apk = base_file
        except zipfile.BadZipFile:
            print(f"  [!] 捆绑包不是 zip: {apk_path.name}")
            return []

    # decompile (cached)
    if not (cache_dir / "sources").exists():
        if no_decompile:
            print(f"  [!] 无缓存且 --no-decompile，跳过 {stem}")
            return []
        print(f"  [jadx] 反编译中...")
        cache_dir.mkdir(parents=True, exist_ok=True)
        if not decompile(target_apk, cache_dir):
            print(f"  [!] 反编译失败")
            return []
    sources = cache_dir / "sources"

    results = []
    for rule in SDK_RULES:
        if not sdk_exists(sources, rule):
            continue
        ver_sdk, ver_src = extract_version(sources, rule)
        init_loc = find_init_locations(sources, rule)
        services, receivers = extract_manifest_info(sources, rule)
        sdk_pkg = ", ".join(rule["packages"]).replace("/", ".")
        conf = "high" if ver_sdk else "medium"
        results.append({
            "应用文件": apk_path.name,
            "应用名称": app_name,
            "应用包名": pkg,
            "应用版本": ver,
            "APK大小(MB)": f"{size_mb:.1f}",
            "SDK名称": rule["name"],
            "SDK厂商": rule["vendor"],
            "SDK版本": ver_sdk or "未提取",
            "SDK包名": sdk_pkg,
            "置信度": conf,
            "证据数": "1" if ver_sdk else "0",
            "初始化位置": init_loc,
            "后台Service": services,
            "后台Receiver": receivers,
            "关联敏感权限": ", ".join(rule["permissions"]),
            "版本来源": ("jadx反编译" if ver_src else ""),
        })
        print(f"  [{rule['name']}] {ver_sdk or '未提取'} ({conf})")
    return results


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--only", default="", help="只处理包含该关键字的 APK")
    parser.add_argument("--no-decompile", action="store_true", help="仅用已缓存反编译结果")
    args = parser.parse_args()

    # 扫描目录：APP_set_foreign 根目录 + xapk_out 子目录
    scan_dirs = [APK_DIR, APK_DIR / "xapk_out"]
    apks = []
    for d in scan_dirs:
        if d.exists():
            apks.extend(f for f in d.iterdir()
                        if f.is_file() and f.suffix.lower() in (".apk", ".apkm", ".xapk"))
    apks = sorted(set(apks))
    if args.only:
        apks = [f for f in apks if args.only in f.name]

    # app name from filename (before first _)
    all_results = []
    for apk in apks:
        app_name = apk.stem.split("_", 1)[0]
        try:
            all_results.extend(process_apk(apk, app_name, args.no_decompile))
        except Exception as e:
            print(f"  [!] {apk.name}: {e}")

    if all_results:
        cols = ["应用文件", "应用名称", "应用包名", "应用版本", "APK大小(MB)",
                "SDK名称", "SDK厂商", "SDK版本", "SDK包名", "置信度", "证据数",
                "初始化位置", "后台Service", "后台Receiver", "关联敏感权限", "版本来源"]
        OUTPUT_CSV.parent.mkdir(parents=True, exist_ok=True)
        exists = OUTPUT_CSV.exists() and OUTPUT_CSV.stat().st_size > 0
        with open(OUTPUT_CSV, "a", encoding="utf-8-sig", newline="") as f:
            w = csv.DictWriter(f, fieldnames=cols)
            if not exists:
                w.writeheader()
            w.writerows(all_results)
        print(f"\n已追加: {OUTPUT_CSV}  (+{len(all_results)} 条, 共 {sum(1 for _ in open(OUTPUT_CSV, encoding='utf-8-sig'))-1} 条)")
    else:
        print("\n无结果")


if __name__ == "__main__":
    main()
