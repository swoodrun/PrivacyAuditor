"""
extract_sdk_versions_jadx.py
使用 jadx 反编译 APK，批量提取 SDK 版本号。
只扫描已审计的 App（证据收集目录中存在的包名）。

提取策略（按优先级）：
  1. AndroidManifest.xml 中的 meta-data 版本标签
  2. SDK 自身 BuildConfig.VERSION_NAME
  3. SDK 源码中的版本常量（VERSION / SDK_VERSION / VER 等）
  4. 混淆场景：在 SDK 包路径附近搜索版本号模式
"""

import argparse
import csv
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
APK_DIR = PROJECT_ROOT / "APP_set"
EVIDENCE_DIR = PROJECT_ROOT / "证据收集"
SDK_SUMMARY = PROJECT_ROOT / "output" / "sdk_summary.csv"
OUTPUT_CSV = PROJECT_ROOT / "output" / "sdk_versions_jadx.csv"
JADX_JAR = PROJECT_ROOT / "jadx" / "jadx-gui-1.5.3-win" / "lib" / "jadx-gui-1.5.3-all.jar"

# 已知 SDK 的版本提取规则
# 每条规则：(SDK名称, SDK包名前缀列表, 版本搜索策略)
SDK_VERSION_RULES = [
    {
        "name": "支付宝 SDK",
        "packages": ["com/alipay/sdk", "com/alipay/mobile"],
        "manifest_keys": ["com.alipay.sdk.version"],
        "class_patterns": [
            r'VERSION(?:_NAME)?\s*=\s*"([^"]+)"',
            r'SDK_VERSION\s*=\s*"([^"]+)"',
        ],
        "buildconfig": True,
    },
    {
        "name": "极光推送 JPush",
        "packages": ["cn/jpush/android", "cn/jiguang"],
        "manifest_keys": ["JPUSH_VERSION", "cn.jpush.android.VERSION"],
        "class_patterns": [
            r'VERSION\s*=\s*"(\d+\.\d+[\.\d]*[^"]*)"',
            r'SDK_VERSION\s*=\s*"([^"]+)"',
        ],
        "buildconfig": True,
    },
    {
        "name": "个推 Getui",
        "packages": ["com/igexin", "com/getui"],
        "manifest_keys": [],
        "class_patterns": [
            r'VERSION\s*=\s*"([^"]+)"',
            r'SDK_VERSION\s*=\s*"([^"]+)"',
            r'PUSH_VERSION\s*=\s*"([^"]+)"',
        ],
        "buildconfig": True,
    },
    {
        "name": "小米 Push",
        "packages": ["com/xiaomi/mipush", "com/xiaomi/push"],
        "manifest_keys": ["com.xiaomi.push.sdk.version"],
        "class_patterns": [
            r'VERSION\s*=\s*"([^"]+)"',
            r'SDK_VERSION\s*=\s*"([^"]+)"',
        ],
        "buildconfig": True,
    },
    {
        "name": "OPPO Push SDK",
        "packages": ["com/heytap/msp/push"],
        "manifest_keys": ["com.heytap.msp.push.version"],
        "class_patterns": [
            r'VERSION\s*=\s*"([^"]+)"',
            r'SDK_VERSION\s*=\s*"([^"]+)"',
        ],
        "buildconfig": True,
    },
    {
        "name": "OPPO 广告联盟",
        "packages": ["com/heytap/openid"],
        "manifest_keys": [],
        "class_patterns": [
            r'VERSION\s*=\s*"([^"]+)"',
            r'SDK_VERSION\s*=\s*"([^"]+)"',
        ],
        "buildconfig": True,
    },
    {
        "name": "vivo Push SDK",
        "packages": ["com/vivo/push"],
        "manifest_keys": ["com.vivo.push.sdk_version"],
        "class_patterns": [
            r'VERSION\s*=\s*"([^"]+)"',
            r'SDK_VERSION\s*=\s*"([^"]+)"',
        ],
        "buildconfig": True,
    },
    {
        "name": "华为 HMS Ads",
        "packages": ["com/huawei/hms/ads"],
        "manifest_keys": [
            "com.huawei.hms.client.service.name:ads-lite",
            "com.huawei.hms.version",
            "com.huawei.hms.client.version",
        ],
        "class_patterns": [
            r'VERSION\s*=\s*"([^"]+)"',
            r'SDK_VERSION\s*=\s*"([^"]+)"',
            r'HMS_VERSION\s*=\s*"([^"]+)"',
        ],
        "buildconfig": True,
    },
    {
        "name": "荣耀广告 SDK",
        "packages": ["com/hihonor/ads"],
        "manifest_keys": ["com.hihonor.ads.sdk.version"],
        "class_patterns": [
            r'VERSION\s*=\s*"([^"]+)"',
        ],
        "buildconfig": True,
    },
    {
        "name": "微信 Open SDK",
        "packages": ["com/tencent/mm/opensdk"],
        "manifest_keys": [],
        "class_patterns": [
            r'VERSION\s*=\s*"([^"]+)"',
            r'SDK_VERSION\s*=\s*"([^"]+)"',
            r'SDK_INT\s*=\s*(\d+)',
        ],
        "buildconfig": True,
    },
    {
        "name": "腾讯优量汇 GDT",
        "packages": ["com/qq/e/ads", "com/qq/e/comm"],
        "manifest_keys": ["com.qq.e.gdt.version"],
        "class_patterns": [
            r'VERSION\s*=\s*"([^"]+)"',
            r'SDK_VERSION\s*=\s*"([^"]+)"',
            r'GDT_SDK_VERSION\s*=\s*"([^"]+)"',
        ],
        "buildconfig": True,
    },
    {
        "name": "穿山甲 Pangolin",
        "packages": ["com/bytedance/sdk/openadsdk", "com/ss/android/downloadlib"],
        "manifest_keys": ["com.bytedance.pangle.version"],
        "class_patterns": [
            r'VERSION\s*=\s*"([^"]+)"',
            r'SDK_VERSION\s*=\s*"([^"]+)"',
            r'PANGLE_SDK_VER\s*=\s*"([^"]+)"',
        ],
        "buildconfig": True,
    },
    {
        "name": "字节 RangersAppLog",
        "packages": ["com/bytedance/applog"],
        "manifest_keys": [],
        "class_patterns": [
            r'VERSION\s*=\s*"([^"]+)"',
            r'SDK_VERSION\s*=\s*"([^"]+)"',
        ],
        "buildconfig": True,
    },
    {
        "name": "字节 APMPlus",
        "packages": ["com/bytedance/apm"],
        "manifest_keys": [],
        "class_patterns": [
            r'VERSION\s*=\s*"([^"]+)"',
        ],
        "buildconfig": True,
    },
    {
        "name": "友盟+ Umeng",
        "packages": ["com/umeng/analytics", "com/umeng/commonsdk"],
        "manifest_keys": [],
        "class_patterns": [
            r'VERSION\s*=\s*"([^"]+)"',
            r'SDK_VERSION\s*=\s*"([^"]+)"',
            r'UMENG_SDK_VER\s*=\s*"([^"]+)"',
        ],
        "buildconfig": True,
    },
    {
        "name": "百度 MobAds",
        "packages": ["com/baidu/mobads"],
        "manifest_keys": ["com.baidu.mobads.version"],
        "class_patterns": [
            r'VERSION\s*=\s*"([^"]+)"',
            r'SDK_VERSION\s*=\s*"([^"]+)"',
        ],
        "buildconfig": True,
    },
    {
        "name": "Google AdMob",
        "packages": ["com/google/android/gms/ads"],
        "manifest_keys": [],
        "class_patterns": [
            r'VERSION\s*=\s*"([^"]+)"',
            r'SDK_VERSION\s*=\s*"([^"]+)"',
        ],
        "buildconfig": True,
    },
    {
        "name": "中国移动一键登录",
        "packages": ["com/cmic/sso", "com/mobile/auth"],
        "manifest_keys": [],
        "class_patterns": [
            r'VERSION\s*=\s*"([^"]+)"',
            r'SDK_VERSION\s*=\s*"([^"]+)"',
        ],
        "buildconfig": True,
    },
    {
        "name": "中国联通一键登录",
        "packages": ["com/unicom/online"],
        "manifest_keys": [],
        "class_patterns": [
            r'VERSION\s*=\s*"([^"]+)"',
        ],
        "buildconfig": True,
    },
    {
        "name": "阿里 EMAS",
        "packages": ["com/alibaba/sdk/android/emas", "com/alicom"],
        "manifest_keys": ["com.alibaba.emas.version"],
        "class_patterns": [
            r'VERSION\s*=\s*"([^"]+)"',
        ],
        "buildconfig": True,
    },
]

# 版本号合法性校验
VERSION_VALID_RE = re.compile(r"^\d+\.\d+[\.\d]*(?:[-_.][a-zA-Z0-9]+)*$")
# 宽松版本搜索（用于混淆场景）
VERSION_LOOSE_RE = re.compile(r'"(\d+\.\d+\.\d+[\.\d]*(?:[-_][a-zA-Z0-9]+)*)"')


def is_valid_version(ver):
    """过滤 IP 地址、AppKey、时间戳等误识别的版本号"""
    if not ver or ver == "None":
        return False
    # 排除十六进制 AppKey（如 522698b056240be8cc09878e）
    if re.match(r"^[0-9a-fA-F]{12,}$", ver):
        return False
    # 排除含非十六进制字母的随机 ID（如 86yu3jUaqjABKMGOECRca4）
    if len(ver) > 15 and not re.match(r"^[\d.]+", ver):
        return False
    parts = ver.split(".")
    # 排除 IP 地址：恰好 4 段且每段 ≤ 255、首段 ≥ 10
    if len(parts) == 4 and all(p.isdigit() for p in parts):
        nums = [int(p) for p in parts]
        if all(0 <= n <= 255 for n in nums) and nums[0] >= 10:
            return False
    # 排除含超长数字段的时间戳版本（如 1.0.0.211015113556）
    for p in parts:
        if p.isdigit() and len(p) > 6:
            return False
    return True


def get_audited_packages():
    """从证据收集目录提取已审计的包名集合"""
    pkgs = set()
    if not EVIDENCE_DIR.exists():
        return pkgs
    for d in EVIDENCE_DIR.iterdir():
        if not d.is_dir():
            continue
        name = d.name
        for sep in ["：", ":"]:
            if sep in name:
                pkg = name.split(sep, 1)[1].strip()
                if "(" in pkg:
                    pkg = pkg.split("(")[0].strip()
                if pkg:
                    pkgs.add(pkg)
                break
    return pkgs


def find_apk_for_package(pkg):
    """在 APK_set 中找到匹配包名的 APK 文件"""
    if not APK_DIR.exists():
        return None
    for f in APK_DIR.iterdir():
        if f.suffix.lower() == ".apk" and f.name.startswith(pkg + "_"):
            return f
        if f.suffix.lower() == ".apk" and pkg in f.name:
            return f
    return None


def run_jadx(apk_path, output_dir):
    """通过 jadx-gui all-jar 的 CLI 入口反编译 APK"""
    if not JADX_JAR.exists():
        print(f"    [!] jadx jar 不存在: {JADX_JAR}")
        return False
    cmd = [
        "java", "-Xmx4g", "-cp", str(JADX_JAR),
        "jadx.cli.JadxCLI",
        "--threads-count", "4",
        "--output-dir", str(output_dir),
        str(apk_path),
    ]
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=900, encoding="utf-8",
            errors="replace"
        )
        if result.returncode != 0:
            stderr_snippet = (result.stderr or "")[:500]
            if stderr_snippet:
                print(f"    [!] jadx stderr: {stderr_snippet}")
        sources_dir = output_dir / "sources" if isinstance(output_dir, Path) else Path(output_dir) / "sources"
        if sources_dir.exists() and any(sources_dir.rglob("*.java")):
            return True
        return result.returncode == 0
    except subprocess.TimeoutExpired:
        print(f"    [!] jadx 超时（15分钟）")
        sources_dir = output_dir / "sources" if isinstance(output_dir, Path) else Path(output_dir) / "sources"
        if sources_dir.exists() and any(sources_dir.rglob("*.java")):
            print(f"    [*] 超时但已有部分反编译结果，继续提取")
            return True
        return False
    except FileNotFoundError:
        print(f"    [!] java 未找到，请确认已安装 JDK")
        return False


def search_manifest_versions(jadx_output, rule):
    """从 AndroidManifest.xml 中搜索版本 meta-data"""
    versions = {}
    manifest = jadx_output / "resources" / "AndroidManifest.xml"
    if not manifest.exists():
        return versions

    try:
        content = manifest.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return versions

    for key in rule.get("manifest_keys", []):
        pattern = re.compile(
            r'android:name\s*=\s*"' + re.escape(key) + r'"'
            r'[^>]*android:value\s*=\s*"([^"]+)"',
            re.DOTALL
        )
        m = pattern.search(content)
        if m:
            val = m.group(1).strip()
            if VERSION_VALID_RE.match(val) or re.match(r"\d+", val):
                versions[f"manifest:{key}"] = val

        pattern2 = re.compile(
            r'android:value\s*=\s*"([^"]+)"'
            r'[^>]*android:name\s*=\s*"' + re.escape(key) + r'"',
            re.DOTALL
        )
        m2 = pattern2.search(content)
        if m2:
            val = m2.group(1).strip()
            if VERSION_VALID_RE.match(val) or re.match(r"\d+", val):
                versions[f"manifest:{key}"] = val

    return versions


def search_source_versions(jadx_output, rule):
    """在反编译的 Java 源码中搜索版本常量"""
    versions = {}
    sources_dir = jadx_output / "sources"
    if not sources_dir.exists():
        return versions

    for pkg_path in rule.get("packages", []):
        pkg_dir = sources_dir / pkg_path
        if not pkg_dir.exists():
            pkg_slash = pkg_path.replace("/", os.sep)
            pkg_dir = sources_dir / pkg_slash
        if not pkg_dir.exists():
            continue

        # 搜索 BuildConfig
        if rule.get("buildconfig"):
            for bc in pkg_dir.rglob("BuildConfig.java"):
                try:
                    text = bc.read_text(encoding="utf-8", errors="replace")
                except Exception:
                    continue
                m = re.search(r'VERSION_NAME\s*=\s*"([^"]+)"', text)
                if m and VERSION_VALID_RE.match(m.group(1)):
                    versions[f"BuildConfig:{bc.relative_to(sources_dir)}"] = m.group(1)
                m = re.search(r'VERSION_CODE\s*=\s*(\d+)', text)
                if m:
                    versions[f"BuildConfig.VERSION_CODE:{bc.relative_to(sources_dir)}"] = m.group(1)

        # 搜索版本常量
        java_files = list(pkg_dir.rglob("*.java"))
        for jf in java_files[:200]:
            try:
                text = jf.read_text(encoding="utf-8", errors="replace")
            except Exception:
                continue

            for pat_str in rule.get("class_patterns", []):
                pat = re.compile(pat_str)
                for m in pat.finditer(text):
                    val = m.group(1)
                    if VERSION_VALID_RE.match(val):
                        rel = jf.relative_to(sources_dir)
                        versions[f"source:{rel}"] = val

        # 混淆场景：SDK 包存在但类名被混淆，搜索所有字符串中的版本号
        if not versions:
            for jf in java_files[:100]:
                try:
                    text = jf.read_text(encoding="utf-8", errors="replace")
                except Exception:
                    continue
                for m in VERSION_LOOSE_RE.finditer(text):
                    val = m.group(1)
                    if len(val) >= 3 and not val.startswith("0.0.0"):
                        rel = jf.relative_to(sources_dir)
                        key = f"obfuscated:{rel}"
                        if key not in versions:
                            versions[key] = val

    return versions


def sdk_exists_in_apk(jadx_output, rule):
    """检查 SDK 的包目录是否存在于反编译结果中"""
    sources_dir = jadx_output / "sources"
    if not sources_dir.exists():
        return False
    for pkg_path in rule.get("packages", []):
        pkg_dir = sources_dir / pkg_path
        if pkg_dir.exists():
            return True
        pkg_slash = pkg_path.replace("/", os.sep)
        pkg_dir = sources_dir / pkg_slash
        if pkg_dir.exists():
            return True
    return False


def search_res_properties(jadx_output, rule):
    """搜索 assets / res 中与 SDK 相关的属性文件和配置"""
    versions = {}
    res_dir = jadx_output / "resources"
    if not res_dir.exists():
        return versions

    sdk_keywords = set()
    for pkg in rule.get("packages", []):
        parts = pkg.replace("/", ".").split(".")
        for p in parts:
            if len(p) > 3 and p not in ("android", "sdk", "com", "java", "net", "org",
                                         "mobile", "push", "ads", "open", "online", "auth"):
                sdk_keywords.add(p.lower())

    if not sdk_keywords:
        return versions

    for prop_file in res_dir.rglob("*.properties"):
        fname_lower = prop_file.name.lower()
        if not any(kw in fname_lower for kw in sdk_keywords):
            continue
        try:
            text = prop_file.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue
        for line in text.splitlines():
            if "version" in line.lower() and "=" in line:
                key, _, val = line.partition("=")
                val = val.strip()
                if VERSION_VALID_RE.match(val):
                    versions[f"properties:{prop_file.name}:{key.strip()}"] = val

    return versions


def pick_best_version(versions_dict):
    """从多个提取结果中选择最可信的版本号"""
    if not versions_dict:
        return None, None

    # 优先级：manifest > BuildConfig.VERSION_NAME > source > properties > obfuscated
    priority = [
        ("manifest:", 1),
        ("BuildConfig:", 2),
        ("source:", 3),
        ("properties:", 4),
        ("json:", 5),
        ("obfuscated:", 6),
    ]

    best = None
    best_pri = 99
    best_source = None

    for source, ver in versions_dict.items():
        if "VERSION_CODE" in source:
            continue
        if not is_valid_version(ver):
            continue
        for prefix, pri in priority:
            if source.startswith(prefix) and pri < best_pri:
                best = ver
                best_pri = pri
                best_source = source
                break

    return best, best_source


def process_apk(apk_path, app_name, app_pkg):
    """处理单个 APK 文件"""
    results = []
    print(f"\n{'='*50}", flush=True)
    print(f"  App: {app_name} ({app_pkg})", flush=True)
    print(f"  APK: {apk_path.name}", flush=True)
    print(f"{'='*50}", flush=True)

    # 使用短路径避免 Windows MAX_PATH 限制
    local_tmp = PROJECT_ROOT / "_jadx_tmp"
    local_tmp.mkdir(exist_ok=True)
    tmp_dir = Path(tempfile.mkdtemp(prefix="j_", dir=str(local_tmp)))

    try:
        print(f"  [1/2] jadx 反编译中...", flush=True)
        if not run_jadx(apk_path, tmp_dir):
            print(f"  [!] 反编译失败，跳过", flush=True)
            return results

        print(f"  [2/2] 提取 SDK 版本...", flush=True)

        for rule in SDK_VERSION_RULES:
            # 核心改进：先确认 SDK 存在于此 APK 中
            has_manifest = bool(search_manifest_versions(tmp_dir, rule))
            has_source = sdk_exists_in_apk(tmp_dir, rule)

            if not has_manifest and not has_source:
                continue

            all_versions = {}

            # 策略 1: AndroidManifest
            if has_manifest:
                manifest_vers = search_manifest_versions(tmp_dir, rule)
                all_versions.update(manifest_vers)

            # 策略 2+3: 源码搜索（含混淆场景）
            if has_source:
                source_vers = search_source_versions(tmp_dir, rule)
                all_versions.update(source_vers)

            # 策略 4: 资源文件（仅在 SDK 确认存在时才搜索）
            if has_source:
                res_vers = search_res_properties(tmp_dir, rule)
                all_versions.update(res_vers)

            if all_versions:
                best_ver, best_source = pick_best_version(all_versions)
                is_obfuscated = best_source and best_source.startswith("obfuscated:")

                print(f"    [{rule['name']}] {best_ver}"
                      f"{'  (混淆代码中提取)' if is_obfuscated else ''}"
                      f"  <- {best_source}")

                results.append({
                    "App": app_name,
                    "包名": app_pkg,
                    "SDK": rule["name"],
                    "版本号": best_ver or "",
                    "来源": best_source or "",
                    "是否混淆": "是" if is_obfuscated else "否",
                    "全部候选": "; ".join(f"{k}={v}" for k, v in all_versions.items()),
                })

    finally:
        try:
            shutil.rmtree(tmp_dir, ignore_errors=True)
        except Exception:
            pass

    if not results:
        print(f"    (未找到任何 SDK 版本信息)")

    return results


def load_app_info_from_csv():
    """从 sdk_summary.csv 加载 App 名称映射"""
    info = {}
    if not SDK_SUMMARY.exists():
        return info
    with open(SDK_SUMMARY, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            pkg = row.get("应用包名", "").strip()
            name = row.get("应用名称", "").strip()
            if pkg and name:
                info[pkg] = name
    return info


def parse_args():
    parser = argparse.ArgumentParser(description="SDK 版本号提取工具 (jadx 反编译)")
    parser.add_argument("--only", type=str, default="",
                        help="只处理指定 APK 文件名（逗号分隔），绕过已审计检查")
    parser.add_argument("--output", type=str, default="",
                        help="自定义输出 CSV 路径")
    return parser.parse_args()


def main():
    args = parse_args()
    output_csv = Path(args.output) if args.output else OUTPUT_CSV

    print("=" * 60)
    print("  SDK 版本号提取工具 (jadx 反编译)")
    print("=" * 60)

    # 2. 扫描 APK 目录
    if not APK_DIR.exists():
        print(f"[!] APK 目录不存在: {APK_DIR}")
        sys.exit(1)

    app_info = load_app_info_from_csv()
    tasks = []

    if args.only:
        # --only 模式：直接处理指定文件，无需已审计检查
        only_names = [n.strip() for n in args.only.split(",") if n.strip()]
        for fname in only_names:
            apk = APK_DIR / fname
            if not apk.exists():
                print(f"  [!] 未找到: {fname}")
                continue
            stem = apk.stem
            pkg_guess = stem.rsplit("_", 1)[0] if "_" in stem else stem
            app_name = app_info.get(pkg_guess, pkg_guess)
            tasks.append((apk, app_name, pkg_guess))
        print(f"\n指定处理: {len(tasks)} 个 APK")
    else:
        # 默认模式：只处理已审计的
        audited_pkgs = get_audited_packages()
        print(f"\n已审计 App 包名: {len(audited_pkgs)} 个")

        apk_files = [f for f in APK_DIR.iterdir() if f.suffix.lower() == ".apk"]
        print(f"APK_set 中共 {len(apk_files)} 个 APK 文件")

        skipped = []
        for apk in sorted(apk_files):
            stem = apk.stem
            pkg_guess = stem.rsplit("_", 1)[0] if "_" in stem else stem

            if pkg_guess in audited_pkgs:
                app_name = app_info.get(pkg_guess, pkg_guess)
                tasks.append((apk, app_name, pkg_guess))
            else:
                matched = False
                for audit_pkg in audited_pkgs:
                    if audit_pkg in stem or stem.startswith(audit_pkg.replace(".", "")):
                        app_name = app_info.get(audit_pkg, audit_pkg)
                        tasks.append((apk, app_name, audit_pkg))
                        matched = True
                        break
                if not matched:
                    skipped.append(apk.name)

        print(f"\n将扫描: {len(tasks)} 个 APK（已审计）")
        if skipped:
            print(f"跳过（未审计）: {len(skipped)} 个")
            for s in skipped[:10]:
                print(f"  - {s}")
            if len(skipped) > 10:
                print(f"  ... 及另外 {len(skipped)-10} 个")

    if not tasks:
        print("\n[!] 没有匹配的 APK 文件")
        sys.exit(0)

    # 4. 逐个处理
    all_results = []
    for i, (apk, name, pkg) in enumerate(tasks):
        print(f"\n--- [{i+1}/{len(tasks)}] ---", flush=True)
        try:
            results = process_apk(apk, name, pkg)
            all_results.extend(results)
        except Exception as e:
            print(f"  [!] 处理失败: {e}", flush=True)

    # 5. 输出 CSV
    if all_results:
        with open(output_csv, "w", encoding="utf-8-sig", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=[
                "App", "包名", "SDK", "版本号", "来源", "是否混淆", "全部候选"
            ])
            writer.writeheader()
            writer.writerows(all_results)
        print(f"\n{'='*60}")
        print(f"结果已保存: {output_csv}")
        print(f"共提取 {len(all_results)} 条 SDK 版本记录")
    else:
        print("\n未提取到任何 SDK 版本信息")

    # 6. 摘要
    print(f"\n{'='*60}")
    print(f"  提取摘要")
    print(f"{'='*60}")
    print(f"{'App':<12} {'SDK':<24} {'版本号':<20} {'混淆'}")
    print("-" * 70)
    for r in all_results:
        print(f"{r['App']:<12} {r['SDK']:<24} {r['版本号']:<20} {r['是否混淆']}")

    # 7. 与 sdk_summary.csv 比对
    print(f"\n{'='*60}")
    print("  与 sdk_summary.csv 缺失项比对")
    print(f"{'='*60}")
    filled = 0
    extracted_map = {(r["包名"], r["SDK"]): r["版本号"] for r in all_results if r["版本号"]}

    if SDK_SUMMARY.exists():
        with open(SDK_SUMMARY, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                pkg = row.get("应用包名", "").strip()
                sdk = row.get("SDK名称", "").strip()
                old_ver = row.get("SDK版本", "").strip()
                if old_ver and old_ver != "未提取":
                    continue
                if (pkg, sdk) in extracted_map:
                    new_ver = extracted_map[(pkg, sdk)]
                    print(f"  [+] {pkg} / {sdk}: {old_ver} -> {new_ver}")
                    filled += 1

    print(f"\n可补全 {filled} 条缺失版本")


if __name__ == "__main__":
    main()
