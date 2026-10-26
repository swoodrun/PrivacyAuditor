"""
Fetch and parse privacy policies from app websites.
Extract declared data collection scope, then compare with actual audit findings.
"""
import requests
from bs4 import BeautifulSoup
import re, json, os, sys, time, zipfile, glob

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Linux; Android 13; Pixel 7) AppleWebKit/537.36 "
                  "(KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
    "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
}

KNOWN_DATA_KEYWORDS = {
    "IMEI": ["IMEI", "imei", "设备识别码", "国际移动设备识别码"],
    "IMSI": ["IMSI", "imsi", "国际移动用户识别码"],
    "Android ID": ["Android ID", "AndroidID", "android_id", "安卓ID"],
    "OAID": ["OAID", "oaid", "匿名设备标识"],
    "MAC 地址": ["MAC地址", "MAC 地址", "mac地址", "网卡地址", "WLAN地址"],
    "GPS 经纬度": ["GPS", "gps", "经纬度", "地理位置", "位置信息", "精确位置", "地理位置信息"],
    "IP 地址": ["IP地址", "IP 地址", "ip地址", "网络地址"],
    "SSID / BSSID": ["SSID", "WiFi名称", "WiFi信息", "WLAN", "无线网络"],
    "SIM 卡信息": ["SIM", "sim卡", "SIM卡", "运营商", "手机号", "电话号码", "手机号码"],
    "设备型号": ["设备型号", "手机型号", "设备信息", "设备类型", "硬件信息"],
    "操作系统版本": ["操作系统", "系统版本", "Android版本"],
    "应用列表": ["应用列表", "安装列表", "已安装应用", "应用安装"],
    "通讯录": ["通讯录", "联系人", "通信录"],
    "相册 / 存储": ["相册", "存储", "文件", "照片", "媒体"],
    "剪贴板": ["剪贴板", "粘贴板", "剪切板"],
    "账号 Token / Session": ["token", "Token", "session", "Session", "登录凭证", "会话"],
    "广告标识": ["广告标识", "广告ID", "IDFA", "GAID"],
    "传感器数据": ["传感器", "加速度", "陀螺仪", "sensor"],
    "摄像头 / 麦克风": ["摄像头", "相机", "麦克风", "录音"],
}

# URLs verified from APK extraction
PRIVACY_URLS = {
    "cn.jj": {
        "name": "jj斗地主",
        "url": "https://www.jj.cn/agreement/privacy_protocols.html",
    },
    "tv.danmaku.bili": {
        "name": "哔哩哔哩",
        "url": "https://www.bilibili.com/blackboard/privacy-pc.html",
        "spa": True,
    },
    "com.zhihu.android": {
        "name": "知乎",
        "url": "https://www.zhihu.com/term/privacy",
    },
    "com.xingin.xhs": {
        "name": "小红书",
        "url": "https://www.xiaohongshu.com/crown/community/privacy_intl",
    },
    "com.sina.weibo": {
        "name": "微博",
        "url": "https://m.weibo.cn/c/privacy",
    },
    "com.sankuai.meituan": {
        "name": "美团",
        "url": "https://about.meituan.com/privacy/main",
    },
    "com.baidu.tieba": {
        "name": "百度贴吧",
        "url": "https://tieba.baidu.com/mo/q/hybrid-privacy",
    },
    "com.taobao.idlefish": {
        "name": "闲鱼",
        "url": "https://market.m.taobao.com/app/idlefish-wiki-fe/idle-privacy/pages/index",
    },
    "com.tencent.mm": {
        "name": "微信",
        "url": "https://weixin.qq.com/cgi-bin/readtemplate?lang=zh_CN&t=weixin_agreement&s=privacy",
    },
    "com.tencent.mobileqq": {
        "name": "QQ",
        "url": "https://ti.qq.com/agreement/qqface/privacy.html",
    },
    "com.kuaishou.nebula": {
        "name": "快手极速版",
        "url": "https://www.kuaishou.com/about/policy",
    },
    "com.ss.android.ugc.aweme": {
        "name": "抖音",
        "url": "https://www.douyin.com/draft/douyin_agreement/douyin_agreement_privacy.html",
    },
    "com.vivo.space": {
        "name": "vivo 官网",
        "url": "https://www.vivo.com.cn/about-vivo/service-privacy-policy",
    },
    "cn.soulapp.android": {
        "name": "Soul",
        "url": "https://soulapp.cn/privacy.html",
    },
    "com.block.juggle": {
        "name": "Block Blast",
        "url": "https://www.hungrystudio.com/privacyus.html",
    },
    "com.wondershare.filmorago": {
        "name": "FilmoraGo",
        "url": "https://www.wondershare.com/privacy.html",
    },
    "com.tencent.qqlive": {
        "name": "腾讯视频",
        "url": "https://m.v.qq.com/about/privacy_item.html",
    },
    "com.hexin.plat.android": {
        "name": "同花顺",
        "url": "https://activity.10jqka.com.cn/acmake/YSZCDetail/index.html",
    },
    "com.tencent.portfolio": {
        "name": "腾讯自选股",
        "url": "https://stockapp.finance.qq.com/info/privacy.html",
    },
    "com.mihoyo.hyperion": {
        "name": "米游社",
        "url": "https://user.mihoyo.com/protocol/privacy",
    },
    "com.lofter.android": {
        "name": "LOFTER",
        "url": "https://www.lofter.com/agreement/privacy",
    },
    "com.taobao.taobao": {
        "name": "淘宝",
        "url": "https://terms.alicdn.com/legal-agreement/terms/privacy_policy/20231109180939630/20231109180939630.html",
    },
    "com.alibaba.wireless": {
        "name": "1688",
        "url": "https://rule.1688.com/rule/detail/4015.htm",
    },
    "com.shizhuang.duapp": {
        "name": "得物",
        "url": "https://m.dewu.com/h5/basic/privacy-agreement",
    },
    "com.achievo.vipshop": {
        "name": "唯品会",
        "url": "https://m.vip.com/privacy_policy.html",
    },
    "com.wuba.zhuanzhuan": {
        "name": "转转",
        "url": "https://m.zhuanzhuan.com/user/privacy.html",
    },
    "com.unionpay": {
        "name": "云闪付",
        "url": "https://www.unionpay.com/upowhtml/common/privacy.html",
    },
    "com.cmcc.cmvideo": {
        "name": "咪咕视频",
        "url": "https://www.miguvideo.com/p/privacy",
    },
    "com.phoenix.read": {
        "name": "凤凰新闻",
        "url": "https://app.ifeng.com/protocol/privacy",
    },
    "com.amazon.mShop.android.shopping": {
        "name": "Amazon",
        "url": "https://www.amazon.com/gp/help/customer/display.html?nodeId=GX7NJQ4ZB8MHFRNJ",
    },
    "com.binance.dev": {
        "name": "Binance",
        "url": "https://www.binance.com/en/privacy",
    },
    "com.fusionmedia.investing": {
        "name": "Investing",
        "url": "https://www.investing.com/about-us/privacy-policy",
    },
    "com.smile.gifmaker": {
        "name": "快手",
        "url": "https://www.kuaishou.com/about/policy",
    },
    "com.cctv.yangshipin.app.androidp": {
        "name": "央视频",
        "url": "https://m.yangshipin.cn/static/camera_privacy.html",
    },
    "com.dz.hmjc": {
        "name": "河马剧场",
        "url": "https://www.dz.hmjc.com/privacy",
        "spa": True,
    },
    "com.renrendai.haohuan": {
        "name": "好还",
        "url": "https://www.renrendai.com/cms/privacy.html",
    },
}


def fetch_text(url, timeout=15):
    try:
        resp = requests.get(url, headers=HEADERS, timeout=timeout, verify=False)
        resp.encoding = resp.apparent_encoding or "utf-8"
        if resp.status_code != 200:
            return None, f"HTTP {resp.status_code}"
        soup = BeautifulSoup(resp.text, "html.parser")
        for tag in soup(["script", "style", "noscript", "header", "footer", "nav"]):
            tag.decompose()
        text = soup.get_text(separator="\n", strip=True)
        return text, None
    except Exception as e:
        return None, str(e)


def extract_declared_fields(text):
    found = {}
    for field_name, keywords in KNOWN_DATA_KEYWORDS.items():
        for kw in keywords:
            if kw in text:
                ctx = ""
                idx = text.find(kw)
                start = max(0, idx - 40)
                end = min(len(text), idx + len(kw) + 60)
                ctx = text[start:end].replace("\n", " ").strip()
                found[field_name] = ctx
                break
    return found


def main():
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    targets = PRIVACY_URLS
    if len(sys.argv) > 1 and sys.argv[1] == "--demo":
        demo_pkgs = ["cn.jj", "tv.danmaku.bili", "com.zhihu.android"]
        targets = {k: v for k, v in PRIVACY_URLS.items() if k in demo_pkgs}

    results = {}
    for pkg, info in targets.items():
        name = info["name"]
        url = info["url"]
        print(f"\n{'='*60}")
        print(f"[{name}] {pkg}")
        print(f"  URL: {url}")

        if info.get("spa"):
            print(f"  [SKIP] SPA page, needs headless browser")
            results[pkg] = {"name": name, "url": url, "error": "SPA", "fields": {}}
            continue

        text, err = fetch_text(url)
        if err:
            print(f"  [FAIL] {err}")
            results[pkg] = {"name": name, "url": url, "error": err, "fields": {}}
            continue

        char_count = len(text)
        if char_count < 100:
            print(f"  [SKIP] Only {char_count} chars (likely SPA/empty)")
            results[pkg] = {"name": name, "url": url, "error": "SPA/empty", "fields": {}}
            continue

        print(f"  [OK] Fetched {char_count} chars")

        fields = extract_declared_fields(text)
        print(f"  Declared data fields ({len(fields)}):")
        for f, ctx in sorted(fields.items()):
            print(f"    - {f}: ...{ctx}...")

        results[pkg] = {
            "name": name,
            "url": url,
            "char_count": char_count,
            "fields": fields,
            "field_names": sorted(fields.keys()),
        }

        time.sleep(0.5)

    out_path = os.path.join(
        os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
        "output", "privacy_policy_fields.json"
    )
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(results, f, ensure_ascii=False, indent=2)
    print(f"\n\nResults saved to: {out_path}")

    print("\n\n=== SUMMARY ===")
    print(f"{'App':<20s} {'Status':<8s} {'Fields':>6s}  Declared types")
    print("-" * 80)
    for pkg, r in sorted(results.items(), key=lambda x: x[1]["name"]):
        name = r["name"]
        if "error" in r:
            print(f"{name:<20s} {'FAIL':<8s} {'--':>6s}  {r['error'][:40]}")
        else:
            n = len(r["fields"])
            types = ", ".join(r["field_names"][:6])
            if len(r["field_names"]) > 6:
                types += f" (+{len(r['field_names'])-6})"
            print(f"{name:<20s} {'OK':<8s} {n:>6d}  {types}")


if __name__ == "__main__":
    main()
