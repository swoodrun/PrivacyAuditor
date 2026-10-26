"""
Fetch privacy policies from SPA pages using Playwright headless browser.
Merges results into the existing privacy_policy_fields.json.
"""
from playwright.sync_api import sync_playwright
from bs4 import BeautifulSoup
import json, os, sys, time, re

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

SPA_TARGETS = {
    "tv.danmaku.bili": {
        "name": "哔哩哔哩",
        "url": "https://www.bilibili.com/blackboard/privacy-pc.html",
    },
    "com.xingin.xhs": {
        "name": "小红书",
        "url": "https://www.xiaohongshu.com/crown/community/privacy_intl",
    },
    "com.sina.weibo": {
        "name": "微博",
        "url": "https://m.weibo.cn/c/privacy",
    },
    "com.baidu.tieba": {
        "name": "百度贴吧",
        "url": "https://tieba.baidu.com/mo/q/hybrid-privacy",
    },
    "com.tencent.mobileqq": {
        "name": "QQ",
        "url": "https://rule.tencent.com/rule/preview/46a15b49-3baf-4c60-8199-fd28589f1e05",
    },
    "com.hexin.plat.android": {
        "name": "同花顺",
        "url": "https://activity.10jqka.com.cn/acmake/YSZCDetail/index.html",
    },
    "com.tencent.portfolio": {
        "name": "腾讯自选股",
        "url": "https://stockapp.finance.qq.com/info/privacy.html",
    },
    "com.achievo.vipshop": {
        "name": "唯品会",
        "url": "https://mst.vip.com/privacy/index.html",
    },
    "com.cctv.yangshipin.app.androidp": {
        "name": "央视频",
        "url": "https://app.cctv.com/special/m/liveclient/yspprivacy.html",
    },
    "com.mihoyo.hyperion": {
        "name": "米游社",
        "url": "https://user.mihoyo.com/#/privacyPolicy",
    },
    "com.sankuai.meituan": {
        "name": "美团",
        "url": "https://rules-center.meituan.com/rules-detail/4",
    },
    "cn.soulapp.android": {
        "name": "Soul",
        "url": "https://w.soulapp.cn/app-h5/protocolPage/privacy-soul",
    },
    "com.taobao.idlefish": {
        "name": "闲鱼",
        "url": "https://market.m.taobao.com/app/idlefish-wiki-fe/idle-privacy/pages/index",
    },
    "com.lofter.android": {
        "name": "LOFTER",
        "url": "https://www.lofter.com/privacypolicy",
    },
    "com.dz.hmjc": {
        "name": "河马剧场",
        "url": "https://qugame.chuanshanjia.com/privacy?appId=hmjc",
    },
}


def extract_declared_fields(text):
    found = {}
    for field_name, keywords in KNOWN_DATA_KEYWORDS.items():
        for kw in keywords:
            if kw in text:
                idx = text.find(kw)
                start = max(0, idx - 40)
                end = min(len(text), idx + len(kw) + 60)
                ctx = text[start:end].replace("\n", " ").strip()
                found[field_name] = ctx
                break
    return found


def main():
    out_path = os.path.join(
        os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
        "output", "privacy_policy_fields.json"
    )
    existing = {}
    if os.path.exists(out_path):
        with open(out_path, "r", encoding="utf-8") as f:
            existing = json.load(f)

    results = {}
    with sync_playwright() as pw:
        browser = pw.chromium.launch(headless=True)
        context = browser.new_context(
            user_agent="Mozilla/5.0 (Linux; Android 13; Pixel 7) AppleWebKit/537.36 "
                       "(KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
            locale="zh-CN",
        )

        for pkg, info in SPA_TARGETS.items():
            name = info["name"]
            url = info["url"]
            print(f"\n{'='*60}")
            print(f"[{name}] {pkg}")
            print(f"  URL: {url}")

            try:
                page = context.new_page()
                page.goto(url, wait_until="networkidle", timeout=20000)
                page.wait_for_timeout(2000)
                html = page.content()
                page.close()

                soup = BeautifulSoup(html, "html.parser")
                for tag in soup(["script", "style", "noscript"]):
                    tag.decompose()
                text = soup.get_text(separator="\n", strip=True)

                if len(text) < 100:
                    print(f"  [SKIP] Only {len(text)} chars after render")
                    results[pkg] = {"name": name, "url": url, "error": "empty after render", "fields": {}}
                    continue

                print(f"  [OK] Rendered {len(text)} chars")
                fields = extract_declared_fields(text)
                print(f"  Declared data fields ({len(fields)}):")
                for f, ctx in sorted(fields.items()):
                    print(f"    - {f}")

                results[pkg] = {
                    "name": name,
                    "url": url,
                    "char_count": len(text),
                    "fields": fields,
                    "field_names": sorted(fields.keys()),
                    "method": "playwright",
                }

            except Exception as e:
                print(f"  [FAIL] {e}")
                results[pkg] = {"name": name, "url": url, "error": str(e)[:100], "fields": {}}

            time.sleep(0.3)

        browser.close()

    existing.update(results)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(existing, f, ensure_ascii=False, indent=2)

    print(f"\n\nMerged results saved to: {out_path}")
    print(f"\n=== SPA FETCH SUMMARY ===")
    print(f"{'App':<20s} {'Status':<8s} {'Fields':>6s}")
    print("-" * 50)
    ok = 0
    fail = 0
    for pkg, r in sorted(results.items(), key=lambda x: x[1]["name"]):
        name = r["name"]
        if "error" in r:
            print(f"{name:<20s} {'FAIL':<8s} {'--':>6s}  {r.get('error','')[:40]}")
            fail += 1
        else:
            n = len(r["fields"])
            print(f"{name:<20s} {'OK':<8s} {n:>6d}")
            ok += 1
    print(f"\nOK: {ok}, FAIL: {fail}")


if __name__ == "__main__":
    main()
