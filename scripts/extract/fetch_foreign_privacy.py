# -*- coding: utf-8 -*-
"""抓取国外应用隐私政策，解析声明的数据采集字段。

产出 output/privacy_policy_fields_foreign.json：
{ pkg: { name, url, char_count, fields, field_names, error? } }

关键词匹配逻辑与国内版 fetch_privacy_policy.py 保持一致（中英双语关键词）。
"""
import json
import os
import sys
import time
import re
from pathlib import Path

import requests
from bs4 import BeautifulSoup

ROOT = Path(__file__).resolve().parents[2]
OUT_PATH = ROOT / "output" / "privacy_policy_fields_foreign.json"

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Linux; Android 13; Pixel 7) AppleWebKit/537.36 "
                  "(KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
    "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
}

# 国外应用隐私政策 URL（从 Google Play 详情页提取，人工补充修正）
PRIVACY_URLS = {
    "air.com.sgn.cookiejam.gp": {"name": "Cookie Jam", "url": "http://jamcity.com/privacy/"},
    "coloring.color.number.happy.paint.art.drawing.puzzle": {"name": "Tap Color Pro", "url": "http://tapcolor.taplayer.net/topic/privacy"},
    "com.aim.racing": {"name": "Extreme Car Driving Simulator", "url": "https://www.axesinmotion.com/privacy"},
    "com.aniplex.fategrandorder": {"name": "Fate/GO", "url": "http://www.aniplex.co.jp/help/privacy.html"},
    "com.ansangha.drdriving": {"name": "Dr. Driving", "url": "https://www.studioupdown.com/privacy"},
    "com.apps2us.slither.slink.io": {"name": "Slink.io", "url": "http://www.cutplay.com/privacy-policy/"},
    "com.blockchainvault": {"name": "Pi", "url": "https://socialchain.app/privacy"},
    "com.bridgebase.BridgeBase": {"name": "BridgeBase", "url": "https://www.bridgebase.com/privacy"},
    "com.bumble.app": {"name": "Bumble", "url": "https://bumble.com/privacy/"},
    "com.canva.editor": {"name": "Canva", "url": "https://about.canva.com/privacy-policy/"},
    "com.colorup.game": {"name": "Color Bump 3D", "url": "https://aigames.ae/policy#privacy"},
    "com.contextlogic.wish": {"name": "Wish", "url": "https://www.wish.com/privacy_policy"},
    "com.cyworld.camera": {"name": "Cymera", "url": "https://photovideoeditors.me/cymera/privacy/"},
    "com.ea.game.simcitymobile_row": {"name": "SimCity", "url": "http://privacy.ea.com/en"},
    "com.etermax.preguntados.lite": {"name": "Trivia Crack", "url": "https://etermax.com/privacy/"},
    "com.farlightgames.pgame.gp": {"name": "Clash of Critters", "url": "https://www.farlightgames.com/privacy"},
    "com.fungames.blockcraft": {"name": "Block Craft 3D", "url": "https://wildlifestudios.com/policy-center/privacy-policy/"},
    "com.gamebasics.osm": {"name": "Online Soccer Manager", "url": "https://en.onlinesoccermanager.com/PrivacyPolicy"},
    "com.google.android.apps.youtube.kids": {"name": "YouTube Kids", "url": "https://www.google.com/intl/en/policies/privacy/"},
    "com.halfbrick.fruitninjafree": {"name": "Fruit Ninja", "url": "https://www.halfbrick.com/pp"},
    "com.jio.media.jiobeats": {"name": "JioSaavn", "url": "https://www.jiosaavn.com/corporate/privacy/"},
    "com.keplerians.icescreamtwo": {"name": "Ice Scream 2", "url": "https://keplerians.com/privacy-policy/"},
    "com.kiloo.subwaysurf": {"name": "Subway Surf", "url": "https://sybogames.com/privacy-policy/"},
    "com.lemon.lvoverseas": {"name": "CapCut", "url": "https://www.capcut.com/clause/privacy-policy"},
    "com.merge.animals": {"name": "Merge Animals", "url": "https://say.games/privacy-policy"},
    "com.microsoft.skydrive": {"name": "Microsoft OneDrive", "url": "http://go.microsoft.com/fwlink/p/?LinkId=253457"},
    "com.millecrepestudios.couplelife": {"name": "Couple Life 3D", "url": "https://millecrepestudios.com/privacy-policy"},
    "com.miniclip.plagueinc": {"name": "Plague Inc.", "url": "https://www.ndemiccreations.com/en/24-legal"},
    "com.naturalmotion.customstreetracer2": {"name": "CSR Racing 2", "url": "https://www.take2games.com/privacy"},
    "com.nautilus.RealCricket3DLite": {"name": "Real Cricket GO", "url": "https://www.nautilusmobile.com/privacy-policy"},
    "com.naver.labs.translator": {"name": "Papago", "url": "https://nid.naver.com/mobile/user/help/termAgree.nhn?m=viewTermAgree3"},
    "com.netflix.ninja": {"name": "Netflix", "url": "http://www.netflix.com/privacy"},
    "com.nianticlabs.pokemongo.ares": {"name": "Pokémon GO", "url": "https://nianticlabs.com/privacy/pokemongo/en"},
    "com.opera.mini.native.beta": {"name": "Opera Mini beta", "url": "http://www.opera.com/privacy"},
    "com.outfit7.herodash": {"name": "Talking Tom Hero Dash", "url": "https://talkingtomandfriends.com/privacy-policy-games/en"},
    "com.patreon.android": {"name": "Patreon", "url": "https://privacy.patreon.com/policies"},
    "com.plarium.raidlegends": {"name": "Raid", "url": "https://company.plarium.com/en/terms/privacy-and-cookie-policy/"},
    "com.playgendary.polyspherecoolgame": {"name": "Polysphere", "url": "https://aigames.ae/policy"},
    "com.playrix.gardenscapes": {"name": "Gardenscapes", "url": "https://www.playrix.com/privacy/index.html"},
    "com.popreach.dumbways": {"name": "Dumb Ways to Die", "url": "https://www.playsidestudios.com/privacy-policy"},
    "com.reliancegames.rschampions": {"name": "Real Steel Boxing Champions", "url": "https://www.reliancegames.com/privacy-policy/"},
    "com.roblox.client": {"name": "Roblox", "url": "https://www.roblox.com/info/privacy"},
    "com.robtopx.geometryjumplite": {"name": "Geometry Dash Lite", "url": "http://www.robtopgames.com/privacy"},
    "com.rubygames.assassin": {"name": "Hunter Assassin", "url": "https://rubygamestudio.com/privacy/"},
    "com.sankuai.sailor.afooddelivery": {"name": "Keeta", "url": "https://www.mykeeta.com/contents/zh/privacy.html"},
    "com.sgn.pandapop.gp": {"name": "Panda Pop", "url": "http://www.jamcity.com/privacy"},
    "com.skgames.trafficrider": {"name": "Traffic Rider", "url": "https://skgames.net/privacy-policy.html"},
    "com.spotify.music": {"name": "Spotify", "url": "https://www.spotify.com/legal/privacy-policy/"},
    "com.studio27.MelonPlayground": {"name": "Melon Sandbox", "url": "https://playducky.com/privacypolicy"},
    "com.talkingtomgoldrun.newtipsguidee": {"name": "Talking Tom gold run", "url": "https://talkingtomandfriends.com/privacy-policy-games/en"},
    "com.tbegames.and.top_speed_racing": {"name": "Top Speed", "url": "http://t-bull.com/privacy-policy"},
    "com.turborilla.MadSkillsMotocross2": {"name": "Mad Skills Motocross 2", "url": "https://www.turborilla.com/privacy"},
    "com.vive.riderleague": {"name": "Race.io", "url": ""},
    "com.youmusic.magictiles": {"name": "Magic Tiles 3", "url": "https://www.amanotes.com/privacy-policy"},
    "flipboard.app": {"name": "Flipboard", "url": "https://about.flipboard.com/privacy-policy/"},
    "info.flowersoft.theotown.theotown": {"name": "TheoTown", "url": "https://forum.theotown.com/theotown-privacy-policy"},
    "io.faceapp": {"name": "FaceApp", "url": "http://www.faceapp.com/privacy"},
    "jp.konami.masterduel": {"name": "Master Duel", "url": "https://legal.konami.com/games/privacy/"},
    "jp.pxv.android": {"name": "pixiv", "url": "https://policies.pixiv.net/ja/privacy_policy.html"},
    "kr.co.tf.starwars": {"name": "FANNSTAR", "url": "https://fannstar.tf.co.kr/serviceinfo/privacy"},
    "org.nanobit.hollywood": {"name": "Hollywood Story", "url": "https://www.superchargemobile.app/privacy-policy"},
}

# 与国内版一致的字段关键词（含英文，适配国外政策）
KNOWN_DATA_KEYWORDS = {
    "IMEI": ["IMEI", "imei", "国际移动设备识别码"],
    "IMSI": ["IMSI", "imsi", "国际移动用户识别码"],
    "Android ID": ["Android ID", "AndroidID", "android_id", "安卓ID"],
    "OAID": ["OAID", "oaid", "匿名设备标识"],
    "MAC 地址": ["MAC地址", "MAC 地址", "mac address", "WLAN地址", "网卡地址"],
    "GPS 经纬度": ["GPS", "gps", "经纬度", "geolocation", "location data", "地理位置"],
    "IP 地址": ["IP地址", "IP 地址", "ip address", "网络地址"],
    "SSID / BSSID": ["SSID", "BSSID", "WiFi名称", "WiFi信息", "WLAN", "wireless network"],
    "SIM 卡信息": ["SIM", "sim card", "SIM卡", "运营商", "phone number", "手机号码"],
    "设备型号": ["设备型号", "手机型号", "device model", "device type", "硬件信息"],
    "操作系统版本": ["操作系统", "system version", "OS version", "系统版本"],
    "应用列表": ["应用列表", "安装列表", "已安装应用", "installed apps", "app list"],
    "通讯录": ["通讯录", "联系人", "contacts", "contact list"],
    "相册 / 存储": ["相册", "存储", "照片", "photos", "media", "storage", "文件"],
    "剪贴板": ["剪贴板", "clipboard", "粘贴板"],
    "账号 Token / Session": ["token", "Token", "session", "Session", "登录凭证", "登录令牌"],
    "广告标识": ["广告标识", "广告ID", "IDFA", "GAID", "advertising ID", "ad identifier"],
    "传感器数据": ["传感器", "加速度", "陀螺仪", "sensor", "accelerometer", "gyroscope"],
    "摄像头 / 麦克风": ["摄像头", "相机", "麦克风", "录音", "camera", "microphone", "录音"],
    "Android ID等设备标识": ["设备标识", "device identifier", "device ID", "unique identifier"],
}


def fetch_text(url, timeout=15, verify=True):
    try:
        resp = requests.get(url, headers=HEADERS, timeout=timeout, verify=verify)
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
            if kw.lower() in text.lower():
                idx = text.lower().find(kw.lower())
                start = max(0, idx - 40)
                end = min(len(text), idx + len(kw) + 60)
                ctx = text[start:end].replace("\n", " ").strip()
                found[field_name] = ctx
                break
    return found


def main():
    targets = PRIVACY_URLS
    results = {}

    for pkg, info in sorted(targets.items()):
        name = info["name"]
        url = info.get("url")
        print(f"\n{'='*60}")
        print(f"[{name}] {pkg}")

        if not url:
            print("  [SKIP] 无政策 URL")
            results[pkg] = {"name": name, "url": None, "error": "无政策URL", "fields": {}}
            continue

        print(f"  URL: {url}")

        text, err = fetch_text(url)
        if err:
            # 证书类错误：降级一次不校验（国外站点证书链常不完整）
            if "certificate" in (err or "").lower() or "ssl" in (err or "").lower():
                import urllib3
                urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
                text, err2 = fetch_text(url, verify=False)
                if err2:
                    print(f"  [FAIL] {err} / {err2}")
                    results[pkg] = {"name": name, "url": url, "error": err2, "fields": {}}
                    continue
            else:
                print(f"  [FAIL] {err}")
                results[pkg] = {"name": name, "url": url, "error": err, "fields": {}}
                continue

        char_count = len(text) if text else 0
        if char_count < 100:
            print(f"  [SKIP] 仅 {char_count} 字符（SPA/空页）")
            results[pkg] = {"name": name, "url": url, "error": "SPA/empty", "fields": {}}
            continue

        print(f"  [OK] 抓取 {char_count} 字符")
        fields = extract_declared_fields(text)
        print(f"  声明字段 ({len(fields)}): {', '.join(sorted(fields.keys())) or '(无)'}")

        results[pkg] = {
            "name": name,
            "url": url,
            "char_count": char_count,
            "fields": fields,
            "field_names": sorted(fields.keys()),
        }
        time.sleep(0.5)

    OUT_PATH.write_text(json.dumps(results, ensure_ascii=False, indent=2), encoding="utf-8")

    ok = sum(1 for v in results.values() if "fields" in v and v.get("fields"))
    fetched = sum(1 for v in results.values() if "char_count" in v)
    print(f"\n{'='*60}")
    print(f"抓到政策文本: {fetched}/{len(results)}")
    print(f"提取到声明字段: {ok}/{len(results)}")
    print(f"结果保存: {OUT_PATH}")


if __name__ == "__main__":
    main()
