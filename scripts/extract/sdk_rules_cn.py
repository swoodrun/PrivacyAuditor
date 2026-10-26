# -*- coding: utf-8 -*-
"""
sdk_rules_cn.py — 全量 SDK 识别规则表（国内 + 海外）
供 APP_set_re 等 APK SDK 提取脚本复用。输出对齐 sdk_complete.csv 的 16 列。

SDK 集合 = extract_sdk_versions_jadx.py（20 中国）
          + analyze_foreign_sdks.py（17 海外）
          + sdk_complete.csv 补齐（5：快手广告联盟/快手内容联盟/vivo广告联盟/穿山甲GroMore/小米广告）
共 42 种。

规则字段：
  name         SDK 名称（与 sdk_complete.csv 的 SDK名称 列一致）
  vendor       SDK 厂商
  packages     源码包目录（jadx sources 下的路径，/ 分隔）
  manifest_keys AndroidManifest.xml meta-data 版本键（可选）
  version_patterns 源码中的版本常量正则（可选）
  buildconfig   是否搜 BuildConfig.VERSION_NAME
  permissions   该 SDK 关联的敏感权限中文标签（用于无 manifest 时的兜底；有 manifest 用实际权限）
"""

# ── Android 敏感权限 → 中文标签 映射（对齐 sdk_complete.csv 权限词元）──
PERMISSION_MAP = {
    # 存储
    "android.permission.READ_EXTERNAL_STORAGE": "存储读取",
    "android.permission.WRITE_EXTERNAL_STORAGE": "存储写入",
    "android.permission.READ_MEDIA_IMAGES": "存储读取",
    "android.permission.READ_MEDIA_VIDEO": "存储读取",
    "android.permission.READ_MEDIA_AUDIO": "存储读取",
    "android.permission.MANAGE_EXTERNAL_STORAGE": "存储读写",
    "android.permission.ACCESS_MEDIA_LOCATION": "存储读取",
    # 设备标识
    "android.permission.READ_PHONE_STATE": "设备标识(IMEI等)",
    "android.permission.READ_PHONE_NUMBERS": "设备标识(IMEI等)",
    "android.permission.GET_ACCOUNTS": "通讯录",
    "android.permission.READ_PRIVILEGED_PHONE_STATE": "设备标识(IMEI等)",
    # 相机 / 麦克风
    "android.permission.CAMERA": "相机",
    "android.permission.RECORD_AUDIO": "麦克风",
    # 位置
    "android.permission.ACCESS_FINE_LOCATION": "精确位置",
    "android.permission.ACCESS_COARSE_LOCATION": "粗略位置",
    "android.permission.ACCESS_BACKGROUND_LOCATION": "后台位置",
    # 通讯录
    "android.permission.READ_CONTACTS": "通讯录",
    "android.permission.WRITE_CONTACTS": "通讯录",
    # 短信 / 通话
    "android.permission.READ_SMS": "短信",
    "android.permission.RECEIVE_SMS": "短信",
    "android.permission.SEND_SMS": "短信",
    "android.permission.READ_CALL_LOG": "通话记录",
    "android.permission.READ_PHONE_STATE": "设备标识(IMEI等)",
    # 应用列表 / 使用统计
    "android.permission.PACKAGE_USAGE_STATS": "应用使用统计",
    "android.permission.QUERY_ALL_PACKAGES": "应用列表",
    # 网络状态
    "android.permission.ACCESS_NETWORK_STATE": "网络状态",
    "android.permission.ACCESS_WIFI_STATE": "WiFi信息",
    "android.permission.CHANGE_WIFI_STATE": "WiFi信息",
    "android.permission.INTERNET": "网络状态",
}

# 需要从 manifest 提取的权限（映射不到中文则按此分组）
PERMISSION_FALLBACK = "其他敏感权限"


def map_manifest_permissions(permissions):
    """把 aapt dump permissions 的权限列表映射为中文标签集合（去重、保序）"""
    labels = []
    seen = set()
    for p in permissions:
        label = PERMISSION_MAP.get(p)
        if not label:
            continue
        if label in seen:
            continue
        seen.add(label)
        labels.append(label)
    return labels


# ── 全量 SDK 规则表 ─────────────────────────────────
SDK_RULES = [
    # ── 支付 / 认证 ──
    {"name": "支付宝 SDK", "vendor": "蚂蚁集团",
     "packages": ["com/alipay/sdk", "com/alipay/mobile"],
     "manifest_keys": ["com.alipay.sdk.version"],
     "version_patterns": [r'VERSION(?:_NAME)?\s*=\s*"([^"]+)"', r'SDK_VERSION\s*=\s*"([^"]+)"'],
     "buildconfig": True, "permissions": ["网络状态"]},
    {"name": "中国移动一键登录", "vendor": "中国移动",
     "packages": ["com/cmic/sso", "com/mobile/auth"],
     "manifest_keys": [],
     "version_patterns": [r'VERSION\s*=\s*"([^"]+)"', r'SDK_VERSION\s*=\s*"([^"]+)"'],
     "buildconfig": True, "permissions": ["网络状态"]},
    {"name": "中国联通一键登录", "vendor": "中国联通",
     "packages": ["com/unicom/online"],
     "manifest_keys": [],
     "version_patterns": [r'VERSION\s*=\s*"([^"]+)"'],
     "buildconfig": True, "permissions": ["网络状态"]},
    {"name": "微信 Open SDK", "vendor": "腾讯",
     "packages": ["com/tencent/mm/opensdk"],
     "manifest_keys": [],
     "version_patterns": [r'VERSION\s*=\s*"([^"]+)"', r'SDK_VERSION\s*=\s*"([^"]+)"'],
     "buildconfig": True, "permissions": ["网络状态"]},

    # ── 推送 ──
    {"name": "极光推送 JPush", "vendor": "极光",
     "packages": ["cn/jpush/android", "cn/jiguang"],
     "manifest_keys": ["JPUSH_VERSION", "cn.jpush.android.VERSION"],
     "version_patterns": [r'VERSION\s*=\s*"(\d+\.\d+[\.\d]*[^"]*)"', r'SDK_VERSION\s*=\s*"([^"]+)"'],
     "buildconfig": True, "permissions": ["网络状态"]},
    {"name": "个推推送 SDK", "vendor": "个推",
     "packages": ["com/igexin", "com/getui"],
     "manifest_keys": [],
     "version_patterns": [r'VERSION\s*=\s*"([^"]+)"', r'SDK_VERSION\s*=\s*"([^"]+)"', r'PUSH_VERSION\s*=\s*"([^"]+)"'],
     "buildconfig": True, "permissions": ["网络状态"]},
    {"name": "小米 Push", "vendor": "小米",
     "packages": ["com/xiaomi/mipush", "com/xiaomi/push"],
     "manifest_keys": ["com.xiaomi.push.sdk.version"],
     "version_patterns": [r'VERSION\s*=\s*"([^"]+)"', r'SDK_VERSION\s*=\s*"([^"]+)"'],
     "buildconfig": True, "permissions": ["网络状态"]},
    {"name": "OPPO Push SDK", "vendor": "OPPO",
     "packages": ["com/heytap/msp/push"],
     "manifest_keys": ["com.heytap.msp.push.version"],
     "version_patterns": [r'VERSION\s*=\s*"([^"]+)"', r'SDK_VERSION\s*=\s*"([^"]+)"'],
     "buildconfig": True, "permissions": ["网络状态"]},
    {"name": "vivo Push SDK", "vendor": "vivo",
     "packages": ["com/vivo/push"],
     "manifest_keys": ["com.vivo.push.sdk_version"],
     "version_patterns": [r'VERSION\s*=\s*"([^"]+)"', r'SDK_VERSION\s*=\s*"([^"]+)"'],
     "buildconfig": True, "permissions": ["网络状态"]},
    {"name": "Google Firebase Messaging (FCM)", "vendor": "Google",
     "packages": ["com/google/firebase/messaging", "com/google/firebase/iid"],
     "manifest_keys": [],
     "version_patterns": [r'VERSION\s*=\s*"([^"]+)"', r'SDK_VERSION\s*=\s*"([^"]+)"'],
     "buildconfig": True, "permissions": ["网络状态"],
     "services": ["com.google.firebase.messaging.FirebaseMessagingService"],
     "receivers": []},

    # ── 广告 / 变现（国内）──
    {"name": "腾讯优量汇 GDT", "vendor": "腾讯",
     "packages": ["com/qq/e/ads", "com/qq/e/comm"],
     "manifest_keys": ["com.qq.e.gdt.version"],
     "version_patterns": [r'VERSION\s*=\s*"([^"]+)"', r'SDK_VERSION\s*=\s*"([^"]+)"', r'GDT_SDK_VERSION\s*=\s*"([^"]+)"'],
     "buildconfig": True, "permissions": ["网络状态"]},
    {"name": "穿山甲 Pangolin (CSJ)", "vendor": "字节跳动",
     "packages": ["com/bytedance/sdk/openadsdk", "com/ss/android/downloadlib", "com/bytedance/pangle", "com/bykv/vk"],
     "manifest_keys": ["com.bytedance.pangle.version"],
     "version_patterns": [r'VERSION\s*=\s*"([^"]+)"', r'SDK_VERSION\s*=\s*"([^"]+)"', r'PANGLE_SDK_VER\s*=\s*"([^"]+)"'],
     "buildconfig": True, "permissions": ["网络状态"]},
    {"name": "穿山甲 GroMore 聚合", "vendor": "字节跳动",
     "packages": ["com/bytedance/msdk/adapter", "com/bytedance/msdk/api"],
     "manifest_keys": [],
     "version_patterns": [r'VERSION\s*=\s*"([^"]+)"', r'SDK_VERSION\s*=\s*"([^"]+)"'],
     "buildconfig": True, "permissions": ["网络状态"]},
    {"name": "百度 MobAds (百青藤)", "vendor": "百度",
     "packages": ["com/baidu/mobads"],
     "manifest_keys": ["com.baidu.mobads.version"],
     "version_patterns": [r'VERSION\s*=\s*"([^"]+)"', r'SDK_VERSION\s*=\s*"([^"]+)"'],
     "buildconfig": True, "permissions": ["网络状态"]},
    {"name": "华为 HMS Ads", "vendor": "华为",
     "packages": ["com/huawei/hms/ads", "com/huawei/openalliance/ad"],
     "manifest_keys": ["com.huawei.hms.client.service.name:ads-lite", "com.huawei.hms.version", "com.huawei.hms.client.version"],
     "version_patterns": [r'VERSION\s*=\s*"([^"]+)"', r'SDK_VERSION\s*=\s*"([^"]+)"', r'HMS_VERSION\s*=\s*"([^"]+)"'],
     "buildconfig": True, "permissions": ["网络状态"]},
    {"name": "荣耀广告 SDK", "vendor": "荣耀",
     "packages": ["com/hihonor/ads"],
     "manifest_keys": ["com.hihonor.ads.sdk.version"],
     "version_patterns": [r'VERSION\s*=\s*"([^"]+)"'],
     "buildconfig": True, "permissions": ["网络状态"]},
    {"name": "OPPO 广告联盟", "vendor": "OPPO",
     "packages": ["com/heytap/openid"],
     "manifest_keys": [],
     "version_patterns": [r'VERSION\s*=\s*"([^"]+)"', r'SDK_VERSION\s*=\s*"([^"]+)"'],
     "buildconfig": True, "permissions": ["网络状态"]},
    {"name": "vivo 广告联盟", "vendor": "vivo",
     "packages": ["com/vivo/mobilead"],
     "manifest_keys": [],
     "version_patterns": [r'VERSION\s*=\s*"([^"]+)"', r'SDK_VERSION\s*=\s*"([^"]+)"'],
     "buildconfig": True, "permissions": ["网络状态"]},
    {"name": "小米广告 SDK", "vendor": "小米",
     "packages": ["com/miui/zeus"],
     "manifest_keys": [],
     "version_patterns": [r'VERSION\s*=\s*"([^"]+)"', r'SDK_VERSION\s*=\s*"([^"]+)"'],
     "buildconfig": True, "permissions": ["网络状态"]},
    {"name": "快手广告联盟", "vendor": "快手",
     "packages": ["com/kwad/sdk"],
     "manifest_keys": [],
     "version_patterns": [r'VERSION\s*=\s*"([^"]+)"', r'SDK_VERSION\s*=\s*"([^"]+)"', r'SDK_VER\s*=\s*"([^"]+)"'],
     "buildconfig": True, "permissions": ["网络状态"]},
    {"name": "快手内容联盟 SDK", "vendor": "快手",
     "packages": ["com/kwad/components"],
     "manifest_keys": [],
     "version_patterns": [r'VERSION\s*=\s*"([^"]+)"', r'SDK_VERSION\s*=\s*"([^"]+)"'],
     "buildconfig": True, "permissions": ["网络状态"]},

    # ── 广告 / 变现（海外）──
    {"name": "Google AdMob", "vendor": "Google",
     "packages": ["com/google/android/gms/ads", "com/google/ads"],
     "manifest_keys": [],
     "version_patterns": [r'VERSION\s*=\s*"([^"]+)"', r'SDK_VERSION\s*=\s*"([^"]+)"'],
     "buildconfig": True, "permissions": ["网络状态"]},
    {"name": "Facebook Audience Network", "vendor": "Meta",
     "packages": ["com/facebook/ads"],
     "manifest_keys": [],
     "version_patterns": [r'VERSION\s*=\s*"([^"]+)"', r'SDK_VERSION\s*=\s*"([^"]+)"'],
     "buildconfig": True, "permissions": ["网络状态"]},
    {"name": "Unity Ads", "vendor": "Unity Technologies",
     "packages": ["com/unity3d/ads", "com/unity3d/services"],
     "manifest_keys": [],
     "version_patterns": [r'VERSION\s*=\s*"([^"]+)"', r'SDK_VERSION\s*=\s*"([^"]+)"'],
     "buildconfig": True, "permissions": ["网络状态"]},
    {"name": "IronSource (Unity LevelPlay)", "vendor": "Unity / IronSource",
     "packages": ["com/ironsource", "com/unity3d/mediation"],
     "manifest_keys": [],
     "version_patterns": [r'VERSION\s*=\s*"([^"]+)"', r'SDK_VERSION\s*=\s*"([^"]+)"'],
     "buildconfig": True, "permissions": ["网络状态"]},
    {"name": "AppLovin MAX", "vendor": "AppLovin",
     "packages": ["com/applovin"],
     "manifest_keys": [],
     "version_patterns": [r'VERSION\s*=\s*"([^"]+)"', r'SDK_VERSION\s*=\s*"([^"]+)"'],
     "buildconfig": True, "permissions": ["网络状态"]},
    {"name": "AdColony", "vendor": "AdColony",
     "packages": ["com/jirbo/adcolony", "com/adcolony"],
     "manifest_keys": [],
     "version_patterns": [r'VERSION\s*=\s*"([^"]+)"', r'SDK_VERSION\s*=\s*"([^"]+)"'],
     "buildconfig": True, "permissions": ["网络状态"]},
    {"name": "Vungle 广告", "vendor": "Vungle",
     "packages": ["com/vungle"],
     "manifest_keys": [],
     "version_patterns": [r'VERSION\s*=\s*"([^"]+)"', r'SDK_VERSION\s*=\s*"([^"]+)"'],
     "buildconfig": True, "permissions": ["网络状态"]},
    {"name": "Tapjoy", "vendor": "Tapjoy",
     "packages": ["com/tapjoy"],
     "manifest_keys": [],
     "version_patterns": [r'VERSION\s*=\s*"([^"]+)"', r'SDK_VERSION\s*=\s*"([^"]+)"'],
     "buildconfig": True, "permissions": ["网络状态"]},
    {"name": "InMobi 广告", "vendor": "InMobi",
     "packages": ["com/inmobi"],
     "manifest_keys": [],
     "version_patterns": [r'VERSION\s*=\s*"([^"]+)"', r'SDK_VERSION\s*=\s*"([^"]+)"'],
     "buildconfig": True, "permissions": ["网络状态"]},
    {"name": "Mintegral 广告", "vendor": "Mintegral",
     "packages": ["com/mbridge"],
     "manifest_keys": [],
     "version_patterns": [r'VERSION\s*=\s*"([^"]+)"', r'SDK_VERSION\s*=\s*"([^"]+)"'],
     "buildconfig": True, "permissions": ["网络状态"]},
    {"name": "Mobvista / Mintegral", "vendor": "汇量科技",
     "packages": ["com/mobvista", "com/mintegral"],
     "manifest_keys": [],
     "version_patterns": [r'VERSION\s*=\s*"([^"]+)"', r'SDK_VERSION\s*=\s*"([^"]+)"'],
     "buildconfig": True, "permissions": ["网络状态"]},

    # ── 归因 / 数据分析 ──
    {"name": "AppsFlyer / OneLink 归因", "vendor": "AppsFlyer",
     "packages": ["com/appsflyer"],
     "manifest_keys": [],
     "version_patterns": [r'VERSION\s*=\s*"([^"]+)"', r'SDK_VERSION\s*=\s*"([^"]+)"'],
     "buildconfig": True, "permissions": ["网络状态"]},
    {"name": "Adjust 归因", "vendor": "Adjust",
     "packages": ["com/adjust/sdk", "com/adjust"],
     "manifest_keys": [],
     "version_patterns": [r'VERSION\s*=\s*"([^"]+)"', r'SDK_VERSION\s*=\s*"([^"]+)"'],
     "buildconfig": True, "permissions": ["网络状态"]},
    {"name": "Firebase Analytics", "vendor": "Google",
     "packages": ["com/google/firebase/analytics"],
     "manifest_keys": [],
     "version_patterns": [r'VERSION\s*=\s*"([^"]+)"', r'SDK_VERSION\s*=\s*"([^"]+)"'],
     "buildconfig": True, "permissions": ["网络状态"]},
    {"name": "TalkingData 数据分析", "vendor": "TalkingData",
     "packages": ["com/tendcloud/tenddata", "com/talkingdata"],
     "manifest_keys": [],
     "version_patterns": [r'VERSION\s*=\s*"([^"]+)"', r'SDK_VERSION\s*=\s*"([^"]+)"'],
     "buildconfig": True, "permissions": ["网络状态"]},
    {"name": "神策数据 Sensors Analytics", "vendor": "神策",
     "packages": ["com/sensorsdata", "cn/sensorsdata"],
     "manifest_keys": [],
     "version_patterns": [r'VERSION\s*=\s*"([^"]+)"', r'SDK_VERSION\s*=\s*"([^"]+)"'],
     "buildconfig": True, "permissions": ["网络状态"]},
    {"name": "友盟+ Umeng", "vendor": "阿里 / 友盟",
     "packages": ["com/umeng/analytics", "com/umeng/commonsdk", "com/umeng/message", "com/uc/crashsdk", "com/efs"],
     "manifest_keys": [],
     "version_patterns": [r'VERSION\s*=\s*"([^"]+)"', r'SDK_VERSION\s*=\s*"([^"]+)"', r'UMENG_SDK_VER\s*=\s*"([^"]+)"'],
     "buildconfig": True, "permissions": ["网络状态"]},

    # ── 性能 / 监控 ──
    {"name": "腾讯 Bugly 崩溃监控", "vendor": "腾讯",
     "packages": ["com/tencent/bugly"],
     "manifest_keys": [],
     "version_patterns": [r'VERSION\s*=\s*"([^"]+)"', r'SDK_VERSION\s*=\s*"([^"]+)"'],
     "buildconfig": True, "permissions": ["网络状态"]},
    {"name": "字节 APMPlus 性能监控", "vendor": "字节跳动 / 火山引擎",
     "packages": ["com/bytedance/apm", "com/bytedance/applog"],
     "manifest_keys": [],
     "version_patterns": [r'VERSION\s*=\s*"([^"]+)"'],
     "buildconfig": True, "permissions": ["网络状态"]},
    {"name": "字节 RangersAppLog (火山引擎增长分析)", "vendor": "字节跳动 / 火山引擎",
     "packages": ["com/bytedance/applog"],
     "manifest_keys": [],
     "version_patterns": [r'VERSION\s*=\s*"([^"]+)"', r'SDK_VERSION\s*=\s*"([^"]+)"'],
     "buildconfig": True, "permissions": ["网络状态"]},
    {"name": "阿里 EMAS / 高可用 SDK", "vendor": "阿里巴巴",
     "packages": ["com/alibaba/sdk/android/emas", "com/alibaba/ha", "com/alibaba/sdk/android"],
     "manifest_keys": ["com.alibaba.emas.version"],
     "version_patterns": [r'VERSION\s*=\s*"([^"]+)"'],
     "buildconfig": True, "permissions": ["网络状态"]},

    # ── 工具 / 存储 ──
    {"name": "七牛云 SDK", "vendor": "七牛",
     "packages": ["com/qiniu"],
     "manifest_keys": [],
     "version_patterns": [r'VERSION\s*=\s*"([^"]+)"', r'SDK_VERSION\s*=\s*"([^"]+)"'],
     "buildconfig": True, "permissions": ["存储读取", "存储写入"]},
]


# SDK 名称 → 规则（供查找）
SDK_RULES_BY_NAME = {r["name"]: r for r in SDK_RULES}
