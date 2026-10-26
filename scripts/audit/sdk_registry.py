"""
sdk_registry.py — 已知 SDK 域名与端点分类注册表
基于团队采集的 API 常量整理，并结合 sdk_summary.csv 静态扫描结果同步更新。

覆盖 SDK（共 56 个）：
  国内：支付宝 / 百度MobAds / 穿山甲Pangolin / Pangle Global / 字节RangersAppLog / 字节APMPlus
       爱奇艺 / 腾讯优量汇GDT / 微信Open SDK / 腾讯Bugly
       友盟+ / 小米 / 中国移动 / 中国联通 / id6 / 阿里EMAS
       OPPO广告联盟+Push / vivo Push / 荣耀广告 / 华为HMS Ads
       极光JPush / 个推Getui
  海外：AdMob / Firebase（Analytics/FCM/Crashlytics）/ Facebook Audience Network
       Unity Ads / AppLovin MAX / IronSource / Vungle / InMobi / Mintegral / AdColony / Tapjoy
       Chartboost / BidMachine / MoPub / Fyber / Amazon Ads / PubNative HyBid / Bigo Ads
       Yandex / myTarget / Ogury / Maio / HyprMX / Smaato / MobileFuse / PubMatic
       IAB OM SDK / Prebid
  归因：AppsFlyer / Adjust / Singular

用途：
  1. 判断某条请求属于哪个 SDK
  2. 判断端点类型（telemetry/ad_api/cdn/service）
  3. 为 privacy_auditor.py 提供归属信息，辅助风险判定

无 mitmproxy 依赖，纯 Python 标准库，可独立使用。
"""

import re
from dataclasses import dataclass, field
from typing import Optional



#  端点类型定义

EP_TELEMETRY = "telemetry"   # 日志/埋点/崩溃/监控上报 — 数据泄漏的高风险目标
EP_AD_API    = "ad_api"      # 广告请求/竞价/渲染 API — 中等风险
EP_CDN       = "cdn"         # 静态资源/素材分发 — 低风险，可静默忽略
EP_SERVICE   = "service"     # 业务 API（如支付）— 正常业务
EP_UNKNOWN   = "unknown"     # 未分类


#  SDK 定义

@dataclass
class SDKDef:
    key: str # 短标识
    label: str  # 中文标签
    vendor: str # 厂商
    host_suffixes: list = field(default_factory=list) # 以此结尾的 host
    host_regexes: list = field(default_factory=list) # 正则匹配
    telemetry_path_keywords: list = field(default_factory=list)  # 路径中含此关键字 => telemetry
    ad_api_path_keywords: list = field(default_factory=list) # 路径中含此关键字 => ad_api
    cdn_host_keywords: list = field(default_factory=list) # host 中含此关键字 => CDN
    notes: str = "" # 备注

    _host_rx = None

    def __post_init__(self):
        if self.host_regexes:
            self._host_rx = [re.compile(r, re.IGNORECASE) for r in self.host_regexes]

    def matches(self, host: str) -> bool: # 判断归属，既能匹配根域名，也能匹配其子域名
        host_lower = host.lower()
        for suffix in self.host_suffixes:
            if host_lower == suffix or host_lower.endswith("." + suffix) or host_lower.endswith(suffix):
                return True
        if self._host_rx:
            for rx in self._host_rx:
                if rx.search(host_lower):
                    return True
        return False

    def classify(self, host: str, path: str) -> str: # 判断端点用途
        '''
        判断的分类顺序为
        CDN → telemetry → ad_api → service
        '''
        host_lower = host.lower()
        path_lower = (path or "").lower()

        # CDN 判定优先
        for kw in self.cdn_host_keywords:
            if kw.lower() in host_lower:
                return EP_CDN

        # 路径关键字匹配
        for kw in self.telemetry_path_keywords:
            if kw.lower() in path_lower:
                return EP_TELEMETRY
        for kw in self.ad_api_path_keywords:
            if kw.lower() in path_lower:
                return EP_AD_API

        return EP_SERVICE

#  采集的SDK注册表

SDK_REGISTRY: list = [

    # 支付宝（不完全是广告SDK）
    SDKDef(
        key="alipay",
        label="支付宝",
        vendor="蚂蚁集团",
        host_suffixes=[
            "alipay.com", "alipayobjects.com", "alicdn.com",
            "mcgw.alipay.com", "mclient.alipay.com", "render.alipay.com",
        ],
        ad_api_path_keywords=[],
        telemetry_path_keywords=["/rest.htm", "/gateway.do"],  # 涉及敏感字段时可疑
        notes="支付业务 API，但接口可能携带设备信息",
    ),

    # 百度 MobAds / 百青藤
    SDKDef(
        key="baidu_mobads",
        label="百度 MobAds / 百青藤",
        vendor="百度",
        host_suffixes=[
            "mobads.baidu.com", "mobads-logs.baidu.com",
            "hmma.baidu.com", "bes-mtj.baidu.com",
            "dxp.baidu.com", "aden.baidu.com",
            "cpu-openapi.baidu.com", "cpu.baidu.com",
            "wn.pos.baidu.com", "union.baidu.com",
            "browserkernel.baidu.com", "media-interact.baidu.com",
            "haokan.baidu.com", "m.baidu.com",
            "cpro.baidustatic.com",
            "mobads-pre-config.bj.bcebos.com",
            "mobads-pre-config.cdn.bcebos.com",
            "render-server.cdn.bcebos.com",
            "b.bdstatic.com", "pms-zeus-xcdn.bdstatic.com",
        ],
        telemetry_path_keywords=[
            "/dz.zb", "/brwhis.log", "/app.gif", "/auto.gif",
            "/autotracker", "/circleconfig", "/vizparser",
        ],
        ad_api_path_keywords=[
            "/cpro/ui/mads.php", "/query_ad", "/ads/preload",
            "/ads/pa/", "/b.php", "/en.php",
            "/api/v2/data/", "/api/v2/aggregation",
        ],
        cdn_host_keywords=[
            "bcebos.com", "baidustatic.com", "bdstatic.com",
        ],
    ),

    # 百度 Tools（AI 对话 + 日志）
    SDKDef(
        key="baidu_tools",
        label="百度 MobAds Tools",
        vendor="百度",
        host_suffixes=[
            "aibqt.baidu.com",
        ],
        telemetry_path_keywords=["/aigc/bot/"],
        notes="AI 对话初始化和聊天端点，对话内容敏感",
    ),

    # ── 字节 RangersAppLog（火山引擎增长分析）──
    # 注意：必须置于 pangolin 之前，否则 volces.com / snssdk.com 的通配会先命中
    SDKDef(
        key="rangers_applog",
        label="字节 RangersAppLog（火山引擎增长分析）",
        vendor="字节跳动 / 火山引擎",
        host_suffixes=[
            "applog.volces.com", "log.snssdk.com",
            "mon.snssdk.com",
        ],
        telemetry_path_keywords=[
            "/v3/app/log/", "/service/2/app_log",
            "/sdk/log",
        ],
        notes="com.bytedance.applog — 增长分析埋点，与穿山甲共享部分域名",
    ),

    # ── 穿山甲 / Pangolin / GroMore（字节跳动）──
    SDKDef(
        key="pangolin",
        label="穿山甲 Pangolin",
        vendor="字节跳动",
        host_suffixes=[
            "pangolin-sdk-toutiao.com",
            "pangolin-sdk-toutiao-b.com",
            "pangolin-sdk-toutiao1.com",
            "gromore.pangolin-sdk-toutiao.com",
            "pangle.cn",
            # 日志域
            "snssdk.com", "ctobsnssdk.com",
            "zijieapi.com", "volces.com",
            "bytesfield.com", "bytesfield-b.com",
            # CDN/静态域
            "pglstatp-toutiao.com", "bytesmanager.com",
            "pstatp.com",
            # 集团域
            "bytedance.com", "bytedance.net", "toutiao.com",
            "oceanengine.com", "apps.oceanengine.com",
        ],
        telemetry_path_keywords=[
            "/service/2/app_log",
            "/service/2/device_register",
            "/service/2/log_settings",
            "/service/2/abtest_config",
            "/service/2/device_sdk",
            "/apm/collect", "/monitor/collect",
            "/api/ad/union/sdk/stats",
            "/api/ad/union/sdk/upload/app_info",
            "/inspect/aegis", "/scc_sdk/",
        ],
        ad_api_path_keywords=[
            "/api/ad/union/sdk/get_ads",
            "/api/ad/union/sdk/apply_coupon",
            "/api/ad/union/sdk/settings",
            "/api/ad/union/mediation",
            "/api/ad/union/server_bidding",
            "/customer/api/app/",
        ],
        cdn_host_keywords=[
            "pglstatp-toutiao.com", "bytetos.com",
            "pstatp.com", "bytesmanager.com",
            "cdn-tos", "sf1-", "sf3-", "sf6-",
        ],
    ),

    # 中国移动、联通、电信运营商一键登录
    SDKDef(
        key="cmpassport",
        label="中国移动一键登录",
        vendor="中国移动",
        host_suffixes=["cmpassport.com", "msg.cmpassport.com"],
        telemetry_path_keywords=["/h5/getmobile"],
        notes="会上报本机号码",
    ),
    SDKDef(
        key="unicom_login",
        label="中国联通一键登录",
        vendor="中国联通",
        host_suffixes=["10010.com", "nisportal.10010.com"],
        notes="会上报本机号码",
    ),
    SDKDef(
        key="id6",
        label="id6 设备标识",
        vendor="第三方",
        host_suffixes=["id6.me"],
        telemetry_path_keywords=["/gw/preuniq", "/preuniq.do"],
        notes="设备唯一标识服务",
    ),

    # 爱奇艺广告
    SDKDef(
        key="iqiyi",
        label="爱奇艺广告",
        vendor="爱奇艺",
        host_suffixes=[
            "iqiyi.com", "iqiyipic.com",
            "cupid.iqiyi.com", "msga.cupid.iqiyi.com",
            "t7z.cupid.iqiyi.com", "api-feedback.iqiyi.com",
            "bidinfo-ssp.iqiyi.com", "resource.cupid.iqiyi.com",
        ],
        telemetry_path_keywords=[
            "/mcp2.gif", "/scp2.gif",
            "/track2", "/dsp_track3", "/etx",
        ],
        ad_api_path_keywords=["/mixer", "/anti", "/feedbacks"],
        cdn_host_keywords=["iqiyipic.com", "static-s.iqiyi.com"],
    ),

    # 腾讯优量汇 GDT
    SDKDef(
        key="gdt",
        label="腾讯优量汇 GDT",
        vendor="腾讯",
        host_suffixes=[
            "gdt.qq.com", "e.qq.com", "eff.qq.com",
            "sdk.e.qq.com", "union.eff.qq.com",
            "mi.gdt.qq.com", "win.gdt.qq.com",
            "gdtimg.com", "ugdtimg.com",
            "qzs.gdtimg.com", "pgdt.ugdtimg.com",
        ],
        telemetry_path_keywords=[
            "/open/v1.1/ad/report",
            "/v2/query/gdtmview",
        ],
        ad_api_path_keywords=[
            "/open/v1.1/ad/add",
            "/mediation",
            "/view",
        ],
        cdn_host_keywords=["gdtimg.com", "ugdtimg.com"],
    ),

    # 友盟+（全域几乎都是埋点上报）
    SDKDef(
        key="umeng",
        label="友盟+ Umeng",
        vendor="阿里 / 友盟",
        host_suffixes=[
            "umeng.com", "umengcloud.com",
            "ulogs.umeng.com", "alogsus.umeng.com",
            "cnlogs.umeng.com", "pslog.umeng.com",
            "aspect-upush.umeng.com", "preulogs.umeng.com",
            "ucc.umeng.com", "resolve.umeng.com",
            "ulogs.umengcloud.com",
        ],
        telemetry_path_keywords=[
            # 友盟所有域名基本都用于埋点/推送，路径匹配作为二级判据
            "/common_inout_logs", "/ext_event",
            "/push_cloud_activation",
            "/occa/v1/event/report",
            "/v2/inn/fetch", "/resolve",
        ],
        notes="友盟几乎所有端点都涉及数据采集，默认归为 telemetry",
    ),

    # 小米 SDK
    SDKDef(
        key="xiaomi",
        label="小米 / 米游戏 SDK",
        vendor="小米",
        host_suffixes=[
            "xiaomi.com", "mi.com",
            "account.xiaomi.com",
            "micro.game.xiaomi.com",
            "migc.activity.g.mi.com",
            "support.kefu.mi.com",
            # 测试环境（不应出现在生产流量中，出现即异常）
            "g.mi.srv", "kscn",
        ],
        telemetry_path_keywords=[
            "/reportmonitordata",
            "/gamesdk/notice/crash",
        ],
        ad_api_path_keywords=["/gamevip", "/rn/verify"],
        notes="migame-manager-staging / kscn 等为内网测试域，若出现须关注",
    ),

    # 字节 ApplogPlus / APM（独立域，也属字节）
    SDKDef(
        key="apmplus",
        label="字节 APMPlus 性能监控",
        vendor="字节跳动 / 火山引擎",
        host_suffixes=["apmplus.volces.com"],
        telemetry_path_keywords=[
            "/apm/collect", "/monitor/collect",
        ],
        notes="APM 崩溃/性能/会话上报 (com.bytedance.apm, com.bytedance.applog)",
    ),

    # OPPO 广告联盟 + Push SDK (heytap)
    SDKDef(
        key="oppo",
        label="OPPO 广告联盟 / Push SDK",
        vendor="OPPO",
        host_suffixes=[
            "oi.heytap.com", "openapi.heytap.com",
            "push.heytap.com", "adid.heytap.com",
            "heytap.com",
        ],
        telemetry_path_keywords=[
            "/push/device/register", "/push/ack",
            "/sdk/feedback", "/openid/verify",
        ],
        ad_api_path_keywords=["/ad/request", "/ad/bid"],
        notes="com.heytap.openid (广告联盟) + com.heytap.msp.push (Push SDK)",
    ),

    # vivo Push SDK
    SDKDef(
        key="vivo_push",
        label="vivo Push SDK",
        vendor="vivo",
        host_suffixes=[
            "vpush.vivo.com.cn", "api-push.vivo.com.cn",
            "push.vivo.com.cn",
        ],
        telemetry_path_keywords=[
            "/push/device/register", "/push/message/ack",
            "/stat/report",
        ],
        notes="com.vivo.push — 设备注册即上报 Android ID / 品牌信息",
    ),

    # 微信 Open SDK
    SDKDef(
        key="wechat",
        label="微信 Open SDK",
        vendor="腾讯",
        host_suffixes=[
            "open.weixin.qq.com", "api.weixin.qq.com",
            "wx.tenpay.com", "mp.weixin.qq.com",
        ],
        telemetry_path_keywords=["/sns/userinfo", "/sns/oauth2/userinfo"],
        ad_api_path_keywords=[],
        notes="com.tencent.mm.opensdk — OAuth / 支付，/sns/userinfo 含真实姓名等",
    ),

    # 荣耀广告 SDK
    SDKDef(
        key="honor",
        label="荣耀广告 SDK",
        vendor="荣耀",
        host_suffixes=[
            "ads.hihonor.com", "ad.hihonor.com",
            "push.hihonor.com", "hihonor.com",
        ],
        telemetry_path_keywords=["/adsdk/stat", "/adsdk/report", "/push/device"],
        ad_api_path_keywords=["/ad/request", "/ad/bid"],
        notes="com.hihonor.ads — 置信度多为 medium，广告竞价 + 设备指纹上报",
    ),

    # 华为 HMS Ads
    SDKDef(
        key="huawei_hms",
        label="华为 HMS Ads",
        vendor="华为",
        host_suffixes=[
            "adsjsdk.cloud.huawei.com", "rtcm-drru.cloud.huawei.com",
            "ncs.cloud.huawei.com", "aaid.cloud.huawei.com",
            "hwpush.cloud.huawei.com",
        ],
        telemetry_path_keywords=["/adsdk/stat", "/adsdk/report", "/device/register"],
        ad_api_path_keywords=["/adsdk/ads", "/adsdk/bid"],
        cdn_host_keywords=["res.cloud.huawei.com"],
        notes="com.huawei.hms.ads — AAID 匿名标识符上报，注意 aaid.cloud.huawei.com",
    ),

    # 极光推送 JPush
    SDKDef(
        key="jpush",
        label="极光推送 JPush",
        vendor="极光",
        host_suffixes=[
            "device.jpush.cn", "api.jpush.cn",
            "report.jpush.cn", "jpush.io",
            "jpush.cn", "jiguang.cn",
        ],
        telemetry_path_keywords=[
            "/devices", "/device/register",
            "/push/stat", "/report",
        ],
        notes="cn.jpush.android / cn.jiguang — 设备注册含 IMEI/Android ID",
    ),

    # 个推推送 SDK
    SDKDef(
        key="getui",
        label="个推推送 SDK",
        vendor="个推",
        host_suffixes=[
            "sdk.open.phone.igexin.com", "sdk.open.igexin.com",
            "push.getui.com", "gepush.com",
            "igexin.com", "getui.com",
        ],
        telemetry_path_keywords=[
            "/device/register", "/sdk/register",
            "/push/stat",
        ],
        notes="com.igexin / com.getui — 注册接口上报设备唯一标识",
    ),

    # Google AdMob
    SDKDef(
        key="admob",
        label="Google AdMob",
        vendor="Google",
        host_suffixes=[
            "googleads.g.doubleclick.net", "pagead2.googlesyndication.com",
            "mobileads.google.com", "pubads.g.doubleclick.net",
            "adservice.google.com",
        ],
        telemetry_path_keywords=[
            "/pagead/viewthroughconversion", "/admob/report",
        ],
        ad_api_path_keywords=["/pagead/ads", "/ad/api"],
        cdn_host_keywords=["tpc.googlesyndication.com"],
        notes="com.google.android.gms.ads — 境外广告 SDK，注意设备 ID 出境",
    ),

    # 阿里 EMAS / 高可用 SDK
    SDKDef(
        key="ali_emas",
        label="阿里 EMAS / 高可用 SDK",
        vendor="阿里巴巴",
        host_suffixes=[
            "ha.alibaba.com", "log.alibaba.com",
            "emas.aliyuncs.com", "aliapp.com",
            "logservice.aliyuncs.com",
        ],
        telemetry_path_keywords=[
            "/ha/crash", "/ha/log", "/log/upload",
            "/emas/crash",
        ],
        notes="com.alibaba.ha / com.alibaba.sdk.android — 崩溃 + 性能监控上报",
    ),

    # Facebook Audience Network（Meta）
    SDKDef(
        key="facebook_ads",
        label="Facebook Audience Network",
        vendor="Meta",
        host_suffixes=[
            "graph.facebook.com", "graph-video.facebook.com",
            "b-graph.facebook.com", "www.facebook.com",
            "facebook.com", "fbcdn.net",
        ],
        telemetry_path_keywords=["/act_", "/app_events", "/activities"],
        ad_api_path_keywords=["/ads", "/audience_network"],
        cdn_host_keywords=["fbcdn.net"],
        notes="com.facebook.ads — 境外广告 + 事件回传，注意设备 ID 出境",
    ),

    # Unity Ads
    SDKDef(
        key="unity_ads",
        label="Unity Ads",
        vendor="Unity Technologies",
        host_suffixes=[
            "unityads.unity3d.com", "config.unityads.unity3d.com",
            "unity3d.com", "adsunity.com",
        ],
        telemetry_path_keywords=["/v4/events", "/ads/install", "/config"],
        ad_api_path_keywords=["/ads/load", "/ads/placement", "/ads/init"],
        notes="com.unity3d.ads / com.unity3d.services — 游戏广告 SDK",
    ),

    # AppLovin MAX
    SDKDef(
        key="applovin",
        label="AppLovin MAX",
        vendor="AppLovin",
        host_suffixes=[
            "applovin.com", "ms.applovin.com",
            "applovin.com.s3.amazonaws.com", "applovin.ws",
        ],
        telemetry_path_keywords=["/report", "/events", "/analytics"],
        ad_api_path_keywords=["/ad/request", "/ads", "/bid"],
        notes="com.applovin — 广告聚合 + 归因",
    ),

    # ── IronSource (Unity LevelPlay) ──
    SDKDef(
        key="ironsource",
        label="IronSource (Unity LevelPlay)",
        vendor="Unity / IronSource",
        host_suffixes=[
            "ironsrc.com", "init.supersonicads.com",
            "supersonicads.com", "ironsource.com",
        ],
        telemetry_path_keywords=["/events", "/report", "/impressions"],
        ad_api_path_keywords=["/ad/request", "/ads", "/bid"],
        notes="com.ironsource — 广告聚合 + 变现",
    ),

    # ── Vungle ──
    SDKDef(
        key="vungle",
        label="Vungle 广告",
        vendor="Vungle",
        host_suffixes=[
            "vungle.com", "capi.vungle.com",
            "cdn.vungle.com",
        ],
        telemetry_path_keywords=["/report", "/events", "/ping"],
        ad_api_path_keywords=["/ad/request", "/ads", "/bid"],
        cdn_host_keywords=["cdn.vungle.com"],
        notes="com.vungle — 视频广告 SDK",
    ),

    # ── InMobi ──
    SDKDef(
        key="inmobi",
        label="InMobi 广告",
        vendor="InMobi",
        host_suffixes=[
            "inmobi.com", "w.inmobi.com",
            "sdkad.net",
        ],
        telemetry_path_keywords=["/report", "/events", "/impressions"],
        ad_api_path_keywords=["/ad/request", "/ads", "/bid"],
        notes="com.inmobi — 移动广告 SDK",
    ),

    # ── Mintegral / Mobvista ──
    SDKDef(
        key="mintegral",
        label="Mintegral 广告",
        vendor="Mintegral",
        host_suffixes=[
            "mintegral.com", "mobvista.com",
            "mtg.com", "mtg.cn",
        ],
        telemetry_path_keywords=["/report", "/events", "/track"],
        ad_api_path_keywords=["/ad/request", "/ads", "/bid"],
        notes="com.mbridge — 广告聚合 + 变现",
    ),

    # ── AppsFlyer 归因 ──
    SDKDef(
        key="appsflyer",
        label="AppsFlyer / OneLink 归因",
        vendor="AppsFlyer",
        host_suffixes=[
            "appsflyer.com", "events.appsflyer.com",
            "api3.appsflyer.com", "hq1.appsflyer.com",
        ],
        telemetry_path_keywords=[
            "/inappevent", "/s2s/inapp", "/v1.0/s2s",
            "/install", "/session", "/events",
        ],
        notes="com.appsflyer — 归因 + 安装事件回传，含广告标识符",
    ),

    # ── Adjust 归因 ──
    SDKDef(
        key="adjust",
        label="Adjust 归因",
        vendor="Adjust",
        host_suffixes=[
            "app.adjust.com", "adjust.com",
            "cdn.adjust.com",
        ],
        telemetry_path_keywords=["/session", "/event", "/install", "/sdk"],
        cdn_host_keywords=["cdn.adjust.com"],
        notes="com.adjust.sdk — 归因 + 事件回传",
    ),

    # ── Firebase Analytics / FCM / Crashlytics ──
    SDKDef(
        key="firebase",
        label="Firebase Analytics / FCM / Crashlytics",
        vendor="Google",
        host_suffixes=[
            "app-measurement.com", "fcm.googleapis.com",
            "firebaseio.com", "firebase.google.com",
            "firebaseinstallations.googleapis.com",
            "crashlytics.com",
        ],
        telemetry_path_keywords=[
            "/collect", "/log", "/iid", "/install", "/messaging",
            "/crashlytics", "/reports",
        ],
        notes="com.google.firebase — 数据分析 + 推送 + 崩溃上报，与 AdMob 同属 Google",
    ),

    # ── Tapjoy ──
    SDKDef(
        key="tapjoy",
        label="Tapjoy",
        vendor="Tapjoy",
        host_suffixes=[
            "tapjoy.com", "ws.tapjoyads.com",
            "tapjoyads.com",
        ],
        telemetry_path_keywords=["/events", "/report", "/impressions"],
        ad_api_path_keywords=["/ads", "/bid", "/offer"],
        notes="com.tapjoy — 激励视频广告 SDK",
    ),

    # ── AdColony ──
    SDKDef(
        key="adcolony",
        label="AdColony",
        vendor="AdColony",
        host_suffixes=[
            "adcolony.com", "wd.adcolony.com",
            "adc3-launch.adcolony.com",
        ],
        telemetry_path_keywords=["/report", "/events", "/track"],
        ad_api_path_keywords=["/ads", "/bid", "/ad"],
        notes="com.jirbo.adcolony / com.adcolony — 视频广告 SDK",
    ),

    # ── Pangle Global（字节海外广告）──
    SDKDef(
        key="pangle_global",
        label="Pangle Global",
        vendor="字节跳动",
        host_suffixes=[
            "pangle.com", "pangleglobal.com", "pgl-stat.pangle.com",
            "pangle.global", "pv.pangle.com", "panglecdn.com",
        ],
        telemetry_path_keywords=["/report", "/events", "/log"],
        ad_api_path_keywords=["/ads", "/ad/request", "/bid"],
        cdn_host_keywords=["panglecdn.com"],
        notes="com.bytedance.sdk.openadsdk / com.pangle.global — 穿山甲海外版",
    ),

    # ── IAB OM SDK（广告测量）──
    SDKDef(
        key="iab_omid",
        label="IAB OM SDK 广告测量",
        vendor="IAB Tech Lab",
        host_suffixes=["omsdk.com", "omid-sdk.com"],
        telemetry_path_keywords=["/session", "/impression", "/measurement"],
        notes="com.iab.omid — 广告可见性/测量框架，随主流广告 SDK 集成",
    ),

    # ── Fyber / Digital Turbine ──
    SDKDef(
        key="fyber",
        label="Fyber / Digital Turbine",
        vendor="Digital Turbine",
        host_suffixes=["fyber.com", "fybercdn.com", "digitalturbine.com"],
        telemetry_path_keywords=["/report", "/events", "/impressions"],
        ad_api_path_keywords=["/ads", "/bid", "/ad/request"],
        cdn_host_keywords=["fybercdn.com"],
        notes="com.fyber / com.digitalturbine — 广告聚合 + 变现",
    ),

    # ── Amazon Ads（含 APS 广告竞价）──
    SDKDef(
        key="amazon_ads",
        label="Amazon Ads / Publisher Services",
        vendor="Amazon",
        host_suffixes=[
            "amazon-adsystem.com", "aax.amazon-adsystem.com",
            "aaid.amazon-adsystem.com",
            "aps.amazon.com", "amazon-ads.com",
        ],
        telemetry_path_keywords=["/event", "/report", "/appload"],
        ad_api_path_keywords=["/ad", "/bid", "/openrtb", "/bidrequest"],
        cdn_host_keywords=["media-amazon.com"],
        notes="com.amazon.device.ads / com.amazon.aps — 亚马逊广告 + 供给方平台",
    ),

    # ── Chartboost ──
    SDKDef(
        key="chartboost",
        label="Chartboost",
        vendor="Chartboost",
        host_suffixes=["chartboost.com", "chartboost-mediation.com"],
        telemetry_path_keywords=["/report", "/events", "/impressions"],
        ad_api_path_keywords=["/ads", "/bid", "/ad/request"],
        notes="com.chartboost — 游戏广告变现 + 竞价",
    ),

    # ── BidMachine ──
    SDKDef(
        key="bidmachine",
        label="BidMachine",
        vendor="BidMachine",
        host_suffixes=["bidmachine.io", "bidsrv.bidmachine.io"],
        telemetry_path_keywords=["/event", "/report", "/analytics"],
        ad_api_path_keywords=["/bid", "/ad/request", "/auction"],
        notes="io.bidmachine — 头部竞价 SDK（In-App Bidding）",
    ),

    # ── ExploreStack（BidMachine 广告网络）──
    SDKDef(
        key="explorestack",
        label="ExploreStack 广告",
        vendor="ExploreStack",
        host_suffixes=["explorestack.com"],
        telemetry_path_keywords=["/report", "/events", "/impressions"],
        ad_api_path_keywords=["/ads", "/bid"],
        notes="com.explorestack — 广告网络聚合",
    ),

    # ── PubNative HyBid ──
    SDKDef(
        key="pubnative",
        label="PubNative HyBid",
        vendor="Verve / PubNative",
        host_suffixes=["pubnative.net", "hybid.com", "verve.com"],
        telemetry_path_keywords=["/report", "/events", "/impressions"],
        ad_api_path_keywords=["/ads", "/bid", "/ad/request"],
        notes="net.pubnative.lite.sdk — 聚合 + 头部竞价",
    ),

    # ── Bigo Ads ──
    SDKDef(
        key="bigo_ads",
        label="Bigo Ads",
        vendor="BIGO",
        host_suffixes=["bigo.sg", "bigoads.com", "bigo.com"],
        telemetry_path_keywords=["/report", "/events", "/impressions"],
        ad_api_path_keywords=["/ads", "/bid", "/ad/request"],
        notes="sg.bigo.ads — 视频广告 SDK（BIGO/欢聚集团）",
    ),

    # ── Yandex Mobile Ads ──
    SDKDef(
        key="yandex",
        label="Yandex Mobile Ads",
        vendor="Yandex",
        host_suffixes=["yandex.ru", "yandex.com", "yandex.net", "appmetrica.yandex.com"],
        telemetry_path_keywords=["/report", "/events", "/metrica", "/log"],
        ad_api_path_keywords=["/ads", "/bid", "/ad/request"],
        cdn_host_keywords=["yandex.net"],
        notes="com.yandex.mobile.ads — 俄区广告 + AppMetrica 埋点",
    ),

    # ── myTarget（VK）──
    SDKDef(
        key="mytarget",
        label="myTarget 广告",
        vendor="VK / myTarget",
        host_suffixes=["mytarget.ru", "mycdn.me", "vk.com"],
        telemetry_path_keywords=["/report", "/events", "/impressions"],
        ad_api_path_keywords=["/ads", "/bid", "/ad/request"],
        cdn_host_keywords=["mycdn.me"],
        notes="com.my.target — 俄区广告平台",
    ),

    # ── MoPub（AppLovin 已停运）──
    SDKDef(
        key="mopub",
        label="MoPub",
        vendor="AppLovin / MoPub",
        host_suffixes=[
            "mopub.com", "mopub.com.cn",
            "mopub.com.cloudfront.net",
        ],
        telemetry_path_keywords=["/report", "/events", "/impressions"],
        ad_api_path_keywords=["/m/ads", "/ads", "/bid", "/ad/request"],
        cdn_host_keywords=["mopub.com.cloudfront.net"],
        notes="com.mopub — 已停运的广告聚合（存量 App 仍集成）",
    ),

    # ── MobileFuse ──
    SDKDef(
        key="mobilefuse",
        label="MobileFuse 广告",
        vendor="MobileFuse",
        host_suffixes=["mobilefuse.com", "mobilefuse.net"],
        telemetry_path_keywords=["/report", "/events", "/impressions"],
        ad_api_path_keywords=["/ads", "/bid", "/ad/request"],
        cdn_host_keywords=["mobilefuse.net"],
        notes="com.mobilefuse.sdk — 程序化视频广告",
    ),

    # ── PubMatic OpenWrap ──
    SDKDef(
        key="pubmatic",
        label="PubMatic OpenWrap",
        vendor="PubMatic",
        host_suffixes=["pubmatic.com", "pubmaticads.com"],
        telemetry_path_keywords=["/report", "/events", "/impressions"],
        ad_api_path_keywords=["/ads", "/bid", "/ad/request", "/openrtb"],
        notes="com.pubmatic.sdk — OpenWrap 聚合 + 竞价",
    ),

    # ── Ogury ──
    SDKDef(
        key="ogury",
        label="Ogury 广告",
        vendor="Ogury",
        host_suffixes=["ogury.co", "ogury.io", "ogury.com"],
        telemetry_path_keywords=["/report", "/events", "/impressions"],
        ad_api_path_keywords=["/ads", "/bid", "/ad/request"],
        notes="co.ogury / com.ogury — 广告变现 SDK",
    ),

    # ── Maio（日本）──
    SDKDef(
        key="maio",
        label="Maio 广告",
        vendor="i-mobile",
        host_suffixes=["maio.jp", "ad.maio.jp"],
        telemetry_path_keywords=["/report", "/events", "/impressions"],
        ad_api_path_keywords=["/ads", "/bid", "/ad/request"],
        notes="jp.maio.sdk.android — 日本视频广告",
    ),

    # ── HyprMX ──
    SDKDef(
        key="hyprmx",
        label="HyprMX",
        vendor="HyprMX",
        host_suffixes=["hyprmx.com", "hypr-mx.com"],
        telemetry_path_keywords=["/report", "/events", "/impressions"],
        ad_api_path_keywords=["/ads", "/bid", "/ad/request"],
        notes="com.hyprmx.android.sdk — 激励视频广告",
    ),

    # ── Smaato ──
    SDKDef(
        key="smaato",
        label="Smaato 广告",
        vendor="Smaato",
        host_suffixes=["smaato.net", "smaato.com"],
        telemetry_path_keywords=["/report", "/events", "/impressions"],
        ad_api_path_keywords=["/ads", "/bid", "/ad/request", "/openrtb"],
        notes="com.smaato.sdk — 程序化广告 + 竞价",
    ),

    # ── Prebid Mobile ──
    SDKDef(
        key="prebid",
        label="Prebid Mobile",
        vendor="Prebid",
        host_suffixes=["prebid.org", "prebid.js", "prebid-server", "prebidmobile.com"],
        telemetry_path_keywords=["/report", "/events", "/impressions"],
        ad_api_path_keywords=["/ads", "/bid", "/openrtb", "/auction"],
        notes="org.prebid.mobile — 开源头部竞价 SDK",
    ),

    # ── Singular 归因 ──
    SDKDef(
        key="singular",
        label="Singular 归因",
        vendor="Singular",
        host_suffixes=["singular.net", "singular.com", "s2s.singular.net"],
        telemetry_path_keywords=["/session", "/install", "/event", "/launch"],
        notes="com.singular.sdk — 移动归因 + 事件回传",
    ),

    # ── 腾讯 Bugly（崩溃监控）──
    SDKDef(
        key="bugly",
        label="腾讯 Bugly 崩溃监控",
        vendor="腾讯",
        host_suffixes=["bugly.qq.com", "bugly.qq.com.cn"],
        telemetry_path_keywords=["/upload", "/report", "/log", "/crash"],
        notes="com.tencent.bugly — 崩溃 + 日志上报，与微信同属腾讯",
    ),
]

#  分类入口

# 这些 SDK 的所有流量本质上都是数据上报
# 路径不含明显 ad_api 关键字时强制归为telemetry以提高风险灵敏度。
_ALWAYS_TELEMETRY_SDKS = {
    "umeng",          # 友盟：全域埋点
    "jpush",          # 极光推送：设备注册含 IMEI
    "getui",          # 个推推送：设备注册含唯一标识
    "vivo_push",      # vivo Push：设备注册
    "oppo",           # OPPO Push：设备注册
    "rangers_applog", # 字节增长分析：埋点上报
    "apmplus",        # 字节 APM：崩溃 / 性能上报
    "ali_emas",       # 阿里 EMAS：崩溃 / 日志上报
    "appsflyer",      # AppsFlyer：归因 + 安装/会话事件回传
    "adjust",         # Adjust：归因 + 事件回传
    "firebase",       # Firebase：Analytics 埋点 + FCM 推送 + Crashlytics 崩溃
    "tapjoy",         # Tapjoy：激励广告事件上报
    "adcolony",       # AdColony：广告事件上报
    "singular",       # Singular：归因 + 事件回传
    "bugly",          # 腾讯 Bugly：崩溃/日志上报
    "yandex",         # Yandex：AppMetrica 埋点 + 广告
    "iab_omid",       # IAB OM SDK：广告可见性测量（数据采集）
}


def classify(host: str, path: str = "") -> tuple:
    """
    分类一条请求。
    返回: (sdk_key, sdk_label, endpoint_type)
    未识别时返回 (None, None, 'unknown')
    """
    for sdk in SDK_REGISTRY:
        if sdk.matches(host):
            ep = sdk.classify(host, path)
            if sdk.key in _ALWAYS_TELEMETRY_SDKS and ep == EP_SERVICE:
                ep = EP_TELEMETRY
            return sdk.key, sdk.label, ep
    return None, None, EP_UNKNOWN


def is_known_cdn(host: str, path: str = "") -> bool:
    """是否为已知 CDN（可安全忽略的请求）。"""
    _, _, ep = classify(host, path)
    return ep == EP_CDN


def is_telemetry(host: str, path: str = "") -> bool:
    """是否为已知telemetry端点"""
    _, _, ep = classify(host, path)
    return ep == EP_TELEMETRY


#  可疑系统路径检测（从穿山甲文档里提取的模式）

#  穿山甲 SDK 的动态 URL 中出现了大量形如
#    /proc/cpuinfo、/system/bin/su、/data/anr/traces.txt、/sdcard/
#  这些是典型的：设备指纹采集 / Root 检测 / ANR 日志上传
#  在 URL 或请求体里出现时，应作为可疑行为标记。

SUSPICIOUS_PATH_PATTERNS = [
    (r"/proc/(cpuinfo|version|meminfo|stat|net/)", "读取 /proc 设备信息"),
    (r"/system/(bin|xbin)/su\b",                   "Root 检测（搜索 su 二进制）"),
    (r"/system/build\.prop",                       "读取系统 build.prop"),
    (r"/data/anr/traces",                          "读取 ANR 崩溃日志"),
    (r"/sys/class/net/.*/address",                 "读取硬件 MAC 地址"),
    (r"/sdcard/.*\.(db|json|log|xml)",             "读取 SD 卡数据文件"),
    (r"/cpufreq/cpuinfo_(max|min)_freq",           "读取 CPU 频率指纹"),
]


if __name__ == "__main__":
    # 自测
    tests = [
        ("ulogs.umeng.com",                     "/push_cloud_activation"),
        ("mobads-logs.baidu.com",               "/dz.zb?type=425"),
        ("sf3-fe-tos.pglstatp-toutiao.com",     "/obj/ad-pattern/static/"),
        ("api-access.pangolin-sdk-toutiao.com", "/api/ad/union/sdk/get_ads"),
        ("applog.volces.com",                   "/v3/app/log/"),         # rangers_applog（先于 pangolin）
        ("log.snssdk.com",                      "/service/2/app_log"),   # rangers_applog
        ("apmplus.volces.com",                  "/apm/collect/crash"),
        ("push.heytap.com",                     "/push/device/register"),# oppo
        ("vpush.vivo.com.cn",                   "/push/message/ack"),    # vivo_push
        ("open.weixin.qq.com",                  "/sns/userinfo"),        # wechat
        ("ads.hihonor.com",                     "/ad/request"),          # honor
        ("adsjsdk.cloud.huawei.com",            "/adsdk/ads"),           # huawei_hms
        ("device.jpush.cn",                     "/device/register"),     # jpush
        ("push.getui.com",                      "/device/register"),     # getui
        ("googleads.g.doubleclick.net",         "/pagead/ads"),          # admob
        ("ha.alibaba.com",                      "/ha/crash"),            # ali_emas
        ("example.com",                         "/"),
    ]
    for h, p in tests:
        k, l, e = classify(h, p)
        print(f"{h:50s}{p:40s} => [{e:10s}] {l or '未识别'}")
