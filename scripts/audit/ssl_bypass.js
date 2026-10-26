/**
 * ssl_bypass.js — 通用 SSL Pinning 绕过脚本
 * 
 * 覆盖场景：
 *   1. Android 系统 TrustManager（X509TrustManager）
 *   2. OkHttp3 CertificatePinner
 *   3. HttpsURLConnection HostnameVerifier
 *   4. WebViewClient onReceivedSslError
 *   5. 网络安全配置（NetworkSecurityConfig）
 *   6. Apache HttpClient（旧版 App）
 *   7. Conscrypt / BoringSSL（部分新版 App）
 * 
 * 用法：
 *   frida -U -f com.target.app -l ssl_bypass.js --no-pause
 *   frida -U --attach-name "目标App" -l ssl_bypass.js
 */

"use strict";

const Color = {
    GREEN:  "\x1b[32m",
    YELLOW: "\x1b[33m",
    CYAN:   "\x1b[36m",
    RESET:  "\x1b[0m",
};

function log(tag, msg) {
    console.log(`${Color.GREEN}[SSL Bypass]${Color.RESET} ${Color.CYAN}[${tag}]${Color.RESET} ${msg}`);
}

Java.perform(function () {

    log("init", "SSL Pinning 绕过脚本已加载");

    // ─────────────────────────────────────
    //  1. X509TrustManager — 最通用的绕过
    // ─────────────────────────────────────
    try {
        const X509TrustManager = Java.use("javax.net.ssl.X509TrustManager");
        const SSLContext = Java.use("javax.net.ssl.SSLContext");
        const TrustManager = Java.registerClass({
            name: "com.bypass.TrustManager",
            implements: [X509TrustManager],
            methods: {
                checkClientTrusted(chain, authType) { },
                checkServerTrusted(chain, authType) { },
                getAcceptedIssuers() { return []; },
            },
        });

        const TrustManagers = [TrustManager.$new()];
        const sslContext = SSLContext.getInstance("TLS");
        sslContext.init(null, TrustManagers, null);

        const SSLSocketFactory = Java.use("javax.net.ssl.HttpsURLConnection");
        SSLSocketFactory.setDefaultSSLSocketFactory(sslContext.getSocketFactory());

        log("TrustManager", "已替换系统默认 TrustManager ✓");
    } catch (e) {
        log("TrustManager", "跳过: " + e.message);
    }

    // ─────────────────────────────────────
    //  2. HostnameVerifier
    // ─────────────────────────────────────
    try {
        const HostnameVerifier = Java.use("javax.net.ssl.HostnameVerifier");
        const AllowAll = Java.registerClass({
            name: "com.bypass.HostnameVerifier",
            implements: [HostnameVerifier],
            methods: {
                verify(hostname, session) { return true; },
            },
        });
        const HttpsURLConnection = Java.use("javax.net.ssl.HttpsURLConnection");
        HttpsURLConnection.setDefaultHostnameVerifier(AllowAll.$new());
        log("HostnameVerifier", "已替换默认 HostnameVerifier ✓");
    } catch (e) {
        log("HostnameVerifier", "跳过: " + e.message);
    }

    // ─────────────────────────────────────
    //  3. OkHttp3 CertificatePinner
    // ─────────────────────────────────────
    try {
        const CertificatePinner = Java.use("okhttp3.CertificatePinner");
        CertificatePinner.check.overload("java.lang.String", "java.util.List").implementation = function (hostname, peerCertificates) {
            log("OkHttp3", `CertificatePinner.check("${hostname}") → 放行`);
        };
        // 部分版本还有另一个 check 重载
        try {
            CertificatePinner.check$okhttp.overload("java.lang.String", "kotlin.jvm.functions.Function0").implementation = function (hostname, fn) {
                log("OkHttp3", `CertificatePinner.check$okhttp("${hostname}") → 放行`);
            };
        } catch (_) { }
        log("OkHttp3", "CertificatePinner 已 hook ✓");
    } catch (e) {
        log("OkHttp3", "未发现 OkHttp3 CertificatePinner");
    }

    // OkHttp3 旧版本
    try {
        const OldPinner = Java.use("com.squareup.okhttp.CertificatePinner");
        OldPinner.check.overload("java.lang.String", "java.util.List").implementation = function () {
            log("OkHttp(old)", "CertificatePinner.check → 放行");
        };
        log("OkHttp(old)", "旧版 CertificatePinner 已 hook ✓");
    } catch (e) { }

    // ─────────────────────────────────────
    //  4. WebViewClient SSL 错误处理
    // ─────────────────────────────────────
    try {
        const WebViewClient = Java.use("android.webkit.WebViewClient");
        WebViewClient.onReceivedSslError.implementation = function (view, handler, error) {
            log("WebView", "onReceivedSslError → proceed()");
            handler.proceed();
        };
        log("WebView", "WebViewClient SSL 已 hook ✓");
    } catch (e) { }

    // ─────────────────────────────────────
    //  5. TrustManagerImpl（Android 7+ 系统级）
    // ─────────────────────────────────────
    try {
        const TrustManagerImpl = Java.use("com.android.org.conscrypt.TrustManagerImpl");
        TrustManagerImpl.verifyChain.implementation = function (untrustedChain) {
            log("TrustManagerImpl", "verifyChain → 返回原链");
            return untrustedChain;
        };
        log("TrustManagerImpl", "系统 TrustManagerImpl 已 hook ✓");
    } catch (e) { }

    // ─────────────────────────────────────
    //  6. Conscrypt / BoringSSL
    // ─────────────────────────────────────
    try {
        const Platform = Java.use("com.android.org.conscrypt.Platform");
        Platform.checkServerTrusted.overload(
            "javax.net.ssl.X509TrustManager",
            "[Ljava.security.cert.X509Certificate;",
            "java.lang.String",
            "com.android.org.conscrypt.AbstractConscryptSocket"
        ).implementation = function () {
            log("Conscrypt", "Platform.checkServerTrusted → 放行");
        };
        log("Conscrypt", "Conscrypt Platform 已 hook ✓");
    } catch (e) { }

    // ─────────────────────────────────────
    //  7. Apache HttpClient（旧版 App）
    // ─────────────────────────────────────
    try {
        const AbstractVerifier = Java.use("org.apache.http.conn.ssl.AbstractVerifier");
        AbstractVerifier.verify.overload("java.lang.String", "[Ljava.lang.String;", "[Ljava.lang.String;", "boolean").implementation = function () {
            log("Apache", "AbstractVerifier.verify → 放行");
        };
        log("Apache", "Apache HttpClient 已 hook ✓");
    } catch (e) { }

    // ─────────────────────────────────────
    //  8. Flutter / Dart（如果存在）
    // ─────────────────────────────────────
    try {
        const module = Process.findModuleByName("libflutter.so");
        if (module) {
            // ssl_crypto_x509_session_verify_cert_chain 的常见偏移
            // 具体偏移需要根据 Flutter 版本调整
            log("Flutter", "检测到 libflutter.so，Flutter SSL bypass 需要针对具体版本调整偏移");
        }
    } catch (e) { }

    log("init", "SSL Pinning 绕过完成 ✓ 共尝试 8 个 hook 点");

});
