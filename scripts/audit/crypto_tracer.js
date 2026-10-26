/**
 * crypto_tracer.js — Java 加解密 API 全量 Hook 脚本
 * 
 * 对应赛题"挑战2：加密穿透"
 * 
 * Hook 覆盖：
 *   1. javax.crypto.Cipher          — AES / DES / RSA 加解密，捕获明文 + 密钥 + IV
 *   2. javax.crypto.spec.SecretKeySpec — 对称密钥创建
 *   3. javax.crypto.spec.IvParameterSpec — IV 向量
 *   4. javax.crypto.Mac              — HMAC 签名
 *   5. java.security.MessageDigest   — MD5 / SHA 哈希
 *   6. android.util.Base64           — Base64 编解码
 *   7. java.util.zip.GZIPOutputStream / GZIPInputStream — Gzip 压缩解压
 *   8. javax.crypto.KeyGenerator     — 密钥生成
 *   9. java.security.KeyPairGenerator — RSA 密钥对生成
 *   10. org.json.JSONObject           — JSON 构造（SDK 常用）
 *   11. 自定义加密函数探测           — 按类名关键词搜索
 * 
 * 配置项（修改下方 CONFIG 对象）：
 *   - MAX_DATA_LEN:   打印数据的最大字节数
 *   - PRINT_STACKTRACE: 是否打印调用栈（定位 SDK 调用来源）
 *   - STACKTRACE_DEPTH: 调用栈打印深度
 *   - FILTER_PACKAGES: 只关注这些包名前缀的调用（空数组 = 全部）
 */

// 启用严格模式，避免拼写错误导致隐式全局变量，从而影响被审计 App 的进程。
"use strict";

//  配置

// 集中保存所有可调开关；修改这些值即可控制日志量与 Hook 覆盖范围。
const CONFIG = {
    // 单次输出最多展示多少字节，避免大报文占满 Frida 日志。
    MAX_DATA_LEN: 512,
    // 是否在每个关键事件后输出 Java 调用栈，以追溯 App 或 SDK 来源。
    PRINT_STACKTRACE: true,
    // 调用栈最多保留多少帧；数值越大，定位越充分但日志越长。
    STACKTRACE_DEPTH: 8,
    // 仅记录调用栈中含这些包名前缀的调用；空数组表示不按包名过滤。
    FILTER_PACKAGES: [
        // ── 已有 SDK ──
        // "com.bytedance",           // 穿山甲 Pangolin / RangersAppLog / APMPlus
        // "com.ss.android",          // 穿山甲相关
        // "com.qq.e",                // 腾讯优量汇 GDT
        // "com.umeng",               // 友盟+ Umeng
        // "com.baidu.mobads",        // 百度 MobAds
        // "com.alipay",              // 支付宝 SDK
        // "com.mobile.auth",         // 中国移动一键登录
        // "com.cmic.sso.sdk",        // 中国移动一键登录
        // ── sdk_summary.csv 新增 SDK ──
        // "com.heytap",              // OPPO 广告联盟 / Push SDK (com.heytap.openid / com.heytap.msp.push)
        // "com.vivo.push",           // vivo Push SDK
        // "com.tencent.mm",          // 微信 Open SDK (com.tencent.mm.opensdk)
        // "com.hihonor",             // 荣耀广告 SDK (com.hihonor.ads)
        // "com.huawei.hms",          // 华为 HMS Ads (com.huawei.hms.ads)
        // "cn.jpush",                // 极光推送 JPush (cn.jpush.android)
        // "cn.jiguang",              // 极光推送 JPush 辅助包
        // "com.igexin",              // 个推推送 SDK
        // "com.getui",               // 个推推送 SDK
        // "com.google.android.gms.ads", // Google AdMob
        // "com.alibaba.ha",          // 阿里 EMAS / 高可用 SDK
        // "com.alibaba.sdk.android", // 阿里 EMAS / 高可用 SDK
        // "com.bytedance.applog",    // 字节 RangersAppLog（火山引擎增长分析）
        // 等等
    ],
    // 是否 Hook JSONObject.toString；它常能看到 SDK 加密前构造的明文 JSON。
    HOOK_JSON: true,
    // 是否 Hook 哈希 API；默认关闭，因为哈希调用多且通常不直接体现隐私采集。
    HOOK_HASH: false,
    // 是否 Hook HMAC API；默认关闭，以控制签名类日志噪声。
    HOOK_HMAC: false,
    // 是否 Hook GZIP 压缩与解压；默认关闭，因为调用频繁且日志量大。
    HOOK_GZIP: false,
    // 是否 Hook Base64 编解码；默认关闭，因为它常用于普通编码而非加密。
    HOOK_BASE64: false,
    // 是否在已加载类中按关键词搜索自定义加密类；默认关闭以避免一次性输出过多候选。
    PROBE_CUSTOM_CRYPTO: false,
};

//  工具函数

// 保存 ANSI 终端颜色控制码，使 Frida 控制台中的不同类型证据更易阅读。
const CLR = {
    // 红色通常用于密钥、Cipher 初始化和失败等高关注信息。
    RED:    "\x1b[91m",
    // 绿色通常用于正常输出、明文和成功安装 Hook。
    GREEN:  "\x1b[92m",
    // 黄色通常用于密钥、IV、压缩或需要注意的信息。
    YELLOW: "\x1b[93m",
    // 蓝色用于哈希和 HMAC 等摘要类信息。
    BLUE:   "\x1b[94m",
    // 紫色用于 Cipher、探测类日志等。
    PURPLE: "\x1b[95m",
    // 青色用于输入数据、URL 等辅助信息。
    CYAN:   "\x1b[96m",
    // 白色用于 JSON 等中性内容。
    WHITE:  "\x1b[97m",
    // 灰色用于时间戳与调用栈等背景信息。
    GRAY:   "\x1b[90m",
    // 粗体控制码，用于横幅和重点文本。
    BOLD:   "\x1b[1m",
    // 重置颜色，防止一种颜色泄漏到后续日志。
    RESET:  "\x1b[0m",
};

// 统计本脚本写出的事件数；当前仅自增，保留给后续汇总或调试扩展使用。
let eventCounter = 0;

// 生成 ISO 时间中的时:分:秒.毫秒部分，用作每行日志的轻量时间戳。
function now() {
    // 截取 ISO 字符串的第 11 至 23 位，例如 11:12:04.660。
    return new Date().toISOString().slice(11, 23);
}

// 按统一格式打印一条带时间、标签、颜色的日志。
function log(tag, color, msg) {
    // 每产生一条统一日志就增加计数；不参与审计判定。
    eventCounter++;
    // 将时间戳、彩色标签和正文拼成一行，交由 Frida 的 console 输出。
    console.log(`${CLR.GRAY}[${now()}]${CLR.RESET} ${color}[${tag}]${CLR.RESET} ${msg}`);
}

// 打印一个带标题的文本分隔行，用于把不同 Cipher 事件区分开。
function separator(title) {
    // repeat(20) 仅负责格式化显示，不参与任何加密或审计逻辑。
    console.log(`\n${CLR.BOLD}${CLR.CYAN}${"─".repeat(20)} ${title} ${"─".repeat(20)}${CLR.RESET}`);
}

// 将 Java byte[] 转为十六进制预览文本，适合展示不可打印的密钥、IV 或密文。
function bytesToHex(arr) {
    // 空数组或空引用没有可展示的数据，直接返回占位文字。
    if (!arr) return "<null>";
    // 只处理配置规定的最大字节数，控制日志大小。
    const len = Math.min(arr.length, CONFIG.MAX_DATA_LEN);
    // 用字符串累积每个字节的十六进制表示。
    let hex = "";
    // 依次读取截取范围内的每个字节。
    for (let i = 0; i < len; i++) {
        // & 0xff 把 Java 有符号 byte 转成 0 至 255 的无符号数，再补齐为两位十六进制。
        const b = (arr[i] & 0xff).toString(16).padStart(2, "0");
        // 在每个字节后追加一个空格，便于人工阅读。
        hex += b + " ";
    }
    // 若原始数组被截断，则追加总长度提示，避免误以为日志展示了全部数据。
    if (arr.length > len) hex += `... (共 ${arr.length} 字节)`;
    // 去掉尾部多出的空格并返回最终预览。
    return hex.trim();
}

// 尝试将 Java byte[] 按 UTF-8 解码为文本预览，适合 JSON、参数字符串等明文。
function bytesToUtf8(arr) {
    // 空数组或空引用无法解码，直接返回占位文字。
    if (!arr) return "<null>";
    try {
        // 获取 Java String 类，以使用 Android/Java 的 UTF-8 解码实现。
        const StringClass = Java.use("java.lang.String");
        // 计算允许展示的最大字节数。
        const len = Math.min(arr.length, CONFIG.MAX_DATA_LEN);
        // 将 Frida 可遍历的数组截取后重新包装成 Java byte[]。
        const slice = Java.array("byte", Array.from(arr).slice(0, len));
        // 调用 String(byte[], "UTF-8") 构造函数，将字节转成文本。
        let s = StringClass.$new(slice, "UTF-8");
        // 若发生截断则附加原始总长度说明。
        if (arr.length > len) s += `... (共 ${arr.length} 字节)`;
        // 返回成功解码后的文本。
        return s;
    } catch (e) {
        // 解码失败时不抛异常到目标 App，只返回说明文字。
        return "<decode failed>";
    }
}

// 用抽样方式判断 byte[] 是否大概率为可读文本，从而决定使用 TEXT 还是 HEX 显示。
function isPrintable(arr) {
    // 没有数据或长度为零时，不能视为可打印文本。
    if (!arr || arr.length === 0) return false;
    // 最多抽样前 64 个字节，兼顾判断速度与代表性。
    const sample = Math.min(arr.length, 64);
    // 记录抽样中被认作“可打印”的字节数量。
    let printable = 0;
    // 遍历每个抽样字节。
    for (let i = 0; i < sample; i++) {
        // 统一转换为 0 至 255 的无符号字节值。
        const b = arr[i] & 0xff;
        // ASCII 可打印字符、换行/回车/制表符以及部分高位 UTF-8 字节都计为可打印。
        if ((b >= 0x20 && b <= 0x7e) || b === 0x0a || b === 0x0d || b === 0x09 || b >= 0xc0) {
            // 命中可打印条件则累计计数。
            printable++;
        }
    }
    // 可打印字节比例超过 70% 时，把该数组视为文本。
    return printable / sample > 0.7;
}

// 根据可读性选择文本或十六进制格式，作为所有二进制数据日志的统一入口。
function formatData(arr) {
    // 空引用直接返回占位文字，避免后续访问 length 时报错。
    if (!arr) return "<null>";
    // 可读数据以 UTF-8 文本和绿色 TEXT 标签显示。
    if (isPrintable(arr)) {
        return `${CLR.GREEN}[TEXT]${CLR.RESET} ${bytesToUtf8(arr)}`;
    // 不可读数据以黄色 HEX 标签和十六进制预览显示。
    } else {
        return `${CLR.YELLOW}[HEX]${CLR.RESET} ${bytesToHex(arr)}`;
    }
}

// 获取精简 Java 调用栈，用于把加密动作归因到具体 App 类或 SDK 类。
function getStackTrace() {
    // 调用方关闭调用栈开关时，不创建异常对象，直接返回空字符串。
    if (!CONFIG.PRINT_STACKTRACE) return "";
    try {
        // 取得 Java Exception 类，用临时异常承载当前调用栈。
        const Exception = Java.use("java.lang.Exception");
        // 在目标 App 的 Java 虚拟机中创建一个异常实例。
        const e = Exception.$new();
        // 获取异常携带的 StackTraceElement 数组。
        const stack = e.getStackTrace();
        // 初始化保存格式化栈帧的 JavaScript 数组。
        const lines = [];
        // 同时遵守实际栈深和配置的最大显示深度。
        const depth = Math.min(stack.length, CONFIG.STACKTRACE_DEPTH);
        // 遍历允许展示的每一帧。
        for (let i = 0; i < depth; i++) {
            // 将 Java StackTraceElement 转成易显示的字符串。
            const frame = stack[i].toString();
            // 跳过名称含 bypass 或 frida 的注入相关帧，突出业务调用者。
            if (frame.includes("bypass") || frame.includes("frida")) continue;
            // 为业务栈帧添加缩进和灰色样式后写入数组。
            lines.push(`    ${CLR.GRAY}at ${frame}${CLR.RESET}`);
        }
        // 以换行连接各栈帧；前置换行使其显示在主日志的下一行。
        return "\n" + lines.join("\n");
    } catch (e) {
        // 获取调用栈失败时静默返回空字符串，确保 Hook 不会影响业务逻辑。
        return "";
    }
}

// 判断当前调用是否应被包名前缀过滤；返回 true 表示不记录这次调用。
function shouldFilter() {
    // 过滤列表为空代表全量审计，因此不应过滤任何调用。
    if (CONFIG.FILTER_PACKAGES.length === 0) return false;
    try {
        // 创建临时异常以取得当前 Java 调用栈。
        const Exception = Java.use("java.lang.Exception");
        // 取得异常实例，后续从中读取栈帧。
        const e = Exception.$new();
        // 读取完整的 Java 调用栈。
        const stack = e.getStackTrace();
        // 最多检查前 20 帧，避免每次加密调用的过滤成本过高。
        for (let i = 0; i < Math.min(stack.length, 20); i++) {
            // 得到当前栈帧所属的完整 Java 类名。
            const cls = stack[i].getClassName();
            // 逐个比较用户配置的关注包名前缀。
            for (const pkg of CONFIG.FILTER_PACKAGES) {
                // 一旦发现匹配前缀，说明是目标包调用，应保留日志并返回 false。
                if (cls.startsWith(pkg)) return false;
            }
        }
        // 检查完仍未找到目标包名，返回 true 表示过滤掉这条调用。
        return true;
    } catch (e) {
        // 若无法获取调用栈，为避免漏掉证据，采用“不过滤”的保守策略。
        return false;
    }
}


// 等待 Frida 确认 Java VM 可用后，再安装所有 Java 加密 API 的 Hook。
Java.perform(function () {

    // 打印启动横幅，便于从混合 Frida 日志中识别本脚本已开始工作。
    separator("Crypto Tracer 已启动");
    // 记录初始化日志。
    log("init", CLR.GREEN, "开始 Hook Java 加解密 API ...");

    //  javax.crypto.Cipher — 核心 Hook

    try {
        // 获取 Java 加密核心类，后续会替换其选定重载的方法实现。
        const Cipher = Java.use("javax.crypto.Cipher");

        // --- Cipher.getInstance() ---
        // Hook 仅接受 transformation 字符串的 getInstance 重载，例如 AES/CBC/PKCS5Padding。
        Cipher.getInstance.overload("java.lang.String").implementation = function (transformation) {
            // 当前调用不在关注包范围内时，直接执行原实现且不写日志。
            if (shouldFilter()) return this.getInstance(transformation);
            // 记录算法/模式/填充组合，帮助判断 App 使用的加密方案。
            log("Cipher", CLR.PURPLE, `getInstance("${transformation}")`);
            // 调用原始 getInstance 并把其 Cipher 对象返回给 App。
            return this.getInstance(transformation);
        };

        // --- Cipher.init() ---
        // init(int opmode, Key key)
        try {
            // Hook 只传“工作模式 + 密钥”的 Cipher.init 重载。
            Cipher.init.overload("int", "java.security.Key").implementation = function (opmode, key) {
                // 仅在调用通过包名过滤时输出密钥及上下文；始终会继续执行原方法。
                if (!shouldFilter()) {
                    // Android Cipher 的 1/2 分别表示加密/解密，其他值按原数值保留。
                    const mode = opmode === 1 ? "ENCRYPT" : opmode === 2 ? "DECRYPT" : `mode=${opmode}`;
                    // 从当前 Cipher 对象读取算法描述。
                    const algo = this.getAlgorithm();
                    // 取得 Key 的可编码字节；某些硬件密钥可能返回 null。
                    const keyBytes = key.getEncoded();
                    // 输出初始化操作、工作模式和算法名。
                    log("Cipher", CLR.RED, `init(${CLR.BOLD}${mode}${CLR.RESET}${CLR.RED}, algo=${algo})`);
                    // 以十六进制形式输出密钥预览，长度受 MAX_DATA_LEN 限制。
                    console.log(`  ${CLR.YELLOW}密钥:${CLR.RESET} ${bytesToHex(keyBytes)}`);
                    // 输出本次初始化发生位置的精简调用栈。
                    console.log(getStackTrace());
                }
                // 调用原始 init，使目标 App 的 Cipher 按原逻辑完成配置。
                this.init(opmode, key);
            };
        } catch (e) {
            // 某系统不提供该重载时跳过，不阻断其他 Cipher Hook。
        }

        // init(int opmode, Key key, AlgorithmParameterSpec params)
        try {
            // Hook 额外传入参数规格的 init 重载，以便从中提取 IV。
            Cipher.init.overload("int", "java.security.Key", "java.security.spec.AlgorithmParameterSpec")
                .implementation = function (opmode, key, params) {
                // 仅在未被包名过滤时打印敏感证据。
                if (!shouldFilter()) {
                    // 将常见的数字工作模式转成 ENCRYPT/DECRYPT 文本。
                    const mode = opmode === 1 ? "ENCRYPT" : opmode === 2 ? "DECRYPT" : `mode=${opmode}`;
                    // 获取当前 Cipher 的算法描述。
                    const algo = this.getAlgorithm();
                    // 从 Key 对象中取出可编码的密钥字节。
                    const keyBytes = key.getEncoded();
                    // 输出初始化操作、模式与算法。
                    log("Cipher", CLR.RED, `init(${CLR.BOLD}${mode}${CLR.RESET}${CLR.RED}, algo=${algo})`);
                    // 输出密钥的十六进制预览。
                    console.log(`  ${CLR.YELLOW}密钥:${CLR.RESET} ${bytesToHex(keyBytes)}`);

                    // 提取 IV
                    try {
                        // 取得标准 IV 参数规格类。
                        const IvParameterSpec = Java.use("javax.crypto.spec.IvParameterSpec");
                        // 仅当 params 确实是 IvParameterSpec 时才继续读取。
                        if (IvParameterSpec.class.isInstance(params)) {
                            // 将通用参数对象转换为 IvParameterSpec，并取出其中的 IV 字节。
                            const iv = Java.cast(params, IvParameterSpec).getIV();
                            // 输出 IV 的十六进制预览。
                            console.log(`  ${CLR.YELLOW}IV:${CLR.RESET}   ${bytesToHex(iv)}`);
                        }
                    } catch (_) {
                        // 参数不是标准 IV 规格或取值失败时跳过 IV 输出。
                    }

                    // 输出初始化调用的来源栈。
                    console.log(getStackTrace());
                }
                // 调用原始三参数 init，让 App 正常完成 Cipher 配置。
                this.init(opmode, key, params);
            };
        } catch (e) {
            // 该重载不可用时不影响其余 Hook。
        }

        // --- Cipher.doFinal(byte[]) ---
        try {
            // Hook 输入为完整 byte[] 的 doFinal，这是最常见的一次性加解密入口。
            Cipher.doFinal.overload("[B").implementation = function (input) {
                // 先执行原始加解密，得到真实输出；后续只观察输入和输出。
                const output = this.doFinal(input);
                // 仅为未被包名过滤的调用写入明文/密文证据。
                if (!shouldFilter()) {
                    // 获取当前 Cipher 使用的算法描述。
                    const algo = this.getAlgorithm();
                    // 保留原脚本读取的分组大小；该变量当前未参与后续判断，也不能代表加解密模式。
                    const opmode = this.getBlockSize();
                    // 用算法名打印一组独立的加解密事件标题。
                    separator(`Cipher.doFinal — ${algo}`);
                    // 输出加密前或解密前的输入数据，并按可读性显示 TEXT/HEX。
                    console.log(`  ${CLR.CYAN}输入 (${input.length} B):${CLR.RESET} ${formatData(input)}`);
                    // 输出加密后或解密后的结果数据，并按可读性显示 TEXT/HEX。
                    console.log(`  ${CLR.GREEN}输出 (${output.length} B):${CLR.RESET} ${formatData(output)}`);
                    // 输出调用 doFinal 的业务调用栈。
                    console.log(getStackTrace());
                }
                // 把原始加解密结果返回给 App，保持功能不变。
                return output;
            };
        } catch (e) {
            // 该重载不可用时跳过。
        }

        // --- Cipher.doFinal() 无参 ---
        try {
            // Hook 无参 doFinal；此时输入可能已通过 update() 分批传入。
            Cipher.doFinal.overload().implementation = function () {
                // 调用原方法取得最终加解密输出。
                const output = this.doFinal();
                // 未被过滤时记录输出长度和内容。
                if (!shouldFilter()) {
                    // 输出无参 doFinal 及其结果长度。
                    log("Cipher", CLR.PURPLE, `doFinal() → ${output.length} 字节`);
                    // 输出最终字节数组的文本或十六进制预览。
                    console.log(`  ${CLR.GREEN}输出:${CLR.RESET} ${formatData(output)}`);
                }
                // 将原结果返回给调用方。
                return output;
            };
        } catch (e) {
            // 该无参重载不可用时跳过。
        }

        // --- Cipher.doFinal(byte[], int, int) ---
        try {
            // Hook 只处理 input 中某个切片的 doFinal 重载。
            Cipher.doFinal.overload("[B", "int", "int").implementation = function (input, offset, len) {
                // 调用原始加解密实现，传入原数组、起始偏移和有效长度。
                const output = this.doFinal(input, offset, len);
                // 仅对需要保留的调用生成日志。
                if (!shouldFilter()) {
                    // 读取当前 Cipher 的算法描述。
                    const algo = this.getAlgorithm();
                    // 输出本次加解密事件标题。
                    separator(`Cipher.doFinal — ${algo}`);
                    try {
                        // 从原始数组中复制 offset 至 offset+len 的有效输入切片。
                        const slice = Java.array("byte", Array.from({length: len}, (_, i) => input[offset + i]));
                        // 输出该有效输入切片。
                        console.log(`  ${CLR.CYAN}输入 (${len} B):${CLR.RESET} ${formatData(slice)}`);
                    } catch (_) {
                        // 如果偏移范围异常或数组转换失败，仍保留“读取失败”提示。
                        console.log(`  ${CLR.CYAN}输入 (${len} B):${CLR.RESET} <读取失败>`);
                    }
                    // 输出原方法实际返回的加解密结果。
                    console.log(`  ${CLR.GREEN}输出 (${output.length} B):${CLR.RESET} ${formatData(output)}`);
                    // 输出本次操作的业务调用栈。
                    console.log(getStackTrace());
                }
                // 将原始结果返回给 App。
                return output;
            };
        } catch (e) {
            // 该三参数重载不可用时跳过。
        }

        // 记录 Cipher 主要 Hook 已安装成功。
        log("Cipher", CLR.GREEN, "javax.crypto.Cipher 已 hook ✓");
    } catch (e) {
        // Cipher 类不可用或主 Hook 失败时，输出错误信息，但继续执行其他模块。
        log("Cipher", CLR.RED, "hook 失败: " + e.message);
    }

    //  2. SecretKeySpec — 密钥创建

    try {
        // 获取标准对称密钥容器类；大量 AES/DES 密钥会由它构造。
        const SecretKeySpec = Java.use("javax.crypto.spec.SecretKeySpec");
        // Hook 以 byte[] 和算法名创建密钥的构造函数。
        SecretKeySpec.$init.overload("[B", "java.lang.String").implementation = function (keyBytes, algo) {
            // 仅记录未被包名过滤的密钥创建行为。
            if (!shouldFilter()) {
                // 将字节长度换算为 bit 长度并输出密钥所对应的算法名。
                log("SecretKey", CLR.YELLOW, `new SecretKeySpec(algo=${algo}, ${keyBytes.length * 8} bit)`);
                // 输出密钥的十六进制预览。
                console.log(`  ${CLR.YELLOW}密钥:${CLR.RESET} ${bytesToHex(keyBytes)}`);
                // 输出构造该密钥的业务调用栈。
                console.log(getStackTrace());
            }
            // 调用原始构造函数，返回当前已初始化的 Java 对象。
            return this.$init(keyBytes, algo);
        };
        // 记录 SecretKeySpec Hook 安装成功。
        log("SecretKeySpec", CLR.GREEN, "已 hook ✓");
    } catch (e) {
        // 当前环境没有该类或此构造函数时静默跳过。
    }


    //  3. IvParameterSpec — IV 向量

    try {
        // 获取标准初始化向量参数类。
        const IvParameterSpec = Java.use("javax.crypto.spec.IvParameterSpec");
        // Hook 以 byte[] 创建 IV 的构造函数。
        IvParameterSpec.$init.overload("[B").implementation = function (iv) {
            // 仅对未被包名过滤的调用写日志。
            if (!shouldFilter()) {
                // 输出 IV 长度，单位从字节转换为 bit。
                log("IV", CLR.YELLOW, `new IvParameterSpec(${iv.length * 8} bit)`);
                // 输出 IV 的十六进制预览。
                console.log(`  ${CLR.YELLOW}IV:${CLR.RESET} ${bytesToHex(iv)}`);
            }
            // 调用原始构造函数，保持 IV 参数对象的正常创建。
            return this.$init(iv);
        };
        // 记录 IV Hook 安装成功。
        log("IvParameterSpec", CLR.GREEN, "已 hook ✓");
    } catch (e) {
        // 当前环境没有该类或此构造函数时静默跳过。
    }


//  4. MessageDigest — 哈希
    

    // 仅当配置开启时才安装哈希 Hook，默认关闭以减少大量摘要日志。
    if (CONFIG.HOOK_HASH) {
    try {
        // 获取 Java 标准消息摘要类，例如 MD5、SHA-1、SHA-256。
        const MessageDigest = Java.use("java.security.MessageDigest");

        // Hook 直接传入 byte[] 并返回摘要值的 digest 重载。
        MessageDigest.digest.overload("[B").implementation = function (input) {
            // 先执行原始摘要运算，取得真实哈希结果。
            const output = this.digest(input);
            // 仅对未被过滤的调用记录输入、算法和哈希输出。
            if (!shouldFilter()) {
                // 输出摘要算法名称与输入长度。
                log("Hash", CLR.BLUE, `MessageDigest.digest(${this.getAlgorithm()}, ${input.length} B)`);
                // 输出待摘要数据的可读预览。
                console.log(`  ${CLR.CYAN}输入:${CLR.RESET} ${formatData(input)}`);
                // 以十六进制输出摘要结果。
                console.log(`  ${CLR.GREEN}哈希:${CLR.RESET} ${bytesToHex(output)}`);
            }
            // 将原始摘要结果返回给 App。
            return output;
        };

        // Hook 无参 digest；此时数据通常已通过 update() 分批加入。
        MessageDigest.digest.overload().implementation = function () {
            // 执行原始无参摘要运算。
            const output = this.digest();
            // 对未被过滤的调用输出算法和结果长度。
            if (!shouldFilter()) {
                // 输出算法名称及输出字节数。
                log("Hash", CLR.BLUE, `MessageDigest.digest(${this.getAlgorithm()}) → ${output.length} B`);
                // 输出摘要值的十六进制形式。
                console.log(`  ${CLR.GREEN}哈希:${CLR.RESET} ${bytesToHex(output)}`);
            }
            // 将原始摘要结果返回给 App。
            return output;
        };

        // 记录 MessageDigest Hook 安装成功。
        log("MessageDigest", CLR.GREEN, "已 hook ✓");
    } catch (e) {
        // 哈希类或重载不可用时静默跳过。
    }
    } // end HOOK_HASH


//  5. Mac — HMAC
    

    // 仅当配置开启时才安装 HMAC Hook，默认关闭以减少签名类日志。
    if (CONFIG.HOOK_HMAC) {
    try {
        // 获取 Java 标准 MAC 类，用于 HMAC 等消息认证码计算。
        const Mac = Java.use("javax.crypto.Mac");
        // Hook 直接传入 byte[] 的 doFinal 重载。
        Mac.doFinal.overload("[B").implementation = function (input) {
            // 先执行原始 MAC 计算，得到真实认证码。
            const output = this.doFinal(input);
            // 对未被过滤的调用输出算法、输入、MAC 与调用栈。
            if (!shouldFilter()) {
                // 输出 MAC 算法名称和输入长度。
                log("HMAC", CLR.BLUE, `Mac.doFinal(${this.getAlgorithm()}, ${input.length} B)`);
                // 输出待签名的输入数据预览。
                console.log(`  ${CLR.CYAN}输入:${CLR.RESET} ${formatData(input)}`);
                // 输出 MAC 结果的十六进制预览。
                console.log(`  ${CLR.GREEN}MAC:${CLR.RESET}  ${bytesToHex(output)}`);
                // 输出调用栈，辅助归因到 SDK 或业务类。
                console.log(getStackTrace());
            }
            // 返回原始 MAC 结果。
            return output;
        };

        // Hook 无参 doFinal；输入可能已通过 update() 分批写入。
        Mac.doFinal.overload().implementation = function () {
            // 执行原始无参 MAC 计算。
            const output = this.doFinal();
            // 对未被过滤的调用输出算法和 MAC 预览。
            if (!shouldFilter()) {
                // 将 MAC 值直接包含在日志正文中。
                log("HMAC", CLR.BLUE, `Mac.doFinal(${this.getAlgorithm()}) → ${bytesToHex(output)}`);
            }
            // 返回原始 MAC 结果。
            return output;
        };

        // 记录 Mac Hook 安装成功。
        log("Mac", CLR.GREEN, "已 hook ✓");
    } catch (e) {
        // MAC 类或重载不可用时静默跳过。
    }
    } // end HOOK_HMAC


//  6. Base64 编解码
    

    // 仅当配置开启时才安装 Base64 Hook，默认关闭以控制常规编码日志的数量。
    if (CONFIG.HOOK_BASE64) {
        try {
            // 获取 Android 提供的 Base64 工具类。
            const Base64 = Java.use("android.util.Base64");

            // Hook Android Base64 的“byte[] 编码为字符串”重载。
            Base64.encodeToString.overload("[B", "int").implementation = function (input, flags) {
                // 先执行原始编码，得到 App 实际使用的 Base64 字符串。
                const output = this.encodeToString(input, flags);
                // 未被过滤时输出原始字节和截断后的编码结果。
                if (!shouldFilter()) {
                    // 输出编码输入的字节长度。
                    log("Base64", CLR.CYAN, `encode(${input.length} B)`);
                    // 输出编码前的数据预览。
                    console.log(`  ${CLR.CYAN}原文:${CLR.RESET} ${formatData(input)}`);
                    // 仅展示配置长度内的编码字符串，避免超长 Base64 撑满日志。
                    console.log(`  ${CLR.GREEN}编码:${CLR.RESET} ${output.substring(0, CONFIG.MAX_DATA_LEN)}`);
                }
                // 返回原始编码字符串。
                return output;
            };

            // Hook Android Base64 的“字符串解码为 byte[]”重载。
            Base64.decode.overload("java.lang.String", "int").implementation = function (str, flags) {
                // 执行原始解码，得到真实字节数组。
                const output = this.decode(str, flags);
                // 未被过滤时输出编码文本和解码后的数据预览。
                if (!shouldFilter()) {
                    // 输出待解码字符串的字符数。
                    log("Base64", CLR.CYAN, `decode(${str.length} chars)`);
                    // 截断展示输入的 Base64 字符串。
                    console.log(`  ${CLR.CYAN}编码:${CLR.RESET} ${str.substring(0, CONFIG.MAX_DATA_LEN)}`);
                    // 输出解码结果的文本或十六进制预览。
                    console.log(`  ${CLR.GREEN}解码:${CLR.RESET} ${formatData(output)}`);
                }
                // 返回原始解码结果。
                return output;
            };

            // Hook Android Base64 的“byte[] 解码为 byte[]”重载。
            Base64.decode.overload("[B", "int").implementation = function (input, flags) {
                // 执行原始解码。
                const output = this.decode(input, flags);
                // 未被过滤时输出输入、输出长度和解码结果。
                if (!shouldFilter()) {
                    // 输出本次解码的输入与输出字节数。
                    log("Base64", CLR.CYAN, `decode(${input.length} B) → ${output.length} B`);
                    // 输出解码后的实际字节数据。
                    console.log(`  ${CLR.GREEN}解码:${CLR.RESET} ${formatData(output)}`);
                }
                // 将原始结果返回给 App。
                return output;
            };

            // 记录 Android Base64 Hook 安装成功。
            log("Base64", CLR.GREEN, "android.util.Base64 已 hook ✓");
        } catch (e) {
            // Android Base64 类或重载不可用时静默跳过。
        }

        // java.util.Base64 (API 26+)
        try {
            // 获取 Java 8+ 的 Base64 编码器内部类。
            const JBase64Encoder = Java.use("java.util.Base64$Encoder");
            // Hook Java Base64 编码器的 byte[] 编码方法。
            JBase64Encoder.encode.overload("[B").implementation = function (input) {
                // 执行原始编码，得到实际 byte[] 格式的编码结果。
                const output = this.encode(input);
                // 未被过滤时记录原文，但原脚本未额外打印编码输出。
                if (!shouldFilter()) {
                    // 输出此次编码的输入长度。
                    log("Base64(J)", CLR.CYAN, `encode(${input.length} B)`);
                    // 输出编码前的输入数据预览。
                    console.log(`  ${CLR.CYAN}原文:${CLR.RESET} ${formatData(input)}`);
                }
                // 返回原始编码结果。
                return output;
            };

            // 获取 Java 8+ 的 Base64 解码器内部类。
            const JBase64Decoder = Java.use("java.util.Base64$Decoder");
            // Hook Java Base64 解码器的 byte[] 解码方法。
            JBase64Decoder.decode.overload("[B").implementation = function (input) {
                // 执行原始解码，得到实际明文字节。
                const output = this.decode(input);
                // 未被过滤时输出解码结果。
                if (!shouldFilter()) {
                    // 输出解码后的字节长度。
                    log("Base64(J)", CLR.CYAN, `decode → ${output.length} B`);
                    // 输出解码后的内容预览。
                    console.log(`  ${CLR.GREEN}解码:${CLR.RESET} ${formatData(output)}`);
                }
                // 返回原始解码结果。
                return output;
            };
            // 记录 Java Base64 Hook 安装成功。
            log("Base64(J)", CLR.GREEN, "java.util.Base64 已 hook ✓");
        } catch (e) {
            // Java Base64 在低版本系统上不可用时静默跳过。
        }
    }


//  7. GZIP 压缩 / 解压
    

    // 仅当配置开启时才安装 GZIP Hook，默认关闭以避免压缩流量产生大量日志。
    if (CONFIG.HOOK_GZIP) {
        try {
            // 获取字节数组输出流类；此变量由原脚本保留，但当前 GZIP Hook 未直接使用它。
            const ByteArrayOutputStream = Java.use("java.io.ByteArrayOutputStream");
            // 获取 GZIP 输出流类，用来观察压缩前写入的数据。
            const GZIPOutputStream = Java.use("java.util.zip.GZIPOutputStream");

            // Hook GZIPOutputStream.write(byte[], offset, length) 的数据写入入口。
            GZIPOutputStream.write.overload("[B", "int", "int").implementation = function (buf, off, len) {
                // 未被包名过滤时，尝试提取本次要压缩的有效字节切片。
                if (!shouldFilter()) {
                    try {
                        // 从原始缓冲区复制 off 开始、长度为 len 的数据为新的 Java byte[]。
                        const data = Java.array("byte", Array.from({length: len}, (_, i) => buf[off + i]));
                        // 输出本次压缩写入的数据长度。
                        log("GZIP", CLR.YELLOW, `compress write(${len} B)`);
                        // 输出压缩前的明文或二进制预览。
                        console.log(`  ${CLR.CYAN}明文:${CLR.RESET} ${formatData(data)}`);
                    } catch (_) {
                        // 缓冲区读取失败时不影响原始写入。
                    }
                }
                // 调用原始 write，将数据真正写入 GZIP 流；该方法本身返回 void。
                this.write(buf, off, len);
            };
            // 记录 GZIP 输出流 Hook 安装成功。
            log("GZIP", CLR.GREEN, "GZIPOutputStream 已 hook ✓");
        } catch (e) {
            // 当前环境没有 GZIP 输出流或重载不可用时静默跳过。
        }

        try {
            // 获取 GZIP 输入流类，用来观察解压后写入调用方缓冲区的数据。
            const GZIPInputStream = Java.use("java.util.zip.GZIPInputStream");
            // Hook GZIPInputStream.read(byte[], offset, length) 的读取入口。
            GZIPInputStream.read.overload("[B", "int", "int").implementation = function (buf, off, len) {
                // 先调用原始 read，因为只有读取完成后缓冲区中才包含解压结果。
                const bytesRead = this.read(buf, off, len);
                // 仅在未被过滤且确实读到至少一个字节时记录解压数据。
                if (!shouldFilter() && bytesRead > 0) {
                    try {
                        // 只复制原方法实际写入的 bytesRead 字节，避免输出未初始化缓冲区。
                        const data = Java.array("byte", Array.from({length: bytesRead}, (_, i) => buf[off + i]));
                        // 输出本次解压读取的实际字节数。
                        log("GZIP", CLR.YELLOW, `decompress read(${bytesRead} B)`);
                        // 输出解压后的内容预览。
                        console.log(`  ${CLR.GREEN}解压:${CLR.RESET} ${formatData(data)}`);
                    } catch (_) {
                        // 缓冲区复制失败时不影响原始 read 的返回结果。
                    }
                }
                // 将原始 read 返回的字节数交还给 App。
                return bytesRead;
            };
            // 记录 GZIP 输入流 Hook 安装成功。
            log("GZIP", CLR.GREEN, "GZIPInputStream 已 hook ✓");
        } catch (e) {
            // 当前环境没有 GZIP 输入流或重载不可用时静默跳过。
        }
    }


//  8. JSONObject.toString() — 抓 SDK 构造的 JSON
    

    // 仅当配置开启时 Hook JSONObject.toString；默认开启，因为它能捕获加密前的 JSON 明文。
    if (CONFIG.HOOK_JSON) {
        try {
            // 获取 Android/Java 常用的 JSON 对象类。
            const JSONObject = Java.use("org.json.JSONObject");
            // Hook 无参 toString，以观察 SDK 序列化 JSON 时得到的完整文本。
            JSONObject.toString.overload().implementation = function () {
                // 先执行原始 toString，取得 App 实际将要使用的 JSON 文本。
                const result = this.toString();
                // 仅记录未被过滤且长度超过 20 个字符的 JSON，排除简单空对象等噪声。
                if (!shouldFilter() && result.length > 20) {
                    // 只打印较长的 JSON（避免噪声）
                    // 输出 JSON 序列化事件和原文本长度。
                    log("JSON", CLR.WHITE, `JSONObject.toString() (${result.length} chars)`);
                    // 当 JSON 很长时只截取前 MAX_DATA_LEN 个字符作为预览。
                    const preview = result.length > CONFIG.MAX_DATA_LEN
                        // 超过长度上限时取前缀并追加省略号。
                        ? result.substring(0, CONFIG.MAX_DATA_LEN) + "..."
                        // 未超过上限时完整保留结果。
                        : result;
                    // 输出 JSON 明文预览。
                    console.log(`  ${CLR.GREEN}${preview}${CLR.RESET}`);
                    // 输出构造此 JSON 的业务调用栈。
                    console.log(getStackTrace());
                }
                // 将原始 JSON 字符串返回给 App。
                return result;
            };
            // 记录 JSONObject Hook 安装成功。
            log("JSONObject", CLR.GREEN, "org.json.JSONObject 已 hook ✓");
        } catch (e) {
            // JSONObject 类或其无参 toString 重载不可用时静默跳过。
        }
    }


//  9. URL / HttpURLConnection — 请求 URL 记录
    

    try {
        // 获取 URL 类；原脚本保留此变量作为网络上下文，当前未直接使用它。
        const URL = Java.use("java.net.URL");
        // 获取 Java HTTP 连接抽象类。
        const HttpURLConnection = Java.use("java.net.HttpURLConnection");

        // Hook 请求体输出流入口；调用该方法通常表示 App 准备写入 HTTP 请求体。
        HttpURLConnection.getOutputStream.implementation = function () {
            // 未被过滤时记录 HTTP 方法与目标 URL，不读取请求体内容。
            if (!shouldFilter()) {
                // 从连接对象读取方法和 URL，并写入一条网络上下文日志。
                log("HTTP", CLR.CYAN, `${this.getRequestMethod()} ${this.getURL().toString()}`);
            }
            // 调用原始 getOutputStream，把真正的输出流交给 App。
            return this.getOutputStream();
        };
        // 记录 HttpURLConnection Hook 安装成功。
        log("HTTP", CLR.GREEN, "HttpURLConnection 已 hook ✓");
    } catch (e) {
        // HTTP 连接类或该方法不可用时静默跳过。
    }


//  10. 自定义加密类探测
    

    // 仅当配置开启时才进行自定义加密类探测；该功能只找候选类，不会为其自动安装 Hook。
    if (CONFIG.PROBE_CUSTOM_CRYPTO) {
        // 延迟执行，等 App 类加载完成
        // 等待 3 秒，让 App 与 SDK 有机会加载更多类，再开始枚举。
        setTimeout(function () {
            // 输出探测开始日志。
            log("Probe", CLR.PURPLE, "开始探测自定义加密类 ...");

            // 定义可能与加密、编码、签名相关的类名关键词。
            const keywords = [
                // 通用动词及常见算法名称。
                "encrypt", "decrypt", "cipher", "crypto",
                // 常见算法与编码关键词。
                "aes", "rsa", "des", "encode", "decode",
                // 签名、密钥和常见工具类命名关键词。
                "sign", "verify", "secret", "SecurityUtil",
                // 常见自定义工具类名。
                "EncryptUtil", "CryptoUtil", "AESUtil", "RSAUtil",
            ];

            // 枚举当前进程中已加载的全部 Java 类。
            Java.enumerateLoadedClasses({
                // 每发现一个类名就执行一次此回调。
                onMatch: function (className) {
                    // 统一转成小写，便于做不区分大小写的关键词匹配。
                    const lower = className.toLowerCase();
                    // 依次检查每一个加密相关关键词。
                    for (const kw of keywords) {
                        // 类名命中关键词且不属于系统、加密库或 Frida 自身时，认定为候选类。
                        if (lower.includes(kw) &&
                            // 排除 Java 核心类，避免列出系统自带加密实现。
                            !lower.startsWith("java.") &&
                            // 排除 javax 标准库类。
                            !lower.startsWith("javax.") &&
                            // 排除 Android 框架类。
                            !lower.startsWith("android.") &&
                            // 排除 com.android 系统实现。
                            !lower.startsWith("com.android.") &&
                            // 排除 Sun/Oracle JDK 内部类。
                            !lower.startsWith("sun.") &&
                            // 排除 Bouncy Castle 等已知第三方通用加密库。
                            !lower.startsWith("org.bouncycastle.") &&
                            // 排除 Frida 自身相关类。
                            !lower.includes("frida") &&
                            // 排除绕过脚本相关类。
                            !lower.includes("bypass")) {
                            // 记录候选自定义加密类的完整名称，供人工后续分析。
                            log("Probe", CLR.PURPLE, `发现可疑加密类: ${CLR.BOLD}${className}${CLR.RESET}`);
                            // 当前类已命中一个关键词即可停止继续匹配其余关键词，防止重复打印。
                            break;
                        }
                    }
                },
                // 枚举所有已加载类后执行一次此回调。
                onComplete: function () {
                    // 输出探测结束日志。
                    log("Probe", CLR.PURPLE, "自定义加密类探测完成");
                },
            });
        // 传入 3000 毫秒，表示延迟三秒执行上述枚举函数。
        }, 3000);
    }


//  11. Protobuf 序列化检测
    

    try {
        // Google Protobuf Lite
        // 获取 Protobuf Lite 消息基类；多数 Lite 消息在序列化时会调用 toByteArray。
        const AbstractMessageLite = Java.use("com.google.protobuf.AbstractMessageLite");
        // Hook Protobuf 消息序列化为 byte[] 的入口。
        AbstractMessageLite.toByteArray.implementation = function () {
            // 先执行原始序列化，得到 App 真实发送或存储的二进制结果。
            const output = this.toByteArray();
            // 未被过滤时输出序列化证据。
            if (!shouldFilter()) {
                // 输出序列化产物的字节长度。
                log("Protobuf", CLR.YELLOW, `toByteArray() → ${output.length} B`);
                // 输出当前 Protobuf 消息对象的具体类名。
                console.log(`  ${CLR.CYAN}类型:${CLR.RESET} ${this.getClass().getName()}`);
                // 尝试 toString 获取可读格式
                try {
                    // 调用消息对象的 toString，部分 Protobuf 实现会给出字段名和值的可读表示。
                    const readable = this.toString();
                    // 只对长度小于 2,000 字符的可读文本输出内容，避免极大日志。
                    if (readable.length < 2000) {
                        // 再按统一的 MAX_DATA_LEN 截取可读内容预览。
                        console.log(`  ${CLR.GREEN}内容:${CLR.RESET} ${readable.substring(0, CONFIG.MAX_DATA_LEN)}`);
                    }
                } catch (_) {
                    // 消息的 toString 不可读或失败时，仅保留类型和长度证据。
                }
                // 输出调用序列化操作的业务调用栈。
                console.log(getStackTrace());
            }
            // 把原始 Protobuf 字节数组返回给 App。
            return output;
        };
        // 记录 Google Protobuf Hook 安装成功。
        log("Protobuf", CLR.GREEN, "com.google.protobuf 已 hook ✓");
    } catch (e) {
        // 未打包 Google Protobuf Lite 的 App 会进入此分支；这不是审计失败。
        log("Protobuf", CLR.GRAY, "未发现 Protobuf 库");
    }

    // 微信/腾讯的 MicroMsg Protobuf
    try {
        // 尝试取得腾讯微信协议中的 Protobuf 基类；当前仅探测其是否存在，未替换任何方法。
        const ProtoBuf = Java.use("com.tencent.mm.protocal.protobuf.AbsProtoBuf");
        // 输出发现腾讯 Protobuf 库的提示，供人工判断是否需要扩展专用 Hook。
        log("Protobuf", CLR.YELLOW, "发现腾讯 Protobuf: com.tencent.mm.protocal.protobuf");
    } catch (e) {
        // 目标 App 未包含该腾讯类时静默跳过。
    }


    // 输出最终横幅，表示所有已启用且可用的 Hook 都已安装完成。
    separator("Hook 完成 — 等待 App 产生加密调用 ...");
    // 输出初始化结束提示；eventCounter 当前未被拼入文案，保留原脚本的提示文本。
    log("init", CLR.GREEN, `共注册 Hook 点，日志输出中 ...`);
    // 告知操作员应继续在 App 中操作，以触发 SDK 或业务层的加解密调用。
    log("tip", CLR.GRAY, "操作 App 触发 SDK 请求，加解密调用将在此处实时打印");
    // 告知操作员使用 Ctrl+C 停止 Frida，并可通过 -o 参数保存日志。
    log("tip", CLR.GRAY, "按 Ctrl+C 停止，日志可用 -o 参数重定向到文件");

// 结束 Java.perform 回调；此后脚本持续驻留，等待被 Hook 方法被 App 调用。
});
