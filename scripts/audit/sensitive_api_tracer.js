/*
 * sensitive_api_tracer.js
 *
 * 作用：在目标 Android App 的 Java 进程内运行，记录剪贴板、定位、基站和设备标识等
 * 敏感 API 的调用；同时基于 Activity 生命周期推断前后台状态，并统计最近一分钟的调用次数。
 *
 * 输出：本脚本只调用 console.log；Dashboard 启动 Frida 时会把这些输出写入 <包名>.txt。
 * 它不读取 API 返回值，也不直接判断数据是否已上传；网络上报要由 privacy_auditor.py 佐证。
 */

// 启用 JavaScript 严格模式，避免隐式创建全局变量等不安全写法。
'use strict';

// ── 滑动窗口频次配置 ──

// 定义频次统计的窗口长度为 60,000 毫秒，即最近 60 秒。
var WINDOW_MS = 60000;

// 为每类敏感 API 设置“最近 60 秒内允许的最大调用次数”；真正告警条件是严格大于该值。
var THRESHOLDS = { location: 10, clipboard: 3, cell: 10, deviceid: 10 };

// 保存各类别的调用时间戳，结构为：类别名 -> [时间戳1, 时间戳2, ...]。
var calls = {};

// ── 前台/后台状态：基于已 start 的 Activity 计数 ──

// 记录已执行 onStart、但还没有执行 onStop 的 Activity 数量。
var startedActivities = 0;

// 记录 App 是否至少进入过一次前台，避免脚本刚注入时把初始状态误判为后台。
var everForeground = false;

// 根据生命周期计数返回当前是否可视为后台：曾进过前台且没有已启动的 Activity。
function isBackground() {
    // 同时满足两个条件时才返回 true，防止初始注入阶段误报后台。
    return everForeground && startedActivities <= 0;
}

// 取得一小段 Java 调用栈，用来说明“是谁触发了这次敏感 API 调用”。
function shortStack() {
    try {
        // 在目标 App 的 Java 虚拟机中取得 Exception 类。
        var Exception = Java.use('java.lang.Exception');

        // 在目标 App 的 Java 虚拟机中取得 Android 日志工具类。
        var Log = Java.use('android.util.Log');

        // 创建一个临时异常，并让 Android 把它格式化为完整调用栈字符串。
        var st = Log.getStackTraceString(Exception.$new());

        // 按换行拆分调用栈，并移除脚本自身和空白行，减少无关信息。
        var lines = st.split('\n').filter(function (l) {
            // 排除包含本脚本名称的栈帧，同时保留非空白的业务栈帧。
            return l.indexOf('sensitive_api_tracer') < 0 && l.trim().length;
        });

        // 跳过异常创建帧后保留最多 4 帧，并以缩进形式合并为一段文本。
        return lines.slice(1, 5).join('\n    ');
    } catch (e) {
        // 如果 Java 类不可用或获取调用栈失败，返回占位文本而不影响目标 App。
        return '(调用栈不可用)';
    }
}

// 处理一次敏感 API 命中：维护窗口计数、判断状态，并输出可读证据。
function hit(group, api) {
    // 获取本次调用发生时的 Unix 时间戳，单位为毫秒。
    var now = Date.now();

    // 取得当前类别的时间戳数组；若首次命中该类别，则创建一个空数组保存它。
    var arr = calls[group] || (calls[group] = []);

    // 将本次调用的时间戳追加到该类别的调用历史中。
    arr.push(now);

    // 从数组头部持续删除 60 秒之前的记录，使数组始终表示“最近一分钟”。
    while (arr.length && arr[0] < now - WINDOW_MS) {
        // 移除最早的一次过期调用记录。
        arr.shift();
    }

    // 基于 Activity 生命周期计数判断本次调用时 App 是否处在后台。
    var bg = isBackground();

    // 当前数组长度就是该类别在最近 60 秒内的调用次数，且已包含本次调用。
    var n = arr.length;

    // 预先声明将要输出的主日志文本。
    var line;

    // 后台状态优先：只要后台仍在读取敏感 API，就标记为后台静默采集。
    if (bg) {
        // 说明 API 名称及其在当前滑动窗口内的第几次调用。
        line = '[后台静默] ' + api + '  ⚠ 应用在后台仍调用敏感 API（窗口内第 ' + n + ' 次/分）';
    // 仅在前台状态下比较频次阈值；未知类别使用 9999，通常不会触发超频次。
    } else if (n > (THRESHOLDS[group] || 9999)) {
        // 输出超频次告警，并同时显示实际次数与配置阈值。
        line = '[超频次][前台] ' + api + '  ⚠ ' + n + ' 次/分 (阈值 ' + THRESHOLDS[group] + ')';
    // 未处于后台、也未超过阈值时，作为普通敏感 API 调用记录。
    } else {
        // 输出前台调用及其在当前 60 秒滑动窗口中的序号。
        line = '[敏感API][前台] ' + api + '  窗口内第 ' + n + ' 次/分';
    }

    // 将主结论输出给 Frida；Dashboard 会把标准输出写入结果 TXT 文件。
    console.log(line);

    // 紧接着输出精简调用栈，便于定位触发调用的 App 类或 SDK 类。
    console.log('    ' + shortStack());
}

// 通用Hook工具：为一个Java类中的若干方法安装“计数 + 放行原实现”的拦截器。
function hookCounter(clazz, methods, group) {
    // 预先声明 Frida 包装后的 Java 类变量。
    var C;

    try {
        // 从当前 App 进程的 Java 虚拟机中取得指定类；某些系统版本不存在该类时会抛异常。
        C = Java.use(clazz);
    } catch (e) {
        // 类不存在时返回 false，让外层日志说明该组 Hook 被跳过。
        return false;
    }

    // 从完整类名中取最后一段，形成更短、更易读的日志名称，例如 LocationManager。
    var simple = clazz.substring(clazz.lastIndexOf('.') + 1);

    // 逐一处理传入的方法名列表。
    methods.forEach(function (m) {
        // 如果当前 Android 版本或厂商实现没有该方法，则跳过它。
        if (!C[m]) {
            return;
        }

        try {
            // 同一 Java 方法可能有多个参数签名；必须为每个重载版本分别安装 Hook。
            C[m].overloads.forEach(function (ov) {
                // 替换此重载版本的实现，使每次调用都会先经过此函数。
                ov.implementation = function () {
                    try {
                        // 先记录本次敏感访问；只记录方法名，不读取方法参数或返回值。
                        hit(group, simple + '.' + m + '()');
                    } catch (e) {
                        // 记录失败时吞掉异常，避免审计脚本影响目标 App 的正常运行。
                    }

                    // 使用同样的参数调用原始 Java 实现并返回原结果，避免形成递归调用。
                    return this[m].apply(this, arguments);
                };
            });
        } catch (e) {
            // 某个重载安装失败时跳过它；其他方法和重载仍可继续安装。
        }
    });

    // 类已成功取得即返回 true；这并不保证列表中的每个方法都一定存在。
    return true;
}

// 等待Frida确认Java运行环境已就绪后，再执行所有Java.use和Hook操作。
Java.perform(function () {
    // 定义统一的安装结果日志函数；done 为 true 表示目标类已成功取得。
    function ok(name, done) {
        // 将各组 Hook 的安装结果写到 Frida 日志中。
        console.log('[sensitive] hook ' + name + (done ? ' ✓' : ' ✗ (类不存在，跳过)'));
    }

    // 输出启动横幅，表示脚本已进入 Java 环境并开始安装 Hook。
    console.log('──────── Sensitive API Tracer 已启动 ────────');

    // 1) 生命周期 Hook：以 Activity 的 onStart/onStop 维护前后台状态机。
    try {
        // 取得 Android Activity 基类，以便拦截生命周期方法。
        var Activity = Java.use('android.app.Activity');

        // 替换 Activity.onStart，在 Activity 开始时增加前台 Activity 计数。
        Activity.onStart.implementation = function () {
            // 将当前已启动 Activity 数量加一。
            startedActivities++;

            // 只要出现过一次 onStart，就记录 App 曾经进入过前台。
            everForeground = true;

            // 调用原始 onStart 实现，使 App 原有生命周期逻辑继续执行。
            return this.onStart();
        };

        // 替换 Activity.onStop，在 Activity 停止时减少前台 Activity 计数。
        Activity.onStop.implementation = function () {
            // 仅在计数为正时递减，避免异常生命周期顺序导致负数。
            if (startedActivities > 0) {
                // 记录一个 Activity 已停止。
                startedActivities--;
            }

            // 当没有任何已启动 Activity 时，输出“可能已切后台”的状态日志。
            if (startedActivities <= 0) {
                // 这是一条状态提示，后续敏感 API 命中才会成为真正的后台读取证据。
                console.log('[状态] ▽ 应用切入后台');
            }

            // 调用原始 onStop 实现，保持目标 App 正常的生命周期执行。
            return this.onStop();
        };

        // 替换 Activity.onResume，用于在特殊生命周期顺序下提示 App 回到前台。
        Activity.onResume.implementation = function () {
            // 若 onResume 时计数仍未恢复，记录一次回前台状态提示。
            if (startedActivities <= 0) {
                // 正常场景通常先触发 onStart 再触发 onResume，因此此日志不一定每次都会出现。
                console.log('[状态] △ 应用回到前台');
            }

            // 调用原始 onResume 实现，避免破坏页面恢复逻辑。
            return this.onResume();
        };

        // 输出生命周期 Hook 已安装的结果。
        ok('Activity 生命周期（前台/后台判定）', true);
    } catch (e) {
        // 若 Activity 类或生命周期方法无法 Hook，则输出失败提示而不中断其他敏感 API Hook。
        ok('Activity 生命周期', false);
    }

    // 2) 安装剪贴板相关读取和探测 API 的计数 Hook。
    ok('ClipboardManager（剪贴板）', hookCounter(
        // 指定需要 Hook 的 Android 剪贴板管理器类。
        'android.content.ClipboardManager',
        // 指定读取剪贴板内容、描述信息或判断是否存在内容的方法。
        ['getPrimaryClip', 'getText', 'getPrimaryClipDescription', 'hasPrimaryClip'],
        // 将上述方法的计数统一归入 clipboard 类别。
        'clipboard'));

    // 3) 安装定位读取或定位请求 API 的计数 Hook。
    ok('LocationManager（定位）', hookCounter(
        // 指定 Android 系统定位管理器类。
        'android.location.LocationManager',
        // 覆盖缓存定位、持续更新、单次更新和当前定位等常见入口。
        ['getLastKnownLocation', 'requestLocationUpdates', 'requestSingleUpdate', 'getCurrentLocation'],
        // 将上述方法的计数统一归入 location 类别。
        'location'));

    // 4) 安装基站和蜂窝信息读取 API 的计数 Hook。
    ok('TelephonyManager（基站）', hookCounter(
        // 指定 Android 电话服务管理器类。
        'android.telephony.TelephonyManager',
        // 覆盖旧版单一基站位置与新版完整小区信息的读取入口。
        ['getCellLocation', 'getAllCellInfo'],
        // 将上述方法的计数统一归入 cell 类别。
        'cell'));

    // 5) 安装设备标识读取 API 的计数 Hook。
    ok('TelephonyManager（设备标识）', hookCounter(
        // 同样使用电话服务管理器类，因为多种蜂窝设备标识由此提供。
        'android.telephony.TelephonyManager',
        // 覆盖设备 ID、IMEI、MEID、IMSI 和 SIM 序列号等读取入口。
        ['getDeviceId', 'getImei', 'getMeid', 'getSubscriberId', 'getSimSerialNumber'],
        // 将上述方法的计数统一归入 deviceid 类别。
        'deviceid'));

    // 输出结束横幅，表示所有可用的敏感 API Hook 已安装，之后等待真实调用。
    console.log('──────── Sensitive API Hook 完成 — 等待敏感调用 ────────');
});
