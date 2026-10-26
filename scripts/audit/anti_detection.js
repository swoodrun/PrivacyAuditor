/*
 * anti_detection.js — 反 Frida 检测（v4 · 退出/杀进程全拦截，含 syscall 兜底）
 *
 * 为什么有 v2：
 *   v1 hook 了 strcmp/strncmp/strstr/fgets 这些超高频 libc 函数，
 *   京东等 App 启动时每秒调用几十万次 → 切进 JS 层 + readCString 再调 libc，
 *   导致严重卡顿甚至死锁（表现为"日志不再输出、卡住"）。
 *   v2 移除所有高频字符串 hook，只保留【低频 + 高价值 + 安全】的拦截：
 *     1) connect() 拦截 27042/27043   —— 让 App 探测 frida 控制端口失败
 *     2) 文件存在性检查（open/openat/access/stat/lstat/fopen）含 frida 路径 → 返回不存在
 *     3) 检测到就自杀：System.exit / Process.killProcess / kill(self) 失效
 *
 * 代价：不再做 /proc 字符串行过滤（那要 hook fgets，太危险）。因此对
 *   "扫 /proc/self/maps 找 frida-agent"这类检测无效——这类硬核 App（如京东）
 *   建议改用 Layer 1：把 frida-server 改随机名 + 换非默认端口，从源头隐藏。
 *
 * 用法（放最前面第一个 -l）：
 *   frida -U -f 包名 -l anti_detection.js -l ssl_bypass.js -l crypto_tracer.js -l sensitive_api_tracer.js -o 包名.txt
 */

'use strict';

var VER = "v4(退出/杀进程全拦截+syscall兜底)";
var NEEDLES = ["frida", "frida-server", "frida-agent", "re.frida", "/data/local/tmp/frida", "gum-js", "linjector"];
var FRIDA_PORTS = [27042, 27043];

function hasFrida(s) {
    if (!s) return false;
    var low = s.toLowerCase();
    for (var i = 0; i < NEEDLES.length; i++) {
        if (low.indexOf(NEEDLES[i]) !== -1) return true;
    }
    return false;
}
function exp(name) { return Module.findExportByName(null, name); }
function anti(tag, msg) { console.log("[anti] " + tag + " " + msg); }

// ════════ 1. 文件存在性检查：路径含 frida → 返回"不存在" ════════
//   只在文件操作时触发（频率远低于 strcmp），安全。
function denyByPath(funcName, pathArgIdx, failVal) {
    var p = exp(funcName);
    if (!p) return;
    try {
        Interceptor.attach(p, {
            onEnter: function (args) {
                this.deny = false;
                try {
                    var path = args[pathArgIdx].readCString();
                    if (path && hasFrida(path)) { this.deny = true; this.path = path; }
                } catch (e) {}
            },
            onLeave: function (retval) {
                if (this.deny) {
                    retval.replace(ptr(failVal));
                    anti("路径隐藏", funcName + "(" + this.path + ") → 不存在");
                }
            }
        });
        console.log("[anti] hook " + funcName + " ✓");
    } catch (e) { console.log("[anti] hook " + funcName + " ✗ " + e); }
}

// ════════ 2. connect() 拦截 frida 控制端口 ════════
function denyFridaPort() {
    var connectPtr = exp("connect");
    if (!connectPtr) return;
    try {
        Interceptor.attach(connectPtr, {
            onEnter: function (args) {
                this.block = false;
                try {
                    var sa = args[1];
                    var family = sa.readU16();
                    if (family === 2 || family === 10) {     // AF_INET / AF_INET6
                        var port = (sa.add(2).readU8() << 8) | sa.add(3).readU8();
                        if (FRIDA_PORTS.indexOf(port) !== -1) this.block = true;
                    }
                } catch (e) {}
            },
            onLeave: function (retval) {
                if (this.block) { retval.replace(ptr("-1")); anti("端口隐藏", "拦截 connect → 27042/27043"); }
            }
        });
        console.log("[anti] hook connect ✓");
    } catch (e) { console.log("[anti] hook connect ✗ " + e); }
}

// ════════ 3. native kill(self) 拦截 ════════
function denyNativeKill() {
    var killPtr = exp("kill");
    if (!killPtr) return;
    try {
        var realKill = new NativeFunction(killPtr, "int", ["int", "int"]);
        var myPid = Process.id;
        Interceptor.replace(killPtr, new NativeCallback(function (pid, sig) {
            if (pid === myPid && (sig === 9 || sig === 15 || sig === 6)) {
                anti("拦截自杀", "kill(self, " + sig + ")");
                return 0;
            }
            return realKill(pid, sig);
        }, "int", ["int", "int"]));
        console.log("[anti] hook kill(self) ✓");
    } catch (e) { console.log("[anti] hook kill ✗ " + e); }
}

// ════════ 3b. native 退出拦截：exit/_exit/abort/raise/tgkill ════════
//   检测到 frida 后走 native 退出（绕过 Java System.exit）。这些只在退出时调用，
//   频率极低 → 拦截安全，不会卡死。注：bionic 里 _exit 与 _Exit 是同一函数，hook _exit 即可。
function denyNativeExit() {
    [["exit", "void", ["int"]], ["_exit", "void", ["int"]],
     ["abort", "void", []]].forEach(function (s) {
        var p = exp(s[0]);
        if (!p) return;
        try {
            Interceptor.replace(p, new NativeCallback(function () {
                anti("拦截退出", s[0] + "() 已被阻止");
            }, s[1], s[2]));
            console.log("[anti] hook " + s[0] + " ✓");
        } catch (e) { console.log("[anti] hook " + s[0] + " ✗ " + e); }
    });
    var myPid = Process.id;
    var fatal = function (sig) { return sig === 6 || sig === 9 || sig === 15; };
    // raise(sig)：自发致命信号
    var raisePtr = exp("raise");
    if (raisePtr) {
        try {
            var realRaise = new NativeFunction(raisePtr, "int", ["int"]);
            Interceptor.replace(raisePtr, new NativeCallback(function (sig) {
                if (fatal(sig)) { anti("拦截退出", "raise(" + sig + ")"); return 0; }
                return realRaise(sig);
            }, "int", ["int"]));
            console.log("[anti] hook raise ✓");
        } catch (e) { console.log("[anti] hook raise ✗ " + e); }
    }
    // tgkill(tgid, tid, sig)：pthread_kill / raise 最终走这里；拦截发给本进程的致命信号
    var tgkillPtr = exp("tgkill");
    if (tgkillPtr) {
        try {
            var realTgkill = new NativeFunction(tgkillPtr, "int", ["int", "int", "int"]);
            Interceptor.replace(tgkillPtr, new NativeCallback(function (tgid, tid, sig) {
                if (tgid === myPid && fatal(sig)) { anti("拦截退出", "tgkill(self," + sig + ")"); return 0; }
                return realTgkill(tgid, tid, sig);
            }, "int", ["int", "int", "int"]));
            console.log("[anti] hook tgkill ✓");
        } catch (e) { console.log("[anti] hook tgkill ✗ " + e); }
    }
}

// ════════ 3c. syscall 兜底：拦截绕过 libc、直接发退出/杀进程 syscall 的检测 ════════
//   有些加固直接 syscall(exit_group / tgkill ...)，绕开上面的 libc hook。
//   做法：在 onEnter 把退出类 syscall 号改成无害的 getpid，让它"杀不掉自己"。
function denySyscallExit() {
    var syscallPtr = exp("syscall");
    if (!syscallPtr) return;
    var NR = {
        "x64":   { exit: 60, exit_group: 231, kill: 62,  tgkill: 234, getpid: 39 },
        "arm64": { exit: 93, exit_group: 94,  kill: 129, tgkill: 131, getpid: 172 },
        "arm":   { exit: 1,  exit_group: 248, kill: 37,  tgkill: 268, getpid: 20 },
        "ia32":  { exit: 1,  exit_group: 252, kill: 37,  tgkill: 270, getpid: 20 }
    }[Process.arch];
    if (!NR) { console.log("[anti] syscall: 未知架构 " + Process.arch + "，跳过"); return; }
    var myPid = Process.id;
    var fatal = function (s) { return s === 6 || s === 9 || s === 15; };
    try {
        Interceptor.attach(syscallPtr, {
            onEnter: function (args) {
                var num = args[0].toInt32();
                if (num === NR.exit_group || num === NR.exit) {
                    anti("拦截退出", "syscall(exit," + num + ")"); args[0] = ptr(NR.getpid);
                } else if (num === NR.tgkill) {
                    if (args[1].toInt32() === myPid && fatal(args[3].toInt32())) {
                        anti("拦截退出", "syscall(tgkill,self)"); args[0] = ptr(NR.getpid);
                    }
                } else if (num === NR.kill) {
                    if (args[1].toInt32() === myPid && fatal(args[2].toInt32())) {
                        anti("拦截退出", "syscall(kill,self)"); args[0] = ptr(NR.getpid);
                    }
                }
            }
        });
        console.log("[anti] hook syscall（退出兜底, arch=" + Process.arch + "）✓");
    } catch (e) { console.log("[anti] hook syscall ✗ " + e); }
}

// ════════ 4. Java 层：让"检测到就自杀"失效 ════════
function denyJavaKill() {
    Java.perform(function () {
        function noop(cls, method) {
            try {
                var C = Java.use(cls);
                C[method].overloads.forEach(function (ov) {
                    ov.implementation = function () { anti("拦截自杀", cls + "." + method + "()"); };
                });
                console.log("[anti] 阻止 " + cls + "." + method + " ✓");
            } catch (e) {}
        }
        noop("java.lang.System", "exit");
        noop("java.lang.Runtime", "exit");
        noop("java.lang.Runtime", "halt");
        noop("android.os.Process", "killProcess");
        try {
            var P = Java.use("android.os.Process");
            if (P.sendSignal) {
                P.sendSignal.implementation = function (pid, sig) { anti("拦截自杀", "Process.sendSignal(" + pid + "," + sig + ")"); };
            }
        } catch (e) {}
    });
}

// ════════ 启动 ════════
console.log("──────── Anti-Detection " + VER + " 已启动（先于 App 检测代码）────────");
try {
    denyByPath("open", 0, "-1");
    denyByPath("openat", 1, "-1");
    denyByPath("access", 0, "-1");
    denyByPath("stat", 0, "-1");
    denyByPath("lstat", 0, "-1");
    denyByPath("fopen", 0, "0");
} catch (e) { console.log("[anti] path hooks 失败 " + e); }
try { denyFridaPort(); }  catch (e) { console.log("[anti] port hook 失败 " + e); }
try { denyNativeKill(); } catch (e) { console.log("[anti] kill hook 失败 " + e); }
try { denyNativeExit(); }  catch (e) { console.log("[anti] exit hook 失败 " + e); }
try { denySyscallExit(); } catch (e) { console.log("[anti] syscall hook 失败 " + e); }
try { denyJavaKill(); }    catch (e) { console.log("[anti] java guards 失败 " + e); }
console.log("──────── Anti-Detection " + VER + " 安装完成 ────────");
