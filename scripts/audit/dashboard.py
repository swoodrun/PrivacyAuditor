#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
dashboard.py — Android 隐私审计一体化仪表盘（编排器）

把原本"3 个命令行窗口 + 手敲命令 + 手动改名"压成一个界面：
  输入包名 → [开始审计] → 在模拟器里操作（用界面上的同意/后台按钮打标记）
          → [结束审计] → 自动生成报告并按包名命名 → 三个按钮打开结果

它做什么：
  · [开始审计] 用受控工作目录同时拉起：
        mitmdump -s privacy_auditor.py        （流量审计，实时写 audit_log.jsonl）
        frida -U -f <包名> -l ssl_bypass.js -l crypto_tracer.js -l sensitive_api_tracer.js -o <包名>.txt
  · 审计中：[✅ 我点了同意] / [📱 切到后台·📲 回到前台] 直接写 consent.marker / background.marker
  · [结束审计] 先 terminate 两个进程（jsonl 每条已 flush，完整），
        再用 gen_report.py 从 jsonl 生成 <包名>.html，并把 audit_log.jsonl 改名为 <包名>.jsonl
  · 结束后亮起：打开 <包名>.txt / <包名>.html / <包名>.jsonl / 工作目录

它【不】做什么（评委需自行准备的前置条件）：
  1. 模拟器已开启，且 WiFi 代理指向 本机IP:8080、已安装 mitmproxy CA 证书
  2. 模拟器内 frida-server 已推送并以 root 运行（adb shell, /data/local/tmp/frida-server &）
  3. 本机已安装：pip install mitmproxy frida-tools

用法：
    python dashboard.py
打包：
    pyinstaller --onefile --windowed dashboard.py   （exe 需与 scripts 目录保持同样的相对位置）
"""

import os
import re
import sys
import queue
import shutil
import threading
import subprocess
import time
from pathlib import Path
from types import SimpleNamespace

try:
    import tkinter as tk
    from tkinter import ttk, filedialog
except ImportError:
    raise SystemExit("未找到 tkinter，请用 python.org 官方 Python 运行。")



#  路径解析（兼容 .py 直接运行 与 PyInstaller 打包后的 exe） ·

if getattr(sys, "frozen", False):
    BASE = Path(sys.executable).resolve().parent
else:
    BASE = Path(__file__).resolve().parent          # scripts/audit


def _locate(name: str, *rel_dirs: str) -> Path:
    """在 BASE 及若干候选相对目录里找文件，找不到返回 BASE/name（便于报错提示）。"""
    cands = [BASE / name]
    for d in rel_dirs:
        cands += [BASE / d / name, BASE.parent / d / name, BASE.parent.parent / d / name]
    for c in cands:
        if c.exists():
            return c
    return BASE / name


AUDITOR    = _locate("privacy_auditor.py", "audit", "scripts/audit")
SSL_JS     = _locate("ssl_bypass.js", "audit", "scripts/audit")
CRYPTO_JS  = _locate("crypto_tracer.js", "audit", "scripts/audit")
SENS_JS    = _locate("sensitive_api_tracer.js", "audit", "scripts/audit")
ANTI_JS    = _locate("anti_detection.js", "audit", "scripts/audit")
GEN_REPORT = _locate("gen_report.py", "report", "scripts/report")
SDK_REG    = _locate("sdk_registry.py", "audit", "scripts/audit")
ICON       = _locate("icon.ico", "audit", "scripts/audit")

CONSENT_MARKER = "consent.marker"
BACKGROUND_MARKER = "background.marker"
JSONL_NAME = "audit_log.jsonl"
STEALTH_MARK = BASE / "frida_stealth.txt"   # start_frida_server.ps1 -Stealth 写入的隐身端口

PKG_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9_]*(\.[a-zA-Z][a-zA-Z0-9_]*)+$")

BUILD = "v1.2 (2026-06-03)"   # 构建标识

# Windows 下：不弹子进程控制台 + 独立进程组（便于干净结束）
if os.name == "nt":
    CREATE_FLAGS = subprocess.CREATE_NO_WINDOW | subprocess.CREATE_NEW_PROCESS_GROUP
else:
    CREATE_FLAGS = 0

# 高流量App日志洪流保护，防止主线程被刷爆而无响应
LOG_QUEUE_CAP  = 4000   # 日志队列上限，超出则丢弃高频行（jsonl不受影响）
DRAIN_PER_TICK = 200    # 每次刷新最多写入UI的行数（确保回调快速返回）
MAX_LOG_LINES  = 1500   # Text 控件保留的最大行数，超出从顶部裁剪

# UI 配色
C_BG="#eef2f7"; C_CARD="#ffffff"; C_BORDER="#e2e8f0"; C_DISABLED="#e2e8f0"
C_HEADER="#1e293b"; C_TITLE="#ffffff"; C_SUB="#94a3b8"
C_TEXT="#1e293b"; C_MUTED="#64748b"
C_PRIMARY="#2563eb"; C_PRIMARY_H="#1d4ed8"   # 开始
C_DANGER="#ef4444";  C_DANGER_H="#dc2626"    # 结束
C_GREEN="#16a34a";   C_GREEN_H="#15803d"     # 同意
C_AMBER="#f59e0b";   C_AMBER_H="#d97706"     # 切后台
C_TEAL="#0d9488";    C_TEAL_H="#0f766e"      # 回前台
C_SLATE="#475569";   C_SLATE_H="#334155"     # 次级按钮
C_LOGBG="#1e1e1e";   C_LOGFG="#d4d4d4"       # 日志区



#  仪表盘

class Dashboard:
    def __init__(self):
        self.workdir = Path.cwd()
        self.pkg = ""
        self.state = "IDLE"                 # IDLE / RUNNING / FINISHED
        self.mitm_proc = None
        self.frida_proc = None
        # 上游代理：模拟器 → 8080(mitmdump) → 本机代理 → 海外。
        # 留空=直连（默认）
        self.upstream_proxy = os.environ.get("UPSTREAM_PROXY", "")
        self.logq: "queue.Queue[str]" = queue.Queue()
        self.out_txt = self.out_html = self.out_jsonl = None
        self.outdir = None                  # <工作目录>/<包名> 结果文件夹
        self._dropped = 0                   # 被丢弃的高频日志行数
        self._jsonl_offset = 0              # jsonl 已计数到的字节偏移（增量计数）
        self._jsonl_count = 0               # jsonl 累计行数

        self._build_ui()
        self._self_check()
        self.root.after(120, self._drain_log)
        self.root.after(800, self._poll_status)

    # UI
    def _build_ui(self):
        self.root = tk.Tk()
        self.root.title(f"Android 隐私审计仪表盘  {BUILD}")
        self.root.geometry("680x640")
        self.root.minsize(620, 580)
        self.root.configure(bg=C_BG)
        try:
            if ICON.exists():
                self.root.iconbitmap(str(ICON))      # 窗口/任务栏图标
        except Exception:
            pass
        self.topmost = tk.BooleanVar(value=True)
        self.anti_var = tk.BooleanVar(value=False)   # 反检测开关（默认关）
        self.root.attributes("-topmost", True)

        # 头部栏
        header = tk.Frame(self.root, bg=C_HEADER)
        header.pack(fill="x")
        tk.Label(header, text="🛡  Android 隐私审计仪表盘", bg=C_HEADER, fg=C_TITLE,
                 font=("微软雅黑", 15, "bold")).pack(anchor="w", padx=18, pady=(12, 0))
        tk.Label(header, text=f"一键编排 · 静态+动态+加密穿透+合规审计      |      构建 {BUILD}",
                 bg=C_HEADER, fg=C_SUB, font=("微软雅黑", 9)).pack(anchor="w", padx=18, pady=(2, 12))

        body = tk.Frame(self.root, bg=C_BG)
        body.pack(fill="both", expand=True, padx=12, pady=10)

        def card(title=None, expand=False):
            fill = "both" if expand else "x"
            outer = tk.Frame(body, bg=C_CARD, highlightbackground=C_BORDER, highlightthickness=1)
            outer.pack(fill=fill, expand=expand, pady=(0, 10))
            if title:
                tk.Label(outer, text=title, bg=C_CARD, fg=C_MUTED,
                         font=("微软雅黑", 9, "bold")).pack(anchor="w", padx=12, pady=(8, 0))
            inner = tk.Frame(outer, bg=C_CARD)
            inner.pack(fill=fill, expand=expand, padx=12, pady=10)
            return inner

        # 卡片1：包名+开始/结束
        c1 = card()
        tk.Label(c1, text="应用包名", bg=C_CARD, fg=C_TEXT, font=("微软雅黑", 10)).pack(side="left")
        self.pkg_entry = tk.Entry(c1, font=("Consolas", 11), relief="flat", bg="#f1f5f9",
                                  fg=C_TEXT, insertbackground=C_TEXT, disabledbackground=C_DISABLED,
                                  disabledforeground=C_MUTED, highlightthickness=1,
                                  highlightbackground=C_BORDER, highlightcolor=C_PRIMARY)
        self.pkg_entry.pack(side="left", fill="x", expand=True, padx=10, ipady=5)
        self.pkg_entry.insert(0, "com.sankuai.meituan")
        self.start_btn = self._mkbtn(c1, "▶ 开始审计", C_PRIMARY, C_PRIMARY_H,
                                     command=self.on_start, padx=14, pady=6)
        self.start_btn.pack(side="left", padx=(0, 6))
        self.stop_btn = self._mkbtn(c1, "■ 结束审计", C_DANGER, C_DANGER_H,
                                    command=self.on_stop, padx=14, pady=6)
        self.stop_btn.pack(side="left")
        self._btn_enable(self.stop_btn, False)

        # 卡片2：工作目录
        c2 = card()
        tk.Label(c2, text="工作目录", bg=C_CARD, fg=C_MUTED, font=("微软雅黑", 9)).pack(side="left")
        self.dir_lbl = tk.Label(c2, text=str(self.workdir), bg=C_CARD, fg=C_TEXT,
                                font=("微软雅黑", 8), anchor="w")
        self.dir_lbl.pack(side="left", fill="x", expand=True, padx=8)
        self._mkbtn(c2, "选择…", C_SLATE, C_SLATE_H, font=("微软雅黑", 8),
                    command=self.choose_dir, padx=10, pady=3).pack(side="left", padx=(0, 8))
        tk.Checkbutton(c2, text="反检测", variable=self.anti_var, bg=C_CARD, fg=C_MUTED,
                       activebackground=C_CARD, selectcolor=C_CARD, font=("微软雅黑", 8)
                       ).pack(side="left", padx=(0, 6))
        tk.Checkbutton(c2, text="置顶", variable=self.topmost, bg=C_CARD, fg=C_MUTED,
                       activebackground=C_CARD, selectcolor=C_CARD, font=("微软雅黑", 8),
                       command=lambda: self.root.attributes("-topmost", self.topmost.get())
                       ).pack(side="left")
        # 上游代理
        tk.Label(c2, text="上游代理", bg=C_CARD, fg=C_MUTED, font=("微软雅黑", 8)).pack(side="left", padx=(12, 0))
        self.upstream_entry = tk.Entry(c2, font=("Consolas", 9), relief="flat", bg="#f1f5f9",
                                       fg=C_TEXT, insertbackground=C_TEXT, highlightthickness=1,
                                       highlightbackground=C_BORDER, highlightcolor=C_PRIMARY, width=18)
        self.upstream_entry.pack(side="left", padx=(6, 8), ipady=2)
        # 默认留空=直连；有 UPSTREAM_PROXY 环境变量则用它的值
        self.upstream_entry.insert(0, self.upstream_proxy)

        # 卡片3：审计中操作
        c3 = card("审计中操作")
        self.consent_btn = self._mkbtn(c3, "✅ 我点了同意", C_GREEN, C_GREEN_H,
                                       font=("微软雅黑", 11, "bold"), hover=False,
                                       command=self.mark_consent, pady=10)
        self.consent_btn.pack(side="left", fill="x", expand=True, padx=(0, 6))
        self.bg_btn = self._mkbtn(c3, "📱 切到后台", C_AMBER, C_AMBER_H,
                                  font=("微软雅黑", 11, "bold"), hover=False,
                                  command=self.toggle_background, pady=10)
        self.bg_btn.pack(side="left", fill="x", expand=True)
        self._btn_enable(self.consent_btn, False)
        self._btn_enable(self.bg_btn, False)

        # 状态
        self.status = tk.Label(body, text="○ 空闲，待开始", bg="#f1f5f9", fg="#475569",
                               font=("微软雅黑", 10, "bold"), anchor="w")
        self.status.pack(fill="x", pady=(0, 10), ipady=7, ipadx=12)

        # 卡片4：结果文件
        c4 = card("结果文件（结束审计后亮起）")
        self.open_txt_btn  = self._mkbtn(c4, "📄 .txt 明文", C_SLATE, C_SLATE_H,
                                         font=("微软雅黑", 9), command=lambda: self._open(self.out_txt), pady=6)
        self.open_html_btn = self._mkbtn(c4, "📊 .html 报告", C_SLATE, C_SLATE_H,
                                         font=("微软雅黑", 9), command=lambda: self._open(self.out_html), pady=6)
        self.open_jsonl_btn= self._mkbtn(c4, "📋 .jsonl 日志", C_SLATE, C_SLATE_H,
                                         font=("微软雅黑", 9), command=lambda: self._open(self.out_jsonl), pady=6)
        self.open_dir_btn  = self._mkbtn(c4, "📁 结果文件夹", C_SLATE, C_SLATE_H,
                                         font=("微软雅黑", 9), command=self._open_outdir, pady=6)
        for b in (self.open_txt_btn, self.open_html_btn, self.open_jsonl_btn, self.open_dir_btn):
            b.pack(side="left", fill="x", expand=True, padx=3)
        for b in (self.open_txt_btn, self.open_html_btn, self.open_jsonl_btn):
            self._btn_enable(b, False)

        # 卡片5：运行日志
        c5 = card("运行日志", expand=True)
        self.log_text = tk.Text(c5, font=("Consolas", 9), bg=C_LOGBG, fg=C_LOGFG,
                                wrap="none", height=9, relief="flat", bd=0,
                                insertbackground=C_LOGFG, padx=8, pady=6)
        self.log_text.pack(side="left", fill="both", expand=True)
        sb = ttk.Scrollbar(c5, command=self.log_text.yview)
        sb.pack(side="right", fill="y")
        self.log_text.config(yscrollcommand=sb.set, state="disabled")

    # UI小工具
    def _mkbtn(self, parent, text, bg, hov, fg="white",
               font=("微软雅黑", 10, "bold"), hover=True, **kw):
        """统一风格的扁平按钮（悬停变深、手型光标）。"""
        b = tk.Button(parent, text=text, bg=bg, fg=fg, activebackground=hov,
                      activeforeground="white", relief="flat", bd=0, cursor="hand2",
                      highlightthickness=0, font=font, **kw)
        b._accent, b._accent_h = bg, hov
        if hover:
            b.bind("<Enter>", lambda e, x=b: x.config(bg=x._accent_h) if str(x["state"]) == "normal" else None)
            b.bind("<Leave>", lambda e, x=b: x.config(bg=x._accent) if str(x["state"]) == "normal" else None)
        return b

    def _btn_enable(self, btn, on, accent=None, accent_h=None):
        """启用→上色，禁用→置灰，统一外观。"""
        if on:
            accent = accent or btn._accent
            accent_h = accent_h or btn._accent_h
            btn._accent, btn._accent_h = accent, accent_h
            btn.config(state="normal", bg=accent, activebackground=accent_h, fg="white")
        else:
            btn.config(state="disabled", bg=C_DISABLED, fg="#94a3b8")

    def _set_status_badge(self, mode, consent=False, bg=False, n=0):
        if mode == "running":
            self.status.config(
                text=f"● 审计中      同意前：{'否' if consent else '是'}      "
                     f"应用：{'后台 ▽' if bg else '前台 △'}      已抓告警：{n}",
                bg="#dcfce7", fg="#166534")
        elif mode == "stopping":
            self.status.config(text="● 正在停止进程并生成报告…", bg="#fef9c3", fg="#854d0e")
        elif mode == "finished":
            self.status.config(text=f"✓ 已完成（{self.pkg}）", bg="#dbeafe", fg="#1e3a8a")
        else:
            self.status.config(text="○ 空闲，待开始", bg="#f1f5f9", fg="#475569")

    # 启动自检-
    def _self_check(self):
        self.log(f"=== Android 隐私审计仪表盘 · 构建 {BUILD} ===")
        ok = True
        # 这些文件由 mitmdump/frida 按路径加载（或被插件导入），必须在 exe 同目录磁盘上
        for label, p in [("privacy_auditor.py", AUDITOR), ("sdk_registry.py", SDK_REG),
                         ("ssl_bypass.js", SSL_JS), ("crypto_tracer.js", CRYPTO_JS),
                         ("sensitive_api_tracer.js", SENS_JS)]:
            if p.exists():
                self.log(f"  [✓] {label}")
            else:
                self.log(f"  [✗] 找不到 {label}（期望在 {p}）")
                ok = False
        # gen_report：打包后已内置 exe（import 即可）；源码运行时才检查磁盘
        if getattr(sys, "frozen", False):
            try:
                import gen_report  # noqa: F401  已打入 exe
                self.log("  [✓] gen_report（已内置 exe）")
            except Exception:
                self.log("  [✗] gen_report 未能从 exe 加载")
                ok = False
        elif GEN_REPORT.exists():
            self.log("  [✓] gen_report.py")
        else:
            self.log(f"  [✗] 找不到 gen_report.py（期望在 {GEN_REPORT}）")
            ok = False
        # anti_detection.js：可选（勾"反检测"时才用），缺失不阻塞开始
        self.log(f"  [{'✓' if ANTI_JS.exists() else '·'}] anti_detection.js（反检测脚本，可选）")
        _sp = self._stealth_port()
        if _sp:
            self.log(f"  [✓] 隐身模式已就绪：frida -H 127.0.0.1:{_sp}（来自 start_frida_server -Stealth）")
        self.mitmdump = shutil.which("mitmdump")
        self.frida = shutil.which("frida")
        self.log(f"  [{'✓' if self.mitmdump else '✗'}] mitmdump  "
                 f"{self.mitmdump or '未找到，请 pip install mitmproxy'}")
        self.log(f"  [{'✓' if self.frida else '✗'}] frida     "
                 f"{self.frida or '未找到，请 pip install frida-tools'}")
        if not (self.mitmdump and self.frida):
            ok = False
        # 上游代理配置（海外 App 审计必须走本地翻墙代理，否则境外 SDK 域名无法连通）
        _up = (self.upstream_entry.get() or "").strip() if hasattr(self, "upstream_entry") else ""
        if _up:
            self.log(f"  [✓] 上游代理 → {_up}（模拟器→8080→代理→海外）")
        else:
            self.log(f"  [·] 上游代理 未配置（直连）——海外 App 的 SDK 域名可能无法连通")
        self.log("前置条件：模拟器已开 + 代理指向 本机IP:8080 + CA 已装 + frida-server 已运行")
        if not ok:
            self.log(">>> 环境不完整，[开始审计] 已禁用，请先补齐上面标 ✗ 的项。")
            self._btn_enable(self.start_btn, False)
        else:
            self.log(">>> 环境就绪，可以开始。")

    # 开始
    def on_start(self):
        if self.state == "RUNNING":
            return
        pkg = self.pkg_entry.get().strip()
        if not PKG_RE.match(pkg):
            self.log(f"[错误] 包名格式不对：{pkg!r}（示例 com.sankuai.meituan）")
            return
        self.pkg = pkg

        # 清理上一轮残留，避免append模式把旧日志混进来
        for f in (CONSENT_MARKER, BACKGROUND_MARKER, JSONL_NAME):
            try:
                (self.workdir / f).unlink()
            except FileNotFoundError:
                pass
        self._jsonl_offset = 0              # 重置增量计数
        self._jsonl_count = 0
        self._dropped = 0

        self.outdir = self.workdir / pkg            # 结果归档文件夹（提前建好，frida 直接写入）
        self.out_txt = self.outdir / f"{pkg}.txt"
        self.out_html = self.outdir / f"{pkg}.html"
        self.out_jsonl = self.outdir / f"{pkg}.jsonl"
        try:
            self.outdir.mkdir(parents=True, exist_ok=True)
        except Exception as e:
            self.log(f"[错误] 创建结果文件夹失败：{e}")
            return

        # 1) mitmdump（-q 静默逐流量输出，只保留插件告警，避免高流量 App 刷爆日志）
        mitm_cmd = [self.mitmdump, "-q", "-s", str(AUDITOR),
                    "--listen-port", "8080", "--set", "block_global=false"]
        upstream = (self.upstream_entry.get() or "").strip()
        if upstream:
            # 模拟器 → 8080(mitmdump) → 上游代理 → 海外；国内直连不出去的域名借此可达
            mitm_cmd += ["--mode", f"upstream:http://{upstream}"]
            self.log(f"[启动] mitmdump（流量审计）@ {self.workdir}  上游代理 → {upstream}")
        else:
            self.log(f"[启动] mitmdump（流量审计）@ {self.workdir}  直连")
        self.mitm_proc = self._spawn(mitm_cmd, "MITM")

        # 2) 稍等代理就绪后再拉起 frida（spawn App）
        self._set_state("RUNNING")
        self.log("[启动] 1.5 秒后拉起 frida 并启动 App…")
        self.root.after(1500, self._start_frida)

    def _start_frida(self):
        if self.state != "RUNNING":          # 早停保护：开始后 1.5s 内点了结束，则不再拉起 frida
            return
        # 隐身模式：若 start_frida_server.ps1 -Stealth 写了端口标记，用 -H 连接，否则默认 -U
        port = self._stealth_port()
        conn = ["-H", f"127.0.0.1:{port}"] if port else ["-U"]
        if port:
            self.log(f"[隐身] 检测到隐身标记 → frida -H 127.0.0.1:{port} 连接")
        frida_cmd = [self.frida] + conn + ["-f", self.pkg]
        # 反检测脚本必须最先加载（先于 App 的检测代码）
        if self.anti_var.get():
            if ANTI_JS.exists():
                frida_cmd += ["-l", str(ANTI_JS)]
                self.log("[反检测] 已启用 anti_detection.js（最先加载）")
            else:
                self.log("[警告] 勾选了反检测，但找不到 anti_detection.js，本次未启用")
        frida_cmd += ["-l", str(SSL_JS), "-l", str(CRYPTO_JS), "-l", str(SENS_JS),
                      "-o", str(self.out_txt)]
        self.log(f"[启动] frida spawn {self.pkg}")
        self.frida_proc = self._spawn(frida_cmd, "FRIDA")
        self.log("操作提示：看到隐私弹窗先别点 → 等 30 秒 → 点同意瞬间按 [我点了同意]")

    # 结束
    def on_stop(self):
        if self.state != "RUNNING":
            return
        self._set_state("STOPPING")
        self._btn_enable(self.consent_btn, False)
        self._btn_enable(self.bg_btn, False)
        self.log("[结束] 正在停止进程并生成报告…")
        threading.Thread(target=self._stop_worker, daemon=True).start()

    def _stop_worker(self):
        # jsonl 每条已 flush，直接 terminate 不丢数据
        self._kill(self.frida_proc, "FRIDA")
        self._kill(self.mitm_proc, "MITM")
        self.frida_proc = self.mitm_proc = None

        # 结果文件夹已在开始时创建，frida 的 txt 已直接写入其中
        try:
            self.outdir.mkdir(parents=True, exist_ok=True)
        except Exception:
            pass

        # jsonl → 生成 HTML（写入结果文件夹）→ 再把 jsonl 移入
        jsonl = self.workdir / JSONL_NAME
        if jsonl.exists() and jsonl.stat().st_size > 0:
            self.logq.put("[报告] 从 jsonl 生成 HTML 报告…")
            _ok, _msg = self._gen_html(jsonl, self.out_html)
            self.logq.put(f"[报告] {_msg}")
            self._safe_move(jsonl, self.out_jsonl, "jsonl 日志")
        else:
            self.logq.put("[报告] 未发现告警日志（audit_log.jsonl 为空）——"
                          "检查代理/证书是否生效、App 是否产生流量。")

        # 回主线程收尾
        self.root.after(0, self._finish_ui)

    def _safe_move(self, src, dst, label, retries=6):
        """把结果文件移入 <包名> 文件夹（覆盖同名）；文件被占用时重试。"""
        if not src.exists():
            return
        for _ in range(retries):
            try:
                if dst.exists():
                    dst.unlink()
                src.replace(dst)
                self.logq.put(f"[归档] {label} → {self.pkg}\\{dst.name}")
                return
            except PermissionError:
                time.sleep(0.6)          # 句柄未释放，稍候重试
            except Exception as e:
                self.logq.put(f"[归档] {label} 移动失败：{e}")
                return
        self.logq.put(f"[归档] {label} 移动失败：文件被占用（已重试 {retries} 次，可手动从工作目录移动）")

    def _open_outdir(self):
        self._open(self.outdir if (self.outdir and self.outdir.exists()) else self.workdir)

    @staticmethod
    def _stealth_port():
        """读取 start_frida_server.ps1 -Stealth 写的隐身端口；无则返回 None（走 -U）。"""
        try:
            if STEALTH_MARK.exists():
                t = STEALTH_MARK.read_text(encoding="ascii", errors="ignore").strip()
                if t.isdigit():
                    return int(t)
        except Exception:
            pass
        return None

    @staticmethod
    def _system_python():
        """冻结(exe)环境下 sys.executable 是 exe 本身，需找真正的 python 解释器。"""
        if not getattr(sys, "frozen", False):
            return sys.executable
        for c in ("python", "python3", "py"):
            p = shutil.which(c)
            if p:
                return p
        return None

    def _gen_html(self, jsonl, out_html):
        """jsonl → HTML。优先进程内调用 gen_report（不依赖外部 python，兼容 PyInstaller 打包），
        失败再回退系统 python 子进程。"""
        in_proc_err = None
        try:
            if str(GEN_REPORT.parent) not in sys.path:
                sys.path.insert(0, str(GEN_REPORT.parent))
            import gen_report as gr
            events = gr.load_events(jsonl)
            args = SimpleNamespace(severity=None, sdk=None, endpoint=None, host=None)
            events = gr.filter_events(events, args)
            gr.generate_html(events, str(jsonl), out_html, args)
            return True, f"已生成 {out_html.name}（{len(events)} 条事件，进程内）"
        except Exception as e:
            in_proc_err = e
        py = self._system_python()
        if py:
            try:
                r = subprocess.run(
                    [py, str(GEN_REPORT), "--log", JSONL_NAME, "--out", out_html.name],
                    cwd=str(self.workdir), capture_output=True, text=True,
                    encoding="utf-8", errors="replace", timeout=120,
                    creationflags=CREATE_FLAGS)
                if r.returncode == 0:
                    return True, f"已生成 {out_html.name}（系统 python 回退）"
                return False, f"gen_report 退出码 {r.returncode}：{(r.stderr or '').strip()}"
            except Exception as e:
                return False, f"生成失败：进程内={in_proc_err}；子进程={e}"
        return False, f"生成失败（进程内={in_proc_err}），且 PATH 中未找到 python。"

    def _finish_ui(self):
        self._set_state("FINISHED")
        for btn, path in [(self.open_txt_btn, self.out_txt),
                          (self.open_html_btn, self.out_html),
                          (self.open_jsonl_btn, self.out_jsonl)]:
            self._btn_enable(btn, bool(path and path.exists()))
        done = [p.name for p in (self.out_txt, self.out_html, self.out_jsonl)
                if p and p.exists()]
        if done and self.outdir:
            self.log(f"[完成] 已归档到文件夹 [{self.outdir.name}\\]：{', '.join(done)}")
        else:
            self.log("[完成] 未生成结果文件。")

    # 标记 —> 有两种标记，同意前标记和前后台切换标记
    def mark_consent(self):
        (self.workdir / CONSENT_MARKER).touch()
        self.log("[标记] consent.marker 已创建 → 之后不再判定“同意前”")

    def toggle_background(self):
        bg = self.workdir / BACKGROUND_MARKER
        if bg.exists():
            bg.unlink(missing_ok=True)
            self.log("[标记] 已回到前台（删除 background.marker）")
        else:
            bg.touch()
            self.log("[标记] 已切到后台（创建 background.marker）")

    # 进程
    def _spawn(self, cmd, tag):
        # 强制子进程（mitmdump/frida 均为 Python）以 UTF-8 输出，
        # 否则插件打印 ⚠ 等字符时会触发 GBK 编码错误
        env = os.environ.copy()
        env["PYTHONIOENCODING"] = "utf-8"
        env["PYTHONUTF8"] = "1"
        try:
            p = subprocess.Popen(
                cmd, cwd=str(self.workdir), env=env,
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, encoding="utf-8", errors="replace",
                bufsize=1, creationflags=CREATE_FLAGS)
        except Exception as e:
            self.log(f"[{tag}] 启动失败：{e}")
            return None
        threading.Thread(target=self._pump, args=(p, tag), daemon=True).start()
        return p

    def _pump(self, proc, tag):
        # 始终快速读取子进程 stdout（避免管道写满使 mitmdump/frida 阻塞），
        # 但队列过长时丢弃高频行，只计数，保护内存与 UI。
        try:
            for line in iter(proc.stdout.readline, ""):
                if not line:
                    continue
                if self.logq.qsize() < LOG_QUEUE_CAP:
                    self.logq.put(f"[{tag}] {line.rstrip()}")
                else:
                    self._dropped += 1
        except Exception:
            pass
        self.logq.put(f"[{tag}] —— 进程已退出 ——")

    def _kill(self, proc, tag):
        if not proc or proc.poll() is not None:
            return
        try:
            proc.terminate()
            proc.wait(timeout=8)
            self.logq.put(f"[{tag}] 已结束")
        except subprocess.TimeoutExpired:
            proc.kill()
            self.logq.put(f"[{tag}] 强制结束")
        except Exception as e:
            self.logq.put(f"[{tag}] 结束异常：{e}")

    # 状态轮询和日志轮询
    def _set_state(self, st):
        self.state = st
        running = st in ("RUNNING", "STOPPING")
        self._btn_enable(self.start_btn, st in ("IDLE", "FINISHED"))
        self._btn_enable(self.stop_btn, st == "RUNNING")
        self.pkg_entry.config(state="disabled" if running else "normal")
        on = (st == "RUNNING")
        self._btn_enable(self.consent_btn, on, C_GREEN, C_GREEN_H)
        self._btn_enable(self.bg_btn, on, C_AMBER, C_AMBER_H)

    def _poll_status(self):
        if self.state == "RUNNING":
            consent = (self.workdir / CONSENT_MARKER).exists()
            bg = (self.workdir / BACKGROUND_MARKER).exists()
            n = self._count_jsonl_incremental()
            # 后台按钮：切后台=琥珀，回前台=青绿
            self._btn_enable(self.bg_btn, True,
                             C_TEAL if bg else C_AMBER, C_TEAL_H if bg else C_AMBER_H)
            self.bg_btn.config(text="📲 回到前台" if bg else "📱 切到后台")
            # 同意按钮：已同意则置灰表示完成
            self._btn_enable(self.consent_btn, not consent, C_GREEN, C_GREEN_H)
            self.consent_btn.config(text="✅ 已同意" if consent else "✅ 我点了同意")
            self._set_status_badge("running", consent, bg, n)
        elif self.state == "STOPPING":
            self._set_status_badge("stopping")
        elif self.state == "FINISHED":
            self._set_status_badge("finished")
        else:
            self._set_status_badge("idle")
        self.root.after(800, self._poll_status)

    def _count_jsonl_incremental(self):
        """只读新增字节统计行数，避免高流量下整文件重读拖死主线程。"""
        jp = self.workdir / JSONL_NAME
        try:
            sz = jp.stat().st_size
        except OSError:
            self._jsonl_offset = self._jsonl_count = 0
            return 0
        if sz < self._jsonl_offset:          # 文件被重建/截断 → 重新计数
            self._jsonl_offset = self._jsonl_count = 0
        if sz > self._jsonl_offset:
            try:
                with jp.open("rb") as f:
                    f.seek(self._jsonl_offset)
                    data = f.read()
                self._jsonl_count += data.count(b"\n")
                self._jsonl_offset = sz
            except OSError:
                pass
        return self._jsonl_count

    def _drain_log(self):
        # 每次最多取 DRAIN_PER_TICK 行，保证回调快速返回，主线程不被洪流卡死
        lines = []
        for _ in range(DRAIN_PER_TICK):
            try:
                lines.append(self.logq.get_nowait())
            except queue.Empty:
                break
        if self._dropped:
            lines.append(f"[i] …省略 {self._dropped} 行高频日志（不影响 jsonl 记录）")
            self._dropped = 0
        if lines:
            self._append_lines(lines)
        self.root.after(120, self._drain_log)

    def _append_lines(self, lines):
        self.log_text.config(state="normal")
        self.log_text.insert("end", "\n".join(lines) + "\n")     # 批量一次插入
        total = int(self.log_text.index("end-1c").split(".")[0])  # 当前行数
        if total > MAX_LOG_LINES:                                 # 超限从顶部裁剪
            self.log_text.delete("1.0", f"{total - MAX_LOG_LINES}.0")
        self.log_text.see("end")
        self.log_text.config(state="disabled")

    def log(self, msg):
        self._append_lines([msg])

    # 杂项
    def choose_dir(self):
        if self.state == "RUNNING":
            return
        d = filedialog.askdirectory(initialdir=str(self.workdir))
        if d:
            self.workdir = Path(d)
            self.dir_lbl.config(text=str(self.workdir))
            self.log(f"[设置] 工作目录 → {self.workdir}")

    def _open(self, path):
        if not path or not Path(path).exists():
            self.log(f"[打开] 文件不存在：{path}")
            return
        try:
            os.startfile(str(path))            # Windows
        except AttributeError:
            subprocess.Popen(["xdg-open", str(path)])

    def run(self):
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)
        self.root.mainloop()

    def _on_close(self):
        if self.state == "RUNNING":
            self._kill(self.frida_proc, "FRIDA")
            self._kill(self.mitm_proc, "MITM")
        self.root.destroy()


if __name__ == "__main__":
    Dashboard().run()
