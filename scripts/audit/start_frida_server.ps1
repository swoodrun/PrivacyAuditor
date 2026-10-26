<#
  start_frida_server.ps1 — 一键启动模拟器内的 frida-server（动态审计前置步骤）

  自动完成：
    1. 定位 adb（优先 jadx 内置 platform-tools，其次系统 PATH）
    2. 等待模拟器连接、检查 root 权限
    3. 确认 /data/local/tmp/frida-server 存在（可选 -LocalServer 推送），并 chmod 755
    4. 若已在运行：默认跳过；加 -Restart 则先停后启
    5. 后台拉起 frida-server，轮询确认进程已起
    6. 若本机装了 frida 客户端，用 frida-ps -U 复验连通

  用法：
    .\start_frida_server.ps1
    .\start_frida_server.ps1 -Restart
    .\start_frida_server.ps1 -LocalServer .\frida-server-17.6.1-android-x86_64
    .\start_frida_server.ps1 -AdbPath "D:\path\to\adb.exe"
  或直接双击 start_frida_server.bat
#>
param(
    [string]$ServerPath = "/data/local/tmp/frida-server",  # 设备上 frida-server 路径
    [string]$LocalServer = "",                              # 可选：本机 frida-server 文件，缺失时推送
    [switch]$Restart,                                       # 已运行也强制重启
    [string]$AdbPath = "",                                  # 可选：手动指定 adb.exe
    [switch]$Stealth,                                       # 隐身模式：改名 + 换端口 + adb forward（对付深度加固）
    [int]$Port = 0,                                         # 隐身监听端口（0=随机）
    [string]$StealthName = ""                               # 隐身进程名（空=随机，避免出现 frida 字样）
)

$ErrorActionPreference = "Stop"

function Info($m) { Write-Host $m }
function Ok($m)   { Write-Host "[OK] $m"  -ForegroundColor Green }
function Warn($m) { Write-Host "[!] $m"   -ForegroundColor Yellow }
function Fail($m) { Write-Host "[X] $m"   -ForegroundColor Red }

# ── 定位 adb ──
function Find-Adb {
    if ($AdbPath) {
        if (Test-Path $AdbPath) { return (Resolve-Path $AdbPath).Path }
        Warn "指定的 -AdbPath 不存在：$AdbPath，改为自动查找"
    }
    # 从脚本目录向上找含 jadx 的项目目录，在 jadx 子树里搜 adb.exe（范围小、快）
    $dir = $PSScriptRoot
    for ($i = 0; $i -lt 6 -and $dir; $i++) {
        $jadx = Join-Path $dir "jadx"
        if (Test-Path $jadx) {
            $hit = Get-ChildItem -Path $jadx -Filter adb.exe -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
            if ($hit) { return $hit.FullName }
        }
        $dir = Split-Path $dir -Parent
    }
    $cmd = Get-Command adb -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    return $null
}

# 执行设备侧 shell 命令，返回字符串
function AdbShell([string]$cmd) {
    return ((& $script:adb shell $cmd) -join "`n")
}

# 解析 adb devices 得到首个设备状态
function Get-DeviceState {
    $lines = & $script:adb devices
    foreach ($l in $lines) {
        if ($l -match '\sdevice$')       { return 'device' }
        if ($l -match '\soffline$')      { return 'offline' }
        if ($l -match '\sunauthorized$') { return 'unauthorized' }
    }
    return 'none'
}

# 取 frida-server PID（按进程名匹配，避免 pgrep 自匹配）
function Get-FsPid {
    $out = (AdbShell "su -c 'pgrep frida-server || ps -A 2>/dev/null | grep frida-server | grep -v grep'").Trim()
    if (-not $out) { return "" }
    $line = ($out -split "`n")[0]
    $m = [regex]::Match($line, '\d+')
    if ($m.Success) { return $m.Value } else { return "" }
}

# 按任意进程名取 PID（隐身模式的随机名）
function Get-NamedPid([string]$name) {
    $out = (AdbShell "su -c 'pgrep $name || ps -A 2>/dev/null | grep $name | grep -v grep'").Trim()
    if (-not $out) { return "" }
    $line = ($out -split "`n")[0]
    $m = [regex]::Match($line, '\d+')
    if ($m.Success) { return $m.Value } else { return "" }
}

# 用本机 frida 客户端复验连通
function Verify-Frida {
    $frida = Get-Command frida-ps -ErrorAction SilentlyContinue
    if (-not $frida) {
        Info "（本机未装 frida 客户端，跳过 frida-ps 复验；装好后可执行 frida-ps -U 验证）"
        return
    }
    try {
        $out = (& frida-ps -U) | Out-String
        if ($LASTEXITCODE -eq 0 -and $out.Trim()) {
            Ok "frida-ps -U 连接成功，frida-server 工作正常"
        } else {
            Warn "frida-ps -U 返回异常，常见原因为客户端/服务端版本不一致。"
        }
    } catch {
        Warn "frida-ps -U 失败：$_  （多为版本不匹配，请下载与客户端同版本的 frida-server）"
    }
}

# ════════════════ 主流程 ════════════════

$script:adb = Find-Adb
if (-not $script:adb) {
    Fail "找不到 adb.exe。请用 -AdbPath 指定，或确认 jadx/platform-tools 存在。"
    exit 1
}
Ok "adb: $script:adb"

& $script:adb start-server | Out-Null

# 1) 等待设备（必要时尝试连接常见模拟器端口）
Info "等待模拟器连接..."
$state = 'none'
$triedConnect = $false
for ($i = 0; $i -lt 30; $i++) {
    $state = Get-DeviceState
    if ($state -eq 'device') { break }
    if (-not $triedConnect -and $i -ge 1) {
        # 新 adb 守护进程有时不自动重连，尝试常见端口：雷电 5555/5557、夜神 62001、逍遥 21503
        foreach ($port in 5555, 5557, 62001, 21503) {
            & $script:adb connect "127.0.0.1:$port" 2>$null | Out-Null
        }
        $triedConnect = $true
    }
    Start-Sleep -Milliseconds 800
}
if ($state -ne 'device') {
    Fail "未检测到就绪的模拟器（状态=$state）。请确认雷电模拟器已开启并启用 USB 调试；若 offline/unauthorized 请重启模拟器。"
    exit 1
}
Ok "模拟器已连接"

# 2) root 检查
$idOut = AdbShell "su -c id"
if ($idOut -match "uid=0") {
    Ok "已获取 root"
} else {
    Warn "未检测到 root（su -c id → $idOut）。雷电模拟器：设置→其他设置→打开 ROOT 权限，重启后重试。"
}

# 3) 架构提示
$abi = (AdbShell "getprop ro.product.cpu.abi").Trim()
Info "设备架构: $abi  （frida-server 须匹配此架构 + frida 客户端版本）"

# 4) 二进制存在性 / 推送
$lsOut = AdbShell "ls $ServerPath 2>/dev/null"
$exists = $lsOut -match [regex]::Escape($ServerPath)
if (-not $exists) {
    if ($LocalServer -and (Test-Path $LocalServer)) {
        Info "设备上无 frida-server，推送本机文件：$LocalServer"
        & $script:adb push $LocalServer $ServerPath | Out-Null
        Ok "已推送到 $ServerPath"
    } else {
        Fail "设备上 $ServerPath 不存在，且未提供 -LocalServer。"
        Info "请下载与客户端同版本、架构=$abi 的 frida-server，用 -LocalServer <文件> 指定后重跑。"
        exit 1
    }
}
AdbShell "su -c 'chmod 755 $ServerPath'" | Out-Null

# 4b) 隐身模式（Layer 1）：把 frida-server 复制成随机名、用随机端口启动、adb forward 映射，
#     并写标记供 dashboard 用 frida -H 连接。对付"扫进程名 frida-server / 扫 27042 端口"的深度加固。
$StealthMarker = Join-Path $PSScriptRoot "frida_stealth.txt"
if ($Stealth) {
    if (-not $StealthName) {
        $cs = 'abcdefghijklmnopqrstuvwxyz'
        $StealthName = -join ((1..8) | ForEach-Object { $cs[(Get-Random -Maximum $cs.Length)] })
    }
    if ($Port -le 0) { $Port = Get-Random -Minimum 20000 -Maximum 60000 }
    $devPath = "/data/local/tmp/$StealthName"
    Info "隐身模式：进程名=$StealthName  监听端口=$Port"

    # 由现有 frida-server 复制为随机名（不带 frida 字样）
    AdbShell "su -c 'cp $ServerPath $devPath && chmod 755 $devPath'" | Out-Null

    $oldPid = Get-NamedPid $StealthName
    if ($oldPid) {
        Info "已有同名隐身进程 (PID $oldPid)，先停止"
        AdbShell "su -c 'pkill $StealthName || kill $oldPid'" | Out-Null
        Start-Sleep -Milliseconds 800
    }

    Info "启动隐身 frida-server ..."
    $startCmd = "su -c 'nohup $devPath -l 0.0.0.0:$Port >/dev/null 2>&1 &'"
    $job = Start-Job -ScriptBlock { param($a, $c) & $a shell $c } -ArgumentList $script:adb, $startCmd
    Wait-Job $job -Timeout 6 | Out-Null
    Remove-Job $job -Force -ErrorAction SilentlyContinue

    & $script:adb forward "tcp:$Port" "tcp:$Port" | Out-Null   # 主机:Port → 设备:Port

    $fpid = ""
    for ($i = 0; $i -lt 12; $i++) {
        Start-Sleep -Milliseconds 600
        $fpid = Get-NamedPid $StealthName
        if ($fpid) { break }
    }
    if (-not $fpid) {
        Fail "隐身 frida-server 启动失败（进程未起）。"
        Info "手动排查：adb shell → su → $devPath -l 0.0.0.0:$Port"
        exit 1
    }
    Ok "隐身 frida-server 已启动 (PID $fpid, 名=$StealthName, 端口=$Port)"

    Set-Content -Path $StealthMarker -Value "$Port" -Encoding ascii
    Ok "已写隐身标记 → dashboard 将用 frida -H 127.0.0.1:$Port 连接"

    $frida = Get-Command frida-ps -ErrorAction SilentlyContinue
    if ($frida) {
        try {
            $out = (& frida-ps -H "127.0.0.1:$Port") | Out-String
            if ($LASTEXITCODE -eq 0 -and $out.Trim()) { Ok "frida-ps -H 127.0.0.1:$Port 连接成功，隐身服务工作正常" }
            else { Warn "frida-ps -H 返回异常，检查端口转发/版本一致。" }
        } catch { Warn "frida-ps -H 失败：$_" }
    } else {
        Info "（本机未装 frida 客户端，跳过复验）"
    }
    Info ""
    Ok "隐身模式就绪。打开 AuditDashboard.exe（建议同时勾上反检测）开始审计。"
    exit 0
}
# 普通模式：清除可能残留的隐身标记，让 dashboard 走默认 -U
Remove-Item $StealthMarker -ErrorAction SilentlyContinue

# 5) 已运行检测
$fpid = Get-FsPid
if ($fpid) {
    if ($Restart) {
        Info "frida-server 已在运行 (PID $fpid)，-Restart → 先停止"
        AdbShell "su -c 'pkill frida-server || kill $fpid'" | Out-Null
        Start-Sleep -Milliseconds 900
    } else {
        Ok "frida-server 已在运行 (PID $fpid)，无需重启（加 -Restart 可强制重启）"
        Verify-Frida
        exit 0
    }
}

# 6) 后台启动（nohup 脱离会话，输出丢弃；用 Start-Job + 超时避免宿主卡住）
Info "启动 frida-server ..."
$startCmd = "su -c 'nohup $ServerPath >/dev/null 2>&1 &'"
$job = Start-Job -ScriptBlock { param($a, $c) & $a shell $c } -ArgumentList $script:adb, $startCmd
Wait-Job $job -Timeout 6 | Out-Null
Remove-Job $job -Force -ErrorAction SilentlyContinue

# 7) 轮询确认
$fpid = ""
for ($i = 0; $i -lt 12; $i++) {
    Start-Sleep -Milliseconds 600
    $fpid = Get-FsPid
    if ($fpid) { break }
}
if ($fpid) {
    Ok "frida-server 已启动 (PID $fpid)"
} else {
    Fail "启动后未检测到 frida-server 进程。"
    Info "可能原因：架构不匹配 / su 受限 / SELinux 拦截。"
    Info "手动排查：adb shell → su → $ServerPath  （看具体报错）"
    exit 1
}

# 8) 复验
Verify-Frida
Info ""
Ok "完成。现在可以打开 AuditDashboard.exe 开始审计。"



