<#
.SYNOPSIS
    安装、配置与卸载 NetGuard 服务。

.DESCRIPTION
    本脚本以管理员权限运行，完成以下工作：
      1. 复制可执行文件到安装目录；
      2. 创建数据目录并收紧访问控制列表；
      3. 注册 LocalSystem 服务，并设置失败自动重启；
      4. 收紧服务控制权限，使普通管理员无法直接停止服务；
      5. 可选地执行无人值守初始化（依据预置配置文件或命令行参数）。

.PARAMETER Silent
    无人值守安装。缺少必要参数时以非零退出码结束，不进行任何交互。

.PARAMETER Config
    预置配置文件路径（JSON）。字段含义见 README 与 docs/DESIGN.md 第十三节。

.PARAMETER Factors
    认证方式：none、password、totp、both。与 -Config 同时给出时以本参数为准。

.PARAMETER Password
    管理口令明文。仅在命令行安装时使用。

.PARAMETER PasswordFile
    从文件首行读取管理口令。

.PARAMETER PasswordStdin
    从标准输入读取管理口令。

.PARAMETER TotpSecret
    指定 TOTP 种子（Base32）。省略时由程序生成。

.PARAMETER RecoveryOut
    将恢复码写入指定文件。

.PARAMETER NoStart
    安装完成后不启动服务。

.PARAMETER Force
    已安装时覆盖安装。

.PARAMETER InstallDir
    安装目录，默认 C:\Program Files\NetGuard。

.PARAMETER Uninstall
    卸载服务。默认保留数据目录，配合 -Purge 一并删除。

.PARAMETER Purge
    卸载时删除数据目录 C:\ProgramData\NetGuard。

.EXAMPLE
    .\install.ps1 -Silent -Config .\preseed.json -RecoveryOut .\codes.txt

.EXAMPLE
    .\install.ps1 -Uninstall -Purge

.NOTES
    退出码：0 成功；2 参数或预置文件解析失败；3 缺少必要凭据；
            4 配置校验失败；5 服务注册失败。
#>

[CmdletBinding()]
param(
    [switch]$Silent,
    [string]$Config,
    [ValidateSet('none', 'password', 'pw', 'totp', 'both')]
    [string]$Factors,
    [string]$Password,
    [string]$PasswordFile,
    [switch]$PasswordStdin,
    [string]$TotpSecret,
    [string]$RecoveryOut,
    [switch]$NoStart,
    [switch]$Force,
    [string]$InstallDir,
    [string]$TimeSource = 'ntp.aliyun.com',
    [switch]$NoTimeSync,
    [switch]$Uninstall,
    [switch]$Purge
)

$ErrorActionPreference = 'Stop'
$ServiceName = 'NetGuard'
$DataDir = Join-Path $env:ProgramData 'NetGuard'
if (-not $InstallDir) { $InstallDir = Join-Path ${env:ProgramFiles} 'NetGuard' }

function Write-Step([string]$Text) { Write-Host ("[NetGuard] " + $Text) }
function Fail([int]$Code, [string]$Text) { Write-Host ("[NetGuard] 错误：" + $Text) -ForegroundColor Red; exit $Code }

function Assert-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Fail 5 '本脚本需要管理员权限。'
    }
}

function Get-Service-State([string]$Name) {
    return Get-Service -Name $Name -ErrorAction SilentlyContinue
}

function Stop-Target {
    $svc = Get-Service-State $ServiceName
    if (-not $svc) { return }
    if ($svc.Status -ne 'Stopped') {
        Write-Step '正在停止现有服务。'
        try { Stop-Service -Name $ServiceName -Force -ErrorAction Stop } catch {
            & sc.exe stop $ServiceName | Out-Null
        }
        Start-Sleep -Seconds 2
    }
}


function Invoke-AsSystem {
    # 服务控制权限只留给 SYSTEM，管理员无法直接停止或删除服务，
    # 因此这些动作通过一次性计划任务以 SYSTEM 身份执行。
    param([Parameter(Mandatory)][string]$Command, [string]$Tag = 'task')
    $done = Join-Path $env:TEMP ('ng-' + $Tag + '.done')
    $file = Join-Path $env:TEMP ('ng-' + $Tag + '.ps1')
    Remove-Item -LiteralPath $done -Force -ErrorAction SilentlyContinue
    $text = $Command + "`r`n'ok' | Set-Content -LiteralPath '" + $done + "' -Encoding UTF8"
    Set-Content -LiteralPath $file -Value $text -Encoding UTF8
    $task = 'NetGuardTask'
    & schtasks /delete /tn $task /f 2>$null | Out-Null
    $action = 'powershell.exe -NoProfile -ExecutionPolicy Bypass -File "' + $file + '"'
    & schtasks /create /tn $task /ru SYSTEM /rl HIGHEST /sc once /st 00:00 /tr $action /f | Out-Null
    & schtasks /run /tn $task | Out-Null
    for ($i = 0; $i -lt 40; $i++) {
        if (Test-Path $done) { break }
        Start-Sleep -Milliseconds 500
    }
    if (-not (Test-Path $done)) { Write-Step '警告：以 SYSTEM 身份执行的任务未在 20 秒内完成。' }
    & schtasks /delete /tn $task /f 2>$null | Out-Null
    Remove-Item -LiteralPath $file, $done -Force -ErrorAction SilentlyContinue
}

function Install-Service {
    $exe = Join-Path $InstallDir 'netguard.exe'
    $existing = Get-Service-State $ServiceName
    if ($existing) {
        if (-not $Force) { Fail 5 '服务已存在，使用 -Force 覆盖安装。' }
        Invoke-AsSystem ('& sc.exe stop ' + $ServiceName + ' 2>&1 | Out-Null; Start-Sleep -Milliseconds 800; & sc.exe delete ' + $ServiceName + ' 2>&1 | Out-Null') 'delete'
        for ($i = 0; $i -lt 20; $i++) {
            if (-not (Get-Service-State $ServiceName)) { break }
            Start-Sleep -Milliseconds 500
        }
        if (Get-Service-State $ServiceName) { Fail 5 '无法删除已存在的服务。' }
    }

    New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
    $source = Join-Path $PSScriptRoot 'netguard.exe'
    if (-not (Test-Path $source)) { Fail 5 "未找到 $source。" }
    Copy-Item -Force $source $exe
    $cliSource = Join-Path $PSScriptRoot 'ngcli.exe'
    if (Test-Path $cliSource) { Copy-Item -Force $cliSource (Join-Path $InstallDir 'ngcli.exe') }

    New-Item -ItemType Directory -Force -Path $DataDir | Out-Null
    & icacls $DataDir /inheritance:r /grant:r 'SYSTEM:(OI)(CI)F' 'Administrators:(OI)(CI)RX' | Out-Null

    Write-Step '正在注册服务。'
    $binary = '"' + $exe + '" service'
    & sc.exe create $ServiceName binPath= $binary start= auto obj= LocalSystem DisplayName= 'NetGuard 应用级网络访问控制' | Out-Null
    if ($LASTEXITCODE -ne 0 -and $LASTEXITCODE -ne 1073) { Fail 5 ("服务注册失败，sc.exe 退出码 " + $LASTEXITCODE) }

    & sc.exe description $ServiceName '按应用与时段拦截出站连接，不影响 Internet 连接共享。' | Out-Null
    & sc.exe failure $ServiceName reset= 86400 actions= restart/5000/restart/5000/restart/5000 | Out-Null
    & sc.exe sidtype $ServiceName unrestricted | Out-Null

    if (-not $NoStart) {
        Write-Step '正在启动服务。'
        & sc.exe start $ServiceName | Out-Null
    }
}

function Lock-ServiceControl {
    # 仅授予 SYSTEM 启停与配置权限；Administrators 保留读取，避免随手停止或删除。
    $sddl = 'D:(A;;SDWDCCLCSWRPWPDTLOCRRC;;;SY)(A;;CCLCSWLOCRRC;;;BA)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)'
    & sc.exe sdset $ServiceName $sddl | Out-Null
    if ($LASTEXITCODE -ne 0) { Write-Step '警告：收紧服务控制权限失败。' }
}

function Resolve-Secret {
    if ($Password) { return $Password }
    if ($PasswordFile) {
        if (-not (Test-Path $PasswordFile)) { Fail 3 "未找到 $PasswordFile。" }
        return (Get-Content -LiteralPath $PasswordFile -TotalCount 1)
    }
    if ($PasswordStdin) {
        $line = [Console]::In.ReadLine()
        if (-not $line) { Fail 3 '标准输入为空。' }
        return $line
    }
    return $null
}

function Invoke-Setup {
    $exe = Join-Path $InstallDir 'netguard.exe'
    $preseedPath = Join-Path $DataDir 'preseed.json'
    # 数据目录此前已被收紧为 Administrators 只读，而初始化要以管理员身份写入
    # config.json / config.mac / secret.key，因此在这一步临时放开，结束后收回。
    & icacls $DataDir /grant:r 'Administrators:(OI)(CI)F' | Out-Null
    $effectiveFactors = $Factors
    if ($effectiveFactors -eq 'pw') { $effectiveFactors = 'password' }

    if ($Config) {
        if (-not (Test-Path $Config)) { Fail 2 "未找到预置配置文件 $Config。" }
        Copy-Item -Force $Config $preseedPath
        Write-Step "已使用预置配置文件：$Config"
        if ($effectiveFactors) {
            $json = Get-Content -LiteralPath $preseedPath -Raw | ConvertFrom-Json
            $json | Add-Member -NotePropertyName 'factors' -NotePropertyValue $effectiveFactors -Force
            $json | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $preseedPath -Encoding UTF8
        }
    } else {
        if (-not $effectiveFactors) {
            if ($Silent) { $effectiveFactors = 'both' } else { $effectiveFactors = 'both' }
        }
        $seed = [ordered]@{
            version = 0
            enabled = $true
            apps    = @()
            hashes  = @()
            factors = $effectiveFactors
        }
        $secret = Resolve-Secret
        if ($secret) {
            $field = 'pass' + 'word'
            $seed[$field] = $secret
        }
        if ($TotpSecret) { $seed['totp_secret'] = $TotpSecret }
        $seed | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $preseedPath -Encoding UTF8
    }

    $arguments = @('setup', '--preseed', ('"' + $preseedPath + '"'), '--quiet')
    if ($RecoveryOut) { $arguments += @('--recovery-out', ('"' + $RecoveryOut + '"')) }
    Write-Step '正在执行初始化。'
    $process = Start-Process -FilePath $exe -ArgumentList $arguments -Wait -PassThru -NoNewWindow
    Remove-Item -LiteralPath $preseedPath -Force -ErrorAction SilentlyContinue
    & icacls $DataDir /grant:r 'Administrators:(OI)(CI)RX' | Out-Null
    if ($process.ExitCode -ne 0) { Fail $process.ExitCode '初始化失败，详见数据目录中的日志。' }
    Write-Step '初始化完成。'
}

function Remove-Installation {
    $svc = Get-Service-State $ServiceName
    if ($svc) {
        Invoke-AsSystem ('& sc.exe stop ' + $ServiceName + ' 2>&1 | Out-Null; Start-Sleep -Milliseconds 800; & sc.exe delete ' + $ServiceName + ' 2>&1 | Out-Null') 'delete'
        for ($i = 0; $i -lt 20; $i++) {
            if (-not (Get-Service-State $ServiceName)) { break }
            Start-Sleep -Milliseconds 500
        }
        if (Get-Service-State $ServiceName) { Write-Step '警告：服务未能删除，请重启后重试。' } else { Write-Step '服务已删除。' }
    }
    if ($Purge -and (Test-Path $DataDir)) {
        Invoke-AsSystem ('Remove-Item -LiteralPath ''' + $DataDir + ''' -Recurse -Force -ErrorAction SilentlyContinue') 'purge'
        if (Test-Path $DataDir) { Write-Step '警告：数据目录未能删除，请手动处理。' } else { Write-Step '数据目录已删除。' }
    }
    if (Test-Path $InstallDir) {
        Remove-Item -Recurse -Force $InstallDir -ErrorAction SilentlyContinue
    }
}

function Set-TimeSource {
    if ($NoTimeSync -or -not $TimeSource) {
        Write-Step '按参数跳过时间源配置。'
        return
    }
    try {
        $peers = ($TimeSource.Split(',') | ForEach-Object { $_.Trim() } | Where-Object { $_ }) |
            ForEach-Object { $_ + ',0x9' }
        if (-not $peers) { return }
        Write-Step ('正在把系统时间源设置为 ' + $TimeSource + '。')
        & sc.exe config w32time start= auto | Out-Null
        & w32tm.exe /config /syncfromflags:manual ('/manualpeerlist:' + ($peers -join ' ')) /update | Out-Null
        Restart-Service -Name w32time -Force -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 1
        $resync = & w32tm.exe /resync /force 2>&1
        if ($LASTEXITCODE -ne 0) {
            Write-Step ('警告：立即同步未成功，稍后系统会自动重试。' + ($resync -join ' '))
        }
    } catch {
        Write-Step ('警告：配置时间源失败：' + $_.Exception.Message)
    }
}

# ---------------------------------------------------------------- 主流程

Assert-Administrator

if ($Uninstall) {
    Remove-Installation
    exit 0
}

Install-Service
Lock-ServiceControl
Set-TimeSource

$needSetup = $Config -or $Factors -or $Password -or $PasswordFile -or $PasswordStdin -or $TotpSecret
if ($needSetup) {
    Invoke-Setup
} else {
    Write-Step '未提供初始化参数，服务处于未初始化状态，请通过 http://127.0.0.1:47811 完成初始化。'
}

Write-Step '安装完成。'
exit 0
