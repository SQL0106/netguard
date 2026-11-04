# 测试前关闭 Windows Update（可逆）
$ErrorActionPreference = 'Continue'

$services = 'wuauserv', 'bits', 'dosvc', 'UsoSvc', 'WaaSMedicSvc'
foreach ($name in $services) {
    try {
        Stop-Service -Name $name -Force -ErrorAction Stop
        Write-Output ("STOP OK   {0}" -f $name)
    } catch {
        Write-Output ("STOP FAIL {0}: {1}" -f $name, $_.Exception.Message)
    }
    try {
        Set-Service -Name $name -StartupType Disabled -ErrorAction Stop
        Write-Output ("DISABLE OK   {0}" -f $name)
    } catch {
        # 受保护服务改注册表
        try {
            Set-ItemProperty -Path ("HKLM:\SYSTEM\CurrentControlSet\Services\{0}" -f $name) -Name Start -Value 4 -Type DWord -ErrorAction Stop
            Write-Output ("DISABLE OK(reg)   {0}" -f $name)
        } catch {
            Write-Output ("DISABLE FAIL {0}: {1}" -f $name, $_.Exception.Message)
        }
    }
}

# 组策略层：不自动更新、不自动重启
$au = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU'
New-Item -Path $au -Force | Out-Null
Set-ItemProperty -Path $au -Name NoAutoUpdate -Value 1 -Type DWord
Set-ItemProperty -Path $au -Name AUOptions -Value 1 -Type DWord
$wu = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'
Set-ItemProperty -Path $wu -Name SetDisableUXWUAccess -Value 1 -Type DWord -ErrorAction SilentlyContinue

# 记录回滚方式
Write-Output ''
Write-Output 'ROLLBACK:'
Write-Output 'Set-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" NoAutoUpdate 0'
foreach ($name in $services) {
    Write-Output ("Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\{0}' Start <原值>; Set-Service {0} -StartupType Manual" -f $name)
}

Write-Output ''
Write-Output '--- 当前状态 ---'
Get-Service $services | Select-Object Name, Status, StartType | Format-Table -AutoSize | Out-String | Write-Output
Write-Output '--- 最近一次更新 ---'
try {
    $last = Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 1
    Write-Output ("LAST HOTFIX {0} {1}" -f $last.HotFixID, $last.InstalledOn)
} catch {
    Write-Output 'LAST HOTFIX unknown'
}
Write-Output ("PENDING REBOOT {0}" -f (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired'))
Write-Output 'DONE'
