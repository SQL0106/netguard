$ErrorActionPreference = 'Continue'
$services = 'wuauserv', 'bits', 'dosvc', 'UsoSvc', 'WaaSMedicSvc'
foreach ($name in $services) {
    try {
        Set-Service -Name $name -StartupType Disabled -ErrorAction Stop
        Write-Output ("DISABLE OK   {0}" -f $name)
    } catch {
        Set-ItemProperty -Path ("HKLM:\SYSTEM\CurrentControlSet\Services\{0}" -f $name) -Name Start -Value 4 -Type DWord -ErrorAction SilentlyContinue
        Write-Output ("DISABLE REG  {0}" -f $name)
    }
}
foreach ($name in $services) {
    try { Stop-Service -Name $name -Force -ErrorAction Stop; Write-Output ("STOP OK   {0}" -f $name) }
    catch { Write-Output ("STOP SKIP {0}: {1}" -f $name, $_.Exception.Message) }
}
Start-Sleep -Seconds 3
Get-Service $services | Select-Object Name, Status, StartType | Format-Table -AutoSize | Out-String | Write-Output
foreach ($name in $services) {
    $p = "HKLM:\SYSTEM\CurrentControlSet\Services\$name"
    $v = (Get-ItemProperty -Path $p -Name Start -ErrorAction SilentlyContinue).Start
    Write-Output ("REG {0} Start={1}" -f $name, $v)
}
Write-Output 'DONE'
