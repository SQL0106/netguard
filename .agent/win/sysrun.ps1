param([Parameter(Mandatory)][string]$Target)
$done = 'C:\ngtest\sys-done.txt'
Remove-Item $done, 'C:\ngtest\sys-out.txt' -Force -ErrorAction SilentlyContinue
$tn = 'ng-sysrun'
& schtasks /delete /tn $tn /f 2>$null | Out-Null
$tr = 'powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\ngtest\syswrap.ps1 -Target ' + $Target
& schtasks /create /tn $tn /ru SYSTEM /rl HIGHEST /sc once /st 00:00 /tr $tr /f | Out-Null
& schtasks /run /tn $tn | Out-Null
$n = 0
while (-not (Test-Path $done)) {
    Start-Sleep -Milliseconds 500
    $n++
    if ($n -gt 240) { Write-Output 'TIMEOUT'; break }
}
if (Test-Path 'C:\ngtest\sys-out.txt') { Get-Content 'C:\ngtest\sys-out.txt' }
if (Test-Path $done) { Get-Content $done }
& schtasks /delete /tn $tn /f 2>$null | Out-Null
