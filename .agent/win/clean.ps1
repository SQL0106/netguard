$svc = Get-Service NetGuard -ErrorAction SilentlyContinue
if ($svc) {
    if ($svc.Status -ne 'Stopped') { Stop-Service NetGuard -Force -ErrorAction SilentlyContinue }
    Start-Sleep -Milliseconds 800
    & sc.exe delete NetGuard | Out-Null
    Start-Sleep -Milliseconds 1200
}
$dd = 'C:\ProgramData\NetGuard'
if (Test-Path $dd) {
    & icacls $dd /grant 'Administrators:(OI)(CI)F' | Out-Null
    Remove-Item -Recurse -Force $dd -ErrorAction SilentlyContinue
}
$id = 'C:\Program Files\NetGuard'
if (Test-Path $id) { Remove-Item -Recurse -Force $id -ErrorAction SilentlyContinue }
Write-Output ('svc_exists=' + [bool](Get-Service NetGuard -ErrorAction SilentlyContinue))
Write-Output ('datadir_exists=' + (Test-Path $dd))
Write-Output 'CLEAN_DONE'
