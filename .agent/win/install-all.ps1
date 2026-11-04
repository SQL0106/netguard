Set-Location 'C:\ngtest'
$svc = Get-Service NetGuard -ErrorAction SilentlyContinue
if ($svc) { Write-Output ('svc_before=' + $svc.Status) } else { Write-Output 'svc_before=absent' }
& .\install.ps1 -Silent -Config 'C:\ngtest\preseed.json' -RecoveryOut 'C:\ngtest\codes.txt'
Write-Output ('install_rc=' + $LASTEXITCODE)
Start-Sleep -Seconds 3
& sc.exe query NetGuard 2>&1 | Out-String | Write-Output
& 'C:\Program Files\NetGuard\netguard.exe' status 2>&1 | Out-String | Write-Output
Get-ChildItem 'C:\ProgramData\NetGuard' -ErrorAction SilentlyContinue | Select-Object Name, Length | Format-Table -AutoSize | Out-String | Write-Output
Write-Output ('time=' + (Get-Date -Format o))
