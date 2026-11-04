Set-Location 'C:\ngtest'
& .\install.ps1 -Force
Write-Output ('install_rc=' + $LASTEXITCODE)
Start-Sleep -Seconds 3
& sc.exe query NetGuard 2>&1 | Out-String | Write-Output
& 'C:\Program Files\NetGuard\netguard.exe' status 2>&1 | Out-String | Write-Output
Write-Output '=== log tail ==='
Get-Content 'C:\ProgramData\NetGuard\netguard.log' -Tail 12 | Out-String | Write-Output
Write-Output ('time=' + (Get-Date -Format o))
