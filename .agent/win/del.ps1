$o = & sc.exe stop NetGuard 2>&1
Write-Output ('stop_rc=' + $LASTEXITCODE)
$o | Write-Output
Start-Sleep -Seconds 2
$o2 = & sc.exe delete NetGuard 2>&1
Write-Output ('delete_rc=' + $LASTEXITCODE)
$o2 | Write-Output
Start-Sleep -Seconds 2
$q = & sc.exe query NetGuard 2>&1
Write-Output ('query_rc=' + $LASTEXITCODE)
$q | Write-Output
