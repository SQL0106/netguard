Set-Location 'C:\ngtest'
$err = 'C:\ngtest\curl-v-err.txt'
$out = 'C:\ngtest\curl-v-out.txt'
Remove-Item $err, $out -ErrorAction SilentlyContinue
$p = Start-Process 'C:\Windows\System32\curl.exe' `
    -ArgumentList '-v','-m','5','-o','NUL','https://example.com' `
    -RedirectStandardError $err -RedirectStandardOutput $out -PassThru -Wait -NoNewWindow
Write-Output ('exit=' + $p.ExitCode)
Write-Output '--- stderr tail ---'
Get-Content $err -Tail 25 -ErrorAction SilentlyContinue | Out-String | Write-Output
Write-Output '--- recent app crash events ---'
Get-WinEvent -FilterHashtable @{LogName='Application'; Id=1000} -MaxEvents 2 -ErrorAction SilentlyContinue |
    ForEach-Object { $_.TimeCreated.ToString('o') + ' ' + (($_.Message -split "`n")[0..4] -join ' | ') } |
    Out-String | Write-Output
Write-Output ('time=' + (Get-Date -Format o))
