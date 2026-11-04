$ErrorActionPreference = 'Continue'
for ($i = 1; $i -le 3; $i++) {
    $p = Start-Process -FilePath 'C:\Windows\System32\curl.exe' -ArgumentList '-s', '-m', '6', '-o', 'NUL', 'https://example.com' -Wait -PassThru -NoNewWindow
    Write-Output ('run' + $i + '=' + $p.ExitCode)
    Start-Sleep -Milliseconds 300
}
Write-Output '=== log tail ==='
Get-Content 'C:\ProgramData\NetGuard\netguard.log' -Tail 8 | Out-String | Write-Output
