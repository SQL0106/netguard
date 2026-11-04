$ErrorActionPreference = 'Continue'
$cases = @(
    @{ n = 'version'; a = @('--version') },
    @{ n = 'blocked'; a = @('-s', '-m', '5', 'https://example.com') },
    @{ n = 'other';   a = @('-s', '-m', '5', 'https://example.com') }
)
$p = Start-Process -FilePath 'C:\Windows\System32\curl.exe' -ArgumentList @('--version') -Wait -PassThru -NoNewWindow -RedirectStandardOutput 'C:\ngtest\curlver.txt'
Write-Output ('curl_version_exit=' + $p.ExitCode)
$p2 = Start-Process -FilePath 'C:\Windows\System32\ping.exe' -ArgumentList @('-n', '1', '8.8.8.8') -Wait -PassThru -NoNewWindow -RedirectStandardOutput 'C:\ngtest\ping.txt'
Write-Output ('ping_exit=' + $p2.ExitCode)
Write-Output '=== ping output ==='
Get-Content 'C:\ngtest\ping.txt' -Tail 4 | Out-String | Write-Output
