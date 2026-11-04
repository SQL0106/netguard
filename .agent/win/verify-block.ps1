# 拦截生效性验证：被拦的 curl.exe 应失败，未被拦的 pwsh 应成功。
$ErrorActionPreference = 'Continue'
Set-Location 'C:\ngtest'

Write-Output '--- curl.exe（在名单内，应失败）---'
$curl = Start-Process -FilePath 'C:\Windows\System32\curl.exe' `
    -ArgumentList '-s','-m','6','-o','NUL','https://example.com' `
    -Wait -PassThru -NoNewWindow
Write-Output ('curl_exit=' + $curl.ExitCode)

Write-Output '--- Invoke-WebRequest（pwsh.exe，不在名单，应成功）---'
try {
    $r = Invoke-WebRequest -Uri 'https://example.com' -UseBasicParsing -TimeoutSec 8
    Write-Output ('web_status=' + $r.StatusCode)
} catch {
    Write-Output ('web_error=' + $_.Exception.Message)
}

Write-Output '--- 过滤器计数 ---'
$xml = Join-Path $env:TEMP 'wfp-ng.xml'
& netsh.exe wfp show filters file=$xml | Out-Null
$hits = Select-String -Path $xml -Pattern 'ng4\||ng6\|' -AllMatches
Write-Output ('filter_names=' + ($hits.Matches.Count))

Write-Output '--- 日志尾部 ---'
Get-Content 'C:\ProgramData\NetGuard\netguard.log' -Tail 10 | Out-String | Write-Output
Write-Output ('time=' + (Get-Date -Format o))
