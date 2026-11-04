$ErrorActionPreference = 'Continue'
Copy-Item 'C:\Windows\System32\curl.exe' 'C:\ngtest\curlcopy.exe' -Force
$c = Start-Process 'C:\ngtest\curlcopy.exe' -ArgumentList '-s','-m','5','-o','NUL','https://example.com' -PassThru -Wait
Write-Output ('copy_https_exit=' + $c.ExitCode)
$h = Start-Process 'C:\Windows\System32\curl.exe' -ArgumentList '-s','-m','5','-o','NUL','http://example.com' -PassThru -Wait
Write-Output ('curl_http_exit=' + $h.ExitCode)
$i = Start-Process 'C:\Windows\System32\curl.exe' -ArgumentList '-s','-m','5','-o','NUL','http://192.168.1.1' -PassThru -Wait
Write-Output ('curl_lan_exit=' + $i.ExitCode)
Write-Output ('time=' + (Get-Date -Format o))
