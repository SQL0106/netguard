param([Parameter(Mandatory)][string]$Target)
& powershell.exe -NoProfile -ExecutionPolicy Bypass -File $Target *> 'C:\ngtest\sys-out.txt'
$code = $LASTEXITCODE
('exit=' + $code) | Set-Content 'C:\ngtest\sys-done.txt'
