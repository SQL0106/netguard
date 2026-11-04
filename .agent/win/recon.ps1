$os = Get-CimInstance Win32_OperatingSystem
Write-Output ("OS        {0} build {1}" -f $os.Caption, $os.BuildNumber)
Write-Output ("PS        {0}" -f $PSVersionTable.PSVersion)
$admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
Write-Output ("USER      {0}  ADMIN={1}" -f $env:USERNAME, $admin)
Write-Output ("UPTIME    {0}" -f ((Get-Date) - $os.LastBootUpTime))

$svc = Get-Service NetGuard -ErrorAction SilentlyContinue
if ($svc) { Write-Output ("NETGUARD  {0}/{1}" -f $svc.Status, $svc.StartType) } else { Write-Output 'NETGUARD  absent' }
Write-Output ("NGDIR     {0}" -f (Test-Path 'C:\ProgramData\NetGuard'))

$xml = Join-Path $env:TEMP 'wfp0.xml'
netsh wfp show state file=$xml | Out-Null
if (Test-Path $xml) {
    $hit = Select-String -Path $xml -Pattern 'NetGuard' -SimpleMatch -Quiet
    Write-Output ("WFPPROV   {0}" -f $(if ($hit) { 'found' } else { 'none' }))
} else { Write-Output 'WFPPROV   no-dump' }

Write-Output ("DISKFREE  {0:N1} GB" -f ((Get-PSDrive C).Free / 1GB))
$mp = Get-MpComputerStatus -ErrorAction SilentlyContinue
if ($mp) { Write-Output ("DEFENDER  RealTime={0} Tamper={1}" -f $mp.RealTimeProtectionEnabled, $mp.IsTamperProtected) } else { Write-Output 'DEFENDER  unavailable' }
$up = Get-NetAdapter | Where-Object Status -eq 'Up'
Write-Output ("ADAPTERS  {0}" -f (($up | ForEach-Object { $_.Name + '/' + $_.InterfaceDescription }) -join '; '))
Write-Output 'DONE'
