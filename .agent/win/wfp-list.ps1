$ErrorActionPreference = 'Continue'
$xml = Join-Path $env:TEMP 'wfp-ng.xml'
if (Test-Path $xml) { Remove-Item $xml -Force }
& netsh.exe wfp show filters file=$xml | Out-Null
Start-Sleep -Milliseconds 500
[xml]$doc = Get-Content $xml -Raw
$items = $doc.wfpdiag.filters.item
Write-Output ('total_filters=' + $items.Count)
$ng = $items | Where-Object { $_.displayData.name -like 'ng4|*' -or $_.displayData.name -like 'ng6|*' }
Write-Output ('ng_filters=' + @($ng).Count)
$ng | ForEach-Object {
    Write-Output ('  id=' + $_.filterId + '  name=' + $_.displayData.name + '  action=' + $_.action.type + '  persistent=' + $_.flags)
}
Write-Output ('time=' + (Get-Date -Format o))
