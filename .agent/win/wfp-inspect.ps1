$ErrorActionPreference = 'Continue'
$xml = Join-Path $env:TEMP 'wfp-ng.xml'
if (-not (Test-Path $xml)) { & netsh.exe wfp show filters file=$xml | Out-Null; Start-Sleep -Milliseconds 500 }
[xml]$doc = Get-Content $xml -Raw
$items = $doc.wfpdiag.filters.item
$ng = $items | Where-Object { $_.displayData.name -like 'ng4|*' }
$ng | Select-Object -First 3 | ForEach-Object {
    Write-Output ('id=' + $_.filterId)
    Write-Output ('  name=' + $_.displayData.name)
    Write-Output ('  layer=' + $_.layerKey)
    Write-Output ('  sublayer=' + $_.subLayerKey)
    Write-Output ('  provider=' + $_.providerKey)
    Write-Output ('  action=' + $_.action.type)
    Write-Output ('  flags=' + ($_.flags.InnerText))
    Write-Output ('  weight=' + $_.weight)
}
Write-Output '--- providers containing NetGuard ---'
$items2 = $doc.wfpdiag.providers.item
@($items2) | Where-Object { $_.displayData.name -like '*NetGuard*' } | ForEach-Object {
    Write-Output ('  providerKey=' + $_.providerKey + ' name=' + $_.displayData.name + ' flags=' + ($_.flags.InnerText))
}
