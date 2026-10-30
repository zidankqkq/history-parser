# Publishes HistoryParser.exe (single self-contained file) to the output folder.
#   ./publish.ps1 [-Version 1.0.0] [-Out publish]
# The build is plain IL (not obfuscated/trimmed) so it can be inspected with ILSpy and matched to this source.
param(
    [string]$Version = '',
    [string]$Out = 'publish'
)
$ErrorActionPreference = 'Stop'
Set-Location $PSScriptRoot
$common = @('-c', 'Release', '-o', $Out, '--nologo')
if ($Version) { $common += "-p:Version=$Version" }
dotnet publish src/HistoryParser.App @common
if ($LASTEXITCODE) { throw 'Publish failed.' }
Write-Host "Published HistoryParser.exe to $Out" -ForegroundColor Green
