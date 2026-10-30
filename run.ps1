# History Parser one-command launcher.
#
#   irm https://github.com/zidankqkq/history-parser/releases/latest/download/run.ps1 | iex
#
# Downloads the latest HistoryParser.exe from this project's GitHub releases into a temp folder,
# checks it against the published SHA-256, and starts it (Windows asks for admin, then you pick
# default or custom rules and start the scan). Nothing is installed; delete the temp folder afterwards.
# run-logparser.ps1 is the old Log Parser link; it now does the same.

$ErrorActionPreference = 'Stop'
$app  = 'HistoryParser'
$repo = 'zidankqkq/history-parser'
$base = "https://github.com/$repo/releases/latest/download"
$dir  = Join-Path $env:TEMP $app
$exe  = Join-Path $dir "$app.exe"

New-Item -ItemType Directory -Force -Path $dir | Out-Null
Write-Host "Downloading $app..." -ForegroundColor Cyan
$ProgressPreference = 'SilentlyContinue'   # Invoke-WebRequest is very slow with the progress bar on
Invoke-WebRequest "$base/$app.exe" -OutFile $exe -UseBasicParsing

# SHA256SUMS.txt has one "hash  file" line per exe; GitHub may serve it as bytes.
$sums = (Invoke-WebRequest "$base/SHA256SUMS.txt" -UseBasicParsing).Content
if ($sums -is [byte[]]) { $sums = [System.Text.Encoding]::ASCII.GetString($sums) }
$line = $sums -split "`n" | Where-Object { $_ -match "\s$app\.exe\s*$" } | Select-Object -First 1
if (-not $line) { throw "SHA256SUMS.txt has no entry for $app.exe. Not running it." }
$expected = ($line -split '\s+')[0].Trim().ToLower()
$actual = (Get-FileHash $exe -Algorithm SHA256).Hash.ToLower()

if ($expected -ne $actual) {
    Remove-Item $exe -Force
    throw "Download does not match the published SHA-256 (expected $expected, got $actual). Not running it."
}

Write-Host "Verified SHA-256 $actual" -ForegroundColor Green
Start-Process -FilePath $exe -Verb RunAs
