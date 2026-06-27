# pack_release.ps1 — собирает ISO_Lister_v*.zip (32+64-bit, README, LICENSE)
$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot

function Get-PluginVersion {
    $tag = (git -C $Root describe --tags --abbrev=0 2>$null).Trim()
    if ($tag -match '^v(.+)$') { return $Matches[1] }
    return "0.0.0"
}

function Write-Inf1251($src, $dst) {
    $utf8 = New-Object System.Text.UTF8Encoding($false)
    $text = [IO.File]::ReadAllText($src, $utf8)
    $enc1251 = [System.Text.Encoding]::GetEncoding(1251)
    [IO.File]::WriteAllText($dst, $text, $enc1251)
}

$version = Get-PluginVersion
$dist = Join-Path $Root "dist"
New-Item -ItemType Directory -Force -Path $dist | Out-Null

$wlx = Join-Path $Root "Release\IsoLister.wlx"
$wlx64 = Join-Path $Root "x64\Release\IsoLister.wlx64"
$license = Join-Path $Root "LICENSE"
$readme = Join-Path $Root "README.md"
$infSrc = Join-Path $PSScriptRoot "pluginst.inf"

foreach ($path in @($wlx, $wlx64, $license, $readme, $infSrc)) {
    if (-not (Test-Path $path)) { throw "Required file not found: $path" }
}

$zipName = "ISO_Lister_v${version}.zip"
$stage = Join-Path $dist "_stage_$zipName"
if (Test-Path $stage) { Remove-Item $stage -Recurse -Force }
New-Item -ItemType Directory -Force -Path $stage | Out-Null

Copy-Item $wlx $stage -Force
Copy-Item $wlx64 $stage -Force
Copy-Item $license $stage -Force
Copy-Item $readme (Join-Path $stage "README.md") -Force
Write-Inf1251 $infSrc (Join-Path $stage "pluginst.inf")

$zipPath = Join-Path $dist $zipName
if (Test-Path $zipPath) { Remove-Item $zipPath -Force }
Compress-Archive -Path (Join-Path $stage "*") -DestinationPath $zipPath -CompressionLevel Optimal
Remove-Item $stage -Recurse -Force

Write-Host "Created $zipPath ($((Get-Item $zipPath).Length) bytes)"