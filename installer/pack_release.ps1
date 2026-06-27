# pack_release.ps1 — собирает ISO_Lister_v*_wlx.zip и ISO_Lister_v*_wlx64.zip
$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot

function Get-PluginVersion {
    $tag = (git -C $Root describe --tags --abbrev=0 2>$null).Trim()
    if ($tag -match '^v(.+)$') { return $Matches[1] }
    return "0.0.0"
}

$version = Get-PluginVersion
$dist = Join-Path $Root "dist"
New-Item -ItemType Directory -Force -Path $dist | Out-Null

$packages = @(
    @{
        Name = "ISO_Lister_v${version}_wlx64.zip"
        Binary = Join-Path $Root "x64\Release\IsoLister.wlx64"
        Inf = Join-Path $PSScriptRoot "pluginst.inf"
    },
    @{
        Name = "ISO_Lister_v${version}_wlx.zip"
        Binary = Join-Path $Root "Release\IsoLister.wlx"
        Inf = Join-Path $PSScriptRoot "pluginst.wlx.inf"
    }
)

$license = Join-Path $Root "LICENSE"
if (-not (Test-Path $license)) { throw "LICENSE not found: $license" }

foreach ($pkg in $packages) {
    if (-not (Test-Path $pkg.Binary)) {
        throw "Binary not found: $($pkg.Binary). Run MSBuild Release first."
    }

    $stage = Join-Path $dist ("_stage_" + [IO.Path]::GetFileNameWithoutExtension($pkg.Name))
    if (Test-Path $stage) { Remove-Item $stage -Recurse -Force }
    New-Item -ItemType Directory -Force -Path $stage | Out-Null

    Copy-Item $pkg.Binary $stage -Force
    Copy-Item $license $stage -Force

    # pluginst.inf: Windows-1251 для корректного русского текста в TC
    $infDst = Join-Path $stage "pluginst.inf"
    $utf8 = New-Object System.Text.UTF8Encoding($false)
    $text = [IO.File]::ReadAllText($pkg.Inf, $utf8)
    $enc1251 = [System.Text.Encoding]::GetEncoding(1251)
    [IO.File]::WriteAllText($infDst, $text, $enc1251)

    $zipPath = Join-Path $dist $pkg.Name
    if (Test-Path $zipPath) { Remove-Item $zipPath -Force }
    Compress-Archive -Path (Join-Path $stage "*") -DestinationPath $zipPath -CompressionLevel Optimal
    Remove-Item $stage -Recurse -Force

    $size = (Get-Item $zipPath).Length
    Write-Host "Created $zipPath ($size bytes)"
}