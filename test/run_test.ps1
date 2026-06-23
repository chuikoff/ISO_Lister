# IsoLister verification test — builds standalone harness and checks ISO/IMG parsing.
$ErrorActionPreference = "Stop"
$root = Split-Path $PSScriptRoot -Parent

$isoCandidates = @(
    "D:\Backup\SSD\1\clonezilla-live-3.2.0-5-amd64.iso",
    "D:\Backup\SSD\1\checkn1x-1.1.7.iso",
    "C:\Program Files (x86)\VMware\VMware Player\darwin.iso"
)

$iso = $isoCandidates | Where-Object { Test-Path $_ } | Select-Object -First 1
if (-not $iso) {
    Write-Error "No test ISO found. Place an ISO at one of: $($isoCandidates -join ', ')"
}

$vcvars = "${env:ProgramFiles}\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"
if (-not (Test-Path $vcvars)) {
    Write-Error "vcvars64.bat not found at $vcvars"
}

$outDir = Join-Path $PSScriptRoot "out"
New-Item -ItemType Directory -Force -Path $outDir | Out-Null
$exe = Join-Path $outDir "IsoListerTest.exe"

Write-Host "==> Building plugin (Release|x64)"
& "${env:ProgramFiles}\Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin\MSBuild.exe" `
    (Join-Path $root "IsoLister.sln") /p:Configuration=Release /p:Platform=x64 /v:minimal /nologo

Write-Host "==> Building standalone test harness"
$bat = Join-Path $PSScriptRoot "build_standalone.bat"
if (-not (Test-Path $bat)) { throw "Missing $bat" }
cmd /c $bat
if ($LASTEXITCODE -ne 0) { throw "Standalone build failed" }

function Invoke-IsoTest([string]$path) {
    $reportPath = Join-Path $outDir "report.txt"
    $errPath = Join-Path $outDir "stderr.txt"
    $p = Start-Process -FilePath $exe -ArgumentList $path -RedirectStandardOutput $reportPath -RedirectStandardError $errPath -Wait -PassThru
    if ($p.ExitCode -ne 0) {
        Get-Content $errPath -ErrorAction SilentlyContinue | Write-Host
        throw "Test failed for $path (exit $($p.ExitCode))"
    }
    Get-Content $errPath -ErrorAction SilentlyContinue | Write-Host
    Get-Content $reportPath -TotalCount 25 | Write-Host
}

Write-Host "==> Testing ISO: $iso"
Invoke-IsoTest $iso

$img = Join-Path $outDir "test_copy.img"
Copy-Item -Force $iso $img
Write-Host "==> Testing IMG copy: $img"
Invoke-IsoTest $img

Write-Host "==> ALL TESTS PASSED"