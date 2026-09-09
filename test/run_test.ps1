# IsoLister verification test — builds standalone harness and checks ISO/IMG parsing.
$ErrorActionPreference = "Stop"
$root = Split-Path $PSScriptRoot -Parent

function Find-VcTools {
    $vswhere = Join-Path ${env:ProgramFiles(x86)} "Microsoft Visual Studio\Installer\vswhere.exe"
    if (Test-Path $vswhere) {
        $installPath = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath 2>$null
        if ($installPath) {
            $vcvars = Join-Path $installPath "VC\Auxiliary\Build\vcvars64.bat"
            $msbuild = Join-Path $installPath "MSBuild\Current\Bin\MSBuild.exe"
            if ((Test-Path $vcvars) -and (Test-Path $msbuild)) {
                return @{ Vcvars = $vcvars; MSBuild = $msbuild }
            }
        }
    }
    $fallbackRoot = Join-Path $env:ProgramFiles "Microsoft Visual Studio\2022\Community"
    $vcvars = Join-Path $fallbackRoot "VC\Auxiliary\Build\vcvars64.bat"
    $msbuild = Join-Path $fallbackRoot "MSBuild\Current\Bin\MSBuild.exe"
    if ((Test-Path $vcvars) -and (Test-Path $msbuild)) {
        return @{ Vcvars = $vcvars; MSBuild = $msbuild }
    }
    throw "vcvars64.bat / MSBuild not found. Install VS2022 C++ tools (vswhere or Community)."
}

function Find-TestIso {
    if ($env:ISO_LISTER_TEST_ISO -and (Test-Path -LiteralPath $env:ISO_LISTER_TEST_ISO)) {
        return (Resolve-Path -LiteralPath $env:ISO_LISTER_TEST_ISO).Path
    }
    $fixtureDirs = @(
        (Join-Path $PSScriptRoot "fixtures"),
        (Join-Path $root "fixtures")
    )
    foreach ($dir in $fixtureDirs) {
        if (Test-Path $dir) {
            $hit = Get-ChildItem -Path $dir -Filter *.iso -File -ErrorAction SilentlyContinue | Select-Object -First 1
            if ($hit) { return $hit.FullName }
        }
    }
    throw "No test ISO found. Set ISO_LISTER_TEST_ISO to an .iso path, or place a *.iso under test\fixtures\ or fixtures\."
}

$tools = Find-VcTools
$iso = Find-TestIso

$outDir = Join-Path $PSScriptRoot "out"
New-Item -ItemType Directory -Force -Path $outDir | Out-Null
$exe = Join-Path $outDir "IsoListerTest.exe"

Write-Host "==> Building plugin (Release|x64)"
& $tools.MSBuild (Join-Path $root "IsoLister.sln") /p:Configuration=Release /p:Platform=x64 /v:minimal /nologo
if ($LASTEXITCODE -ne 0) { throw "MSBuild failed" }

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
