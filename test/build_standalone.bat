@echo off
setlocal
set ROOT=%~dp0..
set OUT=%~dp0out
if not exist "%OUT%" mkdir "%OUT%"

set VCVARS=
for /f "usebackq delims=" %%i in (`"%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath 2^>nul`) do (
  if exist "%%i\VC\Auxiliary\Build\vcvars64.bat" set "VCVARS=%%i\VC\Auxiliary\Build\vcvars64.bat"
)
if not defined VCVARS if exist "%ProgramFiles%\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat" set "VCVARS=%ProgramFiles%\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"
if not defined VCVARS (
  echo ERROR: vcvars64.bat not found. Install VS2022 C++ tools.
  exit /b 1
)
call "%VCVARS%"
cl /nologo /EHsc /std:c++17 /MT /DUNICODE /D_UNICODE /DWIN32_LEAN_AND_MEAN /DNOMINMAX /DISO_LISTER_STANDALONE /utf-8 /I"%ROOT%" "%ROOT%\IsoLister.cpp" /Fe:"%OUT%\IsoListerTest.exe" /Fo:"%OUT%\\" /link user32.lib gdi32.lib
exit /b %ERRORLEVEL%
