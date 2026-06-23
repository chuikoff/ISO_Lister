@echo off
call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"
cl /nologo /EHsc /std:c++17 /MT /DUNICODE /D_UNICODE /DWIN32_LEAN_AND_MEAN /DNOMINMAX /DISO_LISTER_STANDALONE /utf-8 "C:\Users\chuik\source\repos\IsoLister\IsoLister.cpp" /Fe:"C:\Users\chuik\source\repos\IsoLister\test\out\IsoListerTest.exe" /link user32.lib gdi32.lib
