// IsoAnalysis.h — граница между анализом образа (IsoLister.cpp) и отображением
// (IsoView.cpp / IsoPlugin.cpp). Анализ возвращает текстовый отчёт; вид его
// только разбирает и рисует, сам текст отчёта (Ctrl+A/C) не меняется.
#pragma once
#include <windows.h>
#include <string>
#include <cstdint>

// Полный (compact=false, F3) или краткий (compact=true, Ctrl+Q) отчёт.
std::wstring IsoAnalysis_BuildReport(const wchar_t* path, bool compact);

// ListSetDefaultParams: путь к lsplugin.ini, перечитать [IsoLister] и язык TC.
void IsoAnalysis_SetIniPath(const wchar_t* iniPath);
std::wstring IsoAnalysis_IniPath();
std::wstring IsoAnalysis_WincmdIni();

bool IsoAnalysis_UiRussian();
const wchar_t* IsoAnalysis_Tr(const wchar_t* ru, const wchar_t* en);

// [IsoLister] Dark=0|1|2 (свет / тёмная / авто) и прежняя эвристика темы:
// wincmd.ini [Configuration] DarkMode, [Lister] BgColor, яркость родителя.
int IsoAnalysis_DarkOption();
bool IsoAnalysis_DetectDark(HWND parentHint);

std::wstring IsoAnalysis_FormatSize(uint64_t bytes);
void IsoAnalysis_Log(const wchar_t* msg);
