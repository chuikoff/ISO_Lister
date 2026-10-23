// IsoView.h — owner-drawn окно Lister в дизайне C (шапка цвета ОС, плитки, двухколоночные секции).
// Вид получает готовый текстовый отчёт от анализа (IsoAnalysis.h) и только рисует его.
#pragma once
#include <windows.h>

HWND IsoView_Create(HWND parent, const wchar_t* path, int showFlags, HINSTANCE inst);
int  IsoView_Load(HWND view, const wchar_t* path, int showFlags);   // повторная загрузка в то же окно
void IsoView_Copy(HWND view);                                       // lc_copy: выделение или весь отчёт
void IsoView_SelectAll(HWND view);                                  // lc_selectall
void IsoView_NewParams(HWND view, int showFlags);                   // lc_newparams: тема / раскладка
bool IsoView_Search(HWND view, const wchar_t* what, int params);    // ListSearchTextW (lcs_*)
void IsoView_SetInterfaceVersion(int ifaceTimes100);                // из ListSetDefaultParams (2.12 -> 212)
void IsoView_Unregister(HINSTANCE inst);
