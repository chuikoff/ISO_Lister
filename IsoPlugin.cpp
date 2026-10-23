// IsoPlugin.cpp — WLX-экспорты IsoLister для Total Commander.
// Анализ: IsoLister.cpp (IsoAnalysis.h). Отрисовка: IsoView.cpp (дизайн C).
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <strsafe.h>
#include <string>

extern "C" {
#include "listplug.h"
}
#include "IsoAnalysis.h"
#include "IsoView.h"

// MSVC exports these names through IsoLister.def / IsoLister.wlx.def;
// MinGW uses dllexport (+ --kill-at for the 32-bit build).
#if defined(__GNUC__)
#define WLX_EXPORT extern "C" __declspec(dllexport)
#else
#define WLX_EXPORT extern "C"
#endif

static HINSTANCE g_hInst = nullptr;

static std::wstring from_acp(const char* s) {
    if (!s) return std::wstring();
    int n = MultiByteToWideChar(CP_ACP, 0, s, -1, nullptr, 0);
    if (n <= 0) return std::wstring();
    std::wstring w((size_t)n, L'\0');
    MultiByteToWideChar(CP_ACP, 0, s, -1, &w[0], n);
    if (!w.empty() && w.back() == L'\0') w.pop_back();
    return w;
}

WLX_EXPORT HWND __stdcall ListLoadW(HWND ParentWin, WCHAR* FileToLoad, int ShowFlags)
{
    wchar_t msg[600];
    StringCchPrintfW(msg, 600, L"ListLoadW: file=\"%s\" flags=%d", FileToLoad ? FileToLoad : L"(null)", ShowFlags);
    IsoAnalysis_Log(msg);
    if (!ParentWin || !IsWindow(ParentWin)) {
        IsoAnalysis_Log(L"ListLoadW: invalid parent window");
        return nullptr;
    }
    HWND h = IsoView_Create(ParentWin, FileToLoad ? FileToLoad : L"", ShowFlags, g_hInst);
    if (!h) IsoAnalysis_Log(L"ListLoadW: view creation FAILED");
    return h;
}

WLX_EXPORT HWND __stdcall ListLoad(HWND ParentWin, char* FileToLoad, int ShowFlags)
{
    std::wstring w = from_acp(FileToLoad);
    return ListLoadW(ParentWin, &w[0], ShowFlags);
}

// Detect: ISO/DMG/WIM/ESD — обычные файлы; IMG — MULTIMEDIA в TC, без этого флага плагин игнорируется.
// IMG: MULTIMEDIA required by TC; no bare EXT="IMG" (would steal GEM/picture .img).
// BIN: raw dumps; VHD/VHDX: Hyper-V images.
static const char kIsoListerDetectString[] =
    "EXT=\"ISO\" | EXT=\"DMG\" | EXT=\"WIM\" | EXT=\"ESD\" | EXT=\"VHD\" | EXT=\"VHDX\" | "
    "(EXT=\"BIN\" & [510]=85 & [511]=170) | "
    "(EXT=\"BIN\" & SIZE>50000000) | "
    "(MULTIMEDIA & EXT=\"IMG\" & [510]=85 & [511]=170) | "
    "(MULTIMEDIA & EXT=\"IMG\" & [32769]=67 & [32770]=68 & [32771]=48 & [32772]=48 & [32773]=49) | "
    "(MULTIMEDIA & EXT=\"IMG\" & SIZE>50000000)";

WLX_EXPORT void __stdcall ListGetDetectString(char* DetectString, int maxlen)
{
    StringCchCopyA(DetectString, (size_t)maxlen, kIsoListerDetectString);
    IsoAnalysis_Log(L"ListGetDetectString called");
}

WLX_EXPORT void __stdcall ListCloseWindow(HWND ListWin)
{
    IsoAnalysis_Log(L"ListCloseWindow");
    if (ListWin && IsWindow(ListWin)) DestroyWindow(ListWin);
}

WLX_EXPORT int __stdcall ListSendCommand(HWND ListWin, int Command, int Parameter)
{
    if (!IsWindow(ListWin)) return LISTPLUGIN_ERROR;
    switch (Command) {
    case lc_copy: IsoView_Copy(ListWin); return LISTPLUGIN_OK;
    case lc_selectall: IsoView_SelectAll(ListWin); return LISTPLUGIN_OK;
    case lc_newparams: IsoView_NewParams(ListWin, Parameter); return LISTPLUGIN_OK;
    default: break;
    }
    return LISTPLUGIN_ERROR;
}

WLX_EXPORT int __stdcall ListSearchTextW(HWND ListWin, WCHAR* SearchString, int SearchParameter)
{
    if (!IsWindow(ListWin) || !SearchString || !SearchString[0]) return LISTPLUGIN_ERROR;
    return IsoView_Search(ListWin, SearchString, SearchParameter) ? LISTPLUGIN_OK : LISTPLUGIN_ERROR;
}

WLX_EXPORT int __stdcall ListSearchText(HWND ListWin, char* SearchString, int SearchParameter)
{
    if (!SearchString) return LISTPLUGIN_ERROR;
    std::wstring w = from_acp(SearchString);
    if (w.empty()) return LISTPLUGIN_ERROR;
    return ListSearchTextW(ListWin, &w[0], SearchParameter);
}

WLX_EXPORT void __stdcall ListSetDefaultParams(ListDefaultParamStruct* dps)
{
    if (!dps) return;
    DWORD lo = dps->PluginInterfaceVersionLow;
    while (lo >= 100) lo /= 10;
    IsoView_SetInterfaceVersion((int)(dps->PluginInterfaceVersionHi * 100 + lo));
    std::wstring ini = dps->DefaultIniName[0] ? from_acp(dps->DefaultIniName) : std::wstring();
    IsoAnalysis_SetIniPath(ini.c_str());
}

extern "C" BOOL APIENTRY DllMain(HINSTANCE hinst, DWORD reason, LPVOID)
{
    if (reason == DLL_PROCESS_ATTACH) {
        g_hInst = hinst;
        IsoAnalysis_Log(L"DllMain: ATTACH");
    }
    else if (reason == DLL_PROCESS_DETACH) {
        IsoView_Unregister(g_hInst);
    }
    return TRUE;
}
