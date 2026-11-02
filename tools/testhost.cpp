// Minimal Lister host for testing IsoLister.wlx/.wlx64 without Total Commander (box/Wine).
// usage: testhost.exe plugin.wlx64 file [search-text] [--size WxH] [--dark] [--quick] [--ini lsplugin.ini] [--iface 212]
//                    [--shot out.bmp] [--pgdn N] [--copy out.txt] [--back]
#include <windows.h>
#include <cstdio>
#include <string>
typedef HWND(__stdcall* PLoad)(HWND, WCHAR*, int);
typedef int(__stdcall* PSearch)(HWND, WCHAR*, int);
typedef void(__stdcall* PDetect)(char*, int);
typedef HBITMAP(__stdcall* PPreview)(WCHAR*, int, int, char*, int);
typedef void(__stdcall* PClose)(HWND);
typedef int(__stdcall* PCommand)(HWND, int, int);
struct DefParams { int size; DWORD lo; DWORD hi; char ini[MAX_PATH]; };
typedef void(__stdcall* PDefParams)(DefParams*);
static void pump(int ms) {
    DWORD t0 = GetTickCount(); MSG m;
    while (GetTickCount() - t0 < (DWORD)ms) { while (PeekMessageW(&m, nullptr, 0, 0, PM_REMOVE)) { TranslateMessage(&m); DispatchMessageW(&m); } Sleep(10); }
}
static HWND g_plugin;
static LRESULT CALLBACK Proc(HWND h, UINT m, WPARAM w, LPARAM l) {
    if (m == WM_SIZE && g_plugin) { MoveWindow(g_plugin, 0, 0, LOWORD(l), HIWORD(l), TRUE); return 0; }
    if (m == WM_KEYDOWN && w == VK_ESCAPE) { DestroyWindow(h); return 0; }
    if (m == WM_DESTROY) { PostQuitMessage(0); return 0; }
    return DefWindowProcW(h, m, w, l);
}
static void save_bmp(HBITMAP b, const wchar_t* path) {
    BITMAP bm; GetObject(b, sizeof bm, &bm);
    BITMAPINFOHEADER bi = {}; bi.biSize = sizeof bi; bi.biWidth = bm.bmWidth; bi.biHeight = bm.bmHeight; bi.biPlanes = 1; bi.biBitCount = 32; bi.biCompression = BI_RGB;
    std::string px((size_t)bm.bmWidth * bm.bmHeight * 4, '\0');
    HDC dc = GetDC(nullptr); GetDIBits(dc, b, 0, bm.bmHeight, &px[0], (BITMAPINFO*)&bi, DIB_RGB_COLORS); ReleaseDC(nullptr, dc);
    BITMAPFILEHEADER fh = { 0x4D42, (DWORD)(sizeof fh + sizeof bi + px.size()), 0, 0, sizeof fh + sizeof bi };
    FILE* f = _wfopen(path, L"wb"); if (!f) return;
    fwrite(&fh, sizeof fh, 1, f); fwrite(&bi, sizeof bi, 1, f); fwrite(px.data(), px.size(), 1, f); fclose(f);
}
int wmain(int argc, wchar_t** argv) {
    if (argc < 3) { MessageBoxW(nullptr, L"usage: testhost plugin.wlx64 file [search] [--preview out.bmp] [--size WxH]", L"testhost", 0); return 2; }
    { // behave like TC 10+: per-monitor DPI aware
        typedef BOOL(WINAPI * PSet)(HANDLE);
        PSet f = (PSet)(void*)GetProcAddress(GetModuleHandleW(L"user32.dll"), "SetProcessDpiAwarenessContext");
        if (f) f((HANDLE)-4); else SetProcessDPIAware();
    }
    HMODULE dll = LoadLibraryW(argv[1]);
    if (!dll) { fwprintf(stderr, L"cannot load %ls (%lu)\n", argv[1], GetLastError()); return 1; }
    PLoad load = (PLoad)(void*)GetProcAddress(dll, "ListLoadW");
    PSearch search = (PSearch)(void*)GetProcAddress(dll, "ListSearchTextW");
    PDetect detect = (PDetect)(void*)GetProcAddress(dll, "ListGetDetectString");
    PPreview preview = (PPreview)(void*)GetProcAddress(dll, "ListGetPreviewBitmapW");
    PClose close = (PClose)(void*)GetProcAddress(dll, "ListCloseWindow");
    char ds[512] = ""; if (detect) detect(ds, sizeof ds);
    fprintf(stderr, "exports: ListLoadW=%p ListSearchTextW=%p ListGetPreviewBitmapW=%p ListCloseWindow=%p\ndetect: %s\n", (void*)load, (void*)search, (void*)preview, (void*)close, ds);
    int ww = 1180, wh = 860;
    const wchar_t* find = nullptr; const wchar_t* prev = nullptr; const wchar_t* shot = nullptr; const wchar_t* copy = nullptr;
    int flags = 0, pgdn = 0, iface = 0; bool back = false; const wchar_t* ini = nullptr;
    PCommand command = (PCommand)(void*)GetProcAddress(dll, "ListSendCommand");
    for (int i = 3; i < argc; i++) {
        if (!wcscmp(argv[i], L"--preview") && i + 1 < argc) prev = argv[++i];
        else if (!wcscmp(argv[i], L"--size") && i + 1 < argc) { swscanf(argv[++i], L"%dx%d", &ww, &wh); }
        else if (!wcscmp(argv[i], L"--dark")) flags |= 128;
        else if (!wcscmp(argv[i], L"--quick")) flags |= 2;
        else if (!wcscmp(argv[i], L"--ini") && i + 1 < argc) ini = argv[++i];
        else if (!wcscmp(argv[i], L"--iface") && i + 1 < argc) iface = _wtoi(argv[++i]);
        else if (!wcscmp(argv[i], L"--back")) back = true;
        else if (!wcscmp(argv[i], L"--shot") && i + 1 < argc) shot = argv[++i];
        else if (!wcscmp(argv[i], L"--copy") && i + 1 < argc) copy = argv[++i];
        else if (!wcscmp(argv[i], L"--pgdn") && i + 1 < argc) pgdn = _wtoi(argv[++i]);
        else find = argv[i];
    }
    PDefParams defp = (PDefParams)(void*)GetProcAddress(dll, "ListSetDefaultParams");
    if (defp && (ini || iface)) {
        DefParams d = {}; d.size = sizeof d; d.hi = iface / 100; d.lo = iface % 100;
        if (ini) WideCharToMultiByte(CP_ACP, 0, ini, -1, d.ini, MAX_PATH, nullptr, nullptr);
        defp(&d);
    }
    if (prev && preview) {
        HBITMAP b = preview(argv[2], 96, 96, nullptr, 0);
        fprintf(stderr, "preview bitmap: %p\n", (void*)b);
        if (b) { save_bmp(b, prev); DeleteObject(b); }
        return b ? 0 : 1;
    }
    // --quick stands in for Ctrl+Q: the real plugin treats only a TTOTAL_CMD root as Quick View.
    const wchar_t* hostClass = (flags & 2) ? L"TTOTAL_CMD" : L"TestLister";
    WNDCLASSW wc = {}; wc.lpfnWndProc = Proc; wc.hInstance = GetModuleHandleW(nullptr); wc.lpszClassName = hostClass;
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1); wc.hCursor = LoadCursor(nullptr, IDC_ARROW);
    RegisterClassW(&wc);
    std::wstring t = L"Lister - [" + std::wstring(argv[2]) + L"]";
    RECT wr = { 0, 0, ww, wh }; AdjustWindowRect(&wr, WS_OVERLAPPEDWINDOW, FALSE); // --size is the client size
    HWND main = CreateWindowExW(0, hostClass, t.c_str(), WS_OVERLAPPEDWINDOW | WS_VISIBLE | WS_CLIPCHILDREN, 0, 0, wr.right - wr.left, wr.bottom - wr.top, nullptr, nullptr, wc.hInstance, nullptr);
    DWORD t0 = GetTickCount();
    g_plugin = load ? load(main, argv[2], flags) : nullptr;
    fprintf(stderr, "ListLoadW -> %p in %lu ms\n", (void*)g_plugin, GetTickCount() - t0);
    if (!g_plugin) return 1;
    RECT rc; GetClientRect(main, &rc); MoveWindow(g_plugin, 0, 0, rc.right, rc.bottom, TRUE);
    if (find && search) { MSG m; while (PeekMessageW(&m, nullptr, 0, 0, PM_REMOVE)) { TranslateMessage(&m); DispatchMessageW(&m); }
        int r = search(g_plugin, (WCHAR*)find, 1); fprintf(stderr, "search '%ls' -> %d\n", find, r);
        if (back) { int r2 = search(g_plugin, (WCHAR*)find, 0); int r3 = search(g_plugin, (WCHAR*)find, 8); fprintf(stderr, "next -> %d, back -> %d\n", r2, r3); } }
    for (int i = 0; i < pgdn; i++) SendMessageW(g_plugin, WM_KEYDOWN, VK_NEXT, 0);
    if (copy && command) {
        command(g_plugin, 3, 0); command(g_plugin, 1, 0);
        if (OpenClipboard(main)) {
            HANDLE hd = GetClipboardData(CF_UNICODETEXT);
            const wchar_t* t = hd ? (const wchar_t*)GlobalLock(hd) : nullptr;
            if (t) { int n = WideCharToMultiByte(CP_UTF8, 0, t, -1, nullptr, 0, nullptr, nullptr); std::string u(n, 0); WideCharToMultiByte(CP_UTF8, 0, t, -1, &u[0], n, nullptr, nullptr);
                FILE* f = _wfopen(copy, L"wb"); if (f) { fwrite(u.data(), 1, u.size() ? u.size() - 1 : 0, f); fclose(f); } GlobalUnlock(hd); }
            CloseClipboard();
        }
    }
    if (shot) {
        pump(800);
        RECT cr; GetClientRect(main, &cr);
        HDC sdc = GetDC(main), mdc = CreateCompatibleDC(sdc);
        HBITMAP b = CreateCompatibleBitmap(sdc, cr.right, cr.bottom); HGDIOBJ o = SelectObject(mdc, b);
        BitBlt(mdc, 0, 0, cr.right, cr.bottom, sdc, 0, 0, SRCCOPY);
        SelectObject(mdc, o); DeleteDC(mdc); ReleaseDC(main, sdc);
        save_bmp(b, shot); DeleteObject(b);
        DestroyWindow(main);
        return 0;
    }
    MSG msg; while (GetMessageW(&msg, nullptr, 0, 0)) { TranslateMessage(&msg); DispatchMessageW(&msg); }
    if (close && IsWindow(g_plugin)) close(g_plugin);
    return 0;
}
