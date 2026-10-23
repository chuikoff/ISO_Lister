// IsoView.cpp — owner-drawn вид отчёта IsoLister в дизайне C (как APK Lister 0.2.0):
// цветная шапка по ОС образа, шесть плиток с ключевыми фактами, секции в две колонки,
// выделение строк, копирование, поиск TC с подсветкой, прокрутка, DPI, тёмная тема.
// Данные берутся только из текстового отчёта (IsoModel), Ctrl+A/C копирует его без изменений.
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <objidl.h>
#include <strsafe.h>
#include <string>
#include <vector>
#include <algorithm>
#include <climits>
#include <cmath>
namespace Gdiplus { using std::min; using std::max; }
#include <gdiplus.h>

#include "IsoView.h"
#include "IsoModel.h"
#include "IsoAnalysis.h"

#ifdef _MSC_VER
#pragma comment(lib, "gdiplus.lib")
#endif

#define lc_copy 1
#define lc_newparams 2
#define lc_selectall 3
#define lcs_findfirst 1
#define lcs_matchcase 2
#define lcs_wholewords 4
#define lcs_backwards 8
#define lcp_darkmode 128
#define lcp_darkmodenative 256
#define lcp_fittowindow 2
#ifndef WM_DPICHANGED
#define WM_DPICHANGED 0x02E0
#endif
#ifndef WM_DPICHANGED_AFTERPARENT
#define WM_DPICHANGED_AFTERPARENT 0x02E3
#endif

static const wchar_t* kClass = L"IsoListerDesignC";
static ULONG_PTR g_gdip = 0;
static int g_windows = 0;
static int g_iface = 0; // TC plugin interface version * 100, 0 = unknown

static const wchar_t* T(const wchar_t* ru, const wchar_t* en) { return IsoAnalysis_Tr(ru, en); }

// ---- theme: [IsoLister] Theme=auto|light|dark, legacy Dark=0|1, TC dark-mode flags,
// then the previous IsoLister heuristic (wincmd.ini DarkMode / [Lister] BgColor / parent brightness).
// Windows' own app theme is deliberately not consulted: TC has its own dark-mode switch.
static std::wstring read_theme(const std::wstring& ini) {
    if (ini.empty()) return L"";
    wchar_t buf[64] = L"";
    GetPrivateProfileStringW(L"IsoLister", L"Theme", L"", buf, 64, ini.c_str());
    return buf;
}
static bool resolve_dark(int flags, HWND parent) {
    std::wstring t = read_theme(IsoAnalysis_IniPath());
    if (t.empty() || !lstrcmpiW(t.c_str(), L"auto")) {
        std::wstring w = read_theme(IsoAnalysis_WincmdIni());
        if (!w.empty()) t = w;
    }
    if (!lstrcmpiW(t.c_str(), L"dark")) return true;
    if (!lstrcmpiW(t.c_str(), L"light")) return false;
    int legacy = IsoAnalysis_DarkOption();
    if (legacy == 0) return false;
    if (legacy == 1) return true;
    if (flags & (lcp_darkmode | lcp_darkmodenative)) return true;
    if (g_iface >= 212) return false; // TC 11+ reports dark mode through the flags above
    return IsoAnalysis_DetectDark(parent);
}

// ---- colours
static inline int cr(COLORREF c) { return GetRValue(c); }
static inline int cg(COLORREF c) { return GetGValue(c); }
static inline int cb(COLORREF c) { return GetBValue(c); }
static COLORREF hex(unsigned v) { return RGB((v >> 16) & 255, (v >> 8) & 255, v & 255); }
static COLORREF mix(COLORREF a, COLORREF b, double t) { // t = share of b
    return RGB((int)(cr(a) + (cr(b) - cr(a)) * t + 0.5), (int)(cg(a) + (cg(b) - cg(a)) * t + 0.5), (int)(cb(a) + (cb(b) - cb(a)) * t + 0.5));
}
static double lin(int v) { double c = v / 255.0; return c <= 0.03928 ? c / 12.92 : pow((c + 0.055) / 1.055, 2.4); }
static double lum(COLORREF c) { return 0.2126 * lin(cr(c)) + 0.7152 * lin(cg(c)) + 0.0722 * lin(cb(c)); }
static double contrast(COLORREF a, COLORREF b) { double x = lum(a), y = lum(b); if (x < y) std::swap(x, y); return (x + 0.05) / (y + 0.05); }
static COLORREF ensure(COLORREF c, COLORREF bg, double need, COLORREF to) {
    for (int i = 0; i < 40 && contrast(c, bg) < need; i++) c = mix(c, to, 0.08);
    return c;
}
static COLORREF hash_color(const std::wstring& s) {
    static const unsigned pal[] = { 0x1975D0, 0x2E7D32, 0x6A1B9A, 0xC62828, 0x00838F, 0xEF6C00, 0x37474F };
    uint32_t h = 2166136261u;
    for (wchar_t c : s) { h ^= (uint32_t)c; h *= 16777619u; }
    return hex(pal[h % 7]);
}
// brand colour of the detected system (hero band)
static COLORREF os_color(const IsoModel& m, const std::wstring& fileName) {
    struct { const wchar_t* fam; unsigned rgb; } map[] = {
        { L"windows", 0x0078D4 }, { L"ubuntu", 0xE95420 }, { L"debian", 0xA80030 }, { L"alpine", 0x0D597F },
        { L"fedora", 0x3C6EB4 }, { L"arch", 0x1793D1 }, { L"mint", 0x5A9E3A }, { L"opensuse", 0x73BA25 },
        { L"manjaro", 0x35BF5C }, { L"kali", 0x367BF0 }, { L"centos", 0x932279 }, { L"rocky", 0x10B981 },
        { L"alma", 0x0F4266 }, { L"rhel", 0xEE0000 }, { L"gentoo", 0x54487A }, { L"nixos", 0x5277C3 },
        { L"elementary", 0x3689E6 }, { L"pop", 0x48B9C7 }, { L"zorin", 0x15A6F0 }, { L"proxmox", 0xE57000 },
        { L"truenas", 0x0095D5 }, { L"freebsd", 0xAB2B28 }, { L"macos", 0x5E5E66 }, { L"linux", 0x2F3B4C },
    };
    for (auto& e : map) if (m.facts.osFamily == e.fam) return hex(e.rgb);
    switch (m.facts.kind) {
    case IsoKindDisk: return hex(0x546E7A);
    case IsoKindVhd: return hex(0x5C2D91);
    case IsoKindWim: return hex(0x0078D4);
    case IsoKindDmg: return hex(0x5E5E66);
    case IsoKindError: return hex(0x8E3B3B);
    default: break;
    }
    return hash_color(m.facts.label.empty() ? fileName : m.facts.label);
}

struct Pal {
    bool dark = false;
    COLORREF bg, text, muted, key, sec, sel, find, find_text, footer, rule;
    COLORREF band, band_text, band_sub, band_ver, pill_bg, pill_text, icon_box, icon_fg, icon_mid;
    COLORREF tile_bg, tile_bd, tile_lbl, tile_num, tile_hint;
    COLORREF warn_bg, warn_bd, warn_lbl, warn_num, ok_bg, ok_bd, ok_lbl, ok_num;
    COLORREF tag[IsoTagCount];
};
static void make_palette(Pal& p, bool dark, COLORREF band) {
    p.dark = dark;
    COLORREF white = hex(0xffffff), black = hex(0x000000);
    if (!dark) {
        p.bg = white; p.text = hex(0x1f2328); p.muted = hex(0x6e7781); p.key = hex(0x6e7781); p.footer = hex(0x8c959f);
        p.tile_hint = hex(0x6e7781); p.rule = hex(0xe6e8eb);
        p.warn_bg = hex(0xfff3f1); p.warn_bd = hex(0xffd9d4); p.warn_lbl = hex(0xa3554d); p.warn_num = hex(0xc4231c);
        p.ok_bg = hex(0xf1faea); p.ok_bd = hex(0xd8eec6); p.ok_lbl = hex(0x5b7a43); p.ok_num = hex(0x2f6b00);
        const unsigned tg[IsoTagCount] = { 0x6e7781, 0x1a7f37, 0xcf222e, 0x9a6700, 0x8c959f };
        for (int i = 0; i < IsoTagCount; i++) p.tag[i] = hex(tg[i]);
        p.find = hex(0xffd33d); p.find_text = hex(0x1f2328);
    } else {
        p.bg = hex(0x16191d); p.text = hex(0xe6e8eb); p.muted = hex(0x8b949e); p.key = hex(0x8b949e); p.footer = hex(0x7d8792);
        p.tile_hint = hex(0x8b949e); p.rule = hex(0x2a3037);
        p.warn_bg = hex(0x3a1a18); p.warn_bd = hex(0x5c2a26); p.warn_lbl = hex(0xd49a94); p.warn_num = hex(0xff8e86);
        p.ok_bg = hex(0x15291a); p.ok_bd = hex(0x24452c); p.ok_lbl = hex(0x8fb79a); p.ok_num = hex(0x7ee2a0);
        const unsigned tg[IsoTagCount] = { 0x8b949e, 0x3fb950, 0xff7b72, 0xd29922, 0x7d8792 };
        for (int i = 0; i < IsoTagCount; i++) p.tag[i] = hex(tg[i]);
        p.find = hex(0xb08800); p.find_text = white;
    }
    // hero band: white text, the band is darkened until it reads (keeps the brand hue)
    if (dark) band = mix(band, black, 0.18);
    band = ensure(band, white, 4.5, black);
    p.band = band;
    p.band_text = white;
    p.band_sub = mix(white, band, 0.15);
    p.band_ver = mix(white, band, 0.28);
    p.pill_bg = mix(band, white, 0.2);
    p.pill_text = white;
    p.icon_box = white;
    p.icon_fg = band;
    p.icon_mid = mix(band, white, 0.45);
    COLORREF base = band;
    if (!dark) {
        p.tile_bg = mix(base, white, 0.945); p.tile_bd = mix(base, white, 0.85);
        p.tile_num = ensure(mix(base, black, 0.3), p.tile_bg, 7.0, black);
        p.tile_lbl = ensure(mix(p.tile_num, hex(0x6e7781), 0.6), p.tile_bg, 4.5, black);
        p.sec = ensure(base, p.bg, 4.5, black);
        p.sel = mix(p.sec, white, 0.86);
    } else {
        p.tile_bg = mix(hex(0x1f2328), base, 0.06); p.tile_bd = mix(hex(0x30363d), base, 0.12);
        p.tile_num = ensure(mix(base, white, 0.25), p.tile_bg, 6.0, white);
        p.tile_lbl = ensure(mix(p.tile_num, hex(0x8b949e), 0.6), p.tile_bg, 4.5, white);
        p.sec = ensure(mix(base, white, 0.15), p.bg, 4.5, white);
        p.sel = mix(p.sec, p.bg, 0.78);
    }
}

// ---- the drawn view
enum Font { F_NAME, F_SUB, F_PILL, F_VER, F_TL, F_TN, F_TH, F_SEC, F_ROW, F_ROWB, F_MONO, F_TAG, F_NOTE, F_TN2, F_COUNT };
struct FontSpec { int px10; int weight; bool mono; };
static const FontSpec kFonts[F_COUNT] = {
    { 300, FW_BOLD, false }, { 135, FW_NORMAL, false }, { 120, FW_BOLD, false }, { 110, FW_NORMAL, false },
    { 105, FW_BOLD, false }, { 210, FW_BOLD, false }, { 110, FW_NORMAL, false }, { 120, FW_BOLD, false },
    { 125, FW_NORMAL, false }, { 125, FW_SEMIBOLD, false }, { 120, FW_NORMAL, true }, { 105, FW_BOLD, false }, { 115, FW_NORMAL, false },
    { 170, FW_BOLD, false },
};

struct El {
    enum Type { Fill, Text } type = Text;
    RECT r = {};
    COLORREF color = 0, border = CLR_INVALID;
    int radius = 0;
    std::wstring s;
    int font = F_ROW, extra = 0;
    UINT fmt = 0;
    int row = -1;       // row this element belongs to (selection / search)
    bool search = false;
};
struct Row {
    RECT r = {};
    std::wstring plain, value;
};
struct Block { std::vector<El> els; std::vector<Row> rows; int h = 0; };

struct View {
    HWND hwnd = nullptr;
    IsoModel m;
    std::wstring path, fileName, ext;
    unsigned long long size = 0; bool haveSize = false;
    HFONT fonts[F_COUNT] = {};
    int dpi = 96, flags = 0;
    bool dark = false;
    Pal pal;
    std::vector<El> els;
    std::vector<Row> rows;
    int doc_h = 0, sy = 0, lay_w = -1;
    int sel_a = -1, sel_b = -1; bool sel_all = false, dragging = false;
    int m_el = -1, m_off = 0, m_len = 0;
    int wheel = 0;
    HDC mdc = nullptr; HBITMAP mbmp = nullptr; int mw = 0, mh = 0;
    int S(int v) const { return MulDiv(v, dpi, 96); }
    int S10(int v10) const { return MulDiv(v10, dpi, 960); }
};

static int window_dpi(HWND h) {
    typedef UINT(WINAPI * PGetDpiForWindow)(HWND);
    static PGetDpiForWindow f = (PGetDpiForWindow)(void*)GetProcAddress(GetModuleHandleW(L"user32.dll"), "GetDpiForWindow");
    UINT d = f ? f(h) : 0;
    if (!d) { HDC dc = GetDC(h); d = (UINT)GetDeviceCaps(dc, LOGPIXELSY); ReleaseDC(h, dc); }
    return d ? (int)d : 96;
}
static void make_fonts(View* v) {
    for (auto& f : v->fonts) if (f) { DeleteObject(f); f = nullptr; }
    for (int i = 0; i < F_COUNT; i++)
        v->fonts[i] = CreateFontW(-v->S10(kFonts[i].px10), 0, 0, 0, kFonts[i].weight, 0, 0, 0, DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                                  CLEARTYPE_QUALITY, kFonts[i].mono ? FIXED_PITCH | FF_MODERN : VARIABLE_PITCH | FF_SWISS, kFonts[i].mono ? L"Consolas" : L"Segoe UI");
}
static void set_theme(View* v) {
    typedef HRESULT(WINAPI * PSetWindowTheme)(HWND, LPCWSTR, LPCWSTR);
    static HMODULE ux = LoadLibraryW(L"uxtheme.dll");
    static PSetWindowTheme f = ux ? (PSetWindowTheme)(void*)GetProcAddress(ux, "SetWindowTheme") : nullptr;
    v->dark = resolve_dark(v->flags, GetParent(v->hwnd));
    make_palette(v->pal, v->dark, os_color(v->m, v->fileName));
    if (f) f(v->hwnd, v->dark ? L"DarkMode_Explorer" : L"Explorer", nullptr); // scrollbar
}

// text measuring on a shared memory DC
static HDC measure_dc() { static HDC dc = CreateCompatibleDC(nullptr); return dc; }
struct ISize { int cx, cy; };
static ISize text_size(View* v, int font, const std::wstring& s, int width, UINT fmt, int extra = 0) {
    HDC dc = measure_dc();
    HGDIOBJ of = SelectObject(dc, v->fonts[font]);
    SetTextCharacterExtra(dc, extra);
    RECT r = { 0, 0, width > 0 ? width : 100000, 0 };
    std::wstring t = s.empty() ? std::wstring(L" ") : s;
    DrawTextW(dc, t.c_str(), (int)t.size(), &r, fmt | DT_CALCRECT | DT_NOPREFIX);
    SetTextCharacterExtra(dc, 0);
    SelectObject(dc, of);
    ISize z = { (int)(r.right - r.left), (int)(r.bottom - r.top) };
    return z;
}
static int text_w(View* v, int font, const std::wstring& s, int extra = 0) { return text_size(v, font, s, 0, DT_SINGLELINE, extra).cx; }
static int line_h(View* v, int font) { return text_size(v, font, L"Ag", 0, DT_SINGLELINE).cy; }
static const UINT kWrap = DT_WORDBREAK | DT_EDITCONTROL | DT_NOPREFIX;
static const UINT kOne = DT_SINGLELINE | DT_NOPREFIX | DT_END_ELLIPSIS;

static El text_el(int font, const std::wstring& s, RECT r, COLORREF c, UINT fmt, int row = -1, bool search = false, int extra = 0) {
    El e; e.type = El::Text; e.font = font; e.s = s; e.r = r; e.color = c; e.fmt = fmt; e.row = row; e.search = search; e.extra = extra; return e;
}
static El fill_el(RECT r, COLORREF c, int radius = 0, COLORREF border = CLR_INVALID) {
    El e; e.type = El::Fill; e.r = r; e.color = c; e.radius = radius; e.border = border; return e;
}
static std::wstring upper(std::wstring s) { if (!s.empty()) CharUpperBuffW(&s[0], (DWORD)s.size()); return s; }
static std::wstring lower(std::wstring s) { if (!s.empty()) CharLowerBuffW(&s[0], (DWORD)s.size()); return s; }
static std::wstring num(long long n) { return std::to_wstring(n); }
static const std::wstring kSep = L"  \u00B7  ";

static std::wstring find_kv(const IsoModel& m, const wchar_t* ru, const wchar_t* en) {
    for (auto& it : m.items) if (it.kind == IsoItem::KV && (it.key == ru || it.key == en)) return it.value;
    return L"";
}
// "Windows 11 24H2 (26100)" -> "Windows 11 24H2"
static std::wstring drop_paren(const std::wstring& s) {
    size_t k = s.find(L" (");
    return k == std::wstring::npos ? s : s.substr(0, k);
}

// ---- sections
static bool section_wide(const View* v, size_t a, size_t b) {
    for (size_t i = a + 1; i < b; i++) if (v->m.items[i].kind == IsoItem::Table && v->m.items[i].cells.size() >= 3) return true;
    return false;
}
static int dot(View* v, Block& bk, int x, int y, int lh, int tag) {
    int d = v->S(8), yy = y + (lh - d) / 2;
    bk.els.push_back(fill_el(RECT{ x, yy, x + d, yy + d }, v->pal.tag[tag], d));
    return d + v->S(7);
}

// a run of table rows [a, b) laid out at width w starting at y
static int build_table(View* v, Block& bk, size_t a, size_t b, int w, int y) {
    const Pal& p = v->pal; const auto& items = v->m.items;
    size_t cols = 0;
    for (size_t i = a; i < b; i++) cols = std::max(cols, items[i].cells.size());
    if (!cols) return y;
    int gap = v->S(14);
    std::vector<int> nat(cols, 0);
    for (size_t i = a; i < b; i++) {
        const IsoItem& it = items[i];
        for (size_t c = 0; c < it.cells.size(); c++) {
            int f = it.header ? F_TL : (!it.cells[c].empty() && it.cells[c][0] == L'/') ? F_MONO : F_ROW;
            std::wstring s = it.header ? upper(it.cells[c]) : it.cells[c];
            nat[c] = std::max(nat[c], text_w(v, f, s, it.header ? std::max(1, v->S10(5)) : 0) + v->S(2));
        }
    }
    int avail = w - gap * (int)(cols - 1);
    std::vector<int> cw(cols, 0);
    {
        // water-fill: narrow columns keep their natural width, wide ones share the rest
        std::vector<size_t> order(cols);
        for (size_t c = 0; c < cols; c++) order[c] = c;
        std::sort(order.begin(), order.end(), [&](size_t x, size_t y2) { return nat[x] < nat[y2]; });
        int left = avail;
        for (size_t k = 0; k < cols; k++) {
            size_t c = order[k];
            int share = left / (int)(cols - k);
            cw[c] = std::max(v->S(24), std::min(nat[c], share));
            left -= cw[c];
        }
        if (left > 0) cw[cols - 1] += left; // the last column takes the slack
    }
    int pad = v->S(3);
    for (size_t i = a; i < b; i++) {
        const IsoItem& it = items[i];
        int top = y, hmax = 0;
        Row rw; rw.plain = it.plain; rw.value = it.plain;
        for (size_t c = 0; c < it.cells.size(); c++) if (!it.cells[c].empty()) { rw.value = it.cells[c]; break; }
        bk.rows.push_back(rw);
        int row = (int)bk.rows.size() - 1;
        int x = 0;
        for (size_t c = 0; c < cols; c++) {
            std::wstring s = c < it.cells.size() ? it.cells[c] : std::wstring();
            int f = it.header ? F_TL : (!s.empty() && s[0] == L'/') ? F_MONO : F_ROW;
            int ex = it.header ? std::max(1, v->S10(5)) : 0;
            if (it.header) s = upper(s);
            ISize ts = text_size(v, f, s, cw[c], kWrap, ex);
            int ty = y + pad + (f == F_MONO ? (line_h(v, F_ROW) - line_h(v, F_MONO) + 1) / 2 : 0);
            if (it.header) ty = y + pad + (line_h(v, F_ROW) - line_h(v, F_TL)) / 2;
            if (!s.empty())
            {
                int tg = c < it.cellTags.size() ? it.cellTags[c] : IsoTagNone;
                COLORREF col = it.header ? p.muted : (tg == IsoTagOk || tg == IsoTagBad || tg == IsoTagWarn) ? p.tag[tg] : p.text;
                bk.els.push_back(text_el(f, s, RECT{ x, ty, x + cw[c], ty + ts.cy }, col, kWrap, row, true, ex));
            }
            hmax = std::max(hmax, (ty - y) + ts.cy);
            x += cw[c] + gap;
        }
        hmax = std::max(hmax, line_h(v, F_ROW) + pad);
        y += hmax + pad;
        if (i + 1 < b) bk.els.push_back(fill_el(RECT{ 0, y, w, y + std::max(1, v->S(1)) }, it.header ? p.tile_bd : p.rule));
        y += std::max(1, v->S(1));
        bk.rows[row].r = RECT{ 0, top, w, y };
    }
    return y;
}

// one section (items [a, b)) laid out at width w, coordinates relative to the block
static Block build_section(View* v, size_t a, size_t b, int w) {
    Block bk; const Pal& p = v->pal; const auto& items = v->m.items;
    int y = v->S(8);
    auto add_row = [&](RECT r, const std::wstring& plain, const std::wstring& value) {
        Row rw; rw.r = r; rw.plain = plain; rw.value = value; bk.rows.push_back(rw); return (int)bk.rows.size() - 1; };
    {
        const IsoItem& h = items[a];
        std::wstring wt = upper(h.key), wn = h.value;
        int ex = std::max(1, v->S10(7));
        int dw = h.tag != IsoTagNone ? v->S(14) : 0;
        int nw = wn.empty() ? 0 : std::min(text_w(v, F_NOTE, wn) + v->S(2), w / 2) + dw;
        int tw = std::max(v->S(40), w - nw - (nw ? v->S(10) : 0));
        ISize ts = text_size(v, F_SEC, wt, tw, kWrap, ex);
        int row = add_row(RECT{ 0, 0, w, 0 }, h.plain, h.value.empty() ? h.key : h.value);
        bk.els.push_back(text_el(F_SEC, wt, RECT{ 0, y, tw, y + ts.cy }, p.sec, kWrap, row, true, ex));
        if (nw) {
            int lh = line_h(v, F_SEC), nh = line_h(v, F_NOTE);
            if (dw) dot(v, bk, w - nw, y + lh - nh, nh, h.tag);
            bk.els.push_back(text_el(F_NOTE, wn, RECT{ w - nw + dw, y + lh - nh, w, y + lh }, p.footer, kOne | DT_RIGHT, row, true));
        }
        y += ts.cy + v->S(3);
        bk.els.push_back(fill_el(RECT{ 0, y, w, y + v->S(2) }, p.sec));
        y += v->S(2) + v->S(5);
        bk.rows[row].r.bottom = y;
    }
    int lw = 0;
    for (size_t i = a + 1; i < b; i++)
        if (items[i].kind == IsoItem::KV) lw = std::max(lw, text_w(v, F_ROW, items[i].key) + (items[i].ind > 0 ? v->S(14) : 0));
    lw = std::min(std::max(lw + v->S(14), v->S(110)), std::max(v->S(110), w * 40 / 100));
    int pad = v->S(2);
    for (size_t i = a + 1; i < b; i++) {
        const IsoItem& it = items[i];
        if (it.kind == IsoItem::Blank) { y += v->S(8); continue; }
        if (it.kind == IsoItem::Table) {
            size_t j = i;
            while (j < b && items[j].kind == IsoItem::Table) j++;
            y = build_table(v, bk, i, j, w, y + v->S(2)) + v->S(2);
            i = j - 1;
            continue;
        }
        int dx = it.ind > 0 ? v->S(14) * std::min(2, (it.ind + 1) / 2) : 0;
        int top = y;
        int row = add_row(RECT{}, it.plain, it.value);
        int lh = line_h(v, F_ROW);
        if (it.kind == IsoItem::KV) {
            int kx = dx, kw = std::max(v->S(50), lw - dx - v->S(10));
            ISize ks = text_size(v, F_ROW, it.key, kw, kWrap);
            int vf = it.mono ? F_MONO : F_ROW;
            int vx = std::max(lw, kx + kw + v->S(10));
            if (it.tag != IsoTagNone) vx += dot(v, bk, vx, y + pad, lh, it.tag);
            int vw = std::max(v->S(40), w - vx);
            ISize vs = text_size(v, vf, it.value, vw, kWrap);
            int vy = y + pad + (it.mono ? (lh - line_h(v, F_MONO) + 1) / 2 : 0);
            COLORREF vc = (it.tag == IsoTagOk || it.tag == IsoTagBad || it.tag == IsoTagWarn) && !it.mono ? p.tag[it.tag] : p.text;
            bk.els.push_back(text_el(F_ROW, it.key, RECT{ kx, y + pad, kx + kw, y + pad + ks.cy }, p.key, kWrap, row, true));
            bk.els.push_back(text_el(vf, it.value, RECT{ vx, vy, vx + vw, vy + vs.cy }, vc, kWrap, row, true));
            y = std::max(y + pad + ks.cy, vy + vs.cy) + pad;
        } else {
            if (it.strong && i > a + 1) y += v->S(3);
            int f = it.strong ? F_ROWB : it.mono ? F_MONO : F_ROW;
            int x = dx;
            if (it.bullet) {
                bk.els.push_back(text_el(F_ROW, L"\u2022", RECT{ x, y + pad, x + v->S(12), y + pad + lh }, p.muted, DT_SINGLELINE | DT_NOPREFIX));
                x += v->S(12);
            }
            if (it.tag != IsoTagNone) x += dot(v, bk, x, y + pad, lh, it.tag);
            int xw = std::max(v->S(40), w - x);
            ISize ts = text_size(v, f, it.value, xw, kWrap);
            int ty = y + pad + (f == F_MONO ? (lh - line_h(v, F_MONO) + 1) / 2 : 0);
            COLORREF c = it.strong ? p.text : (it.tag == IsoTagWarn || it.tag == IsoTagBad) ? p.tag[it.tag] : p.text;
            bk.els.push_back(text_el(f, it.value, RECT{ x, ty, x + xw, ty + ts.cy }, c, kWrap, row, true));
            y = std::max(y + pad + lh, ty + ts.cy) + pad;
        }
        bk.rows[row].r = RECT{ 0, top, w, y };
    }
    bk.h = y;
    return bk;
}

static void place(View* v, Block& bk, int x, int y) {
    int base = (int)v->rows.size();
    for (auto& r : bk.rows) { OffsetRect(&r.r, x, y); v->rows.push_back(std::move(r)); }
    for (auto& e : bk.els) { OffsetRect(&e.r, x, y); if (e.row >= 0) e.row += base; v->els.push_back(std::move(e)); }
}

// ---- hero and tiles
struct Tile { std::wstring label, num, hint; int style; }; // style 0 normal, 1 warn, 2 ok

static std::wstring size_text(View* v) { return v->haveSize ? IsoAnalysis_FormatSize(v->size) : std::wstring(L"\u2014"); }
static std::wstring or_dash(const std::wstring& s) { return s.empty() ? std::wstring(L"\u2014") : s; }

static std::vector<Tile> build_tiles(View* v) {
    const IsoFacts& f = v->m.facts;
    std::vector<Tile> t;
    switch (f.kind) {
    case IsoKindIso: {
        std::wstring os = !f.distro.empty() ? f.distro : drop_paren(f.os); // version goes to the next tile
        std::wstring osHint = !f.release.empty() && f.release != f.os ? f.release : f.imageType.empty() ? f.label : f.imageType;
        if (osHint == os) osHint.clear();
        t.push_back({ T(L"ОС", L"OS"), or_dash(os), osHint, 0 });
        if (!f.build.empty()) t.push_back({ T(L"Сборка", L"Build"), f.build, f.version, 0 });
        else if (!f.version.empty() && f.osFamily != L"windows") t.push_back({ T(L"Версия", L"Version"), f.version, f.release == f.version ? L"" : drop_paren(f.release), 0 });
        else t.push_back({ T(L"Сборка", L"Build"), L"\u2014", f.version == os ? L"" : f.version, 0 });
        t.push_back({ T(L"Архитектура", L"Architecture"), or_dash(f.arch), L"", 0 });
        Tile boot{ T(L"Загрузка", L"Boot"), L"", L"", 0 };
        if (!f.bootType.empty()) boot.num = f.bootType;
        else boot.num = f.bootable == 0 ? T(L"нет", L"no") : L"\u2014";
        if (!f.signerNote.empty()) { boot.hint = T(L"Secure Boot: CA 2011", L"Secure Boot: CA 2011"); boot.style = 1; }
        else { boot.hint = f.bootloader; boot.style = f.bootable == 1 ? 2 : 0; }
        t.push_back(boot);
        t.push_back({ T(L"Размер", L"Size"), size_text(v), f.fsType, 0 });
        if (f.bypassRules > 0) t.push_back({ T(L"Обход Win11", L"Win11 bypass"), num(f.bypassRules), T(L"правил в autounattend", L"rules in autounattend"), 1 });
        else if (f.editions >= 0) t.push_back({ T(L"Редакции", L"Editions"), num(f.editions), L"install.wim / esd", 0 });
        else if (f.configFiles > 0) t.push_back({ T(L"Конфиги", L"Config files"), num(f.configFiles), T(L"автоустановка, загрузчик", L"unattended, boot menus"), 0 });
        else if (f.files >= 0) t.push_back({ T(L"Файлы", L"Files"), num(f.files), L"", 0 });
        else if (f.osFamily == L"windows") t.push_back({ T(L"Редакции", L"Editions"), L"\u2014", L"", 0 });
        else if (!f.created.empty() && f.created.size() >= 10)
            t.push_back({ T(L"Создан", L"Created"), f.created.substr(0, 10), f.created.size() > 11 ? f.created.substr(11) : L"", 0 });
        else t.push_back({ T(L"Метка", L"Label"), or_dash(f.label), L"", 0 });
        break;
    }
    case IsoKindDisk: case IsoKindVhd: {
        int bootParts = 0;
        for (auto& it : v->m.items)
            if (it.kind == IsoItem::Section && (it.value.find(L"bootable") != std::wstring::npos || it.value.find(L"загруз") != std::wstring::npos)) bootParts++;
        if (f.kind == IsoKindVhd) {
            t.push_back({ T(L"Формат", L"Format"), or_dash(f.format), f.imageType, 0 });
            t.push_back({ T(L"Тип диска", L"Disk type"), or_dash(drop_paren(f.diskType)), L"", 0 });
            t.push_back({ T(L"Виртуальный", L"Virtual size"), or_dash(f.virtualSize), L"", 0 });
        }
        t.push_back({ T(L"Разметка", L"Layout"), or_dash(f.layout), find_kv(v->m, L"Сигнатура диска", L"Disk signature"), 0 });
        t.push_back({ T(L"Разделы", L"Partitions"), or_dash(f.partitions), L"", 0 });
        if (f.kind == IsoKindDisk) {
            std::wstring fs = f.fsList.empty() ? L"\u2014" : f.fsList[0], rest;
            for (size_t i = 1; i < f.fsList.size(); i++) rest += (rest.empty() ? L"" : L", ") + f.fsList[i];
            t.push_back({ T(L"Файловые системы", L"File systems"), fs + (f.fsList.size() > 1 ? L" +" + num((long long)f.fsList.size() - 1) : L""), rest, 0 });
            std::wstring code = find_kv(v->m, L"Загрузочный код", L"Boot code");
            t.push_back({ T(L"Загрузка", L"Boot"), bootParts ? T(L"есть", L"yes") : T(L"нет", L"no"),
                          bootParts ? std::wstring(T(L"активный раздел", L"active partition")) + (code.empty() ? L"" : L", " + code) : code, bootParts ? 2 : 0 });
        }
        t.push_back({ T(L"Размер", L"Size"), size_text(v), f.kind == IsoKindVhd ? L"" : f.imageType, 0 });
        if (f.kind == IsoKindDisk) t.push_back({ T(L"Неразмечено", L"Unallocated"), or_dash(f.unallocated), L"", 0 });
        break;
    }
    case IsoKindWim:
        t.push_back({ T(L"ОС", L"OS"), or_dash(drop_paren(f.os)), f.imageType, 0 });
        t.push_back({ T(L"Сборка", L"Build"), or_dash(f.build), f.version, 0 });
        t.push_back({ T(L"Архитектура", L"Architecture"), or_dash(f.arch), L"", 0 });
        t.push_back({ T(L"Формат", L"Format"), or_dash(drop_paren(f.format)), find_kv(v->m, L"Флаги", L"Flags"), 0 });
        t.push_back({ T(L"Размер", L"Size"), size_text(v), L"", 0 });
        t.push_back({ T(L"Редакции", L"Editions"), f.editions >= 0 ? num(f.editions) : L"\u2014", L"", 0 });
        break;
    case IsoKindDmg: {
        int parts = 0;
        for (auto& it : v->m.items) if (it.kind == IsoItem::Line && it.bullet) parts++;
        t.push_back({ T(L"Формат", L"Format"), L"UDIF", find_kv(v->m, L"UDIF версия", L"UDIF version"), 0 });
        t.push_back({ L"macOS", or_dash(drop_paren(f.os)), L"", 0 });
        t.push_back({ T(L"Развёрнуто", L"Expanded"), or_dash(drop_paren(find_kv(v->m, L"Развёрнутый размер", L"Expanded size"))), L"", 0 });
        t.push_back({ T(L"Сжатие", L"Compression"), or_dash(find_kv(v->m, L"Сжатие (типы блоков)", L"Compression (block types)")), L"", 0 });
        t.push_back({ T(L"Размер", L"Size"), size_text(v), L"", 0 });
        t.push_back({ T(L"Разделы", L"Partitions"), parts ? num(parts) : L"\u2014", L"blkx", 0 });
        break;
    }
    default:
        break;
    }
    return t;
}

static void hero_text(View* v, std::wstring& title, std::wstring& sub, std::wstring& pill) {
    const IsoFacts& f = v->m.facts;
    std::vector<std::wstring> parts;
    if (!v->ext.empty()) parts.push_back(upper(v->ext));
    if (v->haveSize) parts.push_back(IsoAnalysis_FormatSize(v->size));
    switch (f.kind) {
    case IsoKindIso:
        title = !f.os.empty() ? f.os : !f.label.empty() ? f.label : v->fileName;
        if (!f.fsType.empty()) parts.push_back(f.fsType);
        if (f.bootable == 1) parts.push_back(T(L"загрузочный", L"bootable"));
        else if (f.bootable == 0) parts.push_back(T(L"не загрузочный", L"not bootable"));
        if (!f.label.empty() && f.label != title) parts.push_back(f.label);
        if (!f.arch.empty()) pill = f.arch;
        if (!f.bootType.empty()) pill += (pill.empty() ? L"" : kSep) + f.bootType;
        break;
    case IsoKindDisk: case IsoKindVhd:
        title = v->fileName;
        if (!f.imageType.empty()) parts.push_back(drop_paren(f.imageType));
        if (!f.layout.empty()) parts.push_back(f.layout);
        if (!f.partitions.empty()) parts.push_back(f.partitions + L" " + T(L"разд.", L"part."));
        if (!f.layout.empty()) pill = f.layout;
        if (!f.fsList.empty()) { pill += (pill.empty() ? L"" : kSep) + f.fsList[0]; if (f.fsList.size() > 1) pill += L" +" + num((long long)f.fsList.size() - 1); }
        break;
    case IsoKindWim: case IsoKindDmg:
        title = !f.os.empty() ? f.os : v->fileName;
        if (!f.imageType.empty()) parts.push_back(f.imageType);
        if (!f.arch.empty()) pill = f.arch;
        if (f.editions > 0) pill += (pill.empty() ? L"" : kSep) + num(f.editions) + L" " + T(L"ред.", L"ed.");
        break;
    default:
        title = v->fileName;
        if (!f.error.empty()) parts.push_back(f.error);
        break;
    }
    for (size_t i = 0; i < parts.size(); i++) sub += (i ? kSep : L"") + parts[i];
}

// glyph in the white box of the hero: Windows tiles, a drive, or a disc
static void hero_glyph(View* v, int bx, int by, int box) {
    const Pal& p = v->pal; const IsoFacts& f = v->m.facts;
    int cx = bx + box / 2, cy = by + box / 2;
    if (f.osFamily == L"windows" || f.kind == IsoKindWim) {
        int q = box * 26 / 100, g = std::max(2, box * 4 / 100), s = 2 * q + g;
        int x0 = cx - s / 2, y0 = cy - s / 2;
        for (int i = 0; i < 4; i++) {
            int x = x0 + (i % 2) * (q + g), y = y0 + (i / 2) * (q + g);
            v->els.push_back(fill_el(RECT{ x, y, x + q, y + q }, p.icon_fg, std::max(1, v->S(2))));
        }
    } else if (f.kind == IsoKindDisk || f.kind == IsoKindVhd) {
        int w = box * 64 / 100, h = box * 36 / 100;
        RECT r = { cx - w / 2, cy - h / 2, cx + w / 2, cy + h / 2 };
        v->els.push_back(fill_el(r, p.icon_fg, v->S(6)));
        int d = std::max(4, box * 8 / 100);
        v->els.push_back(fill_el(RECT{ r.right - d * 2, cy - d / 2, r.right - d, cy - d / 2 + d }, p.icon_box, d));
        v->els.push_back(fill_el(RECT{ r.left + d, cy - std::max(1, v->S(1)), r.left + w / 2, cy + std::max(1, v->S(1)) }, p.icon_mid));
    } else {
        int d1 = box * 68 / 100, d2 = box * 30 / 100, d3 = box * 12 / 100;
        v->els.push_back(fill_el(RECT{ cx - d1 / 2, cy - d1 / 2, cx - d1 / 2 + d1, cy - d1 / 2 + d1 }, p.icon_fg, d1));
        v->els.push_back(fill_el(RECT{ cx - d2 / 2, cy - d2 / 2, cx - d2 / 2 + d2, cy - d2 / 2 + d2 }, p.icon_mid, d2));
        v->els.push_back(fill_el(RECT{ cx - d3 / 2, cy - d3 / 2, cx - d3 / 2 + d3, cy - d3 / 2 + d3 }, p.icon_box, d3));
    }
}

static void layout(View* v) {
    RECT rc; GetClientRect(v->hwnd, &rc);
    int W = std::max(1, (int)rc.right);
    v->lay_w = W;
    v->els.clear(); v->rows.clear();
    v->m_el = -1;
    const Pal& p = v->pal;
    // hero
    int H = v->S(132);
    v->els.push_back(fill_el(RECT{ 0, 0, W, H }, p.band));
    std::wstring ver = v->m.brand.empty() ? std::wstring(L"IsoLister") : v->m.brand;
    int verw = text_w(v, F_VER, ver);
    v->els.push_back(text_el(F_VER, ver, RECT{ W - v->S(14) - verw, v->S(8), W - v->S(14), v->S(8) + line_h(v, F_VER) }, p.band_ver, DT_SINGLELINE | DT_RIGHT | DT_NOPREFIX));
    bool compact = W < v->S(520);
    int box = compact ? v->S(64) : v->S(88), bx = v->S(22), by = (H - box) / 2;
    v->els.push_back(fill_el(RECT{ bx, by, bx + box, by + box }, p.icon_box, compact ? v->S(15) : v->S(20)));
    hero_glyph(v, bx, by, box);
    std::wstring title, sub, pill;
    hero_text(v, title, sub, pill);
    int tx = bx + box + v->S(18), tr = W - v->S(22);
    int nameF = compact ? F_TN : F_NAME;
    if (!compact && text_w(v, F_NAME, title) > std::min(tr, W - v->S(28) - verw) - tx) nameF = F_TN;
    int nh = line_h(v, nameF), sh = line_h(v, F_SUB), ph = v->S(22);
    int blockh = nh + sh + (pill.empty() ? 0 : v->S(9) + ph);
    int ty = (H - blockh) / 2;
    Row hr; hr.r = RECT{ tx, ty, tr, ty + nh }; hr.plain = title; hr.value = title;
    v->rows.push_back(hr);
    v->els.push_back(text_el(nameF, title, RECT{ tx, ty, std::max(tx + v->S(40), std::min(tr, W - v->S(28) - verw)), ty + nh }, p.band_text, kOne, 0, true));
    ty += nh;
    v->els.push_back(text_el(F_SUB, sub, RECT{ tx, ty, tr, ty + sh }, p.band_sub, kOne, -1, true));
    ty += sh + v->S(9);
    if (!pill.empty()) {
        int pw = std::min(text_w(v, F_PILL, pill) + v->S(22), std::max(v->S(40), tr - tx));
        v->els.push_back(fill_el(RECT{ tx, ty, tx + pw, ty + ph }, p.pill_bg, v->S(11)));
        v->els.push_back(text_el(F_PILL, pill, RECT{ tx + v->S(11), ty, tx + pw - v->S(11), ty + ph }, p.pill_text, kOne | DT_VCENTER | DT_CENTER));
    }
    int y = H;
    // tiles: 6 → 3 → 2 per row
    std::vector<Tile> t = build_tiles(v);
    if (!t.empty()) {
        int cols = W >= v->S(760) ? 6 : W >= v->S(420) ? 3 : 2;
        int px = v->S(14), gap = v->S(8), th = v->S(74);
        int tw = (W - 2 * px - (cols - 1) * gap) / cols;
        y += v->S(12);
        for (size_t i = 0; i < t.size(); i++) {
            int c = (int)i % cols, r = (int)i / cols;
            int x0 = px + c * (tw + gap), y0 = y + r * (th + gap);
            COLORREF bg = t[i].style == 1 ? p.warn_bg : t[i].style == 2 ? p.ok_bg : p.tile_bg;
            COLORREF bd = t[i].style == 1 ? p.warn_bd : t[i].style == 2 ? p.ok_bd : p.tile_bd;
            COLORREF lc = t[i].style == 1 ? p.warn_lbl : t[i].style == 2 ? p.ok_lbl : p.tile_lbl;
            COLORREF nc = t[i].style == 1 ? p.warn_num : t[i].style == 2 ? p.ok_num : p.tile_num;
            v->els.push_back(fill_el(RECT{ x0, y0, x0 + tw, y0 + th }, bg, v->S(8), bd));
            int ix = x0 + v->S(10), iw = x0 + tw - v->S(8);
            int ly = y0 + v->S(8), lh = line_h(v, F_TL);
            v->els.push_back(text_el(F_TL, upper(t[i].label), RECT{ ix, ly, iw, ly + lh }, lc, kOne, -1, false, std::max(1, v->S10(5))));
            int ny = ly + lh + v->S(1), nh2 = line_h(v, F_TN);
            int nf = text_w(v, F_TN, t[i].num) <= iw - ix ? F_TN : F_TN2; // long values in narrow tiles
            int nyy = nf == F_TN ? ny : ny + (nh2 - line_h(v, F_TN2)) / 2;
            v->els.push_back(text_el(nf, t[i].num, RECT{ ix, nyy, iw, nyy + line_h(v, nf) }, nc, kOne, -1, true));
            int hy = ny + nh2, hh = line_h(v, F_TH);
            v->els.push_back(text_el(F_TH, t[i].hint, RECT{ ix, hy, iw, hy + hh }, p.tile_hint, kOne, -1, true));
        }
        y += ((int)t.size() + cols - 1) / cols * (th + gap) - gap + v->S(4);
    }
    // sections: masonry in two columns from 700 px, tables across the full width
    const auto& items = v->m.items;
    size_t n = items.size();
    int px = v->S(14), gap = v->S(22);
    bool two = W >= v->S(700);
    int cw = two ? (W - 2 * px - gap) / 2 : W - 2 * px;
    int colY[2] = { y, y };
    for (size_t a = 0; a < n;) {
        if (items[a].kind != IsoItem::Section) { a++; continue; }
        size_t b = a + 1;
        while (b < n && items[b].kind != IsoItem::Section) b++;
        if (two && section_wide(v, a, b)) {
            int yy = std::max(colY[0], colY[1]);
            Block bk = build_section(v, a, b, W - 2 * px);
            place(v, bk, px, yy);
            colY[0] = colY[1] = yy + bk.h + v->S(10);
        } else {
            Block bk = build_section(v, a, b, cw);
            int c = two && colY[1] < colY[0] ? 1 : 0;
            place(v, bk, px + c * (cw + gap), colY[c]);
            colY[c] += bk.h + v->S(10);
        }
        a = b;
    }
    y = std::max(colY[0], colY[1]);
    v->doc_h = y + v->S(14);
}

static void update_scroll(View* v) {
    RECT rc; GetClientRect(v->hwnd, &rc);
    int maxy = std::max(0, v->doc_h - (int)rc.bottom);
    v->sy = std::min(std::max(0, v->sy), maxy);
    SCROLLINFO si = {}; si.cbSize = sizeof si; si.fMask = SIF_ALL | SIF_DISABLENOSCROLL; si.nMax = std::max(0, v->doc_h - 1); si.nPage = (UINT)rc.bottom; si.nPos = v->sy;
    SetScrollInfo(v->hwnd, SB_VERT, &si, TRUE);
}
static void relayout(View* v) {
    layout(v);
    update_scroll(v);
    RECT rc; GetClientRect(v->hwnd, &rc);
    if (rc.right != v->lay_w) { layout(v); update_scroll(v); } // scrollbar appeared/disappeared
    InvalidateRect(v->hwnd, nullptr, FALSE);
}
static void scroll_to(View* v, int y) {
    RECT rc; GetClientRect(v->hwnd, &rc);
    int maxy = std::max(0, v->doc_h - (int)rc.bottom);
    y = std::min(std::max(0, y), maxy);
    if (y == v->sy) return;
    v->sy = y;
    SetScrollPos(v->hwnd, SB_VERT, y, TRUE);
    InvalidateRect(v->hwnd, nullptr, FALSE);
}

// ---- painting
static void round_rect(HDC dc, const RECT& r, int rad, COLORREF fill, COLORREF border) {
    using namespace Gdiplus;
    Graphics g(dc);
    g.SetSmoothingMode(SmoothingModeAntiAlias);
    g.SetPixelOffsetMode(PixelOffsetModeHalf);
    REAL x = (REAL)r.left, y = (REAL)r.top, w = (REAL)(r.right - r.left), h = (REAL)(r.bottom - r.top);
    if (border != CLR_INVALID) { x += 0.5f; y += 0.5f; w -= 1; h -= 1; }
    REAL d = (REAL)std::min(rad * 2, (int)std::min(r.right - r.left, r.bottom - r.top));
    GraphicsPath path;
    if (d <= 1) path.AddRectangle(RectF(x, y, w, h));
    else {
        path.AddArc(x, y, d, d, 180, 90); path.AddArc(x + w - d, y, d, d, 270, 90);
        path.AddArc(x + w - d, y + h - d, d, d, 0, 90); path.AddArc(x, y + h - d, d, d, 90, 90); path.CloseFigure();
    }
    SolidBrush b(Color(255, (BYTE)cr(fill), (BYTE)cg(fill), (BYTE)cb(fill)));
    g.FillPath(&b, &path);
    if (border != CLR_INVALID) { Pen pen(Color(255, (BYTE)cr(border), (BYTE)cg(border), (BYTE)cb(border)), 1.0f); g.DrawPath(&pen, &path); }
}
static bool row_selected(View* v, int row) {
    if (row < 0) return false;
    if (v->sel_all) return true;
    if (v->sel_a < 0) return false;
    return row >= std::min(v->sel_a, v->sel_b) && row <= std::max(v->sel_a, v->sel_b);
}
static void paint(View* v, HDC out) {
    RECT rc; GetClientRect(v->hwnd, &rc);
    int cw = std::max(1, (int)rc.right), ch = std::max(1, (int)rc.bottom);
    if (!v->mdc || v->mw != cw || v->mh != ch) {
        if (v->mdc) { DeleteDC(v->mdc); DeleteObject(v->mbmp); }
        v->mdc = CreateCompatibleDC(out); v->mbmp = CreateCompatibleBitmap(out, cw, ch); SelectObject(v->mdc, v->mbmp);
        v->mw = cw; v->mh = ch;
    }
    HDC dc = v->mdc; const Pal& p = v->pal;
    HBRUSH bgb = CreateSolidBrush(p.bg); RECT all = { 0, 0, cw, ch }; FillRect(dc, &all, bgb); DeleteObject(bgb);
    SetBkMode(dc, TRANSPARENT);
    int sy = v->sy;
    if (v->sel_all || v->sel_a >= 0)
        for (size_t i = 1; i < v->rows.size(); i++) if (row_selected(v, (int)i)) { // row 0 is the hero title
            RECT r = v->rows[i].r; OffsetRect(&r, 0, -sy); InflateRect(&r, v->S(4), 0);
            if (r.bottom < 0 || r.top > ch) continue;
            round_rect(dc, r, v->S(3), p.sel, CLR_INVALID);
        }
    for (size_t i = 0; i < v->els.size(); i++) {
        const El& e = v->els[i];
        RECT r = e.r; OffsetRect(&r, 0, -sy);
        if (r.bottom < 0 || r.top > ch) continue;
        if (e.type == El::Fill) {
            if (e.radius <= 0 && e.border == CLR_INVALID) { HBRUSH b = CreateSolidBrush(e.color); FillRect(dc, &r, b); DeleteObject(b); }
            else round_rect(dc, r, e.radius, e.color, e.border);
            continue;
        }
        COLORREF tc = e.color;
        HGDIOBJ of = SelectObject(dc, v->fonts[e.font]);
        SetTextCharacterExtra(dc, e.extra);
        if ((int)i == v->m_el && v->m_len > 0) {
            RECT hr = r;
            bool single = (e.fmt & DT_SINGLELINE) || text_size(v, e.font, e.s, r.right - r.left, e.fmt, e.extra).cy <= line_h(v, e.font);
            if (single) {
                SIZE a = {}, b = {}, full = {};
                GetTextExtentPoint32W(dc, e.s.c_str(), v->m_off, &a);
                GetTextExtentPoint32W(dc, e.s.c_str() + v->m_off, v->m_len, &b);
                GetTextExtentPoint32W(dc, e.s.c_str(), (int)e.s.size(), &full);
                int x0 = r.left;
                if (e.fmt & DT_RIGHT) x0 = r.right - full.cx;
                else if (e.fmt & DT_CENTER) x0 = r.left + (r.right - r.left - full.cx) / 2;
                hr.left = x0 + a.cx - 1; hr.right = std::min((int)r.right, (int)(x0 + a.cx + b.cx + 1));
                hr.bottom = std::min((int)r.bottom, (int)r.top + line_h(v, e.font));
                if (e.fmt & DT_VCENTER) { int lh = line_h(v, e.font); hr.top = r.top + (r.bottom - r.top - lh) / 2; hr.bottom = hr.top + lh; }
            }
            HBRUSH hb = CreateSolidBrush(p.find); FillRect(dc, &hr, hb); DeleteObject(hb);
            if (single) {
                SetTextColor(dc, tc);
                DrawTextW(dc, e.s.c_str(), (int)e.s.size(), &r, e.fmt | DT_NOPREFIX);
                HRGN rg = CreateRectRgnIndirect(&hr); SelectClipRgn(dc, rg);
                SetTextColor(dc, p.find_text);
                DrawTextW(dc, e.s.c_str(), (int)e.s.size(), &r, e.fmt | DT_NOPREFIX);
                SelectClipRgn(dc, nullptr); DeleteObject(rg);
                SetTextCharacterExtra(dc, 0); SelectObject(dc, of);
                continue;
            }
            tc = p.find_text;
        }
        SetTextColor(dc, tc);
        DrawTextW(dc, e.s.c_str(), (int)e.s.size(), &r, e.fmt | DT_NOPREFIX);
        SetTextCharacterExtra(dc, 0);
        SelectObject(dc, of);
    }
    BitBlt(out, 0, 0, cw, ch, dc, 0, 0, SRCCOPY);
}

// ---- selection, copy, hit testing
static int hit_row(View* v, int x, int ydoc, bool nearest) {
    for (size_t i = 1; i < v->rows.size(); i++) {
        const RECT& r = v->rows[i].r;
        if (x >= r.left - v->S(6) && x < r.right + v->S(6) && ydoc >= r.top && ydoc < r.bottom) return (int)i;
    }
    if (!nearest) return -1;
    int best = -1, bd = INT_MAX;
    for (size_t i = 1; i < v->rows.size(); i++) {
        const RECT& r = v->rows[i].r;
        int dx = x < r.left ? r.left - x : x >= r.right ? x - r.right : 0;
        int dy = ydoc < r.top ? r.top - ydoc : ydoc >= r.bottom ? ydoc - r.bottom : 0;
        int d = dx * 4 + dy;
        if (d < bd) { bd = d; best = (int)i; }
    }
    return best;
}
static void set_clipboard(HWND h, const std::wstring& w) {
    if (!OpenClipboard(h)) return;
    EmptyClipboard();
    HGLOBAL g = GlobalAlloc(GMEM_MOVEABLE, (w.size() + 1) * sizeof(wchar_t));
    if (g) {
        void* p = GlobalLock(g);
        if (p) { memcpy(p, w.c_str(), (w.size() + 1) * sizeof(wchar_t)); GlobalUnlock(g); }
        if (!SetClipboardData(CF_UNICODETEXT, g)) GlobalFree(g);
    }
    CloseClipboard();
}
// whole report: exactly the text the analysis produced (same as the RichEdit view had)
static std::wstring selection_text(View* v) {
    if (v->sel_all || v->sel_a < 0) return v->m.text;
    int a = std::min(v->sel_a, v->sel_b), b = std::max(v->sel_a, v->sel_b);
    std::wstring s;
    for (int i = a; i <= b && i < (int)v->rows.size(); i++) {
        if (v->rows[i].plain.empty()) continue;
        s += v->rows[i].plain + L"\r\n";
    }
    return s;
}
static void do_copy(View* v) { set_clipboard(v->hwnd, selection_text(v)); }
static void select_all(View* v) { v->sel_all = true; v->sel_a = v->sel_b = -1; InvalidateRect(v->hwnd, nullptr, FALSE); }

static void context_menu(View* v, int sx, int sy) {
    POINT pt = { sx, sy };
    if (sx == -1 && sy == -1) { pt.x = v->S(20); pt.y = v->S(20); ClientToScreen(v->hwnd, &pt); }
    POINT cp = pt; ScreenToClient(v->hwnd, &cp);
    int row = hit_row(v, cp.x, cp.y + v->sy, false);
    if (row >= 0 && !row_selected(v, row)) { v->sel_all = false; v->sel_a = v->sel_b = row; InvalidateRect(v->hwnd, nullptr, FALSE); }
    bool multi = v->sel_all || (v->sel_a >= 0 && v->sel_a != v->sel_b);
    HMENU m = CreatePopupMenu();
    std::wstring val = row >= 0 ? v->rows[row].value : L"";
    if (row >= 0 && !val.empty()) AppendMenuW(m, MF_STRING, 1, T(L"Копировать значение", L"Copy value"));
    if (v->sel_a >= 0 || v->sel_all)
        AppendMenuW(m, MF_STRING, 2, multi ? T(L"Копировать выделенное", L"Copy selection") : T(L"Копировать строку", L"Copy line"));
    AppendMenuW(m, MF_STRING, 3, (std::wstring(T(L"Копировать всё", L"Copy all")) + L"\tCtrl+C").c_str());
    AppendMenuW(m, MF_SEPARATOR, 0, nullptr);
    AppendMenuW(m, MF_STRING, 4, (std::wstring(T(L"Выделить всё", L"Select all")) + L"\tCtrl+A").c_str());
    int cmd = (int)TrackPopupMenu(m, TPM_RETURNCMD | TPM_RIGHTBUTTON, pt.x, pt.y, 0, v->hwnd, nullptr);
    DestroyMenu(m);
    if (cmd == 1) set_clipboard(v->hwnd, val);
    else if (cmd == 2) do_copy(v);
    else if (cmd == 3) set_clipboard(v->hwnd, v->m.text);
    else if (cmd == 4) select_all(v);
}

// ---- loading
static void load_file(View* v, const wchar_t* path) {
    v->path = path ? path : L"";
    size_t k = v->path.find_last_of(L"\\/");
    v->fileName = k == std::wstring::npos ? v->path : v->path.substr(k + 1);
    size_t d = v->fileName.rfind(L'.');
    v->ext = d == std::wstring::npos ? L"" : v->fileName.substr(d + 1);
    WIN32_FILE_ATTRIBUTE_DATA fa = {};
    v->haveSize = GetFileAttributesExW(v->path.c_str(), GetFileExInfoStandard, &fa) != 0;
    v->size = v->haveSize ? ((unsigned long long)fa.nFileSizeHigh << 32) | fa.nFileSizeLow : 0;
    bool quick = (v->flags & lcp_fittowindow) != 0; // Ctrl+Q: compact report, as before
    std::wstring text = IsoAnalysis_BuildReport(v->path.c_str(), quick);
    IsoParseReport(text, IsoAnalysis_UiRussian(), v->m);
    v->sy = 0; v->sel_a = v->sel_b = -1; v->sel_all = false; v->m_el = -1;
    set_theme(v);
    relayout(v);
}

static void key_scroll(View* v, int dy) { scroll_to(v, v->sy + dy); }

static LRESULT CALLBACK WndProc(HWND h, UINT m, WPARAM w, LPARAM l) {
    View* v = (View*)GetWindowLongPtrW(h, GWLP_USERDATA);
    switch (m) {
    case WM_CREATE: {
        v = new View(); v->hwnd = h;
        SetWindowLongPtrW(h, GWLP_USERDATA, (LONG_PTR)v);
        v->dpi = window_dpi(h);
        make_fonts(v);
        return 0;
    }
    case WM_SIZE: if (v && v->lay_w >= 0) relayout(v); return 0;
    case WM_DPICHANGED_AFTERPARENT: case WM_DPICHANGED:
        if (v) { int d = window_dpi(h); if (d != v->dpi) { v->dpi = d; make_fonts(v); relayout(v); } }
        return m == WM_DPICHANGED ? 0 : DefWindowProcW(h, m, w, l);
    case WM_ERASEBKGND: return 1;
    case WM_PAINT: {
        PAINTSTRUCT ps; HDC dc = BeginPaint(h, &ps);
        if (v) paint(v, dc);
        EndPaint(h, &ps);
        return 0;
    }
    case WM_VSCROLL: if (v) {
        RECT rc; GetClientRect(h, &rc);
        SCROLLINFO si = {}; si.cbSize = sizeof si; si.fMask = SIF_TRACKPOS; GetScrollInfo(h, SB_VERT, &si);
        int y = v->sy;
        switch (LOWORD(w)) {
        case SB_LINEUP: y -= v->S(40); break;
        case SB_LINEDOWN: y += v->S(40); break;
        case SB_PAGEUP: y -= rc.bottom - v->S(40); break;
        case SB_PAGEDOWN: y += rc.bottom - v->S(40); break;
        case SB_TOP: y = 0; break;
        case SB_BOTTOM: y = v->doc_h; break;
        case SB_THUMBTRACK: case SB_THUMBPOSITION: y = si.nTrackPos; break;
        }
        scroll_to(v, y);
        return 0;
    } break;
    case WM_MOUSEWHEEL: if (v) {
        v->wheel += GET_WHEEL_DELTA_WPARAM(w);
        UINT lines = 3; SystemParametersInfoW(SPI_GETWHEELSCROLLLINES, 0, &lines, 0);
        int step = lines == WHEEL_PAGESCROLL ? v->mh : (int)lines * v->S(20);
        int n = v->wheel / 40; v->wheel -= n * 40; // smooth for high-resolution wheels
        key_scroll(v, -n * step / 3);
        return 0;
    } break;
    case WM_GETDLGCODE: return DLGC_WANTARROWS | DLGC_WANTCHARS;
    case WM_KEYDOWN: if (v) {
        bool ctrl = GetKeyState(VK_CONTROL) < 0;
        RECT rc; GetClientRect(h, &rc);
        if (ctrl && w == 'A') { select_all(v); return 0; }
        if (ctrl && (w == 'C' || w == VK_INSERT)) { do_copy(v); return 0; }
        switch (w) {
        case VK_UP: key_scroll(v, -v->S(40)); return 0;
        case VK_DOWN: key_scroll(v, v->S(40)); return 0;
        case VK_PRIOR: key_scroll(v, -(int)(rc.bottom - v->S(40))); return 0;
        case VK_NEXT: case VK_SPACE: key_scroll(v, rc.bottom - v->S(40)); return 0;
        case VK_HOME: scroll_to(v, 0); return 0;
        case VK_END: scroll_to(v, v->doc_h); return 0;
        case VK_LEFT: case VK_RIGHT: case VK_SHIFT: case VK_CONTROL: case VK_MENU: return 0;
        case VK_APPS: context_menu(v, -1, -1); return 0;
        }
        // everything else (Esc, N/P, 1-7 view modes, F-keys, ...) goes to Total Commander's lister
        PostMessageW(GetParent(h), m, w, l);
        return 0;
    } break;
    case WM_CHAR: return 0;
    case WM_SYSKEYDOWN: case WM_SYSKEYUP: case WM_SYSCHAR:
        PostMessageW(GetParent(h), m, w, l);
        return 0;
    case WM_LBUTTONDOWN: case WM_LBUTTONDBLCLK: if (v) {
        SetFocus(h);
        int x = (short)LOWORD(l), y = (short)HIWORD(l) + v->sy;
        int row = hit_row(v, x, y, false);
        bool shift = (w & MK_SHIFT) != 0;
        v->sel_all = false;
        if (shift && v->sel_a >= 0 && row >= 0) v->sel_b = row;
        else { v->sel_a = v->sel_b = row; }
        if (row >= 0) { v->dragging = true; SetCapture(h); }
        InvalidateRect(h, nullptr, FALSE);
        return 0;
    } break;
    case WM_MOUSEMOVE: if (v && v->dragging) {
        RECT rc; GetClientRect(h, &rc);
        int x = (short)LOWORD(l), cy = (short)HIWORD(l);
        if (cy < 0) key_scroll(v, cy); else if (cy > rc.bottom) key_scroll(v, cy - rc.bottom);
        int row = hit_row(v, x, std::min(std::max(cy, 0), (int)rc.bottom) + v->sy, true);
        if (row >= 0 && row != v->sel_b) { v->sel_b = row; InvalidateRect(h, nullptr, FALSE); }
        return 0;
    } break;
    case WM_LBUTTONUP: case WM_CAPTURECHANGED:
        if (v && v->dragging) { v->dragging = false; if (m == WM_LBUTTONUP) ReleaseCapture(); }
        return 0;
    case WM_CONTEXTMENU: if (v) { context_menu(v, (short)LOWORD(l), (short)HIWORD(l)); return 0; } break;
    case WM_DESTROY:
        if (v) {
            for (auto f : v->fonts) if (f) DeleteObject(f);
            if (v->mdc) { DeleteDC(v->mdc); DeleteObject(v->mbmp); }
            SetWindowLongPtrW(h, GWLP_USERDATA, 0);
            delete v;
            if (--g_windows == 0 && g_gdip) { Gdiplus::GdiplusShutdown(g_gdip); g_gdip = 0; }
        }
        return 0;
    }
    return DefWindowProcW(h, m, w, l);
}

static bool register_class(HINSTANCE inst) {
    static bool done = false;
    if (done) return true;
    WNDCLASSW wc = {}; wc.lpfnWndProc = WndProc; wc.hInstance = inst; wc.lpszClassName = kClass;
    wc.hCursor = LoadCursor(nullptr, IDC_ARROW); wc.style = CS_DBLCLKS;
    done = RegisterClassW(&wc) != 0 || GetLastError() == ERROR_CLASS_ALREADY_EXISTS;
    return done;
}

static View* view_of(HWND h) { return h && IsWindow(h) ? (View*)GetWindowLongPtrW(h, GWLP_USERDATA) : nullptr; }

HWND IsoView_Create(HWND parent, const wchar_t* path, int showFlags, HINSTANCE inst) {
    if (!register_class(inst)) return nullptr;
    if (!g_gdip) { Gdiplus::GdiplusStartupInput in; if (Gdiplus::GdiplusStartup(&g_gdip, &in, nullptr) != Gdiplus::Ok) g_gdip = 0; }
    if (!g_gdip) return nullptr;
    RECT rc; GetClientRect(parent, &rc);
    g_windows++;
    HWND h = CreateWindowExW(0, kClass, L"IsoLister", WS_CHILD | WS_VISIBLE | WS_VSCROLL | WS_CLIPCHILDREN | WS_TABSTOP,
                             0, 0, rc.right, rc.bottom, parent, nullptr, inst, nullptr);
    if (!h) { if (--g_windows == 0) { Gdiplus::GdiplusShutdown(g_gdip); g_gdip = 0; } return nullptr; }
    View* v = view_of(h);
    v->flags = showFlags;
    HCURSOR oc = SetCursor(LoadCursor(nullptr, IDC_WAIT));
    load_file(v, path);
    SetCursor(oc);
    SetFocus(h);
    return h;
}
int IsoView_Load(HWND view, const wchar_t* path, int showFlags) {
    View* v = view_of(view);
    if (!v) return 1;
    v->flags = showFlags;
    load_file(v, path);
    return 0;
}
void IsoView_Copy(HWND view) { if (View* v = view_of(view)) do_copy(v); }
void IsoView_SelectAll(HWND view) { if (View* v = view_of(view)) select_all(v); }
void IsoView_NewParams(HWND view, int showFlags) {
    View* v = view_of(view);
    if (!v) return;
    v->flags = showFlags;
    set_theme(v);
    relayout(v);
}
void IsoView_SetInterfaceVersion(int iface) { g_iface = iface; }
void IsoView_Unregister(HINSTANCE inst) { UnregisterClassW(kClass, inst); }

static bool is_word(wchar_t c) { return IsCharAlphaNumericW(c) || c == L'_'; }

bool IsoView_Search(HWND win, const wchar_t* what, int params) {
    View* v = view_of(win);
    if (!v || !what || !*what) return false;
    bool mc = (params & lcs_matchcase) != 0, ww = (params & lcs_wholewords) != 0, back = (params & lcs_backwards) != 0;
    std::wstring needle = mc ? std::wstring(what) : lower(what);
    size_t n = needle.size();
    int ne = (int)v->els.size();
    int ei; long long pos; // forward: first index allowed; backward: last start allowed
    if ((params & lcs_findfirst) || v->m_el < 0 || v->m_el >= ne) { ei = back ? ne - 1 : 0; pos = back ? LLONG_MAX : 0; }
    else { ei = v->m_el; pos = back ? (long long)v->m_off - 1 : (long long)v->m_off + 1; }
    for (; ei >= 0 && ei < ne; ei += back ? -1 : 1, pos = back ? LLONG_MAX : 0) {
        const El& e = v->els[ei];
        if (e.type != El::Text || !e.search || e.s.size() < n) continue;
        std::wstring hay = mc ? e.s : lower(e.s);
        for (;;) {
            size_t f;
            if (back) { if (pos < 0) break; f = hay.rfind(needle, pos == LLONG_MAX ? std::wstring::npos : (size_t)pos); }
            else { if (pos > (long long)hay.size()) break; f = hay.find(needle, (size_t)pos); }
            if (f == std::wstring::npos) break;
            bool ok = true;
            if (ww) {
                if (f > 0 && is_word(hay[f - 1])) ok = false;
                if (f + n < hay.size() && is_word(hay[f + n])) ok = false;
            }
            if (ok) {
                v->m_el = ei; v->m_off = (int)f; v->m_len = (int)n;
                v->sel_all = false;
                if (e.row > 0) v->sel_a = v->sel_b = e.row; else v->sel_a = v->sel_b = -1;
                RECT rc; GetClientRect(win, &rc);
                if (e.r.top < v->sy || e.r.bottom > v->sy + rc.bottom) scroll_to(v, e.r.top - rc.bottom / 3);
                InvalidateRect(win, nullptr, FALSE);
                return true;
            }
            if (back) pos = (long long)f - 1; else pos = (long long)f + 1;
        }
    }
    return false;
}
