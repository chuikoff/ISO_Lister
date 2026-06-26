// IsoLister.cpp — WLX Lister plugin для Total Commander
// Вывод таблиц "в стиле TC": колонки таб-стопами, без псевдографики.
// Цветные эмодзи: RichEdit 5.0 + выбор шрифта Segoe UI Emoji для самих эмодзи.
// Разбор ISO: PVD, SVD/Joliet, Rock Ridge, UDF, El Torito Boot Catalog,
// эвристики загрузчиков (GRUB2/legacy, ISOLINUX/SYSLINUX, systemd-boot, Win BootMgr).
//
// Компиляция: Win32/Win64 DLL, /MT, UNICODE, C++17.

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <windowsx.h>
#include <strsafe.h>
#include <string>
#include <sstream>
#include <vector>
#include <queue>
#include <unordered_map>
#include <cstdint>
#include <algorithm>
#include <cwctype>
#include <cstring>   // memcmp

// RichEdit
#include <Richedit.h>
#include <Richole.h>
#ifndef MSFTEDIT_CLASS
#define MSFTEDIT_CLASS L"RICHEDIT50W"
#endif

extern "C" {
#include "listplug.h"
}
#include "version_auto.h"  // генерируется gen_version.ps1

#ifdef _M_IX86
#pragma comment(linker, "/EXPORT:ListLoad=_ListLoad@12")
#pragma comment(linker, "/EXPORT:ListLoadW=_ListLoadW@12")
#pragma comment(linker, "/EXPORT:ListGetDetectString=_ListGetDetectString@8")
#pragma comment(linker, "/EXPORT:ListCloseWindow=_ListCloseWindow@4")
#pragma comment(linker, "/EXPORT:ListSetDefaultParams=_ListSetDefaultParams@4")
#pragma comment(linker, "/EXPORT:ListSendCommand=_ListSendCommand@12")
#else
#pragma comment(linker, "/EXPORT:ListLoad")
#pragma comment(linker, "/EXPORT:ListLoadW")
#pragma comment(linker, "/EXPORT:ListGetDetectString")
#pragma comment(linker, "/EXPORT:ListCloseWindow")
#pragma comment(linker, "/EXPORT:ListSetDefaultParams")
#pragma comment(linker, "/EXPORT:ListSendCommand")
#endif

// -----------------------------------------------------------------------------
// Логирование (в %TEMP%\IsoLister.log)
// -----------------------------------------------------------------------------
#define ISO_DEBUG_LOG 1
#if ISO_DEBUG_LOG
static void log_line(const wchar_t* fmt, ...) {
    wchar_t path[MAX_PATH]; GetTempPathW(MAX_PATH, path);
    StringCchCatW(path, MAX_PATH, L"IsoLister.log");
    HANDLE h = CreateFileW(path, FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return;
    wchar_t buf[4096];
    va_list ap; va_start(ap, fmt);
    StringCchVPrintfW(buf, 4096, fmt, ap);
    va_end(ap);
    DWORD cb;
    LARGE_INTEGER zero = {}, cur = {};
    SetFilePointerEx(h, zero, &cur, FILE_END);
    if (cur.QuadPart == 0) { const WORD bom = 0xFEFF; DWORD wcb = 2; WriteFile(h, &bom, 2, &wcb, nullptr); }
    WriteFile(h, buf, (DWORD)(lstrlenW(buf) * sizeof(wchar_t)), &cb, nullptr);
    const wchar_t* nl = L"\r\n";
    WriteFile(h, nl, (DWORD)(lstrlenW(nl) * sizeof(wchar_t)), &cb, nullptr);
    CloseHandle(h);
}
#else
#define log_line(...) do{}while(0)
#endif

// -----------------------------------------------------------------------------
// Глобальные настройки/состояние
// -----------------------------------------------------------------------------
static HINSTANCE g_hInst = nullptr;
static HFONT     g_hMonoFont = nullptr;       // Consolas/Courier New
static HMODULE   g_hMsftEdit = nullptr;       // Msftedit.dll для RICHEDIT50W
static std::wstring g_iniPath;
static std::unordered_map<HWND, WNDPROC> g_richWndProcMap;
static const UINT IDM_CTX_COPY = 1;
static const UINT IDM_CTX_SELECTALL = 2;

static POINT RichEditContextPoint(HWND hwnd);
static LRESULT CALLBACK RichEditSubclassProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);
static void SubclassRichEdit(HWND hwnd);

static const UINT DEFAULT_SECTOR_SIZE = 2048;
static const UINT VD_START_SECTOR = 16;
static const size_t MAX_DIR_READ = 16 * 1024 * 1024;
static UINT g_sectorSize = DEFAULT_SECTOR_SIZE;

// Опции (по умолчанию — быстрый режим как Rufus)
static int g_optDepth = 6;
static int g_optMaxNodes = 40000;
static int g_optShowBootEntries = 0;
static int g_optShowFileList = 0;
static int g_optMaxFileList = 1000;
static int g_optFullScan = 0;

// Таб‑позиции (в "знаках", конвертируем в twips по шрифту)
static const int TAB_MAIN_1 = 26;   // поле → значение
// Для Boot Catalog (многоколонная таблица)
static const int TAB_BOOT_0 = 4;    // №
static const int TAB_BOOT_1 = 20;   // Платформа
static const int TAB_BOOT_2 = 31;   // Bootable
static const int TAB_BOOT_3 = 50;   // Media
static const int TAB_BOOT_4 = 62;   // Segment
static const int TAB_BOOT_5 = 72;   // SysType
static const int TAB_BOOT_6 = 84;   // Sectors
static const int TAB_BOOT_7 = 98;   // LBA
// Для списка файлов
static const int TAB_FILE_PATH = 4;
static const int TAB_FILE_SIZE = 58;
static const int TAB_FILE_TYPE = 72;
static const int TAB_WIN_IDX = 4;
static const int TAB_WIN_NAME = 10;
static const int TAB_WIN_EDITION = 44;
static const int TAB_WIN_VER = 64;

// -----------------------------------------------------------------------------
// Утилиты строк и кодировок
// -----------------------------------------------------------------------------
static std::wstring ATrimRight(const std::string& s) {
    size_t end = s.find_last_not_of(' ');
    std::string t = (end == std::string::npos) ? std::string() : s.substr(0, end + 1);
    if (t.empty()) return L"";
    int wlen = MultiByteToWideChar(CP_ACP, 0, t.c_str(), (int)t.size(), nullptr, 0);
    std::wstring w(wlen, L'\0');
    MultiByteToWideChar(CP_ACP, 0, t.c_str(), (int)t.size(), &w[0], wlen);
    return w;
}
static std::wstring ToLower(const std::wstring& s) {
    std::wstring t(s);
    std::transform(t.begin(), t.end(), t.begin(),
        [](wchar_t ch) { return (wchar_t)std::towlower(ch); });
    return t;
}
static std::wstring FromUCS2BE(const uint8_t* bytes, int lenBytes) {
    std::wstring out;
    if (lenBytes < 2) return out;
    out.reserve(lenBytes / 2);
    for (int i = 0; i + 1 < lenBytes; i += 2) {
        wchar_t ch = (wchar_t)((bytes[i] << 8) | bytes[i + 1]);
        out.push_back(ch);
    }
    return out;
}
static std::wstring repeat(wchar_t ch, int n) { return std::wstring(n, ch); }

static std::wstring FormatFileSize(uint64_t bytes) {
    wchar_t buf[64];
    if (bytes >= 1024ULL * 1024 * 1024)
        StringCchPrintfW(buf, 64, L"%.2f GiB", bytes / (1024.0 * 1024 * 1024));
    else if (bytes >= 1024ULL * 1024)
        StringCchPrintfW(buf, 64, L"%.2f MiB", bytes / (1024.0 * 1024));
    else if (bytes >= 1024ULL)
        StringCchPrintfW(buf, 64, L"%.1f KiB", bytes / 1024.0);
    else
        StringCchPrintfW(buf, 64, L"%llu B", bytes);
    return buf;
}

static std::wstring GetFileExtensionLower(const wchar_t* path) {
    if (!path) return L"";
    const wchar_t* dot = wcsrchr(path, L'.');
    if (!dot || dot[1] == L'\0') return L"";
    return ToLower(dot + 1);
}

// -----------------------------------------------------------------------------
// Работа с файлом
// -----------------------------------------------------------------------------
struct FileReader {
    HANDLE h = INVALID_HANDLE_VALUE;
    bool open(const wchar_t* path) {
        h = CreateFileW(path, GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        return h != INVALID_HANDLE_VALUE;
    }
    bool read_at(uint64_t off, void* buf, DWORD size) {
        LARGE_INTEGER li; li.QuadPart = off;
        if (!SetFilePointerEx(h, li, nullptr, FILE_BEGIN)) return false;
        DWORD rd = 0;
        return ReadFile(h, buf, size, &rd, nullptr) && rd == size;
    }
    bool read_sector(uint32_t lba, void* buf, DWORD size) {
        return read_at(uint64_t(lba) * g_sectorSize, buf, size);
    }
    uint64_t size_bytes() const {
        LARGE_INTEGER li{};
        if (h == INVALID_HANDLE_VALUE || !GetFileSizeEx(h, &li)) return 0;
        return (uint64_t)li.QuadPart;
    }
    ~FileReader() { if (h != INVALID_HANDLE_VALUE) CloseHandle(h); }
};

static uint32_t rd_le32(const uint8_t* p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}
static uint16_t rd_le16(const uint8_t* p) {
    return (uint16_t)p[0] | ((uint16_t)p[1] << 8);
}
static uint64_t rd_le64(const uint8_t* p) {
    return (uint64_t)rd_le32(p) | ((uint64_t)rd_le32(p + 4) << 32);
}

// -----------------------------------------------------------------------------
// Дата/время ISO9660 (17 байт: YYYYMMDDHHMMSSccTZ)
// -----------------------------------------------------------------------------
static std::wstring FormatIsoDatetime17(const std::string& s17) {
    if (s17.size() < 17) return L"—";
    auto dig = [](char c) { return c >= '0' && c <= '9'; };
    for (size_t i = 0; i < 16; i++) if (!dig(s17[i])) return L"—";

    int Y = stoi(s17.substr(0, 4));
    int m = stoi(s17.substr(4, 2));
    int d = stoi(s17.substr(6, 2));
    int H = stoi(s17.substr(8, 2));
    int M = stoi(s17.substr(10, 2));
    int S = stoi(s17.substr(12, 2));
    int cc = stoi(s17.substr(14, 2));
    int8_t tz = (int8_t)(unsigned char)s17[16]; // шаг 15 минут
    int tzMin = tz * 15;
    wchar_t buf[128];
    StringCchPrintfW(buf, 128, L"%04d-%02d-%02d %02d:%02d:%02d.%02d (UTC%+d:%02d)",
        Y, m, d, H, M, S, cc, tzMin / 60, abs(tzMin % 60));
    return buf;
}

// -----------------------------------------------------------------------------
// Сводная структура
// -----------------------------------------------------------------------------
struct IsoSummary {
    // PVD
    bool   hasPVD = false;
    std::wstring volId, sysId, appId;
    std::wstring volumeSetId, publisherId, dataPreparerId;
    uint16_t volumeSetSize = 0;
    uint16_t volumeSequenceNumber = 0;
    uint32_t volBlocks = 0;
    uint16_t logicalBlockSize = 0;
    uint32_t pathTableL = 0, pathTableM = 0, pathTableSize = 0;
    uint32_t rootDirLBA = 0, rootDirSize = 0;
    std::wstring created, modified;

    // SVD / Joliet
    bool   hasSVD = false;
    bool   joliet = false;
    std::string jolietEsc;
    uint32_t jolietRootLBA = 0, jolietRootSize = 0;

    // Rock Ridge
    bool   rockRidge = false;

    // UDF
    bool   hasUDF = false;
    int    udfNsrVersion = 0;
    std::wstring udfPrimaryVolumeId;
    std::wstring udfLogicalVolumeId;
    std::wstring udfVolumeSetId;
    uint32_t udfPartitionStart = 0;
    uint32_t udfPartitionLength = 0;

    // Boot
    bool   hasBootRecord = false;
    uint32_t bootCatalogLBA = 0;
    std::wstring bootSystemId;
    bool   bootable = false;
    bool   biosBoot = false;
    bool   uefiBoot = false;

    // Heuristics
    bool   foundGRUB2 = false;
    bool   foundGRUBLegacy = false;
    bool   foundISOLINUX = false;
    bool   foundSyslinuxMenu = false;
    bool   foundSystemdBoot = false;
    bool   foundWinBootMgr = false;
    bool   foundGenericEFI = false;

    std::wstring bootLoader; // описание
    std::vector<std::wstring> configHits;
};

// -----------------------------------------------------------------------------
// Парсинг Volume Descriptors (ISO9660)
// -----------------------------------------------------------------------------
static bool is_cd001(const uint8_t* p) { return p[1] == 'C' && p[2] == 'D' && p[3] == '0' && p[4] == '0' && p[5] == '1'; }

static bool probe_iso_layout(FileReader& fr, UINT& sectorSizeOut) {
    const UINT candidates[] = { 2048u, 512u, 4096u };
    uint8_t hdr[4096];
    for (UINT ss : candidates) {
        uint64_t off = (uint64_t)VD_START_SECTOR * ss;
        DWORD toRead = (DWORD)std::min<uint64_t>(ss, sizeof(hdr));
        if (!fr.read_at(off, hdr, toRead)) continue;
        if (is_cd001(hdr)) {
            sectorSizeOut = ss;
            return true;
        }
    }
    return false;
}

static void parse_pvd(const uint8_t* vdbuf, IsoSummary& out) {
    size_t o = 0;
    o += 1 /*type*/ + 5 /*CD001*/ + 1 /*ver*/ + 1 /*unused*/;

    std::string sysId((const char*)vdbuf + o, 32); o += 32;
    std::string volId((const char*)vdbuf + o, 32); o += 32;
    o += 8; // unused

    uint32_t volSpaceLE = rd_le32(vdbuf + o); o += 4; o += 4;
    o += 32; // unused
    out.volumeSetSize = rd_le16(vdbuf + o); o += 2; o += 2;
    out.volumeSequenceNumber = rd_le16(vdbuf + o); o += 2; o += 2;
    uint16_t lbSize = rd_le16(vdbuf + o); o += 2; o += 2;
    uint32_t ptSize = rd_le32(vdbuf + o); o += 4; o += 4;
    uint32_t typeL = rd_le32(vdbuf + o); o += 4;
    uint32_t optL = rd_le32(vdbuf + o); o += 4; (void)optL;
    uint32_t typeM = rd_le32(vdbuf + o); o += 4;
    uint32_t optM = rd_le32(vdbuf + o); o += 4; (void)optM;

    const uint8_t* rdr = vdbuf + o; // Root Directory Record (34)
    uint32_t rdrLBA = rd_le32(rdr + 2);
    uint32_t rdrSize = rd_le32(rdr + 10);
    o += 34;

    {
        std::string volSet((const char*)vdbuf + o, 128); o += 128;
        std::string pub((const char*)vdbuf + o, 128); o += 128;
        std::string prep((const char*)vdbuf + o, 128); o += 128;
        out.volumeSetId = ATrimRight(volSet);
        out.publisherId = ATrimRight(pub);
        out.dataPreparerId = ATrimRight(prep);
    }
    std::string appId((const char*)vdbuf + o, 128); o += 128;
    o += 37 /*copyright*/ + 37 /*abstract*/ + 37 /*bibliographic*/;

    std::string created((const char*)vdbuf + o, 17); o += 17;
    std::string modified((const char*)vdbuf + o, 17); o += 17;

    out.hasPVD = true;
    out.sysId = ATrimRight(sysId);
    out.volId = ATrimRight(volId);
    out.appId = ATrimRight(appId);
    out.volBlocks = volSpaceLE;
    out.logicalBlockSize = lbSize;
    out.pathTableSize = ptSize;
    out.pathTableL = typeL;
    out.pathTableM = typeM;
    out.rootDirLBA = rdrLBA;
    out.rootDirSize = rdrSize;
    out.created = FormatIsoDatetime17(created);
    out.modified = FormatIsoDatetime17(modified);
}

static void parse_svd(const uint8_t* vdbuf, IsoSummary& out) {
    size_t o = 0;
    o += 1 + 5 + 1 + 1;

    o += 32 /*sysId*/ + 32 /*volId*/;
    o += 8; // unused

    uint32_t volSpaceLE = rd_le32(vdbuf + o); (void)volSpaceLE; o += 4; o += 4;

    std::string esc((const char*)vdbuf + o, 32);
    o += 32;

    o += 2 + 2; // set size
    o += 2 + 2; // seq#
    o += 2 + 2; // logical block size
    o += 4 + 4; // path table size
    uint32_t typeL = rd_le32(vdbuf + o); o += 4;
    uint32_t optL = rd_le32(vdbuf + o); o += 4; (void)optL;
    uint32_t typeM = rd_le32(vdbuf + o); o += 4;
    uint32_t optM = rd_le32(vdbuf + o); o += 4; (void)optM;

    const uint8_t* rdr = vdbuf + o; // 34 bytes
    uint32_t rdrLBA = rd_le32(rdr + 2);
    uint32_t rdrSize = rd_le32(rdr + 10);

    out.hasSVD = true;
    if (esc.size() >= 3 && esc[0] == '%' && esc[1] == '/') {
        if (esc[2] == '@' || esc[2] == 'C' || esc[2] == 'E') {
            out.joliet = true;
            out.jolietEsc = esc.substr(0, 3);
            out.jolietRootLBA = rdrLBA;
            out.jolietRootSize = rdrSize;
        }
    }
}

static void parse_boot_record(const uint8_t* vdbuf, IsoSummary& out) {
    // Boot Record (El Torito)
    out.hasBootRecord = true;
    std::string bsid((const char*)vdbuf + 7, 32);
    out.bootSystemId = ATrimRight(bsid);
    out.bootCatalogLBA = rd_le32(vdbuf + 0x47);
}

// -----------------------------------------------------------------------------
// UDF: обнаружение и разбор дескрипторов (ECMA-167)
// -----------------------------------------------------------------------------
static bool udf_tag_valid(const uint8_t* tag) {
    uint8_t cs = 0;
    for (int i = 0; i < 16; i++) if (i != 4) cs = (uint8_t)(cs + tag[i]);
    return cs == tag[4];
}

static bool parse_udf_dstring(const uint8_t* p, int maxChars, std::wstring& out) {
    if (!p) return false;
    uint8_t len = p[0];
    if (len < 2 || len > 255) return false;
    uint8_t comp = p[1];
    out.clear();
    if (comp == 8) {
        int avail = (int)len - 1;
        for (int i = 0; i + 1 < avail && (int)out.size() < maxChars; i += 2) {
            wchar_t ch = (wchar_t)((p[2 + i] << 8) | p[2 + i + 1]);
            if (ch) out.push_back(ch);
        }
        return !out.empty();
    }
    if (comp == 16) {
        for (int i = 2; i < len && (int)out.size() < maxChars; i++) {
            if (p[i]) out.push_back((wchar_t)p[i]);
        }
        return !out.empty();
    }
    return false;
}

static int detect_udf_nsr(FileReader& fr) {
    std::vector<uint8_t> buf(g_sectorSize);
    for (uint32_t s = VD_START_SECTOR; s < VD_START_SECTOR + 256; ++s) {
        if (!fr.read_sector(s, buf.data(), g_sectorSize)) break;
        for (size_t i = 0; i + 5 <= g_sectorSize; i++) {
            if (!memcmp(buf.data() + i, "NSR03", 5)) return 3;
            if (!memcmp(buf.data() + i, "NSR02", 5)) return 2;
        }
    }
    return 0;
}

static bool parse_udf(FileReader& fr, IsoSummary& out) {
    int nsr = detect_udf_nsr(fr);
    if (!nsr) return false;

    out.hasUDF = true;
    out.udfNsrVersion = nsr;

    uint64_t totalSectors = fr.size_bytes() / g_sectorSize;
    if (totalSectors < 257) return true;

    uint32_t anchorSecs[3] = {
        (uint32_t)(totalSectors - 1),
        (uint32_t)(totalSectors - 256),
        256u
    };

    uint32_t mvdsExtent = 0, mvdsLen = 0;
    for (uint32_t as : anchorSecs) {
        uint8_t tag[512]{};
        if (!fr.read_sector(as, tag, (DWORD)std::min<size_t>(512, g_sectorSize))) continue;
        if (!udf_tag_valid(tag)) continue;
        if (rd_le16(tag) != 2) continue;
        mvdsExtent = rd_le32(tag + 16);
        mvdsLen = rd_le32(tag + 20);
        break;
    }
    if (!mvdsLen || mvdsLen > 16 * 1024 * 1024) return true;

    std::vector<uint8_t> seq(mvdsLen);
    if (!fr.read_sector(mvdsExtent, seq.data(), mvdsLen)) return true;

    size_t pos = 0;
    while (pos + 16 <= seq.size()) {
        const uint8_t* t = seq.data() + pos;
        if (!udf_tag_valid(t)) break;
        uint16_t tid = rd_le16(t);
        uint16_t crcLen = rd_le16(t + 10);
        size_t descLen = ((size_t)crcLen + 3) & ~size_t(3);
        if (descLen < 16 || pos + descLen > seq.size()) break;

        if (tid == 1 && crcLen >= 116) {
            parse_udf_dstring(t + 24, 32, out.udfPrimaryVolumeId);
            parse_udf_dstring(t + 84, 32, out.udfVolumeSetId);
        }
        else if (tid == 6 && crcLen >= 212) {
            parse_udf_dstring(t + 84, 128, out.udfLogicalVolumeId);
        }
        else if (tid == 5 && crcLen >= 260) {
            out.udfPartitionStart = rd_le32(t + 252);
            out.udfPartitionLength = rd_le32(t + 256);
        }
        else if (tid == 8) {
            break;
        }
        pos += descLen;
    }
    return true;
}

// -----------------------------------------------------------------------------
// Чтение каталога ISO, Rock Ridge, поиск файлов
// -----------------------------------------------------------------------------
struct DirEntry {
    bool isDir = false;
    uint32_t lba = 0;
    uint32_t size = 0;
    std::wstring name;
    bool rr_susp = false;
};

static bool parse_one_dr(const uint8_t* p, int dr_len, bool joliet, DirEntry& de, bool* rr_hit)
{
    if (dr_len < 34) return false;
    uint8_t len_dr = p[0];
    if (len_dr == 0) return false;
    uint8_t xattr_len = p[1]; (void)xattr_len;
    uint32_t extent = rd_le32(p + 2);
    uint32_t data_len = rd_le32(p + 10);
    uint8_t flags = p[25];
    uint8_t fi_len = p[32];
    const uint8_t* fi = p + 33;

    std::wstring name;
    if (fi_len == 1 && fi[0] == 0)      name = L".";
    else if (fi_len == 1 && fi[0] == 1) name = L"..";
    else {
        if (joliet) name = FromUCS2BE(fi, fi_len);
        else { std::string a((const char*)fi, fi_len); name = ATrimRight(a); }
        size_t sc = name.find_last_of(L';');
        if (sc != std::wstring::npos) name = name.substr(0, sc);
    }

    int su_off = 33 + fi_len; if (su_off & 1) su_off++;
    bool rr = false;
    if (su_off + 4 <= len_dr) {
        const uint8_t* su = p + su_off;
        int remain = len_dr - su_off;
        int pos = 0;
        while (pos + 4 <= remain) {
            const uint8_t* ent = su + pos;
            uint8_t sig1 = ent[0], sig2 = ent[1];
            uint8_t ent_len = ent[2];
            if (ent_len < 4) break;
            if ((sig1 == 'R' && sig2 == 'R') || (sig1 == 'E' && sig2 == 'R') || (sig1 == 'N' && sig2 == 'M') || (sig1 == 'S' && sig2 == 'P')) {
                rr = true; break;
            }
            pos += ent_len;
        }
    }
    if (rr_hit) *rr_hit = rr;

    de.isDir = (flags & 0x02) != 0;
    de.lba = extent;
    de.size = data_len;
    de.name = name;
    de.rr_susp = rr;
    return true;
}

static void read_directory(FileReader& fr, uint32_t lba, uint32_t size, bool joliet,
    std::vector<DirEntry>& out, bool& rrDetected)
{
    rrDetected = false;
    if (size == 0) return;
    size_t toRead = (size > MAX_DIR_READ) ? MAX_DIR_READ : size;
    std::vector<uint8_t> buf(toRead);
    if (!fr.read_sector(lba, buf.data(), (DWORD)toRead)) return;

    size_t off = 0;
    while (off + 1 < buf.size()) {
        uint8_t len_dr = buf[off];
        if (len_dr == 0) {
            size_t next = ((off / g_sectorSize) + 1) * g_sectorSize;
            if (next <= off) break;
            off = next;
            continue;
        }
        if (off + len_dr > buf.size()) break;

        DirEntry de;
        bool rr_hit = false;
        if (parse_one_dr(&buf[off], len_dr, joliet, de, &rr_hit)) {
            if (rr_hit) rrDetected = true;
            out.push_back(std::move(de));
        }
        off += len_dr;
    }
}

// -----------------------------------------------------------------------------
// Чтение файлов из ISO и разбор Windows WIM/ESD
// -----------------------------------------------------------------------------
struct IsoFileRef {
    std::wstring path;
    uint32_t lba = 0;
    uint64_t size = 0;
};

struct WimImageInfo {
    int index = 0;
    std::wstring name;
    std::wstring displayName;
    std::wstring description;
    std::wstring editionId;
    std::wstring arch;
    std::wstring version;
    std::wstring language;
};

struct WindowsInfo {
    bool detected = false;
    bool isInstallMedia = false;
    std::wstring imageType;
    std::wstring productVersion;
    std::wstring buildNumber;
    std::wstring channel;
    std::wstring architecture;
    std::wstring defaultLanguage;
    std::wstring installImagePath;
    uint64_t installImageSize = 0;
    std::wstring bootImagePath;
    uint64_t bootImageSize = 0;
    std::vector<std::wstring> eiCfgEditions;
    std::vector<WimImageInfo> editions;
};

static bool read_iso_file_bytes(FileReader& fr, uint32_t lba, uint64_t fileSize,
    uint64_t offsetInFile, void* buf, DWORD size)
{
    if (size == 0) return false;
    if (offsetInFile >= fileSize) return false;
    if (offsetInFile + size > fileSize)
        size = (DWORD)(fileSize - offsetInFile);
    uint64_t abs = (uint64_t)lba * g_sectorSize + offsetInFile;
    return fr.read_at(abs, buf, size);
}

static std::wstring xml_get_attr(const std::wstring& tag, const wchar_t* name) {
    std::wstring key = std::wstring(name) + L"=\"";
    size_t p = tag.find(key);
    if (p == std::wstring::npos) return L"";
    p += key.size();
    size_t e = tag.find(L'"', p);
    if (e == std::wstring::npos) return L"";
    return tag.substr(p, e - p);
}

static std::wstring xml_get_elem_text(const std::wstring& block, const wchar_t* elem) {
    std::wstring open = std::wstring(L"<") + elem;
    std::wstring close = std::wstring(L"</") + elem + L">";
    size_t p = block.find(open);
    if (p == std::wstring::npos) return L"";
    p = block.find(L">", p);
    if (p == std::wstring::npos) return L"";
    p++;
    size_t e = block.find(close, p);
    if (e == std::wstring::npos) return L"";
    std::wstring val = block.substr(p, e - p);
    size_t lt = val.find(L'<');
    if (lt != std::wstring::npos) val = val.substr(0, lt);
    return val;
}

static std::wstring wim_arch_name(const std::wstring& archNum) {
    if (archNum == L"9") return L"x64";
    if (archNum == L"0") return L"x86";
    if (archNum == L"12") return L"ARM64";
    return archNum;
}

static void parse_wim_xml_images(const std::wstring& xml, std::vector<WimImageInfo>& out) {
    size_t pos = 0;
    while (pos < xml.size()) {
        size_t imgStart = xml.find(L"<IMAGE ", pos);
        if (imgStart == std::wstring::npos) break;

        size_t imgEnd = xml.find(L"</IMAGE>", imgStart);
        std::wstring block;
        if (imgEnd != std::wstring::npos) {
            block = xml.substr(imgStart, imgEnd + 8 - imgStart);
            pos = imgEnd + 8;
        }
        else {
            size_t gt = xml.find(L">", imgStart);
            if (gt == std::wstring::npos) break;
            block = xml.substr(imgStart, gt - imgStart + 1);
            pos = gt + 1;
        }

        size_t gt = block.find(L">");
        if (gt == std::wstring::npos) continue;
        std::wstring openTag = block.substr(0, gt + 1);

        WimImageInfo wi{};
        wi.index = _wtoi(xml_get_attr(openTag, L"INDEX").c_str());
        wi.name = xml_get_elem_text(block, L"NAME");
        if (wi.name.empty()) wi.name = xml_get_attr(openTag, L"NAME");
        wi.description = xml_get_elem_text(block, L"DESCRIPTION");
        wi.displayName = xml_get_elem_text(block, L"DISPLAYNAME");
        if (wi.displayName.empty()) wi.displayName = wi.name;
        if (wi.displayName.empty()) wi.displayName = wi.description;

        std::wstring major = xml_get_elem_text(block, L"MAJOR");
        std::wstring minor = xml_get_elem_text(block, L"MINOR");
        std::wstring build = xml_get_elem_text(block, L"BUILD");
        std::wstring sp = xml_get_elem_text(block, L"SPBUILD");
        if (!major.empty()) {
            wi.version = major + L"." + minor + L"." + build;
            if (!sp.empty() && sp != L"0") wi.version += L"." + sp;
        }

        wi.editionId = xml_get_elem_text(block, L"EDITIONID");
        if (wi.editionId.empty()) wi.editionId = xml_get_attr(block, L"EDITIONID");

        std::wstring archNum = xml_get_elem_text(block, L"ARCH");
        if (archNum.empty()) archNum = xml_get_attr(block, L"ARCH");
        wi.arch = wim_arch_name(archNum);

        wi.language = xml_get_elem_text(block, L"DEFAULT");
        if (wi.language.empty()) wi.language = xml_get_elem_text(block, L"LANGUAGE");
        if (wi.language.empty()) {
            size_t langPos = block.find(L"<LANGUAGES>");
            if (langPos != std::wstring::npos) {
                size_t langEnd = block.find(L"</LANGUAGES>", langPos);
                if (langEnd != std::wstring::npos) {
                    std::wstring langs = block.substr(langPos, langEnd - langPos);
                    wi.language = xml_get_elem_text(langs, L"LANGUAGE");
                }
            }
        }

        if (wi.index > 0 || !wi.displayName.empty() || !wi.editionId.empty())
            out.push_back(std::move(wi));
    }
}

static bool wim_bytes_to_xml(const uint8_t* data, size_t len, std::wstring& xmlOut) {
    if (len < 4) return false;
    if (data[0] == 0xFF && data[1] == 0xFE) {
        size_t chars = (len - 2) / 2;
        xmlOut.assign(chars, L'\0');
        memcpy(&xmlOut[0], data + 2, chars * sizeof(wchar_t));
        return xmlOut.find(L"<IMAGE ") != std::wstring::npos || xmlOut.find(L"<WIM") != std::wstring::npos;
    }
    if (data[0] == '<' && data[1] == '?') {
        xmlOut.assign((const wchar_t*)data, len / sizeof(wchar_t));
        return true;
    }
    size_t chars = len / 2;
    xmlOut.assign(chars, L'\0');
    memcpy(&xmlOut[0], data, chars * sizeof(wchar_t));
    return xmlOut.find(L"<IMAGE ") != std::wstring::npos || xmlOut.find(L"<WIM") != std::wstring::npos;
}

static std::wstring wim_format_version(const uint8_t* hdr) {
    wchar_t buf[32];
    StringCchPrintfW(buf, 32, L"%u.%u.%u", hdr[12], hdr[14], hdr[13]);
    return buf;
}

static bool parse_wim_xml_from_iso(FileReader& fr, uint32_t lba, uint64_t fileSize, std::vector<WimImageInfo>& out) {
    const size_t WIM_HDR = 208;
    uint8_t hdr[WIM_HDR]{};
    if (!read_iso_file_bytes(fr, lba, fileSize, 0, hdr, (DWORD)WIM_HDR)) return false;

    bool isWim = !memcmp(hdr, "MSWIM", 5) || !memcmp(hdr, "WIM", 3);
    if (!isWim) return false;

    std::wstring xml;
    uint64_t xmlOff = rd_le64(hdr + 80);
    uint64_t xmlLen = rd_le64(hdr + 88);
    if (xmlLen == 0 || xmlLen > 32 * 1024 * 1024 || xmlOff + xmlLen > fileSize)
        return false;
    std::vector<uint8_t> xmlBuf((size_t)xmlLen);
    if (!read_iso_file_bytes(fr, lba, fileSize, xmlOff, xmlBuf.data(), (DWORD)xmlLen))
        return false;
    if (!wim_bytes_to_xml(xmlBuf.data(), xmlBuf.size(), xml))
        return false;
    parse_wim_xml_images(xml, out);
    return !out.empty();
}

static void parse_ei_cfg_text(const std::string& text, WindowsInfo& win) {
    std::string section;
    std::istringstream ss(text);
    std::string line;
    while (std::getline(ss, line)) {
        while (!line.empty() && (line.back() == '\r' || line.back() == ' ' || line.back() == '\t')) line.pop_back();
        if (line.empty() || line[0] == ';' || line[0] == '#') continue;
        if (line.front() == '[' && line.back() == ']') {
            section = line;
            continue;
        }
        std::string val = line;
        size_t eq = val.find('=');
        if (eq != std::string::npos) val = val.substr(eq + 1);
        std::wstring wval = ATrimRight(val);
        if (wval.empty()) continue;

        std::wstring sec;
        if (!section.empty()) {
            int slen = MultiByteToWideChar(CP_ACP, 0, section.c_str(), -1, nullptr, 0);
            sec.assign(slen, L'\0');
            MultiByteToWideChar(CP_ACP, 0, section.c_str(), -1, &sec[0], slen);
            if (!sec.empty() && sec.back() == L'\0') sec.pop_back();
        }

        if (sec.find(L"Channel") != std::wstring::npos || val.find("_Channel") != std::string::npos)
            win.channel = wval;
        if (sec.find(L"EditionID") != std::wstring::npos)
            win.eiCfgEditions.push_back(wval);
        if (sec.find(L"VL") != std::wstring::npos && win.channel.empty())
            win.channel = L"Volume";
    }
}

static void enrich_windows_from_metadata(const IsoSummary& sum, WindowsInfo& win) {
    std::wstring v = ToLower(sum.volId + L" " + sum.volumeSetId + L" " + sum.appId);
    if (win.productVersion.empty()) {
        if (v.find(L"win11") != std::wstring::npos || v.find(L"windows11") != std::wstring::npos)
            win.productVersion = L"Windows 11";
        else if (v.find(L"win10") != std::wstring::npos || v.find(L"windows10") != std::wstring::npos)
            win.productVersion = L"Windows 10";
        else if (v.find(L"win8.1") != std::wstring::npos) win.productVersion = L"Windows 8.1";
        else if (v.find(L"win8") != std::wstring::npos) win.productVersion = L"Windows 8";
        else if (v.find(L"win7") != std::wstring::npos || v.find(L"windows7") != std::wstring::npos)
            win.productVersion = L"Windows 7";
        else if (v.find(L"server") != std::wstring::npos) win.productVersion = L"Windows Server";
    }
    if (v.find(L"sp1") != std::wstring::npos && win.productVersion.find(L"SP1") == std::wstring::npos)
        win.productVersion += L" SP1";
    if (v.find(L"x64") != std::wstring::npos || v.find(L"amd64") != std::wstring::npos)
        win.architecture = L"x64";
    else if (v.find(L"x86") != std::wstring::npos) win.architecture = L"x86";
    if (v.find(L"ru") != std::wstring::npos || v.find(L"rus") != std::wstring::npos)
        win.defaultLanguage = L"ru-RU";
    else if (v.find(L"en") != std::wstring::npos) win.defaultLanguage = L"en-US";
    if (win.imageType.empty() && !win.productVersion.empty())
        win.imageType = L"Windows (по метаданным ISO)";
}

static std::wstring guess_windows_product_name(const std::vector<WimImageInfo>& editions) {
    for (const auto& e : editions) {
        std::wstring n = ToLower(e.displayName.empty() ? e.name : e.displayName);
        if (n.find(L"windows 11") != std::wstring::npos) return L"Windows 11";
        if (n.find(L"windows 10") != std::wstring::npos) return L"Windows 10";
        if (n.find(L"windows 8.1") != std::wstring::npos) return L"Windows 8.1";
        if (n.find(L"windows 8") != std::wstring::npos) return L"Windows 8";
        if (n.find(L"windows 7") != std::wstring::npos) return L"Windows 7";
        if (n.find(L"windows server 2025") != std::wstring::npos) return L"Windows Server 2025";
        if (n.find(L"windows server 2022") != std::wstring::npos) return L"Windows Server 2022";
        if (n.find(L"windows server 2019") != std::wstring::npos) return L"Windows Server 2019";
        if (n.find(L"windows server 2016") != std::wstring::npos) return L"Windows Server 2016";
        if (n.find(L"windows pe") != std::wstring::npos) return L"Windows PE";
    }
    return L"";
}

static bool path_iequals_suffix(const std::wstring& path, const std::wstring& suffix) {
    if (path.size() < suffix.size()) return false;
    return ToLower(path.substr(path.size() - suffix.size())) == ToLower(suffix);
}

struct WimDiscovery {
    uint64_t offset = 0;
    uint32_t imageCount = 0;
    uint64_t estimatedSize = 0;
};

static bool wim_header_looks_valid(const uint8_t* hdr) {
    if (memcmp(hdr, "MSWIM", 5) != 0) return false;
    if (rd_le32(hdr + 8) != 208) return false;
    uint32_t imgCount = rd_le32(hdr + 0x1C);
    if (imgCount == 0 || imgCount > 40) return false;
    uint64_t xmlOff = rd_le64(hdr + 80);
    uint64_t xmlLen = rd_le64(hdr + 88);
    if (xmlLen < 64 || xmlLen > 32 * 1024 * 1024) return false;
    if (xmlOff < 208 || xmlOff > 512 * 1024 * 1024ULL) return false;
    return true;
}

static void discover_wim_by_signature_scan(FileReader& fr, uint64_t isoSize, std::vector<WimDiscovery>& out) {
    const uint64_t chunk = 32 * 1024 * 1024;
    const size_t step = 512;
    std::vector<uint8_t> buf((size_t)chunk + 256);

    for (uint64_t base = 34ULL * g_sectorSize; base < isoSize; base += chunk) {
        uint64_t toRead = std::min<uint64_t>(chunk + 256, isoSize - base);
        if (!fr.read_at(base, buf.data(), (DWORD)toRead)) break;

        for (size_t i = 0; i + 208 < toRead; i += step) {
            const uint8_t* hdr = buf.data() + i;
            if (memcmp(hdr, "MSWIM", 5) != 0) continue;
            if (!wim_header_looks_valid(hdr)) continue;

            uint64_t start = base + i;
            bool dup = false;
            for (const auto& d : out) {
                uint64_t delta = start > d.offset ? start - d.offset : d.offset - start;
                if (delta < 4096) { dup = true; break; }
            }
            if (dup) continue;

            WimDiscovery wd{};
            wd.offset = start;
            wd.imageCount = rd_le32(hdr + 0x1C);
            wd.estimatedSize = chunk;
            out.push_back(wd);
        }
    }
}

static bool parse_wim_at_offset(FileReader& fr, uint64_t offset, uint64_t /*maxSize*/, std::vector<WimImageInfo>& out) {
    const size_t WIM_HDR = 208;
    uint8_t hdr[WIM_HDR]{};
    if (!fr.read_at(offset, hdr, (DWORD)WIM_HDR)) return false;
    if (!wim_header_looks_valid(hdr)) return false;

    uint64_t xmlOff = rd_le64(hdr + 80);
    uint64_t xmlLen = rd_le64(hdr + 88);
    if (offset + xmlOff + xmlLen > fr.size_bytes()) return false;

    std::vector<uint8_t> xmlBuf((size_t)xmlLen);
    if (!fr.read_at(offset + xmlOff, xmlBuf.data(), (DWORD)xmlLen)) return false;
    std::wstring xml;
    if (!wim_bytes_to_xml(xmlBuf.data(), xmlBuf.size(), xml)) return false;
    parse_wim_xml_images(xml, out);
    return !out.empty();
}

// BFS-скан по дереву
struct FileListItem {
    std::wstring path;
    uint64_t size = 0;
    bool isDir = false;
};

struct ScanResult {
    bool rrDetected = false;
    bool foundEFI = false;
    bool foundGRUB2 = false;
    bool foundGRUBLegacy = false;
    bool foundISOLINUX = false;
    bool foundSyslinuxMenu = false;
    bool foundSystemdBoot = false;
    bool foundWinBootMgr = false;
    bool foundGenericEFI = false;
    std::vector<std::wstring> configHits;
    std::vector<FileListItem> fileList;
    std::vector<IsoFileRef> winFiles;
    std::vector<FileListItem> largestFiles;
    int totalFiles = 0;
    int totalDirs = 0;
};

static ScanResult bfs_scan(FileReader& fr,
    uint32_t rootLBA, uint32_t rootSize,
    bool joliet, int maxDepth, int maxNodes)
{
    ScanResult res;
    struct QN { uint32_t lba, size; std::wstring path; int depth; };
    std::queue<QN> q;
    q.push({ rootLBA, rootSize, L"", 0 });
    int nodes = 0;

    auto joinp = [](const std::wstring& base, const std::wstring& name)->std::wstring {
        if (base.empty()) return L"/" + name;
        return base + L"/" + name;
        };

    const std::vector<std::wstring> cfgTargets = {
        L"preseed.cfg", L"autounattend.xml", L"unattend.xml", L"ks.cfg", L"loader.conf",
        L"ei.cfg", L"lang.ini", L"idwbfind.xml", L"product.ini"
    };

    auto track_windows_file = [&](const std::wstring& fullPath, const DirEntry& e) {
        static const wchar_t* kWinSuffixes[] = {
            L"/sources/install.wim", L"/sources/install.esd", L"/sources/boot.wim",
            L"/sources/ei.cfg", L"/setup.exe", L"/bootmgr", L"/bootmgr.efi",
            L"/sources/bootmgr", L"/sources/bootmgr.efi", L"/sources/install.wim.xml"
        };
        for (const wchar_t* suf : kWinSuffixes) {
            if (path_iequals_suffix(fullPath, suf)) {
                res.winFiles.push_back({ fullPath, e.lba, e.size });
                break;
            }
        }
    };

    auto track_largest = [&](const std::wstring& fullPath, const DirEntry& e) {
        if (e.isDir) return;
        FileListItem item{ fullPath, e.size, false };
        res.largestFiles.push_back(item);
        std::sort(res.largestFiles.begin(), res.largestFiles.end(),
            [](const FileListItem& a, const FileListItem& b) { return a.size > b.size; });
        if (res.largestFiles.size() > 15) res.largestFiles.resize(15);
    };

    while (!q.empty() && nodes < maxNodes) {
        QN cur = q.front(); q.pop();
        nodes++;

        std::vector<DirEntry> entries;
        bool rrHere = false;
        read_directory(fr, cur.lba, cur.size, joliet, entries, rrHere);
        if (rrHere) res.rrDetected = true;

        for (const auto& e : entries) {
            if (e.name == L"." || e.name == L"..") continue;
            std::wstring lower = ToLower(e.name);

            std::wstring fullPath = joinp(cur.path, e.name);
            if (g_optShowFileList && (int)res.fileList.size() < g_optMaxFileList) {
                FileListItem fl{};
                fl.path = fullPath;
                fl.size = e.size;
                fl.isDir = e.isDir;
                res.fileList.push_back(std::move(fl));
            }
            if (e.isDir) res.totalDirs++;
            else res.totalFiles++;

            if (!e.isDir) {
                track_windows_file(fullPath, e);
                track_largest(fullPath, e);
                if (lower == L"isolinux.bin" || lower == L"ldlinux.c32" || lower == L"isolinux.cfg")
                    res.foundISOLINUX = true;
                if (lower == L"menu.c32" || lower == L"vesamenu.c32" || lower == L"syslinux.cfg")
                    res.foundSyslinuxMenu = true;

                if (lower == L"grub.cfg" || lower.find(L"grub2") != std::wstring::npos || lower == L"grubx64.efi")
                    res.foundGRUB2 = true;
                if (lower == L"menu.lst" || lower.find(L"stage2") != std::wstring::npos || lower == L"grldr")
                    res.foundGRUBLegacy = true;

                if (lower.find(L"bootmgfw.efi") != std::wstring::npos)
                    res.foundWinBootMgr = true;

                if (lower == L"loader.efi" || lower == L"systemd-bootx64.efi")
                    res.foundSystemdBoot = true;
                if (lower == L"bootx64.efi" || lower == L"bootia32.efi")
                    res.foundGenericEFI = true;

                for (const auto& tgt : cfgTargets) {
                    if (lower == tgt) res.configHits.push_back(joinp(cur.path, e.name));
                }
            }
            else {
                std::wstring dl = ToLower(e.name);
                if (dl == L"efi") res.foundEFI = true;
                if (dl == L"grub2") res.foundGRUB2 = true;
            }

            if (e.isDir && cur.depth < maxDepth) {
                q.push({ e.lba, e.size, joinp(cur.path, e.name), cur.depth + 1 });
            }
        }
    }

    return res;
}

// -----------------------------------------------------------------------------
// UDF: обход каталогов (для ISO с UDF-разделом, где лежит install.wim)
// -----------------------------------------------------------------------------
static bool udf_tag_ok(const uint8_t* t) {
    uint8_t cs = 0;
    for (int i = 0; i < 16; i++) if (i != 4) cs = (uint8_t)(cs + t[i]);
    return cs == t[4];
}

static std::wstring udf_dname(const uint8_t* p, int len) {
    if (len <= 0) return L"";
    uint8_t comp = p[0];
    std::wstring out;
    if (comp == 8 || comp == 16) {
        bool ucs2Be = false;
        for (int i = 1; i + 1 < len; i += 2) {
            if (p[i] == 0 && p[i + 1] != 0) { ucs2Be = true; break; }
        }
        if (comp == 8 && !ucs2Be) {
            for (int i = 1; i < len; i++) {
                if (p[i]) out.push_back((wchar_t)p[i]);
            }
            if (!out.empty()) return out;
        }
        for (int i = 1; i + 1 < len; i += 2) {
            wchar_t ch = (wchar_t)((p[i] << 8) | p[i + 1]);
            if (ch) out.push_back(ch);
        }
        if (!out.empty()) return out;
        if (comp == 16) {
            for (int i = 1; i < len; i++) out.push_back((wchar_t)p[i]);
        }
    }
    else {
        std::string a((const char*)p, len);
        return ATrimRight(a);
    }
    return out;
}

static bool udf_read_short_ad(const uint8_t* p, uint32_t& lba, uint32_t& len) {
    uint32_t lt = rd_le32(p);
    if ((lt & 0xC0000000) == 0xC0000000) return false;
    len = lt & 0x3FFFFFFF;
    lba = rd_le32(p + 4);
    return len > 0 || lba > 0;
}

static bool udf_read_long_ad(const uint8_t* p, uint32_t& lba, uint32_t& len) {
    uint32_t lt = rd_le32(p);
    if ((lt & 0xC0000000) == 0xC0000000) return false;
    len = lt & 0x3FFFFFFF;
    lba = rd_le32(p + 4);
    return len > 0 || lba > 0;
}

static bool udf_fe_data_extent(FileReader& fr, uint32_t partBase, uint32_t feLba,
    uint32_t& dataLba, uint32_t& dataLen, uint64_t* infoLen = nullptr)
{
    std::vector<uint8_t> fe(g_sectorSize);
    if (!fr.read_sector(partBase + feLba, fe.data(), g_sectorSize)) return false;
    if (!udf_tag_ok(fe.data()) || rd_le16(fe.data()) != 261) return false;
    if (infoLen) *infoLen = rd_le64(fe.data() + 56);
    uint32_t lEa = rd_le32(fe.data() + 168);
    uint32_t lAd = rd_le32(fe.data() + 172);
    if (176 + lEa + 8 > g_sectorSize) return false;
    const uint8_t* ad = fe.data() + 176 + ((lEa + 3) & ~3u);
    if (lAd >= 16 && udf_read_long_ad(ad, dataLba, dataLen)) return true;
    if (lAd >= 8 && udf_read_short_ad(ad, dataLba, dataLen)) return true;
    return false;
}

static std::vector<std::wstring> split_path_components(const wchar_t* path) {
    std::vector<std::wstring> parts;
    if (!path) return parts;
    std::wstring p = path;
    if (!p.empty() && p[0] == L'/') p = p.substr(1);
    size_t start = 0;
    while (start < p.size()) {
        size_t slash = p.find(L'/', start);
        std::wstring comp = (slash == std::wstring::npos) ? p.substr(start) : p.substr(start, slash - start);
        if (!comp.empty()) parts.push_back(comp);
        if (slash == std::wstring::npos) break;
        start = slash + 1;
    }
    return parts;
}

static void udf_scan_directory(FileReader& fr, uint32_t partBase, uint32_t dirLba, uint32_t dirLen,
    const std::wstring& path, ScanResult& res, int depth, int maxDepth)
{
    if (depth > maxDepth || dirLen == 0) return;
    size_t toRead = (size_t)std::min<uint32_t>(dirLen, 4 * 1024 * 1024);
    std::vector<uint8_t> buf(toRead);
    if (!fr.read_sector(partBase + dirLba, buf.data(), (DWORD)toRead)) return;

    size_t off = 0;
    while (off + 38 <= buf.size()) {
        const uint8_t* d = buf.data() + off;
        if (!udf_tag_ok(d)) break;
        uint16_t tagId = rd_le16(d);
        if (tagId != 257) break;

        uint8_t fileChar = d[18];
        uint8_t nameLen = d[19];
        uint32_t icbLba = 0, icbLen = 0;
        udf_read_long_ad(d + 20, icbLba, icbLen);
        uint16_t iuLen = rd_le16(d + 36);
        size_t nameOff = 38 + iuLen;
        size_t descLen = ((size_t)nameOff + nameLen + 3) & ~size_t(3);
        if (descLen < 38 || off + descLen > buf.size()) break;

        std::wstring name = udf_dname(d + nameOff, nameLen);
        if (!name.empty() && name.back() == L';') {
            size_t sc = name.find_last_of(L';');
            if (sc != std::wstring::npos) name = name.substr(0, sc);
        }

        bool isDir = (fileChar & 0x02) != 0;
        std::wstring full = path.empty() ? (L"/" + name) : (path + L"/" + name);

        uint32_t dataLba = 0, dataLen = 0;
        uint64_t infoLen = 0, fileSize = 0;
        if (isDir) {
            if (!udf_fe_data_extent(fr, partBase, icbLba, dataLba, dataLen))
            { dataLba = icbLba; dataLen = icbLen ? icbLen : g_sectorSize; }
        }
        else {
            if (!udf_fe_data_extent(fr, partBase, icbLba, dataLba, dataLen, &infoLen))
            { dataLba = icbLba; dataLen = icbLen; infoLen = dataLen; }
            fileSize = infoLen ? infoLen : dataLen;
        }

        if (g_optShowFileList && (int)res.fileList.size() < g_optMaxFileList) {
            FileListItem fl{ full, isDir ? 0 : fileSize, isDir };
            res.fileList.push_back(fl);
        }
        if (isDir) res.totalDirs++; else res.totalFiles++;

        if (!isDir) {
            static const wchar_t* kWinSuffixes[] = {
                L"/sources/install.wim", L"/sources/install.esd", L"/sources/boot.wim",
                L"/sources/ei.cfg", L"/setup.exe"
            };
            for (const wchar_t* suf : kWinSuffixes) {
                if (path_iequals_suffix(full, suf)) {
                    res.winFiles.push_back({ full, partBase + dataLba, fileSize });
                    break;
                }
            }
            if (fileSize > 0) {
                FileListItem item{ full, fileSize, false };
                res.largestFiles.push_back(item);
                std::sort(res.largestFiles.begin(), res.largestFiles.end(),
                    [](const FileListItem& a, const FileListItem& b) { return a.size > b.size; });
                if (res.largestFiles.size() > 15) res.largestFiles.resize(15);
            }
        }
        else if (depth < maxDepth && dataLba && name != L"." && name != L"..") {
            udf_scan_directory(fr, partBase, dataLba, dataLen, full, res, depth + 1, maxDepth);
        }

        off += descLen;
    }
}

static bool udf_locate_root(FileReader& fr, const IsoSummary& sum, uint32_t& partBase,
    uint32_t& rootLba, uint32_t& rootLen)
{
    auto try_fsd_in_sector = [&](uint32_t s, uint32_t pBase) -> bool {
        uint8_t sec[2048]{};
        if (!fr.read_sector(s, sec, g_sectorSize)) return false;
        for (size_t base = 0; base + 416 <= g_sectorSize; base += 4) {
            if (!udf_tag_ok(sec + base) || rd_le16(sec + base) != 256) continue;
            uint32_t icbLba = 0, icbLen = 0;
            if (!udf_read_long_ad(sec + base + 400, icbLba, icbLen) || !icbLba) continue;
            partBase = pBase ? pBase : s;
            if (udf_fe_data_extent(fr, partBase, icbLba, rootLba, rootLen))
                return rootLba != 0;
            rootLba = icbLba;
            rootLen = icbLen ? icbLen : g_sectorSize;
            return true;
        }
        return false;
    };

    if (sum.udfPartitionStart) {
        uint32_t searchLen = sum.udfPartitionLength ? std::min(sum.udfPartitionLength, 512u) : 512u;
        for (uint32_t s = sum.udfPartitionStart; s < sum.udfPartitionStart + searchLen; ++s)
            if (try_fsd_in_sector(s, sum.udfPartitionStart)) return true;
    }

    uint64_t totalSectors = fr.size_bytes() / g_sectorSize;
    uint32_t msEnd = (uint32_t)std::min<uint64_t>(4096, totalSectors);
    for (uint32_t s = 256; s < msEnd; ++s)
        if (try_fsd_in_sector(s, 0)) return true;

    for (uint32_t s = 16; s < 256; ++s)
        if (try_fsd_in_sector(s, sum.udfPartitionStart)) return true;
    return false;
}

static bool udf_find_child(FileReader& fr, uint32_t partBase, uint32_t dirLba, uint32_t dirLen,
    const std::wstring& childName, bool wantDir, uint32_t& outLba, uint32_t& outLen, uint64_t& outSize)
{
    std::wstring want = ToLower(childName);
    size_t toRead = (size_t)std::min<uint32_t>(dirLen, 4 * 1024 * 1024);
    if (toRead == 0) toRead = g_sectorSize;
    std::vector<uint8_t> buf(toRead);
    if (!fr.read_sector(partBase + dirLba, buf.data(), (DWORD)toRead)) return false;

    size_t off = 0;
    while (off + 38 <= buf.size()) {
        const uint8_t* d = buf.data() + off;
        if (!udf_tag_ok(d)) break;
        if (rd_le16(d) != 257) break;

        uint8_t fileChar = d[18];
        bool entryIsDir = (fileChar & 0x02) != 0;
        uint8_t nameLen = d[19];
        uint32_t icbLba = 0, icbLen = 0;
        if (!udf_read_long_ad(d + 20, icbLba, icbLen)) { off += 4; continue; }
        uint16_t iuLen = rd_le16(d + 36);
        size_t nameOff = 38 + iuLen;
        size_t descLen = ((size_t)nameOff + nameLen + 3) & ~size_t(3);
        if (descLen < 38 || off + descLen > buf.size()) break;

        std::wstring name = udf_dname(d + nameOff, nameLen);
        if (!name.empty() && name.back() == L';') {
            size_t sc = name.find_last_of(L';');
            if (sc != std::wstring::npos) name = name.substr(0, sc);
        }
        if (ToLower(name) != want) { off += descLen; continue; }
        if (wantDir != entryIsDir) { off += descLen; continue; }

        uint64_t infoLen = 0;
        uint32_t dataLba = 0, dataLen = 0;
        if (entryIsDir) {
            if (!udf_fe_data_extent(fr, partBase, icbLba, outLba, outLen)) {
                outLba = icbLba;
                outLen = icbLen ? icbLen : g_sectorSize;
            }
            outSize = 0;
            return true;
        }
        if (!udf_fe_data_extent(fr, partBase, icbLba, dataLba, dataLen, &infoLen)) {
            dataLba = icbLba;
            dataLen = icbLen;
            infoLen = dataLen;
        }
        outLba = partBase + dataLba;
        outLen = dataLen;
        outSize = infoLen ? infoLen : dataLen;
        return true;
    }
    return false;
}

static bool udf_resolve_path(FileReader& fr, const IsoSummary& sum, const wchar_t* path, IsoFileRef& out) {
    uint32_t partBase = 0, rootLba = 0, rootLen = 0;
    if (!udf_locate_root(fr, sum, partBase, rootLba, rootLen)) return false;

    auto parts = split_path_components(path);
    if (parts.empty()) return false;

    uint32_t curLba = rootLba, curLen = rootLen;
    for (size_t i = 0; i < parts.size(); ++i) {
        bool isLast = (i + 1 == parts.size());
        uint32_t nextLba = 0, nextLen = 0;
        uint64_t nextSize = 0;
        if (!udf_find_child(fr, partBase, curLba, curLen, parts[i], !isLast, nextLba, nextLen, nextSize))
            return false;
        if (isLast) {
            out.path = path;
            out.lba = nextLba;
            out.size = nextSize;
            return true;
        }
        curLba = nextLba;
        curLen = nextLen ? nextLen : g_sectorSize;
    }
    return false;
}

static bool iso9660_find_path(FileReader& fr, uint32_t rootLBA, uint32_t rootSize, bool joliet,
    const wchar_t* path, IsoFileRef& out)
{
    auto parts = split_path_components(path);
    if (parts.empty()) return false;

    uint32_t curLba = rootLBA, curSize = rootSize;
    for (size_t i = 0; i < parts.size(); ++i) {
        std::vector<DirEntry> entries;
        bool rr = false;
        read_directory(fr, curLba, curSize, joliet, entries, rr);
        bool isLast = (i + 1 == parts.size());
        bool found = false;
        for (const auto& e : entries) {
            if (e.name == L"." || e.name == L"..") continue;
            if (ToLower(e.name) != ToLower(parts[i])) continue;
            if (isLast) {
                if (e.isDir) return false;
                out.path = path;
                out.lba = e.lba;
                out.size = e.size;
                return true;
            }
            if (!e.isDir) return false;
            curLba = e.lba;
            curSize = e.size;
            found = true;
            break;
        }
        if (!found) return false;
    }
    return false;
}

struct UefiBootInfo {
    std::wstring path;
    std::wstring signer;
    std::wstring note;
};

static bool scan_pe_cert_string(FileReader& fr, uint32_t lba, uint32_t size, const char* needle, std::wstring& signerOut) {
    const DWORD SCAN = (DWORD)std::min<uint32_t>(size, 256 * 1024);
    std::vector<uint8_t> buf(SCAN);
    if (!read_iso_file_bytes(fr, lba, size, 0, buf.data(), SCAN)) return false;
    const char* p = (const char*)buf.data();
    size_t nlen = strlen(needle);
    for (size_t i = 0; i + nlen < SCAN; ++i) {
        if (memcmp(p + i, needle, nlen) != 0) continue;
        size_t start = i;
        while (start > 0 && p[start - 1] >= 0x20) start--;
        size_t end = i + nlen;
        while (end < SCAN && p[end] >= 0x20 && p[end] < 0x7F) end++;
        std::string s(p + start, end - start);
        int wlen = MultiByteToWideChar(CP_ACP, 0, s.c_str(), -1, nullptr, 0);
        if (wlen <= 0) return true;
        signerOut.assign(wlen, L'\0');
        MultiByteToWideChar(CP_ACP, 0, s.c_str(), -1, &signerOut[0], wlen);
        if (!signerOut.empty() && signerOut.back() == L'\0') signerOut.pop_back();
        return true;
    }
    return false;
}

static void fast_scan_targeted(FileReader& fr, const IsoSummary& sum, ScanResult& scan) {
    static const wchar_t* kPaths[] = {
        L"/sources/install.esd", L"/sources/install.wim", L"/sources/boot.wim",
        L"/sources/ei.cfg", L"/setup.exe", L"/bootmgr", L"/bootmgr.efi",
        L"/efi/boot/bootx64.efi", L"/efi/boot/bootia32.efi"
    };

    uint32_t rootLBA = sum.joliet ? sum.jolietRootLBA : sum.rootDirLBA;
    uint32_t rootSize = sum.joliet ? sum.jolietRootSize : sum.rootDirSize;

    auto add_if_found = [&](const IsoFileRef& ref) {
        for (const auto& w : scan.winFiles) {
            if (ToLower(w.path) == ToLower(ref.path)) return;
        }
        scan.winFiles.push_back(ref);
        scan.totalFiles++;

        std::wstring lp = ToLower(ref.path);
        if (lp.find(L"bootmgr") != std::wstring::npos || lp.find(L"bootmgfw") != std::wstring::npos)
            scan.foundWinBootMgr = true;
        if (lp.find(L"bootx64.efi") != std::wstring::npos || lp.find(L"bootia32.efi") != std::wstring::npos)
            scan.foundGenericEFI = true;
        if (lp.find(L"/efi/") != std::wstring::npos) scan.foundEFI = true;
        if (lp.find(L"ei.cfg") != std::wstring::npos) scan.configHits.push_back(ref.path);
    };

    if (rootLBA && rootSize) {
        for (const wchar_t* p : kPaths) {
            IsoFileRef ref;
            if (iso9660_find_path(fr, rootLBA, rootSize, sum.joliet, p, ref))
                add_if_found(ref);
        }
    }

    if (sum.hasUDF) {
        for (const wchar_t* p : kPaths) {
            IsoFileRef ref;
            if (udf_resolve_path(fr, sum, p, ref))
                add_if_found(ref);
        }
    }
}

static void udf_scan_tree(FileReader& fr, const IsoSummary& sum, ScanResult& res, int maxDepth) {
    if (!sum.hasUDF) return;
    uint32_t partBase = 0, rootLba = 0, rootLen = 0;
    if (!udf_locate_root(fr, sum, partBase, rootLba, rootLen)) return;
    udf_scan_directory(fr, partBase, rootLba, rootLen, L"", res, 0, maxDepth);
}

static void analyze_windows_media(FileReader& fr, const ScanResult& scan, WindowsInfo& win, const IsoSummary& sum) {
    const IsoFileRef* installWim = nullptr;
    const IsoFileRef* installEsd = nullptr;
    const IsoFileRef* bootWim = nullptr;
    const IsoFileRef* eiCfg = nullptr;

    for (const auto& f : scan.winFiles) {
        std::wstring lp = ToLower(f.path);
        if (lp.find(L"/sources/install.wim") != std::wstring::npos) installWim = &f;
        else if (lp.find(L"/sources/install.esd") != std::wstring::npos) installEsd = &f;
        else if (lp.find(L"/sources/boot.wim") != std::wstring::npos) bootWim = &f;
        else if (lp.find(L"/sources/ei.cfg") != std::wstring::npos) eiCfg = &f;
    }

    const IsoFileRef* primary = installWim ? installWim : installEsd;

    bool likelyMicrosoft = ToLower(sum.publisherId).find(L"microsoft") != std::wstring::npos
        || ToLower(sum.volId).find(L"win") != std::wstring::npos
        || ToLower(sum.appId).find(L"oscdimg") != std::wstring::npos
        || sum.foundWinBootMgr || sum.biosBoot || sum.hasBootRecord;

    if (!primary && !bootWim && scan.winFiles.empty() && !likelyMicrosoft) return;

    win.detected = true;
    if (primary) {
        win.isInstallMedia = true;
        win.imageType = installEsd && primary == installEsd ? L"Windows Setup (ESD)" : L"Windows Setup (WIM)";
        win.installImagePath = primary->path;
        win.installImageSize = primary->size;
        parse_wim_xml_from_iso(fr, primary->lba, primary->size, win.editions);
    }
    else if (bootWim) {
        win.imageType = L"Windows PE / Recovery";
        win.bootImagePath = bootWim->path;
        win.bootImageSize = bootWim->size;
        parse_wim_xml_from_iso(fr, bootWim->lba, bootWim->size, win.editions);
    }

    if (bootWim) {
        win.bootImagePath = bootWim->path;
        win.bootImageSize = bootWim->size;
    }

    if (eiCfg && eiCfg->size > 0 && eiCfg->size < 1024 * 1024) {
        std::vector<uint8_t> buf((size_t)eiCfg->size);
        if (read_iso_file_bytes(fr, eiCfg->lba, eiCfg->size, 0, buf.data(), (DWORD)eiCfg->size)) {
            std::string text((const char*)buf.data(), (size_t)eiCfg->size);
            parse_ei_cfg_text(text, win);
        }
    }

    if (!win.editions.empty()) {
        const WimImageInfo* best = &win.editions[0];
        for (const auto& e : win.editions) {
            std::wstring n = ToLower(e.displayName + e.name);
            if (n.find(L"windows") != std::wstring::npos &&
                n.find(L"setup") == std::wstring::npos &&
                n.find(L"pe") == std::wstring::npos) {
                best = &e;
                break;
            }
        }
        win.productVersion = guess_windows_product_name(win.editions);
        if (!best->version.empty()) {
            win.buildNumber = best->version;
            if (win.productVersion.empty()) win.productVersion = L"Windows";
            win.productVersion += L" (build " + best->version + L")";
        }
        if (!best->arch.empty()) win.architecture = best->arch;
        if (!best->language.empty()) win.defaultLanguage = best->language;
    }

    if (win.architecture.empty()) {
        for (const auto& f : scan.winFiles) {
            std::wstring lp = ToLower(f.path);
            if (lp.find(L"x64") != std::wstring::npos || lp.find(L"amd64") != std::wstring::npos)
                win.architecture = L"x64";
            else if (lp.find(L"x86") != std::wstring::npos || lp.find(L"i386") != std::wstring::npos)
                win.architecture = L"x86";
            else if (lp.find(L"arm64") != std::wstring::npos)
                win.architecture = L"ARM64";
        }
        std::wstring volLow = ToLower(sum.volId);
        if (volLow.find(L"x64") != std::wstring::npos) win.architecture = L"x64";
        else if (volLow.find(L"x86") != std::wstring::npos) win.architecture = L"x86";
    }

    if (win.editions.empty() && likelyMicrosoft && g_optFullScan) {
        std::vector<WimDiscovery> discovered;
        discover_wim_by_signature_scan(fr, fr.size_bytes(), discovered);
        std::vector<WimImageInfo> installEditions, bootEditions;
        for (const auto& d : discovered) {
            std::vector<WimImageInfo> imgs;
            if (!parse_wim_at_offset(fr, d.offset, d.estimatedSize, imgs) || imgs.empty()) continue;
            if (d.imageCount >= 4 || imgs.size() >= 4) {
                if (imgs.size() > installEditions.size()) installEditions = std::move(imgs);
            }
            else if (bootEditions.empty() || imgs.size() > bootEditions.size()) {
                bootEditions = std::move(imgs);
            }
            else if (installEditions.empty()) {
                installEditions = std::move(imgs);
            }
        }
        if (!installEditions.empty()) {
            win.detected = true;
            win.isInstallMedia = true;
            win.imageType = L"Windows Setup (WIM, найден по сигнатуре)";
            win.editions = std::move(installEditions);
            win.installImagePath = L"(сканирование MSWIM)";
            if (!win.editions.empty()) {
                win.productVersion = guess_windows_product_name(win.editions);
                for (const auto& e : win.editions) {
                    if (!e.version.empty()) { win.buildNumber = e.version; break; }
                }
                if (!win.buildNumber.empty() && !win.productVersion.empty())
                    win.productVersion += L" (build " + win.buildNumber + L")";
            }
        }
        else if (!bootEditions.empty()) {
            win.detected = true;
            win.imageType = L"Windows PE / Recovery (WIM)";
            win.editions = std::move(bootEditions);
        }
    }

    enrich_windows_from_metadata(sum, win);
    if (!win.productVersion.empty() && win.editions.empty() && sum.hasUDF && win.imageType.find(L"UDF") == std::wstring::npos)
        win.imageType = L"Windows (метаданные ISO + UDF)";
}

// -----------------------------------------------------------------------------
// El Torito Boot Catalog
// -----------------------------------------------------------------------------
struct BootEntry {
    uint8_t platform = 0x00; // 0x00=x86(BIOS), 0xEF=UEFI
    bool bootable = false;
    uint8_t mediaType = 0;
    uint16_t segment = 0;
    uint8_t sysType = 0;
    uint16_t sectorCount = 0;
    uint32_t lba = 0;
};

static const wchar_t* media_type_name(uint8_t m) {
    switch (m) {
    case 0x00: return L"No emulation";
    case 0x01: return L"Floppy 1.2M";
    case 0x02: return L"Floppy 1.44M";
    case 0x03: return L"Floppy 2.88M";
    case 0x04: return L"Hard disk";
    case 0x05: return L"CD/DVD (no emu)";
    default:   return L"Unknown";
    }
}
static const wchar_t* platform_name(uint8_t p) {
    switch (p) {
    case 0x00: return L"BIOS (x86)";
    case 0xEF: return L"UEFI (EFI)";
    default:   return L"Other";
    }
}

static bool parse_boot_catalog(FileReader& fr, uint32_t catalogLBA,
    std::vector<BootEntry>& out, bool& valid, bool& hasBIOS, bool& hasUEFI)
{
    valid = false; hasBIOS = false; hasUEFI = false;
    if (catalogLBA == 0) return false;

    const int MAX_CATSZ = (int)g_sectorSize * 4;
    std::vector<uint8_t> buf(MAX_CATSZ, 0);
    if (!fr.read_sector(catalogLBA, buf.data(), g_sectorSize)) return false;
    fr.read_sector(catalogLBA + 1, buf.data() + g_sectorSize, g_sectorSize);
    fr.read_sector(catalogLBA + 2, buf.data() + 2 * g_sectorSize, g_sectorSize);
    fr.read_sector(catalogLBA + 3, buf.data() + 3 * g_sectorSize, g_sectorSize);

    const uint8_t* val = buf.data();
    if (val[0] != 0x01 || val[30] != 0x55 || val[31] != 0xAA) return false;
    valid = true;

    size_t off = 32;
    uint8_t currentPlatform = 0x00;
    while (off + 32 <= buf.size()) {
        const uint8_t* e = buf.data() + off;
        uint8_t id = e[0];

        if (id == 0x90) { // Section Header
            currentPlatform = e[1]; // 0x00 x86, 0xEF UEFI
            off += 32;
        }
        else if (id == 0x88 || id == 0x00) {
            BootEntry be{};
            be.platform = currentPlatform;
            be.bootable = (id == 0x88);
            be.mediaType = e[1];
            be.segment = rd_le16(e + 2);
            be.sysType = e[4];
            be.sectorCount = rd_le16(e + 6);
            be.lba = rd_le32(e + 8);
            out.push_back(be);
            if (be.bootable) {
                if (be.platform == 0xEF) hasUEFI = true;
                else hasBIOS = true;
            }
            off += 32;
        }
        else if (id == 0x91 || id == 0) {
            off += 32;
        }
        else {
            break;
        }
    }
    return true;
}

// -----------------------------------------------------------------------------
// Утилиты RichEdit: таб-стопы и раскраска эмодзи
// -----------------------------------------------------------------------------
#ifndef ST_UNICODE
#define ST_UNICODE 8
#endif

static void sanitize_wstring_for_richedit(std::wstring& s) {
    std::wstring out;
    out.reserve(s.size());
    for (size_t i = 0; i < s.size(); ++i) {
        wchar_t w = s[i];
        if (w == L'\0') continue;
        if (w >= 0xD800 && w <= 0xDBFF) {
            if (i + 1 < s.size() && s[i + 1] >= 0xDC00 && s[i + 1] <= 0xDFFF) {
                out.push_back(w);
                out.push_back(s[i + 1]);
                ++i;
            }
            continue;
        }
        if (w >= 0xDC00 && w <= 0xDFFF) continue;
        out.push_back(w);
    }
    s.swap(out);
}

static void RichSetDefaultCharFormat(HWND hRE) {
    CHARFORMAT2W cf{};
    cf.cbSize = sizeof(cf);
    cf.dwMask = CFM_FACE | CFM_COLOR | CFM_SIZE;
    cf.crTextColor = RGB(0, 0, 0);
    cf.yHeight = 240;
    StringCchCopyW(cf.szFaceName, LF_FACESIZE, L"Consolas");
    SendMessageW(hRE, EM_SETCHARFORMAT, SCF_ALL, (LPARAM)&cf);
    SendMessageW(hRE, EM_SETBKGNDCOLOR, 0, RGB(255, 255, 255));
}

static bool RichSetTextUnicode(HWND hRE, const std::wstring& text) {
    if (text.empty()) {
        SetWindowTextW(hRE, L"");
        return true;
    }
    SETTEXTEX stx{};
    stx.flags = ST_UNICODE;
    stx.codepage = 1200;
    LRESULT lr = SendMessageW(hRE, EM_SETTEXTEX, (WPARAM)&stx, (LPARAM)text.c_str());
    if (lr) return true;
    SetWindowTextW(hRE, text.c_str());
    return GetWindowTextLengthW(hRE) > 0;
}

static void RichSetTabs(HWND hRE, const std::vector<int>& tabsChars) {
    // Перевод «знаки» → twips по текущему шрифту RichEdit
    HFONT hFont = (HFONT)SendMessage(hRE, WM_GETFONT, 0, 0);
    HDC hdc = GetDC(hRE);
    HFONT old = (HFONT)SelectObject(hdc, hFont);
    TEXTMETRICW tm{};
    GetTextMetricsW(hdc, &tm);
    int dpi = GetDeviceCaps(hdc, LOGPIXELSX);
    SelectObject(hdc, old);
    ReleaseDC(hRE, hdc);

    LONG rg[32] = { 0 };
    int cnt = (int)std::min<size_t>(tabsChars.size(), 32);
    for (int i = 0; i < cnt; i++) {
        int px = tm.tmAveCharWidth * tabsChars[i];
        LONG tw = MulDiv(px, 1440, dpi); // twips
        rg[i] = tw;
    }

    PARAFORMAT2 pf{}; pf.cbSize = sizeof(pf);
    pf.dwMask = PFM_TABSTOPS;
    pf.cTabCount = cnt;
    for (int i = 0; i < cnt; i++) pf.rgxTabs[i] = rg[i];
    SendMessageW(hRE, EM_SETPARAFORMAT, 0, (LPARAM)&pf);
}

static bool is_high(wchar_t ch) { return ch >= 0xD800 && ch <= 0xDBFF; }
static bool is_low(wchar_t ch) { return ch >= 0xDC00 && ch <= 0xDFFF; }
static uint32_t cp_from_pair(wchar_t hi, wchar_t lo) {
    return 0x10000u + (((uint32_t)hi - 0xD800u) << 10) + ((uint32_t)lo - 0xDC00u);
}
static bool is_emoji_cp(uint32_t cp) {
    if (cp == 0x200D || cp == 0xFE0F) return true;              // ZWJ / VS16
    if (cp >= 0x1F300 && cp <= 0x1FAFF) return true;            // Symbols & Pictographs
    if (cp >= 0x1F1E6 && cp <= 0x1F1FF) return true;            // Flags
    if (cp >= 0x2600 && cp <= 0x27BF) return true;            // Misc Symbols + Dingbats
    return false;
}
struct Range { LONG a; LONG b; }; // [a,b)
static std::vector<Range> find_emoji_ranges(const std::wstring& s) {
    std::vector<Range> r;
    size_t i = 0, n = s.size();
    while (i < n) {
        uint32_t cp = 0; size_t step = 1;
        wchar_t ch = s[i];
        if (is_high(ch) && i + 1 < n && is_low(s[i + 1])) { cp = cp_from_pair(ch, s[i + 1]); step = 2; }
        else cp = (uint32_t)ch;

        if (is_emoji_cp(cp)) {
            size_t start = i; i += step;
            // захватим последовательность с ZWJ/VS16 и следующими эмодзи
            while (i < n) {
                uint32_t cp2 = 0; size_t st2 = 1;
                wchar_t c2 = s[i];
                if (is_high(c2) && i + 1 < n && is_low(s[i + 1])) { cp2 = cp_from_pair(c2, s[i + 1]); st2 = 2; }
                else cp2 = (uint32_t)c2;
                if (!is_emoji_cp(cp2)) break;
                i += st2;
            }
            LONG a = (LONG)start, b = (LONG)i;
            if (b > a && (b - a) <= 64)
                r.push_back({ a, b });
        }
        else {
            i += step;
        }
    }
    return r;
}
static void RichColorizeEmojis(HWND hRE, const std::wstring& fullText) {
    auto ranges = find_emoji_ranges(fullText);
    if (ranges.empty()) return;

    for (const auto& rg : ranges) {
        if (rg.b <= rg.a || rg.a < 0 || rg.b > (LONG)fullText.size()) continue;
        CHARRANGE cr{ rg.a, rg.b };
        SendMessageW(hRE, EM_EXSETSEL, 0, (LPARAM)&cr);
        CHARFORMAT2W cf{}; cf.cbSize = sizeof(cf);
        cf.dwMask = CFM_FACE;
        StringCchCopyW(cf.szFaceName, LF_FACESIZE, L"Segoe UI Emoji");
        SendMessageW(hRE, EM_SETCHARFORMAT, SCF_SELECTION, (LPARAM)&cf);
    }
    CHARRANGE crNone{ -1,-1 };
    SendMessageW(hRE, EM_EXSETSEL, 0, (LPARAM)&crNone);
}

// -----------------------------------------------------------------------------
// Чтение опций из INI
// -----------------------------------------------------------------------------
static void load_options_from_ini_file(const wchar_t* iniPath) {
    if (!iniPath || !iniPath[0]) return;
    int depth = GetPrivateProfileIntW(L"IsoLister", L"ScanDepth", g_optDepth, iniPath);
    int maxN = GetPrivateProfileIntW(L"IsoLister", L"MaxNodes", g_optMaxNodes, iniPath);
    int showB = GetPrivateProfileIntW(L"IsoLister", L"ShowBootEntries", g_optShowBootEntries, iniPath);
    int showF = GetPrivateProfileIntW(L"IsoLister", L"ShowFileList", g_optShowFileList, iniPath);
    int maxF = GetPrivateProfileIntW(L"IsoLister", L"MaxFileList", g_optMaxFileList, iniPath);
    int fullScan = GetPrivateProfileIntW(L"IsoLister", L"FullScan", g_optFullScan, iniPath);
    g_optDepth = (depth > 0 && depth <= 32) ? depth : g_optDepth;
    g_optMaxNodes = (maxN >= 1000 && maxN <= 1000000) ? maxN : g_optMaxNodes;
    g_optShowBootEntries = (showB != 0) ? 1 : 0;
    g_optShowFileList = (showF != 0) ? 1 : 0;
    g_optMaxFileList = (maxF >= 50 && maxF <= 100000) ? maxF : g_optMaxFileList;
    g_optFullScan = (fullScan != 0) ? 1 : 0;
}

static void load_options_from_ini() {
    if (g_iniPath.empty()) return;
    load_options_from_ini_file(g_iniPath.c_str());
    wchar_t wincmd[MAX_PATH]{};
    StringCchCopyW(wincmd, MAX_PATH, g_iniPath.c_str());
    wchar_t* slash = wcsrchr(wincmd, L'\\');
    if (slash) {
        StringCchCopyW(slash + 1, MAX_PATH - (size_t)(slash + 1 - wincmd), L"wincmd.ini");
        if (_wcsicmp(wincmd, g_iniPath.c_str()) != 0)
            load_options_from_ini_file(wincmd);
    }
    log_line(L"Options: ScanDepth=%d, MaxNodes=%d, ShowBootEntries=%d, ShowFileList=%d, MaxFileList=%d, FullScan=%d",
        g_optDepth, g_optMaxNodes, g_optShowBootEntries, g_optShowFileList, g_optMaxFileList, g_optFullScan);
}

// -----------------------------------------------------------------------------
// Экспортируемые WLX-функции
// -----------------------------------------------------------------------------
extern "C" BOOL APIENTRY DllMain(HINSTANCE hinst, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        g_hInst = hinst;
        g_hMsftEdit = LoadLibraryW(L"Msftedit.dll"); // для RICHEDIT50W
        // моноширинный шрифт (Consolas 10pt; fallback — Courier New)
        g_hMonoFont = CreateFontW(
            -14, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
            DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, DEFAULT_QUALITY,
            FIXED_PITCH | FF_MODERN, L"Consolas");
        if (!g_hMonoFont) {
            g_hMonoFont = CreateFontW(
                -14, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
                DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, DEFAULT_QUALITY,
                FIXED_PITCH | FF_MODERN, L"Courier New");
        }
        log_line(L"DllMain: ATTACH");
    }
    else if (reason == DLL_PROCESS_DETACH) {
        if (g_hMonoFont) { DeleteObject(g_hMonoFont); g_hMonoFont = nullptr; }
        if (g_hMsftEdit) { FreeLibrary(g_hMsftEdit); g_hMsftEdit = nullptr; }
    }
    return TRUE;
}



static LRESULT CALLBACK RichEditSubclassProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)

{

    auto it = g_richWndProcMap.find(hwnd);

    WNDPROC orig = (it != g_richWndProcMap.end()) ? it->second : DefWindowProcW;



    switch (msg) {

    case WM_CONTEXTMENU: {

        if ((HWND)wParam != hwnd) break;

        HMENU menu = CreatePopupMenu();

        if (!menu) break;



        CHARRANGE cr{};

        SendMessageW(hwnd, EM_EXGETSEL, 0, (LPARAM)&cr);

        bool hasSelection = (cr.cpMax > cr.cpMin);



        AppendMenuW(menu, MF_STRING | (hasSelection ? 0 : MF_GRAYED), IDM_CTX_COPY, L"Копировать	Ctrl+C");

        AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);

        AppendMenuW(menu, MF_STRING, IDM_CTX_SELECTALL, L"Выделить всё	Ctrl+A");



        POINT pt;

        if ((short)GET_X_LPARAM(lParam) == -1 && (short)GET_Y_LPARAM(lParam) == -1) {

            pt = RichEditContextPoint(hwnd);

        }

        else {

            pt.x = GET_X_LPARAM(lParam);

            pt.y = GET_Y_LPARAM(lParam);

        }



        int cmd = TrackPopupMenu(menu, TPM_RIGHTBUTTON | TPM_RETURNCMD, pt.x, pt.y, 0, hwnd, nullptr);

        DestroyMenu(menu);

        if (cmd == IDM_CTX_COPY) {

            SendMessageW(hwnd, WM_COPY, 0, 0);

            return 0;

        }

        if (cmd == IDM_CTX_SELECTALL) {

            SendMessageW(hwnd, EM_SETSEL, 0, -1);

            return 0;

        }

        return 0;

    }

    case WM_NCDESTROY: {

        LRESULT result = CallWindowProcW(orig, hwnd, msg, wParam, lParam);

        if (it != g_richWndProcMap.end()) {

            g_richWndProcMap.erase(it);

        }

        return result;

    }

    default:

        break;

    }



    return CallWindowProcW(orig, hwnd, msg, wParam, lParam);

}



static POINT RichEditContextPoint(HWND hwnd)

{

    POINT pt{ 0, 0 };

    if (GetCaretPos(&pt)) {

        ClientToScreen(hwnd, &pt);

        return pt;

    }

    RECT rc{};

    if (GetClientRect(hwnd, &rc)) {

        pt.x = rc.left + (rc.right - rc.left) / 2;

        pt.y = rc.top + (rc.bottom - rc.top) / 2;

    }

    ClientToScreen(hwnd, &pt);

    return pt;

}



static void SubclassRichEdit(HWND hwnd)

{

    if (!IsWindow(hwnd)) return;

    if (g_richWndProcMap.find(hwnd) != g_richWndProcMap.end()) return;



    SetLastError(0);

    WNDPROC old = (WNDPROC)SetWindowLongPtrW(hwnd, GWLP_WNDPROC, (LONG_PTR)RichEditSubclassProc);

    if (!old) {

        DWORD err = GetLastError();

        if (err != 0) {

            log_line(L"SetWindowLongPtrW(subclass) failed: %lu", err);

        }

        return;

    }

    if (old != RichEditSubclassProc) {

        g_richWndProcMap[hwnd] = old;

    }

}



static std::wstring generate_iso_report(const wchar_t* FileToLoad)
{
    std::wostringstream txt;
    ScanResult scan{};

    txt << L"🔌 IsoLister\tv" << ISO_LISTER_VERSION_WSTR << L" (" << ISO_LISTER_GIT_SHA_WSTR << L")\r\n";
    txt << L"Сборка\t" << ISO_LISTER_BUILD_TIMESTAMP_WSTR << L"\r\n";
    txt << repeat(L'─', 90) << L"\r\n";

    FileReader fr;
    IsoSummary sum;
    std::vector<uint8_t> sec(g_sectorSize);
    g_sectorSize = DEFAULT_SECTOR_SIZE;

    if (!FileToLoad || !fr.open(FileToLoad)) {
        txt << L"Ошибка\tНе удалось открыть файл ❌\r\n";
        return txt.str();
    }

    UINT detectedSector = DEFAULT_SECTOR_SIZE;
    if (!probe_iso_layout(fr, detectedSector)) {
        txt << L"Ошибка\tНе обнаружена сигнатура ISO9660 (CD001) ❌\r\n";
        txt << L"Размер файла\t" << FormatFileSize(fr.size_bytes()) << L"\r\n";
        txt << L"Расширение\t" << GetFileExtensionLower(FileToLoad) << L"\r\n";
        return txt.str();
    }
    g_sectorSize = detectedSector;
    sec.resize(g_sectorSize);

    for (uint32_t s = VD_START_SECTOR; ; ++s) {
        if (!fr.read_sector(s, sec.data(), g_sectorSize)) break;
        uint8_t type = sec[0];
        if (!is_cd001(sec.data())) break;

        if (type == 1) parse_pvd(sec.data(), sum);
        else if (type == 2) parse_svd(sec.data(), sum);
        else if (type == 0) parse_boot_record(sec.data(), sum);
        else if (type == 255) break;
    }

    parse_udf(fr, sum);

    std::vector<BootEntry> bootEntries;
    if (sum.bootCatalogLBA) {
        bool valid = false, hasBIOS = false, hasUEFI = false;
        if (parse_boot_catalog(fr, sum.bootCatalogLBA, bootEntries, valid, hasBIOS, hasUEFI)) {
            sum.bootable = valid && (hasBIOS || hasUEFI);
            sum.biosBoot = hasBIOS;
            sum.uefiBoot = hasUEFI;
        }
    }

    uint32_t rootLBA = sum.joliet ? sum.jolietRootLBA : sum.rootDirLBA;
    uint32_t rootSize = sum.joliet ? sum.jolietRootSize : sum.rootDirSize;

    LARGE_INTEGER t0{}, t1{}, freq{};
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&t0);

    if (g_optFullScan) {
        if (rootLBA && rootSize)
            scan = bfs_scan(fr, rootLBA, rootSize, sum.joliet, g_optDepth, g_optMaxNodes);
        if (sum.hasUDF)
            udf_scan_tree(fr, sum, scan, g_optDepth);
    }
    else {
        fast_scan_targeted(fr, sum, scan);
    }

    if (scan.rrDetected) sum.rockRidge = true;
    sum.foundGRUB2 = scan.foundGRUB2;
    sum.foundGRUBLegacy = scan.foundGRUBLegacy;
    sum.foundISOLINUX = scan.foundISOLINUX;
    sum.foundSyslinuxMenu = scan.foundSyslinuxMenu;
    sum.foundSystemdBoot = scan.foundSystemdBoot;
    sum.foundWinBootMgr = scan.foundWinBootMgr || sum.uefiBoot;
    sum.foundGenericEFI = scan.foundGenericEFI;
    if (!scan.configHits.empty()) sum.configHits = scan.configHits;

    if (sum.foundWinBootMgr) sum.bootLoader = L"Windows Boot Manager 🪟";
    else if (sum.foundGRUB2) sum.bootLoader = L"GRUB2 🐧";
    else if (sum.foundGRUBLegacy) sum.bootLoader = L"GRUB (legacy) 🐧";
    else if (sum.foundSystemdBoot) sum.bootLoader = L"systemd-boot 🐧";
    else if (sum.foundISOLINUX || sum.foundSyslinuxMenu) sum.bootLoader = L"ISOLINUX/SYSLINUX 🧰";
    else if (sum.foundGenericEFI || sum.uefiBoot) sum.bootLoader = L"EFI (generic) ✨";

    WindowsInfo winInfo{};
    analyze_windows_media(fr, scan, winInfo, sum);

    QueryPerformanceCounter(&t1);
    double scanMs = (double)(t1.QuadPart - t0.QuadPart) * 1000.0 / (double)freq.QuadPart;

    std::wstring wimVersion;
    const IsoFileRef* installRef = nullptr;
    for (const auto& f : scan.winFiles) {
        std::wstring lp = ToLower(f.path);
        if (lp.find(L"install.esd") != std::wstring::npos || lp.find(L"install.wim") != std::wstring::npos) {
            installRef = &f;
            break;
        }
    }
    if (installRef && installRef->size > 208) {
        uint8_t hdr[208]{};
        if (read_iso_file_bytes(fr, installRef->lba, installRef->size, 0, hdr, 208) && !memcmp(hdr, "MSWIM", 5))
            wimVersion = wim_format_version(hdr);
    }

    std::vector<UefiBootInfo> uefiBoots;
    static const wchar_t* kUefiPaths[] = { L"/bootmgr.efi", L"/efi/boot/bootx64.efi", L"/efi/boot/bootia32.efi" };
    for (const wchar_t* up : kUefiPaths) {
        IsoFileRef efiRef;
        bool found = false;
        if (rootLBA && iso9660_find_path(fr, rootLBA, rootSize, sum.joliet, up, efiRef)) found = true;
        else if (sum.hasUDF && udf_resolve_path(fr, sum, up, efiRef)) found = true;
        if (!found) continue;
        UefiBootInfo bi{};
        bi.path = up;
        if (scan_pe_cert_string(fr, efiRef.lba, (uint32_t)std::min<uint64_t>(efiRef.size, UINT32_MAX),
                "Microsoft Windows Production PCA", bi.signer))
            bi.signer = L"Microsoft Windows Production PCA 2011";
        else if (scan_pe_cert_string(fr, efiRef.lba, (uint32_t)std::min<uint64_t>(efiRef.size, UINT32_MAX), "Microsoft Corporation", bi.signer))
            bi.signer = L"Microsoft Corporation";
        if (bi.signer.find(L"2011") != std::wstring::npos)
            bi.note = L"Может не пройти Secure Boot на системах с сертификатом Windows UEFI CA 2023";
        uefiBoots.push_back(std::move(bi));
    }

    bool bootMarker = false;
    if (fr.read_sector(17, sec.data(), g_sectorSize) && sec.size() >= 512)
        bootMarker = (sec[510] == 0x55 && sec[511] == 0xAA);

    std::wstring fsType = L"💿 ISO 9660";
    std::vector<std::wstring> ext;
    if (sum.joliet) ext.push_back(L"Joliet");
    if (sum.rockRidge) ext.push_back(L"Rock Ridge");
    if (sum.hasUDF) ext.push_back(L"UDF");
    if (!ext.empty()) {
        fsType += L" + ";
        for (size_t i = 0; i < ext.size(); ++i) {
            fsType += ext[i];
            if (i + 1 < ext.size()) fsType += L", ";
        }
    }

    txt << L"📄 Файл\t" << FileToLoad << L"\r\n";
    txt << L"Размер файла\t" << FormatFileSize(fr.size_bytes()) << L"\r\n";
    txt << L"Расширение\t" << GetFileExtensionLower(FileToLoad) << L"\r\n";
    txt << L"Размер сектора\t" << g_sectorSize << L" байт\r\n";
    txt << L"⏱ Время анализа\t" << (int)(scanMs + 0.5) << L" мс"
        << (g_optFullScan ? L" (полный скан)" : L" (быстрый режим)") << L"\r\n";
    txt << L"🗂 Тип ФС\t" << fsType << L"\r\n";

    txt << repeat(L'─', 90) << L"\r\n";
    txt << L"⚡ Быстрый анализ (как Rufus)\t\r\n";
    if (sum.hasUDF) txt << L"ISO analysis\tОбраз UDF ✅\r\n";
    txt << L"Boot Marker\t" << (bootMarker ? L"да ✅" : L"нет ❌") << L"\r\n";
    if (!uefiBoots.empty()) {
        txt << L"UEFI bootloaders\t\r\n";
        for (const auto& bi : uefiBoots) {
            txt << L"  •\t" << bi.path;
            if (!bi.signer.empty()) txt << L" — " << bi.signer;
            txt << L"\r\n";
            if (!bi.note.empty()) txt << L"  ⚠️\t" << bi.note << L"\r\n";
        }
    }
    if (!sum.volId.empty())
        txt << L"ISO label\t'" << sum.volId << L"'\r\n";
    if (winInfo.detected) {
        std::wstring detected = winInfo.productVersion;
        if (detected.empty()) detected = L"Windows";
        txt << L"Detected\t" << detected << L"\r\n";
        if (!winInfo.buildNumber.empty())
            txt << L"Build\t" << winInfo.buildNumber << L"\r\n";
        if (sum.uefiBoot || !uefiBoots.empty()) txt << L"Uses\tEFI ✅\r\n";
        if (sum.biosBoot || sum.foundWinBootMgr) txt << L"Uses\tBootmgr (BIOS/UEFI) ✅\r\n";
        if (!wimVersion.empty()) {
            std::wstring installName = installRef && installRef->path.find(L".esd") != std::wstring::npos
                ? L"Install.esd" : L"Install.wim";
            txt << L"Uses\t" << installName << L" (version " << wimVersion << L") ✅\r\n";
        }
    }
    if (sum.hasPVD) {
        double MB = (double)sum.volBlocks * sum.logicalBlockSize / (1024.0 * 1024.0);
        txt << L"System ID\t" << sum.sysId << L"\r\n";
        txt << L"Volume ID\t" << sum.volId << L"\r\n";
        txt << L"Application ID\t" << sum.appId << L"\r\n";
        if (!sum.publisherId.empty()) txt << L"Publisher\t" << sum.publisherId << L"\r\n";
        if (!sum.dataPreparerId.empty()) txt << L"Data Preparer\t" << sum.dataPreparerId << L"\r\n";
        if (!sum.volumeSetId.empty()) txt << L"Volume Set ID\t" << sum.volumeSetId << L"\r\n";
        if (sum.volumeSetSize) txt << L"Volume Set Size\t" << sum.volumeSetSize << L"\r\n";
        if (sum.volumeSequenceNumber) txt << L"Volume Sequence\t" << sum.volumeSequenceNumber << L"\r\n";
        txt << L"Logical Block Size\t" << sum.logicalBlockSize << L"\r\n";
        txt << L"Volume Space\t" << sum.volBlocks << L" блоков (≈ " << (int)(MB + 0.5) << L" MB)\r\n";
        txt << L"Path Table\tL " << sum.pathTableL << L", M " << sum.pathTableM
            << L", size " << sum.pathTableSize << L" байт\r\n";
        txt << L"Root Dir\tLBA " << (sum.joliet ? sum.jolietRootLBA : sum.rootDirLBA)
            << L", size " << (sum.joliet ? sum.jolietRootSize : sum.rootDirSize) << L" байт\r\n";
        txt << L"🗓 Создан\t" << sum.created << L"\r\n";
        txt << L"🗓 Изменён\t" << sum.modified << L"\r\n";
        txt << L"Joliet\t" << (sum.joliet ? (L"да ✅ (esc=" + ATrimRight(sum.jolietEsc) + L")") : L"нет ❌") << L"\r\n";
        txt << L"Rock Ridge\t" << (sum.rockRidge ? L"да ✅" : L"нет ❌") << L"\r\n";
    }
    else {
        txt << L"⚠️ Предупреждение\tPVD не найден — возможно, это не ISO9660\r\n";
    }

    if (sum.hasUDF) {
        txt << repeat(L'─', 90) << L"\r\n";
        txt << L"📀 UDF (ECMA-167)\t\r\n";
        txt << L"NSR версия\tNSR0" << sum.udfNsrVersion << L"\r\n";
        if (!sum.udfPrimaryVolumeId.empty())
            txt << L"Primary Volume ID\t" << sum.udfPrimaryVolumeId << L"\r\n";
        if (!sum.udfLogicalVolumeId.empty())
            txt << L"Logical Volume ID\t" << sum.udfLogicalVolumeId << L"\r\n";
        if (!sum.udfVolumeSetId.empty())
            txt << L"Volume Set ID\t" << sum.udfVolumeSetId << L"\r\n";
        if (sum.udfPartitionLength)
            txt << L"Раздел\tLBA " << sum.udfPartitionStart << L", " << sum.udfPartitionLength << L" секторов\r\n";
    }
    else {
        txt << L"UDF\tнет ❌\r\n";
    }

    txt << repeat(L'─', 90) << L"\r\n";
    txt << L"🚀 Загрузка (El Torito)\t\r\n";
    txt << L"Загрузочный ISO\t" << (sum.bootable ? L"да ✅" : L"нет ❌") << L"\r\n";
    if (sum.hasBootRecord) {
        txt << L"Boot Record\tда ✅\r\n";
        txt << L"Boot System ID\t" << (sum.bootSystemId.empty() ? L"—" : sum.bootSystemId.c_str()) << L"\r\n";
        txt << L"Boot Catalog LBA\t" << sum.bootCatalogLBA << L"\r\n";
    }
    else {
        txt << L"Boot Record\tнет ❌\r\n";
    }
    if (sum.biosBoot && sum.uefiBoot) txt << L"Тип загрузки\tBIOS и UEFI\r\n";
    else if (sum.biosBoot)            txt << L"Тип загрузки\tBIOS\r\n";
    else if (sum.uefiBoot)            txt << L"Тип загрузки\tUEFI\r\n";
    else                               txt << L"Тип загрузки\t—\r\n";

    txt << L"Загрузчик\t" << (sum.bootLoader.empty() ? L"не обнаружен ❔" : sum.bootLoader) << L"\r\n";

    if (winInfo.detected) {
        txt << repeat(L'─', 90) << L"\r\n";
        txt << L"🪟 Windows\t\r\n";
        txt << L"Тип образа\t" << (winInfo.imageType.empty() ? L"Windows" : winInfo.imageType) << L"\r\n";
        if (!winInfo.productVersion.empty())
            txt << L"Версия\t" << winInfo.productVersion << L"\r\n";
        if (!winInfo.buildNumber.empty())
            txt << L"Сборка (build)\t" << winInfo.buildNumber << L"\r\n";
        if (!winInfo.architecture.empty())
            txt << L"Архитектура\t" << winInfo.architecture << L"\r\n";
        if (!winInfo.channel.empty())
            txt << L"Канал\t" << winInfo.channel << L"\r\n";
        if (!winInfo.defaultLanguage.empty())
            txt << L"Язык (основной)\t" << winInfo.defaultLanguage << L"\r\n";
        if (winInfo.installImageSize)
            txt << L"install.wim/esd\t" << winInfo.installImagePath << L" (" << FormatFileSize(winInfo.installImageSize) << L")\r\n";
        if (winInfo.bootImageSize)
            txt << L"boot.wim\t" << winInfo.bootImagePath << L" (" << FormatFileSize(winInfo.bootImageSize) << L")\r\n";
        if (!winInfo.eiCfgEditions.empty()) {
            txt << L"ei.cfg EditionID\t";
            for (size_t i = 0; i < winInfo.eiCfgEditions.size(); ++i) {
                txt << winInfo.eiCfgEditions[i];
                if (i + 1 < winInfo.eiCfgEditions.size()) txt << L", ";
            }
            txt << L"\r\n";
        }
        if (!winInfo.editions.empty()) {
            txt << L"Редакции (WIM)\t" << (int)winInfo.editions.size() << L" образ(ов)\r\n";
            txt << L"#\tНазвание\tEditionID\tВерсия\r\n";
            for (const auto& ed : winInfo.editions) {
                txt << ed.index << L"\t"
                    << (ed.displayName.empty() ? ed.name : ed.displayName) << L"\t"
                    << (ed.editionId.empty() ? L"—" : ed.editionId) << L"\t"
                    << (ed.version.empty() ? L"—" : ed.version);
                if (!ed.arch.empty()) txt << L" (" << ed.arch << L")";
                if (!ed.language.empty()) txt << L" [" << ed.language << L"]";
                txt << L"\r\n";
            }
        }
        else if (winInfo.isInstallMedia || winInfo.bootImageSize) {
            txt << L"Редакции\tне удалось прочитать XML из WIM/ESD\r\n";
        }
        else if (sum.hasUDF && scan.totalFiles < 10) {
            txt << L"Примечание\tфайлы в UDF-разделе; install.wim не найден в ISO9660-дереве\r\n";
            txt << L"Подсказка\tдля AIO/кастомных ISO нужен полный UDF-обход (в работе)\r\n";
        }
    }

    if (!scan.largestFiles.empty()) {
        txt << repeat(L'─', 90) << L"\r\n";
        txt << L"📦 Крупнейшие файлы\tтоп-" << (int)scan.largestFiles.size() << L"\r\n";
        txt << L"Путь\tРазмер\tТип\r\n";
        for (const auto& lf : scan.largestFiles) {
            txt << lf.path << L"\t" << FormatFileSize(lf.size) << L"\tFILE\r\n";
        }
    }

    txt << repeat(L'─', 90) << L"\r\n";
    if (!sum.configHits.empty()) {
        txt << L"📝 Конфигурационные файлы\tнайдено: " << (int)sum.configHits.size() << L"\r\n";
        for (auto& p : sum.configHits) txt << L"\t" << p << L"\r\n";
    }
    else {
        txt << L"📝 Конфигурационные файлы\tне найдены\r\n";
    }

    if (g_optShowFileList && !scan.fileList.empty()) {
        txt << repeat(L'─', 90) << L"\r\n";
        txt << L"📁 Содержимое\tфайлов: " << scan.totalFiles << L", каталогов: " << scan.totalDirs;
        if ((int)scan.fileList.size() < scan.totalFiles + scan.totalDirs)
            txt << L" (показано " << (int)scan.fileList.size() << L" из " << (scan.totalFiles + scan.totalDirs) << L")";
        txt << L"\r\n";
        txt << L"Путь\tРазмер\tТип\r\n";
        for (const auto& fl : scan.fileList) {
            txt << fl.path << L"\t"
                << (fl.isDir ? L"—" : FormatFileSize(fl.size)) << L"\t"
                << (fl.isDir ? L"DIR" : L"FILE") << L"\r\n";
        }
    }

    if (g_optShowBootEntries) {
        std::vector<BootEntry> bootEntries2;
        bool v = false, hb = false, hu = false;
        if (sum.bootCatalogLBA && parse_boot_catalog(fr, sum.bootCatalogLBA, bootEntries2, v, hb, hu) && !bootEntries2.empty()) {
            txt << repeat(L'─', 90) << L"\r\n";
            txt << L"📚 Boot Catalog — все записи\r\n";
            txt << L"№\tПлатформа\tBootable\tMedia\tSegment\tSysType\tSectors\tLBA\r\n";
            int idx = 1;
            for (const auto& be : bootEntries2) {
                std::wstring boot = be.bootable ? L"yes ✅" : L"no ❌";
                std::wostringstream seg; seg << L"0x" << std::hex << std::uppercase << be.segment << std::dec;
                std::wostringstream sys; sys << L"0x" << std::hex << std::uppercase << (int)be.sysType << std::dec;
                txt << idx++ << L"\t"
                    << platform_name(be.platform) << L"\t"
                    << boot << L"\t"
                    << media_type_name(be.mediaType) << L"\t"
                    << seg.str() << L"\t"
                    << sys.str() << L"\t"
                    << be.sectorCount << L"\t"
                    << be.lba << L"\r\n";
            }
        }
    }

    return txt.str();
}

extern "C" HWND __stdcall ListLoadW(HWND ParentWin, WCHAR* FileToLoad, int ShowFlags)
{
    log_line(L"ListLoadW: file=\"%s\" flags=%d", FileToLoad ? FileToLoad : L"(null)", ShowFlags);

    std::wstring text = generate_iso_report(FileToLoad);
    sanitize_wstring_for_richedit(text);
    log_line(L"ListLoadW: report chars=%u", (unsigned)text.size());

    bool wrapText = (ShowFlags & lcp_wraptext) != 0;
    DWORD reStyle = WS_CHILD | WS_VISIBLE | WS_VSCROLL |
        ES_MULTILINE | ES_AUTOVSCROLL | ES_READONLY | ES_WANTRETURN;
    if (!wrapText) reStyle |= WS_HSCROLL | ES_AUTOHSCROLL;

    HWND hRE = CreateWindowExW(
        WS_EX_CLIENTEDGE,
        MSFTEDIT_CLASS,
        L"",
        reStyle,
        0, 0, 0, 0,
        ParentWin,
        (HMENU)1,
        g_hInst,
        nullptr
    );
    if (!hRE) {
        log_line(L"CreateWindowExW(RICHEDIT50W) FAILED, GetLastError=%lu", GetLastError());
        return nullptr;
    }

    SubclassRichEdit(hRE);

    if (g_hMonoFont) SendMessageW(hRE, WM_SETFONT, (WPARAM)g_hMonoFont, TRUE);
    RichSetDefaultCharFormat(hRE);

    if (wrapText)
        SendMessageW(hRE, EM_SETTARGETDEVICE, 0, 0);

    std::vector<int> tabs = {
        TAB_MAIN_1,
        TAB_BOOT_0, TAB_BOOT_1, TAB_BOOT_2, TAB_BOOT_3,
        TAB_BOOT_4, TAB_BOOT_5, TAB_BOOT_6, TAB_BOOT_7,
        TAB_FILE_PATH, TAB_FILE_SIZE, TAB_FILE_TYPE,
        TAB_WIN_IDX, TAB_WIN_NAME, TAB_WIN_EDITION, TAB_WIN_VER
    };
    RichSetTabs(hRE, tabs);

    if (!RichSetTextUnicode(hRE, text)) {
        log_line(L"ListLoadW: RichSetTextUnicode failed, len=%u", (unsigned)text.size());
        RichSetTextUnicode(hRE, L"Ошибка отображения отчёта в RichEdit.\r\n");
    }

    RichColorizeEmojis(hRE, text);
    SendMessageW(hRE, EM_SETSEL, 0, 0);
    SendMessageW(hRE, EM_SCROLLCARET, 0, 0);

    return hRE;
}

extern "C" HWND __stdcall ListLoad(HWND ParentWin, char* FileToLoad, int ShowFlags)
{
    int wlen = MultiByteToWideChar(CP_ACP, 0, FileToLoad ? FileToLoad : "", -1, nullptr, 0);
    std::wstring w(wlen, L'\0');
    MultiByteToWideChar(CP_ACP, 0, FileToLoad ? FileToLoad : "", -1, &w[0], wlen);
    return ListLoadW(ParentWin, &w[0], ShowFlags);
}

extern "C" void __stdcall ListGetDetectString(char* DetectString, int maxlen)
{
    StringCchCopyA(DetectString, (size_t)maxlen, "EXT=\"ISO\" EXT=\"IMG\"");
    log_line(L"ListGetDetectString called");
}

extern "C" void __stdcall ListCloseWindow(HWND ListWin)
{
    if (IsWindow(ListWin)) DestroyWindow(ListWin);
    log_line(L"ListCloseWindow");
}

extern "C" int __stdcall ListSendCommand(HWND ListWin, int Command, int Parameter)
{
    UNREFERENCED_PARAMETER(Parameter);
    if (!IsWindow(ListWin)) return LISTPLUGIN_ERROR;

    switch (Command) {
    case lc_copy:
        SendMessageW(ListWin, WM_COPY, 0, 0);
        return LISTPLUGIN_OK;
    case lc_selectall:
        SendMessageW(ListWin, EM_SETSEL, 0, -1);
        return LISTPLUGIN_OK;
    default:
        break;
    }

    return LISTPLUGIN_ERROR;
}

extern "C" void __stdcall ListSetDefaultParams(ListDefaultParamStruct* dps)
{
    if (dps && dps->DefaultIniName && dps->DefaultIniName[0]) {
        int wlen = MultiByteToWideChar(CP_ACP, 0, dps->DefaultIniName, -1, nullptr, 0);
        g_iniPath.assign(wlen, L'\0');
        MultiByteToWideChar(CP_ACP, 0, dps->DefaultIniName, -1, &g_iniPath[0], wlen);
        if (!g_iniPath.empty() && g_iniPath.back() == L'\0') g_iniPath.pop_back();
        log_line(L"ListSetDefaultParams: INI=%s", g_iniPath.c_str());
        load_options_from_ini();
    }
    else {
        log_line(L"ListSetDefaultParams: no INI passed");
    }
}

#ifdef ISO_LISTER_STANDALONE
#include <stdio.h>
#include <fcntl.h>
#include <io.h>
int wmain(int argc, wchar_t** argv) {
    _setmode(_fileno(stdout), _O_U16TEXT);
    _setmode(_fileno(stderr), _O_U16TEXT);
    if (argc < 2) {
        fwprintf(stderr, L"Usage: %s <path-to-iso-or-img>\n", argv[0]);
        return 2;
    }
    std::wstring report = generate_iso_report(argv[1]);
    fputws(report.c_str(), stdout);
    const wchar_t* checks[] = {
        L"IsoLister", L"Volume ID", L"ISO 9660", nullptr
    };
    for (int i = 0; checks[i]; ++i) {
        if (report.find(checks[i]) == std::wstring::npos) {
            fwprintf(stderr, L"VERIFY FAIL: missing '%s'\n", checks[i]);
            return 1;
        }
    }
    fwprintf(stderr, L"VERIFY OK\n");
    return 0;
}
#endif
