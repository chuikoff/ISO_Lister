// IsoLister.cpp — WLX Lister plugin для Total Commander
// Вывод таблиц "в стиле TC": колонки таб-стопами, без псевдографики.
// Цветные эмодзи: RichEdit 5.0 + выбор шрифта Segoe UI Emoji для самих эмодзи.
// Разбор ISO: PVD, SVD/Joliet, Rock Ridge, UDF, El Torito Boot Catalog,
// эвристики загрузчиков (GRUB2/legacy, ISOLINUX/SYSLINUX, systemd-boot, Win BootMgr).
//
// Компиляция: Win32/Win64 DLL, /MT, UNICODE, C++17.

#define WIN32_LEAN_AND_MEAN
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <strsafe.h>
#include <string>
#include <sstream>
#include <vector>
#include <queue>
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
#else
#pragma comment(linker, "/EXPORT:ListLoad")
#pragma comment(linker, "/EXPORT:ListLoadW")
#pragma comment(linker, "/EXPORT:ListGetDetectString")
#pragma comment(linker, "/EXPORT:ListCloseWindow")
#pragma comment(linker, "/EXPORT:ListSetDefaultParams")
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

static const UINT SECTOR_SIZE = 2048;
static const UINT VD_START_SECTOR = 16;
static const size_t MAX_DIR_READ = 16 * 1024 * 1024;

// Опции (по умолчанию)
static int g_optDepth = 6;
static int g_optMaxNodes = 40000;
static int g_optShowBootEntries = 0;

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
    ~FileReader() { if (h != INVALID_HANDLE_VALUE) CloseHandle(h); }
};

static uint32_t rd_le32(const uint8_t* p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}
static uint16_t rd_le16(const uint8_t* p) {
    return (uint16_t)p[0] | ((uint16_t)p[1] << 8);
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

static void parse_pvd(const uint8_t* vdbuf, IsoSummary& out) {
    size_t o = 0;
    o += 1 /*type*/ + 5 /*CD001*/ + 1 /*ver*/ + 1 /*unused*/;

    std::string sysId((const char*)vdbuf + o, 32); o += 32;
    std::string volId((const char*)vdbuf + o, 32); o += 32;
    o += 8; // unused

    uint32_t volSpaceLE = rd_le32(vdbuf + o); o += 4; o += 4;
    o += 32; // unused
    o += 2 + 2; // volume_set_size
    o += 2 + 2; // volume_sequence_number
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

    o += 128 /*volume_set_id*/ + 128 /*publisher_id*/ + 128 /*data_preparer_id*/;
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
// UDF обнаружение
// -----------------------------------------------------------------------------
static bool detect_udf(FileReader& fr) {
    std::vector<uint8_t> buf(SECTOR_SIZE);
    for (uint32_t s = VD_START_SECTOR; s < VD_START_SECTOR + 256; ++s) {
        if (!fr.read_at(uint64_t(s) * SECTOR_SIZE, buf.data(), SECTOR_SIZE)) break;
        for (size_t i = 0; i + 5 <= SECTOR_SIZE; i++) {
            if (!memcmp(buf.data() + i, "NSR02", 5) || !memcmp(buf.data() + i, "NSR03", 5))
                return true;
        }
    }
    return false;
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
    if (!fr.read_at(uint64_t(lba) * SECTOR_SIZE, buf.data(), (DWORD)toRead)) return;

    size_t off = 0;
    while (off + 1 < buf.size()) {
        uint8_t len_dr = buf[off];
        if (len_dr == 0) {
            size_t next = ((off / SECTOR_SIZE) + 1) * SECTOR_SIZE;
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

// BFS-скан по дереву
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
        L"preseed.cfg", L"autounattend.xml", L"unattend.xml", L"ks.cfg", L"loader.conf"
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

            if (!e.isDir) {
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

    const int MAX_CATSZ = SECTOR_SIZE * 4;
    std::vector<uint8_t> buf(MAX_CATSZ, 0);
    if (!fr.read_at(uint64_t(catalogLBA) * SECTOR_SIZE, buf.data(), SECTOR_SIZE)) return false;
    fr.read_at(uint64_t(catalogLBA + 1) * SECTOR_SIZE, buf.data() + SECTOR_SIZE, SECTOR_SIZE);
    fr.read_at(uint64_t(catalogLBA + 2) * SECTOR_SIZE, buf.data() + 2 * SECTOR_SIZE, SECTOR_SIZE);
    fr.read_at(uint64_t(catalogLBA + 3) * SECTOR_SIZE, buf.data() + 3 * SECTOR_SIZE, SECTOR_SIZE);

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
            r.push_back({ (LONG)start, (LONG)i });
        }
        else {
            i += step;
        }
    }
    return r;
}
static void RichColorizeEmojis(HWND hRE, const std::wstring& fullText) {
    // Базовый шрифт уже назначен моноширинный. Эмодзи сделаем Segoe UI Emoji.
    auto ranges = find_emoji_ranges(fullText);
    if (ranges.empty()) return;

    for (const auto& rg : ranges) {
        CHARRANGE cr{ rg.a, rg.b };
        SendMessageW(hRE, EM_EXSETSEL, 0, (LPARAM)&cr);
        CHARFORMAT2W cf{}; cf.cbSize = sizeof(cf);
        cf.dwMask = CFM_FACE;
        StringCchCopyW(cf.szFaceName, LF_FACESIZE, L"Segoe UI Emoji");
        SendMessageW(hRE, EM_SETCHARFORMAT, SCF_SELECTION, (LPARAM)&cf);
    }
    // Снимем выделение
    CHARRANGE crNone{ -1,-1 }; SendMessageW(hRE, EM_EXSETSEL, 0, (LPARAM)&crNone);
}

// -----------------------------------------------------------------------------
// Чтение опций из INI
// -----------------------------------------------------------------------------
static void load_options_from_ini() {
    if (g_iniPath.empty()) return;
    int depth = GetPrivateProfileIntW(L"IsoLister", L"ScanDepth", g_optDepth, g_iniPath.c_str());
    int maxN = GetPrivateProfileIntW(L"IsoLister", L"MaxNodes", g_optMaxNodes, g_iniPath.c_str());
    int showB = GetPrivateProfileIntW(L"IsoLister", L"ShowBootEntries", g_optShowBootEntries, g_iniPath.c_str());
    g_optDepth = (depth > 0 && depth <= 32) ? depth : g_optDepth;
    g_optMaxNodes = (maxN >= 1000 && maxN <= 1000000) ? maxN : g_optMaxNodes;
    g_optShowBootEntries = (showB != 0) ? 1 : 0;
    log_line(L"Options: ScanDepth=%d, MaxNodes=%d, ShowBootEntries=%d", g_optDepth, g_optMaxNodes, g_optShowBootEntries);
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

extern "C" HWND __stdcall ListLoadW(HWND ParentWin, WCHAR* FileToLoad, int ShowFlags)
{
    log_line(L"ListLoadW: file=\"%s\" flags=%d", FileToLoad ? FileToLoad : L"(null)", ShowFlags);

    std::wostringstream txt;

    // --- Шапка плагина (2-колоночная таблица, таб-стоп на TAB_MAIN_1)
    txt << L"🔧 Плагин\tIsoLister " << ISO_LISTER_VERSION_WSTR << L"\r\n";
    txt << L"🔖 Коммит\t" << ISO_LISTER_GIT_SHA_WSTR << L"\r\n";
    txt << L"⏱ Сборка времени\t" << ISO_LISTER_BUILD_TIMESTAMP_WSTR << L"\r\n";
    txt << repeat(L'─', 90) << L"\r\n";

    FileReader fr;
    IsoSummary sum;
    std::vector<uint8_t> sec(SECTOR_SIZE);

    if (!FileToLoad || !fr.open(FileToLoad)) {
        txt << L"Ошибка\tНе удалось открыть файл ❌\r\n";
    }
    else {
        // Volume Descriptors
        for (uint32_t s = VD_START_SECTOR; ; ++s) {
            if (!fr.read_at(uint64_t(s) * SECTOR_SIZE, sec.data(), SECTOR_SIZE)) break;
            uint8_t type = sec[0];
            if (!is_cd001(sec.data())) break;

            if (type == 1) parse_pvd(sec.data(), sum);
            else if (type == 2) parse_svd(sec.data(), sum);
            else if (type == 0) parse_boot_record(sec.data(), sum);
            else if (type == 255) break;
        }

        // UDF
        sum.hasUDF = detect_udf(fr);

        // Boot Catalog
        std::vector<BootEntry> bootEntries;
        if (sum.bootCatalogLBA) {
            bool valid = false, hasBIOS = false, hasUEFI = false;
            if (parse_boot_catalog(fr, sum.bootCatalogLBA, bootEntries, valid, hasBIOS, hasUEFI)) {
                sum.bootable = valid && (hasBIOS || hasUEFI);
                sum.biosBoot = hasBIOS;
                sum.uefiBoot = hasUEFI;
            }
        }

        // Дерево (Joliet приоритетнее)
        uint32_t rootLBA = sum.joliet ? sum.jolietRootLBA : sum.rootDirLBA;
        uint32_t rootSize = sum.joliet ? sum.jolietRootSize : sum.rootDirSize;

        if (rootLBA && rootSize) {
            ScanResult scan = bfs_scan(fr, rootLBA, rootSize, sum.joliet, g_optDepth, g_optMaxNodes);
            if (scan.rrDetected) sum.rockRidge = true;

            sum.foundGRUB2 = scan.foundGRUB2;
            sum.foundGRUBLegacy = scan.foundGRUBLegacy;
            sum.foundISOLINUX = scan.foundISOLINUX;
            sum.foundSyslinuxMenu = scan.foundSyslinuxMenu;
            sum.foundSystemdBoot = scan.foundSystemdBoot;
            sum.foundWinBootMgr = scan.foundWinBootMgr;
            sum.foundGenericEFI = scan.foundGenericEFI;
            sum.configHits = scan.configHits;

            if (sum.foundWinBootMgr) sum.bootLoader = L"Windows Boot Manager 🪟";
            else if (sum.foundGRUB2) sum.bootLoader = L"GRUB2 🐧";
            else if (sum.foundGRUBLegacy) sum.bootLoader = L"GRUB (legacy) 🐧";
            else if (sum.foundSystemdBoot) sum.bootLoader = L"systemd-boot 🐧";
            else if (sum.foundISOLINUX || sum.foundSyslinuxMenu) sum.bootLoader = L"ISOLINUX/SYSLINUX 🧰";
            else if (sum.foundGenericEFI || sum.uefiBoot) sum.bootLoader = L"EFI (generic) ✨";
        }

        // Тип ФС
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

        // 2‑колоночная сводка
        txt << L"📄 Файл\t" << (FileToLoad ? FileToLoad : L"(null)") << L"\r\n";
        txt << L"🗂 Тип ФС\t" << fsType << L"\r\n";
        if (sum.hasPVD) {
            double MB = (double)sum.volBlocks * sum.logicalBlockSize / (1024.0 * 1024.0);
            txt << L"System ID\t" << sum.sysId << L"\r\n";
            txt << L"Volume ID\t" << sum.volId << L"\r\n";
            txt << L"Application ID\t" << sum.appId << L"\r\n";
            txt << L"Logical Block Size\t" << sum.logicalBlockSize << L"\r\n";
            txt << L"Volume Space\t" << sum.volBlocks << L" блоков (≈ " << (int)(MB + 0.5) << L" MB)\r\n";
            txt << L"Root Dir\tLBA " << (sum.joliet ? sum.jolietRootLBA : sum.rootDirLBA)
                << L", size " << (sum.joliet ? sum.jolietRootSize : sum.rootDirSize) << L" байт\r\n";
            txt << L"🗓 Создан\t" << sum.created << L"\r\n";
            txt << L"🗓 Изменён\t" << sum.modified << L"\r\n";
            txt << L"Joliet\t" << (sum.joliet ? (L"да ✅ (esc=" + ATrimRight(sum.jolietEsc) + L")") : L"нет ❌") << L"\r\n";
            txt << L"Rock Ridge\t" << (sum.rockRidge ? L"да ✅" : L"нет ❌") << L"\r\n";
            txt << L"UDF (гибрид)\t" << (sum.hasUDF ? L"да ✅" : L"нет ❌") << L"\r\n";
        }
        else {
            txt << L"⚠️ Предупреждение\tPVD не найден — возможно, это не ISO9660\r\n";
        }

        txt << repeat(L'─', 90) << L"\r\n";
        txt << L"🚀 Загрузка (El Torito)\t\r\n";
        txt << L"Загрузочный ISO\t" << (sum.bootable ? L"да ✅" : L"нет ❌") << L"\r\n";
        if (sum.hasBootRecord) {
            txt << L"Boot Record\tда ✅ (ID: " << sum.bootSystemId
                << L", Boot Catalog LBA: " << sum.bootCatalogLBA << L")\r\n";
        }
        else {
            txt << L"Boot Record\tнет ❌\r\n";
        }
        if (sum.biosBoot && sum.uefiBoot) txt << L"Тип загрузки\tBIOS и UEFI\r\n";
        else if (sum.biosBoot)            txt << L"Тип загрузки\tBIOS\r\n";
        else if (sum.uefiBoot)            txt << L"Тип загрузки\tUEFI\r\n";
        else                               txt << L"Тип загрузки\t—\r\n";

        txt << L"Загрузчик\t" << (sum.bootLoader.empty() ? L"не обнаружен ❔" : sum.bootLoader) << L"\r\n";

        txt << repeat(L'─', 90) << L"\r\n";
        if (!sum.configHits.empty()) {
            txt << L"📝 Конфигурационные файлы\tнайдено: " << (int)sum.configHits.size() << L"\r\n";
            for (auto& p : sum.configHits) txt << L"\t" << p << L"\r\n"; // вторичная колонка
        }
        else {
            txt << L"📝 Конфигурационные файлы\tне найдены\r\n";
        }

        if (g_optShowBootEntries) {
            std::vector<BootEntry> bootEntries2;
            bool v = false, hb = false, hu = false;
            if (sum.bootCatalogLBA && parse_boot_catalog(fr, sum.bootCatalogLBA, bootEntries2, v, hb, hu) && !bootEntries2.empty()) {
                txt << repeat(L'─', 90) << L"\r\n";
                txt << L"📚 Boot Catalog — все записи\r\n";
                // Заголовок таблицы (многоколонной)
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
    }

    // ----- СОЗДАНИЕ ОКНА ПЛАГИНА (RichEdit) -----
    HWND hRE = CreateWindowExW(
        WS_EX_CLIENTEDGE,
        MSFTEDIT_CLASS,
        L"",
        WS_CHILD | WS_VISIBLE | WS_VSCROLL | WS_HSCROLL |
        ES_MULTILINE | ES_AUTOVSCROLL | ES_AUTOHSCROLL | ES_READONLY | ES_WANTRETURN,
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

    // Базовый шрифт — моноширинный (табличный текст), без переносов
    if (g_hMonoFont) SendMessageW(hRE, WM_SETFONT, (WPARAM)g_hMonoFont, TRUE);

    // Глобальные табы: сначала — сводка (две колонки),
    // + далее — запас под многоколонный Boot Catalog.
    // Все табы задаём сразу — RichEdit применяет их ко всему тексту.
    std::vector<int> tabs = {
        TAB_MAIN_1,         // основная сводка: "Поле" -> "Значение"
        TAB_BOOT_0, TAB_BOOT_1, TAB_BOOT_2, TAB_BOOT_3,
        TAB_BOOT_4, TAB_BOOT_5, TAB_BOOT_6, TAB_BOOT_7
    };
    RichSetTabs(hRE, tabs);

    // Текст
    std::wstring text = txt.str();
    SetWindowTextW(hRE, text.c_str());

    // Сделаем эмодзи цветными
    RichColorizeEmojis(hRE, text);

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
    StringCchCopyA(DetectString, (size_t)maxlen, "EXT=\"ISO\"");
    log_line(L"ListGetDetectString called");
}

extern "C" void __stdcall ListCloseWindow(HWND ListWin)
{
    if (IsWindow(ListWin)) DestroyWindow(ListWin);
    log_line(L"ListCloseWindow");
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
