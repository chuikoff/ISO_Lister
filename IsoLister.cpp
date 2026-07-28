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
#include <commdlg.h>
#include <strsafe.h>
#ifndef FR_DOWN
#define FR_DOWN 0x00000001
#endif
#ifndef FR_WHOLEWORD
#define FR_WHOLEWORD 0x00000002
#endif
#ifndef FR_MATCHCASE
#define FR_MATCHCASE 0x00000004
#endif
#ifndef EM_FINDTEXTEXW
#define EM_FINDTEXTEXW (WM_USER + 124)
#endif
#include <string>
#include <sstream>
#include <vector>
#include <queue>
#include <unordered_map>
#include <cstdint>
#include <algorithm>
#include <cwctype>
#include <cstring>   // memcmp
#include <set>

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

#pragma comment(linker, "/EXPORT:ListLoad")
#pragma comment(linker, "/EXPORT:ListLoadW")
#pragma comment(linker, "/EXPORT:ListGetDetectString")
#pragma comment(linker, "/EXPORT:ListCloseWindow")
#pragma comment(linker, "/EXPORT:ListSetDefaultParams")
#pragma comment(linker, "/EXPORT:ListSendCommand")
#pragma comment(linker, "/EXPORT:ListSearchText")
#pragma comment(linker, "/EXPORT:ListSearchTextW")

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
static void UnsubclassRichEdit(HWND hwnd);
static void FitWindowToParentClient(HWND child, HWND parent);
static HWND CreateRichEditView(HWND parent, DWORD style);
static std::wstring generate_iso_report(const wchar_t* FileToLoad, bool compact = false);

static const UINT DEFAULT_SECTOR_SIZE = 2048;
static const UINT VD_START_SECTOR = 16;
static const uint32_t kMaxVolumeDescriptors = 64;
static const size_t MAX_DIR_READ = 16 * 1024 * 1024;
static const size_t kMaxSmallTextFile = 64 * 1024;

// Опции (по умолчанию — быстрый режим)
static int g_optDepth = 6;
static int g_optMaxNodes = 40000;
static int g_optShowBootEntries = 0;
static int g_optShowFileList = 0;
static int g_optMaxFileList = 1000;
static int g_optFullScan = 0;
static int g_optVerbose = 0; // 0 = краткий отчёт (без PVD/Path Table и т.п.)
// Dark: 0=force light, 1=force dark, 2=auto → TC [Configuration] DarkMode (cm_SwitchDarkMode)
static int g_optDark = 2;

// UI: русский, если LanguageIni TC содержит RUS; иначе английский
static bool g_uiRu = false;
static bool g_darkMode = false;
static COLORREF g_fgColor = RGB(30, 30, 30);
static COLORREF g_bgColor = RGB(255, 255, 255);

static const wchar_t* tr(const wchar_t* ru, const wchar_t* en) {
    return g_uiRu ? ru : en;
}
static std::wstring yesno(bool v) {
    return v ? tr(L"да ✅", L"yes ✅") : tr(L"нет ❌", L"no ❌");
}

static bool path_looks_russian_lang(const wchar_t* s) {
    if (!s || !s[0]) return false;
    std::wstring t(s);
    for (auto& ch : t) ch = (wchar_t)towlower(ch);
    return t.find(L"rus") != std::wstring::npos
        || t.find(L"russian") != std::wstring::npos
        || t.find(L"wcmd_ru") != std::wstring::npos
        || t.find(L"\\ru\\") != std::wstring::npos
        || t.find(L"_ru.") != std::wstring::npos;
}

static void detect_ui_language_from_ini(const wchar_t* iniPath) {
    if (!iniPath || !iniPath[0]) return;
    wchar_t buf[MAX_PATH]{};
    GetPrivateProfileStringW(L"Configuration", L"LanguageIni", L"", buf, MAX_PATH, iniPath);
    if (!buf[0])
        GetPrivateProfileStringW(L"Configuration", L"LanguageDll", L"", buf, MAX_PATH, iniPath);
    if (!buf[0])
        GetPrivateProfileStringW(L"Configuration", L"Language", L"", buf, MAX_PATH, iniPath);
    if (path_looks_russian_lang(buf))
        g_uiRu = true;
}

// TC cm_SwitchDarkMode state is persisted as DarkMode=0|1 in [Configuration] of wincmd.ini
// (not Windows AppsUseLightTheme — TC has its own switch).
static bool detect_tc_dark_mode(const wchar_t* wincmdPath) {
    if (!wincmdPath || !wincmdPath[0]) return false;
    return GetPrivateProfileIntW(L"Configuration", L"DarkMode", 0, wincmdPath) != 0;
}

static void recompute_theme(const wchar_t* wincmdPath) {
    if (g_optDark == 0)
        g_darkMode = false;
    else if (g_optDark == 1)
        g_darkMode = true;
    else
        g_darkMode = detect_tc_dark_mode(wincmdPath);

    if (g_darkMode) {
        // Match typical TC dark palette (not OS theme)
        g_bgColor = RGB(32, 32, 32);
        g_fgColor = RGB(220, 220, 220);
    }
    else {
        g_bgColor = RGB(255, 255, 255);
        g_fgColor = RGB(30, 30, 30);
        // In light mode only: prefer Lister panel colors if set
        if (wincmdPath && wincmdPath[0]) {
            int fg = GetPrivateProfileIntW(L"Lister", L"FgColor", -1, wincmdPath);
            int bg = GetPrivateProfileIntW(L"Lister", L"BgColor", -1, wincmdPath);
            if (fg >= 0) g_fgColor = (COLORREF)fg;
            if (bg >= 0) g_bgColor = (COLORREF)bg;
        }
    }
    log_line(L"Theme: dark=%d DarkOpt=%d (TC DarkMode / cm_SwitchDarkMode)",
        g_darkMode ? 1 : 0, g_optDark);
}

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
    UINT sectorSize = DEFAULT_SECTOR_SIZE;

    FileReader() = default;
    FileReader(const FileReader&) = delete;
    FileReader& operator=(const FileReader&) = delete;
    FileReader(FileReader&& o) noexcept : h(o.h), sectorSize(o.sectorSize) {
        o.h = INVALID_HANDLE_VALUE;
    }
    FileReader& operator=(FileReader&& o) noexcept {
        if (this != &o) {
            if (h != INVALID_HANDLE_VALUE) CloseHandle(h);
            h = o.h;
            sectorSize = o.sectorSize;
            o.h = INVALID_HANDLE_VALUE;
        }
        return *this;
    }

    bool open(const wchar_t* path) {
        if (h != INVALID_HANDLE_VALUE) {
            CloseHandle(h);
            h = INVALID_HANDLE_VALUE;
        }
        h = CreateFileW(path, GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        return h != INVALID_HANDLE_VALUE;
    }
    bool read_at(uint64_t off, void* buf, DWORD size) {
        if (h == INVALID_HANDLE_VALUE || !buf || size == 0) return false;
        LARGE_INTEGER li; li.QuadPart = (LONGLONG)off;
        if (!SetFilePointerEx(h, li, nullptr, FILE_BEGIN)) return false;
        DWORD rd = 0;
        return ReadFile(h, buf, size, &rd, nullptr) && rd == size;
    }
    bool read_sector(uint32_t lba, void* buf, DWORD size) {
        return read_at(uint64_t(lba) * sectorSize, buf, size);
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
            fr.sectorSize = ss;
            return true;
        }
    }
    return false;
}

// -----------------------------------------------------------------------------
// Образ диска (MBR/GPT) — raw .img/.bin, не ISO9660
// -----------------------------------------------------------------------------
static const UINT DISK_SECTOR_SIZE = 512;

static bool has_boot_signature(const uint8_t* sec) {
    return sec[510] == 0x55 && sec[511] == 0xAA;
}

static std::wstring mbr_partition_type_name(uint8_t type) {
    switch (type) {
    case 0x00: return L"Пусто";
    case 0x01: return L"FAT12";
    case 0x04: return L"FAT16 (<32M)";
    case 0x05: return L"Extended";
    case 0x06: return L"FAT16";
    case 0x07: return L"NTFS / exFAT / HPFS";
    case 0x0B: return L"FAT32 (CHS)";
    case 0x0C: return L"FAT32 (LBA)";
    case 0x0E: return L"FAT16 (LBA)";
    case 0x0F: return L"Extended (LBA)";
    case 0x11: return L"FAT12 (скрытый)";
    case 0x14: return L"FAT16 (скрытый, <32M)";
    case 0x16: return L"FAT16 (скрытый)";
    case 0x17: return L"NTFS (скрытый)";
    case 0x1B: return L"FAT32 (скрытый)";
    case 0x1C: return L"FAT32 LBA (скрытый)";
    case 0x1E: return L"FAT16 LBA (скрытый)";
    case 0x27: return L"Windows RE / Recovery";
    case 0x82: return L"Linux swap";
    case 0x83: return L"Linux";
    case 0x84: return L"Hibernation";
    case 0x85: return L"Linux extended";
    case 0xA8: return L"Recovery";
    case 0xEE: return L"GPT (защитная MBR)";
    case 0xEF: return L"EFI System";
    case 0xFD: return L"Linux RAID";
    default: {
        wchar_t buf[32];
        StringCchPrintfW(buf, 32, L"0x%02X", type);
        return buf;
    }
    }
}

static std::wstring trim_ascii_label(const char* s, size_t len) {
    std::string t(s, len);
    while (!t.empty() && (unsigned char)t.back() <= ' ') t.pop_back();
    size_t i = 0;
    while (i < t.size() && (unsigned char)t[i] <= ' ') ++i;
    t = t.substr(i);
    if (t.empty()) return L"";
    bool printable = true;
    for (unsigned char c : t) {
        if (c < 0x20 || c == 0x7F) { printable = false; break; }
    }
    return printable ? ATrimRight(t) : L"";
}

struct DiskPartitionInfo {
    int index = 0;
    uint8_t mbrType = 0;
    bool bootable = false;
    uint64_t startLBA = 0;
    uint64_t sectorCount = 0;
    std::wstring tableType;   // MBR / GPT
    std::wstring typeName;
    std::wstring gptName;
    std::wstring fsName;
    std::wstring fsDetail;
    std::wstring volumeLabel;
    std::wstring oemId;
};

struct DiskImageInfo {
    bool valid = false;
    bool gpt = false;
    uint32_t diskSignature = 0;
    std::wstring bootCodeHint;
    std::vector<DiskPartitionInfo> partitions;
};

static bool guid_equal(const uint8_t* a, const uint8_t* b) {
    return memcmp(a, b, 16) == 0;
}

static const uint8_t kGuidEfiSystem[] = {
    0x28,0x73,0x2A,0xC1,0x1F,0xF8,0xD2,0x11,0xBA,0x4B,0x00,0xA0,0xC9,0x3E,0xC9,0x3B };
static const uint8_t kGuidMsBasicData[] = {
    0xA2,0xA0,0xD0,0xEB,0xE5,0xB9,0x33,0x44,0x87,0xC0,0x68,0xB6,0xB7,0x26,0x99,0xC7 };
static const uint8_t kGuidLinuxFs[] = {
    0xAF,0x3D,0xC6,0x0F,0x83,0x84,0x72,0x47,0x8E,0x79,0x3D,0x69,0xD8,0x47,0x7D,0xE4 };

static std::wstring gpt_type_name(const uint8_t* typeGuid) {
    if (guid_equal(typeGuid, kGuidEfiSystem)) return L"EFI System";
    if (guid_equal(typeGuid, kGuidMsBasicData)) return L"Microsoft Basic Data";
    if (guid_equal(typeGuid, kGuidLinuxFs)) return L"Linux filesystem";
    wchar_t buf[64];
    StringCchPrintfW(buf, 64, L"%02X%02X%02X%02X-...",
        typeGuid[3], typeGuid[2], typeGuid[1], typeGuid[0]);
    return buf;
}

static void detect_fs_vbr(FileReader& fr, uint64_t startLBA, DiskPartitionInfo& part) {
    uint8_t vbr[512];
    if (!fr.read_at(startLBA * DISK_SECTOR_SIZE, vbr, 512) || !has_boot_signature(vbr))
        return;

    part.oemId = trim_ascii_label((const char*)vbr + 3, 8);
    if (memcmp(vbr + 3, "NTFS    ", 8) == 0) {
        part.fsName = L"NTFS";
        uint16_t bps = rd_le16(vbr + 11);
        uint8_t spc = vbr[13];
        uint64_t total = rd_le64(vbr + 48);
        wchar_t buf[128];
        StringCchPrintfW(buf, 128, L"%u байт/сек, %u сек/кластер, %llu секторов",
            bps, spc, total);
        part.fsDetail = buf;
        return;
    }
    if (memcmp(vbr + 3, "EXFAT   ", 8) == 0) {
        part.fsName = L"exFAT";
        return;
    }
    if (memcmp(vbr + 82, "FAT32   ", 8) == 0 || part.mbrType == 0x0B || part.mbrType == 0x0C) {
        part.fsName = L"FAT32";
        part.volumeLabel = trim_ascii_label((const char*)vbr + 0x47, 11);
        if (part.volumeLabel.empty())
            part.volumeLabel = trim_ascii_label((const char*)vbr + 0x5B, 11);
        uint16_t bps = rd_le16(vbr + 11);
        uint8_t spc = vbr[13];
        uint32_t total32 = rd_le32(vbr + 32);
        wchar_t buf[128];
        StringCchPrintfW(buf, 128, L"%u байт/сек, %u сек/кластер, %u секторов",
            bps, spc, total32);
        part.fsDetail = buf;
        return;
    }
    if (memcmp(vbr + 54, "FAT16   ", 8) == 0 || memcmp(vbr + 54, "FAT12   ", 8) == 0) {
        part.fsName = memcmp(vbr + 54, "FAT12   ", 8) == 0 ? L"FAT12" : L"FAT16";
        part.volumeLabel = trim_ascii_label((const char*)vbr + 0x2B, 11);
        return;
    }
    if (memcmp(vbr + 3, "MSDOS5.0", 8) == 0 || memcmp(vbr + 3, "mkfs.fat", 8) == 0 ||
        memcmp(vbr + 3, "MSWIN4.1", 8) == 0) {
        part.fsName = L"FAT";
        part.volumeLabel = trim_ascii_label((const char*)vbr + 0x47, 11);
    }
}

static bool parse_gpt_partitions(FileReader& fr, DiskImageInfo& out) {
    uint8_t hdr[512];
    if (!fr.read_at(DISK_SECTOR_SIZE, hdr, 512)) return false;
    if (memcmp(hdr, "EFI PART", 8) != 0) return false;

    uint32_t entryLBA = (uint32_t)rd_le64(hdr + 72);
    uint32_t entryCount = rd_le32(hdr + 80);
    uint32_t entrySize = rd_le32(hdr + 84);
    if (!entryLBA || !entryCount || entrySize < 128 || entrySize > 4096) return false;

    std::vector<uint8_t> entries((size_t)entryCount * entrySize);
    uint64_t bytes = (uint64_t)entryCount * entrySize;
    if (!fr.read_at((uint64_t)entryLBA * DISK_SECTOR_SIZE, entries.data(), (DWORD)std::min<uint64_t>(bytes, 2 * 1024 * 1024)))
        return false;

    out.gpt = true;
    int idx = 0;
    for (uint32_t i = 0; i < entryCount; ++i) {
        const uint8_t* e = entries.data() + (size_t)i * entrySize;
        bool empty = true;
        for (int b = 0; b < 16; ++b) if (e[b]) { empty = false; break; }
        if (empty) continue;

        uint64_t first = rd_le64(e + 32);
        uint64_t last = rd_le64(e + 40);
        if (!first || last < first) continue;

        DiskPartitionInfo p{};
        p.index = ++idx;
        p.tableType = L"GPT";
        p.typeName = gpt_type_name(e);
        p.startLBA = first;
        p.sectorCount = last - first + 1;
        for (int c = 56; c + 1 < (int)entrySize && c < 56 + 72; c += 2) {
            wchar_t ch = (wchar_t)rd_le16(e + c);
            if (!ch) break;
            p.gptName.push_back(ch);
        }
        detect_fs_vbr(fr, p.startLBA, p);
        out.partitions.push_back(std::move(p));
    }
    return !out.partitions.empty();
}

static bool probe_disk_image(FileReader& fr, DiskImageInfo& out) {
    uint8_t mbr[512];
    if (!fr.read_at(0, mbr, 512) || !has_boot_signature(mbr)) return false;

    out.valid = true;
    out.diskSignature = rd_le32(mbr + 440);
    if (mbr[0] == 0x33 && mbr[1] == 0xC0) out.bootCodeHint = L"x86 MBR загрузчик";
    else if (!memcmp(mbr, "\xEB\x58\x90", 3) || !memcmp(mbr, "\xEB\x63\x90", 3)) out.bootCodeHint = L"x86 VBR/загрузчик";

    bool hasGptProtective = false;
    for (int i = 0; i < 4; ++i) {
        const uint8_t* pe = mbr + 446 + i * 16;
        if (pe[4] == 0xEE) hasGptProtective = true;
    }
    if (hasGptProtective && parse_gpt_partitions(fr, out))
        return true;

    int idx = 0;
    for (int i = 0; i < 4; ++i) {
        const uint8_t* pe = mbr + 446 + i * 16;
        uint8_t type = pe[4];
        uint32_t start = rd_le32(pe + 8);
        uint32_t count = rd_le32(pe + 12);
        if (!type && !start && !count) continue;

        DiskPartitionInfo p{};
        p.index = ++idx;
        p.tableType = L"MBR";
        p.mbrType = type;
        p.bootable = (pe[0] == 0x80);
        p.typeName = mbr_partition_type_name(type);
        p.startLBA = start;
        p.sectorCount = count;
        if (type != 0x05 && type != 0x0F && type != 0xEE)
            detect_fs_vbr(fr, p.startLBA, p);
        out.partitions.push_back(std::move(p));
    }
    return !out.partitions.empty();
}

static void append_disk_partitions(std::wostringstream& txt, FileReader& fr, const DiskImageInfo& disk) {
    txt << L"🧱 " << tr(L"Разметка диска", L"Disk layout") << L"\t" << (disk.gpt ? L"GPT ✅" : L"MBR ✅") << L"\r\n";
    if (disk.diskSignature)
        txt << tr(L"Сигнатура диска", L"Disk signature") << L"\t0x" << std::hex << std::uppercase << disk.diskSignature << std::dec << L"\r\n";
    if (!disk.bootCodeHint.empty())
        txt << tr(L"Загрузочный код", L"Boot code") << L"\t" << disk.bootCodeHint << L"\r\n";
    txt << tr(L"Разделов", L"Partitions") << L"\t" << disk.partitions.size() << L"\r\n";
    txt << repeat(L'─', 90) << L"\r\n";

    for (const auto& p : disk.partitions) {
        txt << L"📦 " << tr(L"Раздел #", L"Partition #") << p.index << L"\t" << p.tableType;
        if (p.bootable) txt << L" (bootable)";
        txt << L"\r\n";
        txt << L"  " << tr(L"Тип", L"Type") << L"\t" << p.typeName;
        if (p.mbrType) txt << L" (0x" << std::hex << std::uppercase << (int)p.mbrType << std::dec << L")";
        txt << L"\r\n";
        if (!p.gptName.empty()) txt << L"  " << tr(L"Имя GPT", L"GPT name") << L"\t" << p.gptName << L"\r\n";
        txt << L"  " << tr(L"Начало", L"Start") << L"\tLBA " << p.startLBA << L" (" << FormatFileSize(p.startLBA * DISK_SECTOR_SIZE) << L")\r\n";
        txt << L"  " << tr(L"Размер", L"Size") << L"\t" << FormatFileSize(p.sectorCount * DISK_SECTOR_SIZE)
            << L" (" << p.sectorCount << L" " << tr(L"секторов", L"sectors") << L")\r\n";
        if (!p.fsName.empty()) txt << L"  " << tr(L"ФС", L"FS") << L"\t" << p.fsName << L" ✅\r\n";
        if (!p.fsDetail.empty()) txt << L"  " << tr(L"Детали ФС", L"FS details") << L"\t" << p.fsDetail << L"\r\n";
        if (!p.volumeLabel.empty()) txt << L"  " << tr(L"Метка тома", L"Volume label") << L"\t'" << p.volumeLabel << L"'\r\n";
        if (!p.oemId.empty()) txt << L"  OEM ID\t" << p.oemId << L"\r\n";
        txt << L"\r\n";
    }

    uint64_t imageSectors = fr.size_bytes() / DISK_SECTOR_SIZE;
    uint64_t used = 0;
    for (const auto& p : disk.partitions) used += p.sectorCount;
    if (imageSectors > used)
        txt << tr(L"Неразмечено", L"Unallocated") << L"\t" << FormatFileSize((imageSectors - used) * DISK_SECTOR_SIZE) << L"\r\n";
}

static std::wstring generate_disk_image_report(const wchar_t* FileToLoad, FileReader& fr, const DiskImageInfo& disk) {
    std::wostringstream txt;
    (void)FileToLoad;
    txt << tr(L"Тип образа", L"Image type") << L"\t💽 " << tr(L"Образ диска (raw sector dump)", L"Disk image (raw sector dump)") << L"\r\n";
    txt << repeat(L'─', 90) << L"\r\n";
    append_disk_partitions(txt, fr, disk);
    txt << repeat(L'─', 90) << L"\r\n";
    txt << L"ℹ️ " << tr(L"Примечание", L"Note") << L"\t"
        << tr(L"Это образ диска, не ISO9660. Анализ ISO/UDF внутри разделов не выполняется.",
              L"This is a disk image, not ISO9660. ISO/UDF inside partitions is not scanned.") << L"\r\n";
    return txt.str();
}

// -----------------------------------------------------------------------------
// VHD / VHDX
// -----------------------------------------------------------------------------
struct VhdInfo {
    bool isVhd = false;
    bool isVhdx = false;
    bool isFixed = false;
    bool isDynamic = false;
    bool isDifferencing = false;
    uint64_t virtualSize = 0;
    uint64_t currentSize = 0;
    uint32_t diskType = 0; // VHD: 2 fixed, 3 dynamic, 4 differencing
    std::wstring typeLabel;
};

static bool probe_vhd(FileReader& fr, VhdInfo& out) {
    uint64_t sz = fr.size_bytes();
    if (sz < 512) return false;
    uint8_t foot[512]{};
    if (!fr.read_at(sz - 512, foot, 512)) return false;
    if (memcmp(foot, "conectix", 8) != 0) return false;
    auto be32 = [](const uint8_t* p) -> uint32_t {
        return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | (uint32_t)p[3];
    };
    auto be64 = [&](const uint8_t* p) -> uint64_t {
        return ((uint64_t)be32(p) << 32) | be32(p + 4);
    };
    out.isVhd = true;
    out.diskType = be32(foot + 0x3C);
    out.currentSize = be64(foot + 0x28);
    out.virtualSize = out.currentSize;
    out.isFixed = (out.diskType == 2);
    out.isDynamic = (out.diskType == 3);
    out.isDifferencing = (out.diskType == 4);
    if (out.isFixed) out.typeLabel = L"Fixed VHD";
    else if (out.isDynamic) out.typeLabel = L"Dynamic VHD";
    else if (out.isDifferencing) out.typeLabel = L"Differencing VHD";
    else out.typeLabel = L"VHD";
    return true;
}

static bool probe_vhdx(FileReader& fr, VhdInfo& out) {
    uint8_t hdr[16]{};
    if (!fr.read_at(0, hdr, 8)) return false;
    if (memcmp(hdr, "vhdxfile", 8) != 0) return false;
    out.isVhdx = true;
    out.typeLabel = L"VHDX";
    // Virtual size is in metadata region — best-effort: report file size
    out.currentSize = fr.size_bytes();
    out.virtualSize = out.currentSize;
    // Try to find dynamic header signature "head" at 64KB / 128KB (common)
    uint8_t dh[512]{};
    for (uint64_t off : { 64ull * 1024, 128ull * 1024 }) {
        if (off + 512 > fr.size_bytes()) continue;
        if (!fr.read_at(off, dh, 512)) continue;
        if (memcmp(dh, "head", 4) != 0) continue;
        // SequenceNumber at +8 (LE), FileWriteGuid etc. — VirtualDiskSize in metadata
        break;
    }
    return true;
}

static std::wstring generate_vhd_report(const wchar_t* FileToLoad, FileReader& fr, const VhdInfo& vhd) {
    std::wostringstream txt;
    (void)FileToLoad;
    txt << tr(L"Тип образа", L"Image type") << L"\t💾 " << vhd.typeLabel << L"\r\n";
    txt << repeat(L'─', 90) << L"\r\n";
    txt << tr(L"Формат", L"Format") << L"\t" << (vhd.isVhdx ? L"VHDX" : L"VHD") << L" ✅\r\n";
    if (vhd.diskType)
        txt << tr(L"Тип диска", L"Disk type") << L"\t" << vhd.diskType
            << (vhd.isFixed ? L" (fixed)" : vhd.isDynamic ? L" (dynamic)" : vhd.isDifferencing ? L" (differencing)" : L"") << L"\r\n";
    if (vhd.currentSize)
        txt << tr(L"Размер файла / current", L"File / current size") << L"\t" << FormatFileSize(vhd.currentSize) << L"\r\n";
    if (vhd.virtualSize && vhd.virtualSize != vhd.currentSize)
        txt << tr(L"Виртуальный размер", L"Virtual size") << L"\t" << FormatFileSize(vhd.virtualSize) << L"\r\n";

    if (vhd.isVhd && vhd.isFixed) {
        DiskImageInfo disk;
        if (probe_disk_image(fr, disk)) {
            txt << repeat(L'─', 90) << L"\r\n";
            append_disk_partitions(txt, fr, disk);
        }
    }
    else {
        txt << repeat(L'─', 90) << L"\r\n";
        txt << L"ℹ️ " << tr(L"Примечание", L"Note") << L"\t"
            << tr(L"Динамические/разностные VHD и полный разбор VHDX: показаны метаданные; fixed VHD разбирается как raw.",
                  L"Dynamic/differencing VHD and full VHDX parse: metadata only; fixed VHD is scanned as raw.") << L"\r\n";
    }
    return txt.str();
}

// -----------------------------------------------------------------------------
// Apple Disk Image (UDIF / .dmg)
// -----------------------------------------------------------------------------
static uint16_t rd_be16(const uint8_t* p) {
    return (uint16_t)(((uint16_t)p[0] << 8) | p[1]);
}
static uint32_t rd_be32(const uint8_t* p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}
static uint64_t rd_be64(const uint8_t* p) {
    return ((uint64_t)rd_be32(p) << 32) | rd_be32(p + 4);
}

static bool b64val(int c) {
    if (c >= 'A' && c <= 'Z') return true;
    if (c >= 'a' && c <= 'z') return true;
    if (c >= '0' && c <= '9') return true;
    return c == '+' || c == '/';
}

static bool base64_decode(const std::string& in, std::vector<uint8_t>& out) {
    static const int8_t tbl[256] = {
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,62,-1,-1,-1,63,52,53,54,55,56,57,58,59,60,61,-1,-1,-1,-1,-1,-1,
        -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,-1,-1,-1,-1,-1,
        -1,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,48,49,50,51,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1
    };
    out.clear();
    uint32_t acc = 0;
    int bits = 0;
    for (unsigned char c : in) {
        if (c == '=' || c == '\r' || c == '\n' || c == ' ' || c == '\t') continue;
        if (!b64val(c)) return false;
        acc = (acc << 6) | (uint32_t)tbl[c];
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out.push_back((uint8_t)((acc >> bits) & 0xFF));
        }
    }
    return !out.empty();
}

static std::wstring udif_chunk_type_name(uint32_t t) {
    switch (t) {
    case 0x00000000: return L"zero-fill";
    case 0x00000001: return L"raw";
    case 0x00000002: return L"ignored";
    case 0x80000004: return L"adc";
    case 0x80000005: return L"zlib";
    case 0x80000006: return L"bzip2";
    case 0x7ffffffe: return L"comment";
    case 0xffffffff: return L"end";
    default: {
        wchar_t buf[16];
        StringCchPrintfW(buf, 16, L"0x%08X", t);
        return buf;
    }
    }
}

static std::wstring udif_format_label(const std::set<uint32_t>& types) {
    if (types.count(0x80000006)) return L"UDBZ (bzip2)";
    if (types.count(0x80000005)) return L"UDZO (zlib)";
    if (types.count(0x80000004)) return L"UDCO (adc)";
    if (types.count(0x00000001) && types.size() <= 2) return L"UDRO (raw)";
    if (!types.empty()) return L"UDIF (mixed)";
    return L"UDIF";
}

struct UdIfPartitionInfo {
    std::wstring name;
    uint64_t sectorCount = 0;
    bool appleHfs = false;
    bool appleApfs = false;
    bool efi = false;
    bool structural = false;
};

struct UdIfInfo {
    bool valid = false;
    uint32_t version = 0;
    uint32_t flags = 0;
    uint64_t dataForkLength = 0;
    uint64_t xmlOffset = 0;
    uint64_t xmlLength = 0;
    uint64_t sectorCount = 0;
    std::set<uint32_t> chunkTypes;
    std::vector<UdIfPartitionInfo> partitions;
    std::wstring hfsMountedVersion;
    std::wstring macOsHint;
};

static std::wstring classify_udif_partition_name(const std::wstring& name, UdIfPartitionInfo& p) {
    std::wstring n = name;
    while (!n.empty() && (n.front() == L' ' || n.front() == L'\t')) n.erase(n.begin());
    std::wstring low = ToLower(n);
    p.structural = (low.find(L"gpt") != std::wstring::npos || low.find(L"mbr") != std::wstring::npos ||
        low.find(L"driver descriptor") != std::wstring::npos || low.find(L"apple_free") != std::wstring::npos);
    p.appleHfs = (low.find(L"apple_hfs") != std::wstring::npos || low.find(L"hfs :") != std::wstring::npos);
    p.appleApfs = (low.find(L"apfs") != std::wstring::npos);
    p.efi = (low.find(L"efi system") != std::wstring::npos || low.find(L"c12a7328") != std::wstring::npos);
    return n;
}

static void udif_analyze_mish(const uint8_t* mish, size_t len, UdIfInfo& info) {
    if (len < 0xCC + 40 || memcmp(mish, "mish", 4) != 0) return;
    uint32_t nChunks = rd_be32(mish + 0xC8);
    size_t off = 0xCC;
    for (uint32_t c = 0; c < nChunks && off + 40 <= len; ++c) {
        uint32_t et = rd_be32(mish + off);
        uint64_t sn = rd_be64(mish + off + 8);
        uint64_t sc = rd_be64(mish + off + 16);
        uint64_t co = rd_be64(mish + off + 24);
        (void)sc;
        info.chunkTypes.insert(et);
        if (et == 0x00000001 && sn <= 2 && 2 < sn + rd_be64(mish + off + 16)) {
            (void)co;
        }
        off += 40;
        if (et == 0xffffffff) break;
    }
}

static bool udif_sniff_hfs_version(FileReader& fr, const UdIfInfo& info, const std::string& xml, std::wstring& outVer) {
    size_t pos = 0;
    while (true) {
        size_t dpos = xml.find("<key>Data</key>", pos);
        if (dpos == std::string::npos) break;
        dpos = xml.find("<data>", dpos);
        if (dpos == std::string::npos) break;
        dpos += 6;
        size_t dend = xml.find("</data>", dpos);
        if (dend == std::string::npos) break;
        std::vector<uint8_t> mish;
        if (!base64_decode(xml.substr(dpos, dend - dpos), mish) || mish.size() < 0xCC + 40) {
            pos = dend;
            continue;
        }
        if (memcmp(mish.data(), "mish", 4) != 0) { pos = dend; continue; }
        uint32_t nChunks = rd_be32(mish.data() + 0xC8);
        size_t off = 0xCC;
        for (uint32_t c = 0; c < nChunks && off + 40 <= mish.size(); ++c) {
            uint32_t et = rd_be32(mish.data() + off);
            uint64_t sn = rd_be64(mish.data() + off + 8);
            uint64_t sc = rd_be64(mish.data() + off + 16);
            uint64_t co = rd_be64(mish.data() + off + 24);
            off += 40;
            if (et != 0x00000001) continue;
            if (sn > 2 || sn + sc <= 2) continue;
            uint8_t vh[512];
            uint64_t fileOff = co + (2 - sn) * 512;
            if (!fr.read_at(fileOff, vh, 512)) continue;
            if (rd_be16(vh) != 0x482B) continue;
            char ver[5] = {};
            memcpy(ver, vh + 8, 4);
            bool ok = true;
            for (int i = 0; i < 4; ++i) {
                if (ver[i] && (ver[i] < 0x20 || ver[i] > 0x7E)) ok = false;
            }
            if (!ok) continue;
            outVer = ATrimRight(std::string(ver, ver + strnlen(ver, 4)));
            return true;
        }
        pos = dend;
    }
    return false;
}

static std::wstring macos_marketing_name(const std::wstring& ver, const wchar_t* path) {
    std::wstring fn = path ? ToLower(path) : L"";
    if (fn.find(L"catalina") != std::wstring::npos) return L"macOS Catalina (10.15)";
    if (fn.find(L"bigsur") != std::wstring::npos || fn.find(L"big_sur") != std::wstring::npos) return L"macOS Big Sur (11)";
    if (fn.find(L"monterey") != std::wstring::npos) return L"macOS Monterey (12)";
    if (fn.find(L"ventura") != std::wstring::npos) return L"macOS Ventura (13)";
    if (fn.find(L"sonoma") != std::wstring::npos) return L"macOS Sonoma (14)";
    if (fn.find(L"sequoia") != std::wstring::npos) return L"macOS Sequoia (15)";
    if (fn.find(L"tahoe") != std::wstring::npos) return L"macOS Tahoe (26)";
    if (ver == L"10.15") return L"macOS Catalina";
    if (ver == L"10.14") return L"macOS Mojave";
    if (ver == L"10.13") return L"macOS High Sierra";
    if (ver.rfind(L"11.", 0) == 0) return L"macOS Big Sur";
    if (ver.rfind(L"12.", 0) == 0) return L"macOS Monterey";
    if (ver.rfind(L"13.", 0) == 0) return L"macOS Ventura";
    if (ver.rfind(L"14.", 0) == 0) return L"macOS Sonoma";
    if (ver.rfind(L"15.", 0) == 0) return L"macOS Sequoia";
    if (!ver.empty()) return L"macOS " + ver;
    return L"macOS";
}

static std::wstring plist_extract_string(const std::string& block, const char* key) {
    std::string needle = std::string("<key>") + key + "</key>";
    size_t kpos = block.find(needle);
    if (kpos == std::string::npos) return L"";
    size_t spos = block.find("<string>", kpos);
    if (spos == std::string::npos) return L"";
    spos += 8;
    size_t send = block.find("</string>", spos);
    if (send == std::string::npos) return L"";
    std::string utf8 = block.substr(spos, send - spos);
    int wlen = MultiByteToWideChar(CP_UTF8, 0, utf8.c_str(), -1, nullptr, 0);
    if (wlen <= 1) return L"";
    std::wstring w((size_t)wlen - 1, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, utf8.c_str(), -1, &w[0], wlen);
    return w;
}

static bool parse_udif_xml(const std::string& xml, UdIfInfo& info) {
    size_t blkx = xml.find("<key>blkx</key>");
    if (blkx == std::string::npos) return false;
    size_t pos = blkx;
    while (true) {
        size_t dstart = xml.find("<dict>", pos);
        if (dstart == std::string::npos) break;
        size_t dend = xml.find("</dict>", dstart);
        if (dend == std::string::npos) break;
        std::string block = xml.substr(dstart, dend - dstart);
        if (block.find("<key>Data</key>") == std::string::npos) {
            pos = dend + 7;
            continue;
        }
        std::wstring wname = plist_extract_string(block, "Name");
        if (wname.empty()) wname = plist_extract_string(block, "CFName");
        size_t dpos = block.find("<data>");
        if (dpos == std::string::npos) { pos = dend + 7; continue; }
        dpos += 6;
        size_t dend2 = block.find("</data>", dpos);
        if (dend2 == std::string::npos) { pos = dend + 7; continue; }
        std::vector<uint8_t> mish;
        if (base64_decode(block.substr(dpos, dend2 - dpos), mish) && mish.size() >= 24) {
            UdIfPartitionInfo p{};
            p.name = classify_udif_partition_name(wname, p);
            p.sectorCount = rd_be64(mish.data() + 16);
            udif_analyze_mish(mish.data(), mish.size(), info);
            info.partitions.push_back(std::move(p));
        }
        pos = dend + 7;
    }
    return !info.partitions.empty();
}

static bool probe_udif_dmg(FileReader& fr, UdIfInfo& out, const wchar_t* pathForHints) {
    uint64_t size = fr.size_bytes();
    if (size < 1024) return false;
    uint8_t koly[512];
    if (!fr.read_at(size - 512, koly, 512) || memcmp(koly, "koly", 4) != 0) return false;

    out.valid = true;
    out.version = rd_be32(koly + 4);
    out.flags = rd_be32(koly + 12);
    out.dataForkLength = rd_be64(koly + 32);
    out.xmlOffset = rd_be64(koly + 0xD8);
    out.xmlLength = rd_be64(koly + 0xE0);
    out.sectorCount = rd_be64(koly + 0x1EC);

    if (!out.xmlLength || out.xmlLength > 16 * 1024 * 1024) return false;
    if (out.xmlOffset >= size || out.xmlOffset + out.xmlLength > size) return false;

    std::vector<char> xmlBuf((size_t)out.xmlLength + 1);
    if (!fr.read_at(out.xmlOffset, xmlBuf.data(), (DWORD)out.xmlLength)) return false;
    xmlBuf[(size_t)out.xmlLength] = '\0';
    if (!parse_udif_xml(xmlBuf.data(), out)) return false;

    udif_sniff_hfs_version(fr, out, xmlBuf.data(), out.hfsMountedVersion);
    bool hasMacPart = false;
    for (const auto& p : out.partitions) {
        if (p.appleHfs || p.appleApfs) hasMacPart = true;
    }
    if (hasMacPart || !out.hfsMountedVersion.empty())
        out.macOsHint = macos_marketing_name(out.hfsMountedVersion, pathForHints);
    return true;
}

static std::wstring generate_udif_dmg_report(const wchar_t* FileToLoad, FileReader& fr, const UdIfInfo& dmg) {
    std::wostringstream txt;
    (void)FileToLoad;
    (void)fr;
    txt << tr(L"Тип образа", L"Image type") << L"\t🍎 Apple Disk Image (UDIF .dmg)\r\n";
    txt << repeat(L'─', 90) << L"\r\n";
    txt << L"📀 UDIF\t\r\n";
    txt << tr(L"Формат", L"Format") << L"\t" << udif_format_label(dmg.chunkTypes) << L" ✅\r\n";
    txt << tr(L"UDIF версия", L"UDIF version") << L"\t" << dmg.version << L"\r\n";
    txt << L"Data fork\t" << FormatFileSize(dmg.dataForkLength) << L"\r\n";
    txt << tr(L"Развёрнутый размер", L"Expanded size") << L"\t" << FormatFileSize(dmg.sectorCount * 512)
        << L" (" << dmg.sectorCount << L" " << tr(L"секторов", L"sectors") << L")\r\n";
    if (!dmg.chunkTypes.empty()) {
        txt << tr(L"Сжатие (типы блоков)", L"Compression (block types)") << L"\t";
        bool first = true;
        for (uint32_t t : dmg.chunkTypes) {
            if (t == 0x7ffffffe || t == 0xffffffff) continue;
            if (!first) txt << L", ";
            txt << udif_chunk_type_name(t);
            first = false;
        }
        txt << L"\r\n";
    }

    bool hasMac = false;
    for (const auto& p : dmg.partitions) {
        if (p.appleHfs || p.appleApfs) { hasMac = true; break; }
    }
    if (hasMac || !dmg.macOsHint.empty()) {
        txt << repeat(L'─', 90) << L"\r\n";
        txt << L"🍎 macOS\t\r\n";
        txt << tr(L"Тип образа", L"Image type") << L"\t"
            << tr(L"Установочный / recovery DMG", L"Installer / recovery DMG") << L"\r\n";
        if (!dmg.macOsHint.empty())
            txt << tr(L"Обнаружено", L"Detected") << L"\t" << dmg.macOsHint << L"\r\n";
        if (!dmg.hfsMountedVersion.empty())
            txt << L"HFS+ lastMountedVersion\t" << dmg.hfsMountedVersion << L"\r\n";
    }

    txt << repeat(L'─', 90) << L"\r\n";
    txt << L"🧱 " << tr(L"Разделы (blkx)", L"Partitions (blkx)") << L"\t" << dmg.partitions.size() << L"\r\n";
    int shown = 0;
    for (const auto& p : dmg.partitions) {
        if (p.structural) continue;
        if (p.name.empty() && p.sectorCount <= 64) continue;
        ++shown;
        txt << L"📦\t" << (p.name.empty() ? tr(L"(без имени)", L"(unnamed)") : p.name.c_str());
        if (p.sectorCount) txt << L" — " << FormatFileSize(p.sectorCount * 512);
        if (p.appleHfs) txt << L" [HFS+]";
        if (p.appleApfs) txt << L" [APFS]";
        if (p.efi) txt << L" [EFI]";
        txt << L"\r\n";
    }
    if (!shown) {
        for (const auto& p : dmg.partitions) {
            txt << L"📦\t" << (p.name.empty() ? tr(L"(без имени)", L"(unnamed)") : p.name.c_str());
            if (p.sectorCount) txt << L" — " << FormatFileSize(p.sectorCount * 512);
            txt << L"\r\n";
        }
    }

    txt << repeat(L'─', 90) << L"\r\n";
    txt << L"ℹ️ " << tr(L"Примечание", L"Note") << L"\t"
        << tr(L"Содержимое сжатых блоков не распаковывается — показаны метаданные UDIF и разметка.",
              L"Compressed blocks are not expanded — UDIF metadata and layout only.") << L"\r\n";
    return txt.str();
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
    std::vector<uint8_t> buf(fr.sectorSize);
    for (uint32_t s = VD_START_SECTOR; s < VD_START_SECTOR + 256; ++s) {
        if (!fr.read_sector(s, buf.data(), fr.sectorSize)) break;
        for (size_t i = 0; i + 5 <= fr.sectorSize; i++) {
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

    uint64_t totalSectors = fr.size_bytes() / fr.sectorSize;
    if (totalSectors < 257) return true;

    uint32_t anchorSecs[3] = {
        (uint32_t)(totalSectors - 1),
        (uint32_t)(totalSectors - 256),
        256u
    };

    uint32_t mvdsExtent = 0, mvdsLen = 0;
    for (uint32_t as : anchorSecs) {
        uint8_t tag[512]{};
        if (!fr.read_sector(as, tag, (DWORD)std::min<size_t>(512, fr.sectorSize))) continue;
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
            size_t next = ((off / fr.sectorSize) + 1) * fr.sectorSize;
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

struct LinuxInfo {
    bool detected = false;
    std::wstring distro;
    std::wstring version;
    std::wstring flavor;
    std::wstring arch;
    std::wstring imageType;
    std::wstring diskInfoLine;
    std::wstring kernelPath;
    std::wstring squashfsPath;
};

static bool read_iso_file_bytes(FileReader& fr, uint32_t lba, uint64_t fileSize,
    uint64_t offsetInFile, void* buf, DWORD size)
{
    if (size == 0) return false;
    if (size > 0x7FFFFFFF) return false;
    if (offsetInFile >= fileSize) return false;
    if (offsetInFile + size > fileSize) {
        uint64_t avail = fileSize - offsetInFile;
        if (avail > 0x7FFFFFFF) return false;
        size = (DWORD)avail;
    }
    uint64_t abs = (uint64_t)lba * fr.sectorSize + offsetInFile;
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
#ifdef _M_IX86
    if (xmlLen > 16 * 1024 * 1024) return false;
#endif
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
#ifdef _M_IX86
    const uint64_t chunk = 8 * 1024 * 1024;
#else
    const uint64_t chunk = 32 * 1024 * 1024;
#endif
    const size_t step = 512;
    std::vector<uint8_t> buf((size_t)chunk + 256);

    for (uint64_t base = 34ULL * fr.sectorSize; base < isoSize; base += chunk) {
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
    std::vector<IsoFileRef> linuxFiles;
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
    std::vector<uint8_t> fe(fr.sectorSize);
    if (!fr.read_sector(partBase + feLba, fe.data(), fr.sectorSize)) return false;
    if (!udf_tag_ok(fe.data()) || rd_le16(fe.data()) != 261) return false;
    if (infoLen) *infoLen = rd_le64(fe.data() + 56);
    uint32_t lEa = rd_le32(fe.data() + 168);
    uint32_t lAd = rd_le32(fe.data() + 172);
    if (176 + lEa + 8 > fr.sectorSize) return false;
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
            { dataLba = icbLba; dataLen = icbLen ? icbLen : fr.sectorSize; }
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
        if (!fr.read_sector(s, sec, fr.sectorSize)) return false;
        for (size_t base = 0; base + 416 <= fr.sectorSize; base += 4) {
            if (!udf_tag_ok(sec + base) || rd_le16(sec + base) != 256) continue;
            uint32_t icbLba = 0, icbLen = 0;
            if (!udf_read_long_ad(sec + base + 400, icbLba, icbLen) || !icbLba) continue;
            partBase = pBase ? pBase : s;
            if (udf_fe_data_extent(fr, partBase, icbLba, rootLba, rootLen))
                return rootLba != 0;
            rootLba = icbLba;
            rootLen = icbLen ? icbLen : fr.sectorSize;
            return true;
        }
        return false;
    };

    if (sum.udfPartitionStart) {
        uint32_t searchLen = sum.udfPartitionLength ? std::min(sum.udfPartitionLength, 512u) : 512u;
        for (uint32_t s = sum.udfPartitionStart; s < sum.udfPartitionStart + searchLen; ++s)
            if (try_fsd_in_sector(s, sum.udfPartitionStart)) return true;
    }

    uint64_t totalSectors = fr.size_bytes() / fr.sectorSize;
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
    if (toRead == 0) toRead = fr.sectorSize;
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
                outLen = icbLen ? icbLen : fr.sectorSize;
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
        curLen = nextLen ? nextLen : fr.sectorSize;
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

static std::wstring trim_w(const std::wstring& s) {
    size_t a = 0, b = s.size();
    while (a < b && iswspace(s[a])) a++;
    while (b > a && iswspace(s[b - 1])) b--;
    return (a < b) ? s.substr(a, b - a) : std::wstring{};
}

static bool has_windows_install_evidence(const ScanResult& scan) {
    for (const auto& f : scan.winFiles) {
        std::wstring lp = ToLower(f.path);
        if (lp.find(L"/sources/install.") != std::wstring::npos) return true;
        if (lp.find(L"/sources/boot.wim") != std::wstring::npos) return true;
        if (lp.find(L"/sources/ei.cfg") != std::wstring::npos) return true;
        if (lp.find(L"/setup.exe") != std::wstring::npos) return true;
        if (lp.find(L"bootmgr") != std::wstring::npos) return true;
    }
    return false;
}

static bool is_likely_microsoft_iso(const IsoSummary& sum, const ScanResult& scan) {
    if (has_windows_install_evidence(scan)) return true;
    if (scan.foundWinBootMgr) return true;
    std::wstring pub = ToLower(sum.publisherId + L" " + sum.dataPreparerId);
    std::wstring app = ToLower(sum.appId);
    if (pub.find(L"microsoft") != std::wstring::npos && app.find(L"oscdimg") != std::wstring::npos)
        return true;
    std::wstring vol = ToLower(sum.volId);
    if (vol.find(L"windows") != std::wstring::npos) return true;
    if (vol.find(L"win7") != std::wstring::npos || vol.find(L"win8") != std::wstring::npos) return true;
    if (vol.find(L"win10") != std::wstring::npos || vol.find(L"win11") != std::wstring::npos) return true;
    if (vol.find(L"_win") != std::wstring::npos) return true;
    if (vol.find(L"win_") != std::wstring::npos) return true;
    return false;
}

static bool is_likely_linux_iso(const IsoSummary& sum, const ScanResult& scan) {
    if (!scan.linuxFiles.empty()) return true;
    std::wstring vol = ToLower(sum.volId + L" " + sum.sysId);
    if (vol.find(L"ubuntu") != std::wstring::npos) return true;
    if (vol.find(L"debian") != std::wstring::npos) return true;
    if (vol.find(L"fedora") != std::wstring::npos) return true;
    if (vol.find(L"linuxmint") != std::wstring::npos || vol.find(L"linux mint") != std::wstring::npos) return true;
    if (vol.find(L"archlinux") != std::wstring::npos || vol.find(L"arch linux") != std::wstring::npos) return true;
    if (vol.find(L"opensuse") != std::wstring::npos || vol.find(L"open suse") != std::wstring::npos) return true;
    if (vol.find(L"centos") != std::wstring::npos) return true;
    if (vol.find(L"clonezilla") != std::wstring::npos) return true;
    return false;
}

static std::wstring linux_arch_from_text(const std::wstring& text) {
    std::wstring t = ToLower(text);
    if (t.find(L"amd64") != std::wstring::npos || t.find(L"x86_64") != std::wstring::npos) return L"x64";
    if (t.find(L"i386") != std::wstring::npos || t.find(L"i686") != std::wstring::npos) return L"x86";
    if (t.find(L"arm64") != std::wstring::npos || t.find(L"aarch64") != std::wstring::npos) return L"ARM64";
    return L"";
}

static void enrich_linux_from_vol_id(const std::wstring& volId, LinuxInfo& linux) {
    std::wstring v = trim_w(volId);
    if (v.empty()) return;
    std::wstring low = ToLower(v);
    auto set_distro = [&](const wchar_t* name) {
        linux.detected = true;
        linux.distro = name;
    };
    if (low.find(L"ubuntu") != std::wstring::npos) set_distro(L"Ubuntu");
    else if (low.find(L"debian") != std::wstring::npos) set_distro(L"Debian");
    else if (low.find(L"fedora") != std::wstring::npos) set_distro(L"Fedora");
    else if (low.find(L"linuxmint") != std::wstring::npos || low.find(L"linux mint") != std::wstring::npos)
        set_distro(L"Linux Mint");
    else if (low.find(L"archlinux") != std::wstring::npos) set_distro(L"Arch Linux");
    else if (low.find(L"opensuse") != std::wstring::npos) set_distro(L"openSUSE");
    else if (low.find(L"centos") != std::wstring::npos) set_distro(L"CentOS");
    else if (low.find(L"clonezilla") != std::wstring::npos) set_distro(L"Clonezilla");
    else return;

    linux.arch = linux_arch_from_text(v);
    size_t sp = v.find(L' ');
    if (sp != std::wstring::npos && sp + 1 < v.size()) {
        std::wstring rest = trim_w(v.substr(sp + 1));
        std::wstring restLow = ToLower(rest);
        size_t archPos = restLow.find(L" amd64");
        if (archPos == std::wstring::npos) archPos = restLow.find(L" x86_64");
        if (archPos == std::wstring::npos) archPos = restLow.find(L" i386");
        if (archPos != std::wstring::npos)
            linux.version = trim_w(rest.substr(0, archPos));
        else
            linux.version = rest;
    }
    if (low.find(L"desktop") != std::wstring::npos) linux.flavor = L"desktop";
    else if (low.find(L"server") != std::wstring::npos) linux.flavor = L"server";
    else if (low.find(L"live") != std::wstring::npos) linux.flavor = L"live";
    if (low.find(L"lts") != std::wstring::npos && linux.version.find(L"LTS") == std::wstring::npos)
        linux.version += L" LTS";
}

static void parse_dot_disk_info_text(const std::string& text, LinuxInfo& linux) {
    std::istringstream ss(text);
    std::string line;
    while (std::getline(ss, line)) {
        while (!line.empty() && (line.back() == '\r' || line.back() == ' ' || line.back() == '\t')) line.pop_back();
        if (line.empty() || line[0] == '#') {
            if (line.size() > 1 && line[0] == '#') {
                std::string content = line.substr(1);
                while (!content.empty() && content[0] == ' ') content.erase(0, 1);
                if (!content.empty()) line = content;
                else continue;
            }
            else continue;
        }
        int wlen = MultiByteToWideChar(CP_UTF8, 0, line.c_str(), -1, nullptr, 0);
        if (wlen <= 0) continue;
        std::wstring wline(wlen, L'\0');
        MultiByteToWideChar(CP_UTF8, 0, line.c_str(), -1, &wline[0], wlen);
        if (!wline.empty() && wline.back() == L'\0') wline.pop_back();
        linux.diskInfoLine = wline;
        enrich_linux_from_vol_id(wline, linux);
        break;
    }
}

static void fast_scan_linux_paths(FileReader& fr, const IsoSummary& sum, ScanResult& scan) {
    static const wchar_t* kPaths[] = {
        L"/.disk/info", L"/.disk/cd_type", L"/.disk/base_installable",
        L"/casper/vmlinuz", L"/casper/filesystem.squashfs", L"/casper/filesystem.manifest",
        L"/casper/install/filesystem.manifest",
        L"/boot/grub/grub.cfg", L"/EFI/ubuntu/grubx64.efi",
        L"/isolinux/isolinux.cfg", L"/live/filesystem.squashfs"
    };

    uint32_t rootLBA = sum.joliet ? sum.jolietRootLBA : sum.rootDirLBA;
    uint32_t rootSize = sum.joliet ? sum.jolietRootSize : sum.rootDirSize;

    auto add_if_found = [&](const IsoFileRef& ref) {
        for (const auto& w : scan.linuxFiles) {
            if (ToLower(w.path) == ToLower(ref.path)) return;
        }
        scan.linuxFiles.push_back(ref);
        scan.totalFiles++;
        std::wstring lp = ToLower(ref.path);
        if (lp.find(L"grub") != std::wstring::npos) scan.foundGRUB2 = true;
        if (lp.find(L"isolinux") != std::wstring::npos) scan.foundISOLINUX = true;
        if (lp.find(L"/efi/ubuntu") != std::wstring::npos) {
            scan.foundGRUB2 = true;
            scan.foundEFI = true;
        }
        if (lp.find(L"/casper/") != std::wstring::npos) scan.foundEFI = true;
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

static void analyze_linux_media(FileReader& fr, const ScanResult& scan, const IsoSummary& sum, LinuxInfo& linux) {
    if (!is_likely_linux_iso(sum, scan)) return;
    if (is_likely_microsoft_iso(sum, scan) && has_windows_install_evidence(scan)) return;

    linux.detected = true;
    enrich_linux_from_vol_id(sum.volId, linux);

    const IsoFileRef* diskInfo = nullptr;
    for (const auto& f : scan.linuxFiles) {
        std::wstring lp = ToLower(f.path);
        if (lp.find(L"/.disk/info") != std::wstring::npos) diskInfo = &f;
        else if (lp.find(L"/casper/vmlinuz") != std::wstring::npos) linux.kernelPath = f.path;
        else if (lp.find(L"filesystem.squashfs") != std::wstring::npos) linux.squashfsPath = f.path;
        else if (lp.find(L"/casper/") != std::wstring::npos && linux.squashfsPath.empty())
            linux.squashfsPath = f.path;
    }

    if (diskInfo && diskInfo->size > 0) {
        size_t n = (size_t)std::min<uint64_t>(diskInfo->size, kMaxSmallTextFile);
        std::vector<uint8_t> buf(n);
        if (read_iso_file_bytes(fr, diskInfo->lba, diskInfo->size, 0, buf.data(), (DWORD)n)) {
            std::string text((const char*)buf.data(), n);
            parse_dot_disk_info_text(text, linux);
        }
    }

    if (linux.distro.empty()) linux.distro = L"Linux";
    if (linux.arch.empty()) linux.arch = linux_arch_from_text(sum.volId);
    if (!linux.kernelPath.empty() || !linux.squashfsPath.empty()) {
        linux.imageType = L"Live ISO (casper)";
        if (linux.flavor.empty()) linux.flavor = L"desktop (live)";
    }
    else if (linux.flavor == L"server")
        linux.imageType = L"Install ISO (server)";
    else
        linux.imageType = L"Linux ISO";
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

    if (!is_likely_microsoft_iso(sum, scan)) return;
    if (is_likely_linux_iso(sum, scan) && !has_windows_install_evidence(scan)) return;

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

    if (eiCfg && eiCfg->size > 0) {
        size_t n = (size_t)std::min<uint64_t>(eiCfg->size, kMaxSmallTextFile);
        std::vector<uint8_t> buf(n);
        if (read_iso_file_bytes(fr, eiCfg->lba, eiCfg->size, 0, buf.data(), (DWORD)n)) {
            std::string text((const char*)buf.data(), n);
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

    if (win.editions.empty() && is_likely_microsoft_iso(sum, scan) && g_optFullScan) {
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

    const int MAX_CATSZ = (int)fr.sectorSize * 4;
    std::vector<uint8_t> buf(MAX_CATSZ, 0);
    if (!fr.read_sector(catalogLBA, buf.data(), fr.sectorSize)) return false;
    fr.read_sector(catalogLBA + 1, buf.data() + fr.sectorSize, fr.sectorSize);
    fr.read_sector(catalogLBA + 2, buf.data() + 2 * fr.sectorSize, fr.sectorSize);
    fr.read_sector(catalogLBA + 3, buf.data() + 3 * fr.sectorSize, fr.sectorSize);

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
    cf.crTextColor = g_fgColor;
    cf.yHeight = 240;
    StringCchCopyW(cf.szFaceName, LF_FACESIZE, L"Consolas");
    SendMessageW(hRE, EM_SETCHARFORMAT, SCF_ALL, (LPARAM)&cf);
    SendMessageW(hRE, EM_SETBKGNDCOLOR, 0, (LPARAM)g_bgColor);
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
    int verbose = GetPrivateProfileIntW(L"IsoLister", L"Verbose", g_optVerbose, iniPath);
    int dark = GetPrivateProfileIntW(L"IsoLister", L"Dark", g_optDark, iniPath);
    g_optDepth = (depth > 0 && depth <= 32) ? depth : g_optDepth;
    g_optMaxNodes = (maxN >= 1000 && maxN <= 1000000) ? maxN : g_optMaxNodes;
    g_optShowBootEntries = (showB != 0) ? 1 : 0;
    g_optShowFileList = (showF != 0) ? 1 : 0;
    g_optMaxFileList = (maxF >= 50 && maxF <= 100000) ? maxF : g_optMaxFileList;
    g_optFullScan = (fullScan != 0) ? 1 : 0;
    g_optVerbose = (verbose != 0) ? 1 : 0;
    if (dark >= 0 && dark <= 2) g_optDark = dark;
}

static void resolve_wincmd_ini(wchar_t* out, size_t cch) {
    out[0] = 0;
    if (!g_iniPath.empty()) {
        StringCchCopyW(out, cch, g_iniPath.c_str());
        wchar_t* slash = wcsrchr(out, L'\\');
        if (slash) {
            StringCchCopyW(slash + 1, cch - (size_t)(slash + 1 - out), L"wincmd.ini");
            if (GetFileAttributesW(out) != INVALID_FILE_ATTRIBUTES) return;
        }
    }
    wchar_t appdata[MAX_PATH]{};
    if (GetEnvironmentVariableW(L"APPDATA", appdata, MAX_PATH) > 0) {
        StringCchPrintfW(out, cch, L"%s\\GHISLER\\wincmd.ini", appdata);
        if (GetFileAttributesW(out) != INVALID_FILE_ATTRIBUTES) return;
        StringCchPrintfW(out, cch, L"%s\\GHISLER\\WINCMD.INI", appdata);
    }
}

static void load_options_from_ini() {
    g_uiRu = false;
    if (!g_iniPath.empty())
        load_options_from_ini_file(g_iniPath.c_str());

    wchar_t wincmd[MAX_PATH]{};
    resolve_wincmd_ini(wincmd, MAX_PATH);
    if (wincmd[0] && (g_iniPath.empty() || _wcsicmp(wincmd, g_iniPath.c_str()) != 0))
        load_options_from_ini_file(wincmd);

    if (wincmd[0])
        detect_ui_language_from_ini(wincmd);
    if (!g_iniPath.empty())
        detect_ui_language_from_ini(g_iniPath.c_str());

    // Theme follows TC DarkMode (cm_SwitchDarkMode), not OS AppsUseLightTheme
    recompute_theme(wincmd[0] ? wincmd : (g_iniPath.empty() ? nullptr : g_iniPath.c_str()));

    log_line(L"Options: ScanDepth=%d MaxNodes=%d ShowBootEntries=%d ShowFileList=%d MaxFileList=%d FullScan=%d Verbose=%d Dark=%d uiRu=%d darkMode=%d",
        g_optDepth, g_optMaxNodes, g_optShowBootEntries, g_optShowFileList, g_optMaxFileList,
        g_optFullScan, g_optVerbose, g_optDark, g_uiRu ? 1 : 0, g_darkMode ? 1 : 0);
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



        AppendMenuW(menu, MF_STRING | (hasSelection ? 0 : MF_GRAYED), IDM_CTX_COPY,
            tr(L"Копировать	Ctrl+C", L"Copy	Ctrl+C"));

        AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);

        AppendMenuW(menu, MF_STRING, IDM_CTX_SELECTALL,
            tr(L"Выделить всё	Ctrl+A", L"Select all	Ctrl+A"));



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

    // WM_SIZE: do not MoveWindow(self) here — re-enters WM_SIZE and can loop.
    // Size is set once in ListLoadW via FitWindowToParentClient; TC resizes the child itself.

    case WM_NCDESTROY: {
        WNDPROC saved = orig;
        UnsubclassRichEdit(hwnd);
        return CallWindowProcW(saved, hwnd, msg, wParam, lParam);
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



static void UnsubclassRichEdit(HWND hwnd) {
    auto it = g_richWndProcMap.find(hwnd);
    if (it == g_richWndProcMap.end()) return;
    WNDPROC orig = it->second;
    g_richWndProcMap.erase(it);
    if (IsWindow(hwnd))
        SetWindowLongPtrW(hwnd, GWLP_WNDPROC, (LONG_PTR)orig);
}

static void FitWindowToParentClient(HWND child, HWND parent) {
    if (!IsWindow(child) || !IsWindow(parent)) return;
    RECT rc{};
    if (!GetClientRect(parent, &rc)) return;
    int w = rc.right - rc.left;
    int h = rc.bottom - rc.top;
    if (w < 1) w = 1;
    if (h < 1) h = 1;
    MoveWindow(child, 0, 0, w, h, TRUE);
}

static HWND CreateRichEditView(HWND parent, DWORD style) {
    static const wchar_t* kClasses[] = { MSFTEDIT_CLASS, L"RichEdit20W", nullptr };
    for (int i = 0; kClasses[i]; ++i) {
        const wchar_t* cls = kClasses[i];
        if (cls == MSFTEDIT_CLASS) {
            if (!g_hMsftEdit) g_hMsftEdit = LoadLibraryW(L"Msftedit.dll");
            if (!g_hMsftEdit) continue;
        }
        else {
            LoadLibraryW(L"Riched20.dll");
        }
        HWND h = CreateWindowExW(
            WS_EX_CLIENTEDGE, cls, L"", style,
            0, 0, 0, 0, parent, (HMENU)1, g_hInst, nullptr);
        if (h) {
            log_line(L"CreateRichEditView: class=%s ok", cls);
            return h;
        }
        log_line(L"CreateRichEditView: class=%s failed err=%lu", cls, GetLastError());
    }
    return nullptr;
}

static void SubclassRichEdit(HWND hwnd) {
    if (!IsWindow(hwnd)) return;
    if (g_richWndProcMap.find(hwnd) != g_richWndProcMap.end()) return;

    SetLastError(0);
    WNDPROC old = (WNDPROC)SetWindowLongPtrW(hwnd, GWLP_WNDPROC, (LONG_PTR)RichEditSubclassProc);
    if (!old || old == RichEditSubclassProc) {
        if (GetLastError() != 0)
            log_line(L"SetWindowLongPtrW(subclass) failed: %lu", GetLastError());
        return;
    }
    g_richWndProcMap[hwnd] = old;
}



static std::wstring generate_iso_report(const wchar_t* FileToLoad, bool compact)
{
    std::wostringstream txt;
    ScanResult scan{};

    FileReader fr;
    IsoSummary sum;

    if (!FileToLoad || !fr.open(FileToLoad)) {
        txt << tr(L"Ошибка", L"Error") << L"\t"
            << tr(L"Не удалось открыть файл ❌", L"Failed to open file ❌") << L"\r\n";
        return txt.str();
    }

    UINT detectedSector = DEFAULT_SECTOR_SIZE;
    if (!probe_iso_layout(fr, detectedSector)) {
        UdIfInfo dmg;
        if (probe_udif_dmg(fr, dmg, FileToLoad))
            return generate_udif_dmg_report(FileToLoad, fr, dmg);
        VhdInfo vhd;
        if (probe_vhdx(fr, vhd) || probe_vhd(fr, vhd))
            return generate_vhd_report(FileToLoad, fr, vhd);
        DiskImageInfo disk;
        if (probe_disk_image(fr, disk))
            return generate_disk_image_report(FileToLoad, fr, disk);
        txt << tr(L"Ошибка", L"Error") << L"\t"
            << tr(L"Не обнаружена сигнатура ISO9660, UDIF (.dmg), VHD/VHDX и разметка диска (MBR/GPT) ❌",
                  L"No ISO9660, UDIF (.dmg), VHD/VHDX or disk layout (MBR/GPT) signature found ❌") << L"\r\n";
        return txt.str();
    }
    fr.sectorSize = detectedSector;
    std::vector<uint8_t> sec(fr.sectorSize);

    for (uint32_t s = VD_START_SECTOR; s < VD_START_SECTOR + kMaxVolumeDescriptors; ++s) {
        if (!fr.read_sector(s, sec.data(), fr.sectorSize)) break;
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

    if (g_optFullScan) {
        if (rootLBA && rootSize)
            scan = bfs_scan(fr, rootLBA, rootSize, sum.joliet, g_optDepth, g_optMaxNodes);
        if (sum.hasUDF)
            udf_scan_tree(fr, sum, scan, g_optDepth);
    }
    else {
        fast_scan_targeted(fr, sum, scan);
        fast_scan_linux_paths(fr, sum, scan);
    }

    if (scan.rrDetected) sum.rockRidge = true;
    sum.foundGRUB2 = scan.foundGRUB2;
    sum.foundGRUBLegacy = scan.foundGRUBLegacy;
    sum.foundISOLINUX = scan.foundISOLINUX;
    sum.foundSyslinuxMenu = scan.foundSyslinuxMenu;
    sum.foundSystemdBoot = scan.foundSystemdBoot;
    sum.foundWinBootMgr = scan.foundWinBootMgr;
    sum.foundGenericEFI = scan.foundGenericEFI;
    if (!scan.configHits.empty()) sum.configHits = scan.configHits;

    if (sum.foundWinBootMgr) sum.bootLoader = L"Windows Boot Manager 🪟";
    else if (sum.foundGRUB2) sum.bootLoader = L"GRUB2 🐧";
    else if (sum.foundGRUBLegacy) sum.bootLoader = L"GRUB (legacy) 🐧";
    else if (sum.foundSystemdBoot) sum.bootLoader = L"systemd-boot 🐧";
    else if (sum.foundISOLINUX || sum.foundSyslinuxMenu) sum.bootLoader = L"ISOLINUX/SYSLINUX 🧰";
    else if (sum.foundGenericEFI || sum.uefiBoot) sum.bootLoader = L"EFI (generic) ✨";

    WindowsInfo winInfo{};
    LinuxInfo linuxInfo{};
    analyze_linux_media(fr, scan, sum, linuxInfo);
    analyze_windows_media(fr, scan, winInfo, sum);

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
            bi.note = tr(L"Может не пройти Secure Boot на системах с сертификатом Windows UEFI CA 2023",
                         L"May fail Secure Boot on systems with Windows UEFI CA 2023 certificate");
        uefiBoots.push_back(std::move(bi));
    }

    bool bootMarker = false;
    if (fr.read_sector(17, sec.data(), fr.sectorSize) && sec.size() >= 512)
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

    auto append_wim_editions = [&](bool withHeader) {
        if (!winInfo.detected || winInfo.editions.empty()) return;
        if (withHeader) txt << repeat(L'─', 90) << L"\r\n";
        txt << tr(L"Редакции (WIM)", L"WIM editions") << L"\t"
            << (int)winInfo.editions.size() << L" "
            << tr(L"образ(ов)", L"image(s)") << L"\r\n";
        txt << L"#\t" << tr(L"Название", L"Name") << L"\tEditionID\t" << tr(L"Версия", L"Version") << L"\r\n";
        for (const auto& ed : winInfo.editions) {
            txt << ed.index << L"\t"
                << (ed.displayName.empty() ? ed.name : ed.displayName) << L"\t"
                << (ed.editionId.empty() ? L"—" : ed.editionId) << L"\t"
                << (ed.version.empty() ? L"—" : ed.version);
            if (!ed.arch.empty()) txt << L" (" << ed.arch << L")";
            if (!ed.language.empty()) txt << L" [" << ed.language << L"]";
            txt << L"\r\n";
        }
    };

    txt << L"🗂 " << tr(L"Тип ФС", L"FS type") << L"\t" << fsType << L"\r\n";
    txt << repeat(L'─', 90) << L"\r\n";
    if (sum.hasUDF)
        txt << tr(L"Анализ ISO", L"ISO analysis") << L"\t" << tr(L"Образ UDF ✅", L"UDF image ✅") << L"\r\n";
    txt << L"Boot Marker\t" << yesno(bootMarker) << L"\r\n";
    if (!uefiBoots.empty()) {
        txt << tr(L"UEFI-загрузчики", L"UEFI bootloaders") << L"\t\r\n";
        for (const auto& bi : uefiBoots) {
            txt << L"  •\t" << bi.path;
            if (!bi.signer.empty()) txt << L" — " << bi.signer;
            txt << L"\r\n";
            if (!bi.note.empty()) txt << L"  ⚠️\t" << bi.note << L"\r\n";
        }
    }
    if (!sum.volId.empty())
        txt << tr(L"Метка ISO", L"ISO label") << L"\t'" << sum.volId << L"'\r\n";
    if (linuxInfo.detected) {
        std::wstring detected = linuxInfo.distro;
        if (!linuxInfo.version.empty()) detected += L" " + linuxInfo.version;
        txt << tr(L"Обнаружено", L"Detected") << L"\t" << detected << L"\r\n";
        if (!linuxInfo.arch.empty())
            txt << tr(L"Архитектура", L"Architecture") << L"\t" << linuxInfo.arch << L"\r\n";
        if (sum.uefiBoot || !uefiBoots.empty()) txt << tr(L"Использует", L"Uses") << L"\tEFI ✅\r\n";
        if (sum.biosBoot || scan.foundISOLINUX) txt << tr(L"Использует", L"Uses") << L"\tBIOS (isolinux/grub) ✅\r\n";
        if (!linuxInfo.squashfsPath.empty())
            txt << tr(L"Использует", L"Uses") << L"\t" << tr(L"Live-система (squashfs)", L"Live system (squashfs)") << L" ✅\r\n";
    }
    else if (winInfo.detected) {
        std::wstring detected = winInfo.productVersion;
        if (detected.empty()) detected = L"Windows";
        txt << tr(L"Обнаружено", L"Detected") << L"\t" << detected << L"\r\n";
        if (!winInfo.buildNumber.empty())
            txt << L"Build\t" << winInfo.buildNumber << L"\r\n";
        if (sum.uefiBoot || !uefiBoots.empty()) txt << tr(L"Использует", L"Uses") << L"\tEFI ✅\r\n";
        if (sum.biosBoot || sum.foundWinBootMgr) txt << tr(L"Использует", L"Uses") << L"\tBootmgr (BIOS/UEFI) ✅\r\n";
        if (!wimVersion.empty()) {
            std::wstring installName = installRef && installRef->path.find(L".esd") != std::wstring::npos
                ? L"Install.esd" : L"Install.wim";
            txt << tr(L"Использует", L"Uses") << L"\t" << installName
                << L" (" << tr(L"версия", L"version") << L" " << wimVersion << L") ✅\r\n";
        }
    }

    // Редакции WIM — всегда вверху (и F3, и Ctrl+Q)
    append_wim_editions(true);

    if (compact) {
        if (sum.biosBoot && sum.uefiBoot) txt << tr(L"Тип загрузки", L"Boot type") << L"\tBIOS + UEFI\r\n";
        else if (sum.biosBoot)            txt << tr(L"Тип загрузки", L"Boot type") << L"\tBIOS\r\n";
        else if (sum.uefiBoot)            txt << tr(L"Тип загрузки", L"Boot type") << L"\tUEFI\r\n";
        if (!sum.bootLoader.empty())
            txt << tr(L"Загрузчик", L"Bootloader") << L"\t" << sum.bootLoader << L"\r\n";
        return txt.str();
    }

    if (g_optVerbose) {
        if (sum.hasPVD) {
            double MB = (double)sum.volBlocks * sum.logicalBlockSize / (1024.0 * 1024.0);
            txt << repeat(L'─', 90) << L"\r\n";
            txt << L"System ID\t" << sum.sysId << L"\r\n";
            txt << L"Volume ID\t" << sum.volId << L"\r\n";
            txt << L"Application ID\t" << sum.appId << L"\r\n";
            if (!sum.publisherId.empty()) txt << L"Publisher\t" << sum.publisherId << L"\r\n";
            if (!sum.dataPreparerId.empty()) txt << L"Data Preparer\t" << sum.dataPreparerId << L"\r\n";
            if (!sum.volumeSetId.empty()) txt << L"Volume Set ID\t" << sum.volumeSetId << L"\r\n";
            if (sum.volumeSetSize) txt << L"Volume Set Size\t" << sum.volumeSetSize << L"\r\n";
            if (sum.volumeSequenceNumber) txt << L"Volume Sequence\t" << sum.volumeSequenceNumber << L"\r\n";
            txt << L"Logical Block Size\t" << sum.logicalBlockSize << L"\r\n";
            txt << L"Volume Space\t" << sum.volBlocks << L" "
                << tr(L"блоков", L"blocks") << L" (≈ " << (int)(MB + 0.5) << L" MB)\r\n";
            txt << L"Path Table\tL " << sum.pathTableL << L", M " << sum.pathTableM
                << L", size " << sum.pathTableSize << L" " << tr(L"байт", L"bytes") << L"\r\n";
            txt << L"Root Dir\tLBA " << (sum.joliet ? sum.jolietRootLBA : sum.rootDirLBA)
                << L", size " << (sum.joliet ? sum.jolietRootSize : sum.rootDirSize)
                << L" " << tr(L"байт", L"bytes") << L"\r\n";
            txt << L"🗓 " << tr(L"Создан", L"Created") << L"\t" << sum.created << L"\r\n";
            txt << L"🗓 " << tr(L"Изменён", L"Modified") << L"\t" << sum.modified << L"\r\n";
            txt << L"Joliet\t" << (sum.joliet ? (yesno(true) + L" (esc=" + ATrimRight(sum.jolietEsc) + L")") : yesno(false)) << L"\r\n";
            txt << L"Rock Ridge\t" << yesno(sum.rockRidge) << L"\r\n";
        }
        else {
            txt << L"⚠️ " << tr(L"Предупреждение", L"Warning") << L"\t"
                << tr(L"PVD не найден — возможно, это не ISO9660", L"PVD not found — may not be ISO9660") << L"\r\n";
        }

        if (sum.hasUDF) {
            txt << repeat(L'─', 90) << L"\r\n";
            txt << L"📀 UDF (ECMA-167)\t\r\n";
            txt << tr(L"NSR версия", L"NSR version") << L"\tNSR0" << sum.udfNsrVersion << L"\r\n";
            if (!sum.udfPrimaryVolumeId.empty())
                txt << L"Primary Volume ID\t" << sum.udfPrimaryVolumeId << L"\r\n";
            if (!sum.udfLogicalVolumeId.empty())
                txt << L"Logical Volume ID\t" << sum.udfLogicalVolumeId << L"\r\n";
            if (!sum.udfVolumeSetId.empty())
                txt << L"Volume Set ID\t" << sum.udfVolumeSetId << L"\r\n";
            if (sum.udfPartitionLength)
                txt << tr(L"Раздел", L"Partition") << L"\tLBA " << sum.udfPartitionStart << L", "
                    << sum.udfPartitionLength << L" " << tr(L"секторов", L"sectors") << L"\r\n";
        }
    }
    else if (sum.hasPVD) {
        // краткий режим: только даты, без Path Table / Root Dir
        if (!sum.created.empty() || !sum.modified.empty()) {
            if (!sum.created.empty())
                txt << L"🗓 " << tr(L"Создан", L"Created") << L"\t" << sum.created << L"\r\n";
            if (!sum.modified.empty())
                txt << L"🗓 " << tr(L"Изменён", L"Modified") << L"\t" << sum.modified << L"\r\n";
        }
        if (sum.joliet || sum.rockRidge) {
            txt << L"Joliet\t" << yesno(sum.joliet) << L"\r\n";
            txt << L"Rock Ridge\t" << yesno(sum.rockRidge) << L"\r\n";
        }
    }

    txt << repeat(L'─', 90) << L"\r\n";
    txt << L"🚀 " << tr(L"Загрузка (El Torito)", L"Boot (El Torito)") << L"\t\r\n";
    txt << tr(L"Загрузочный ISO", L"Bootable ISO") << L"\t" << yesno(sum.bootable) << L"\r\n";
    if (sum.hasBootRecord) {
        txt << L"Boot Record\t" << yesno(true) << L"\r\n";
        if (g_optVerbose) {
            txt << L"Boot System ID\t" << (sum.bootSystemId.empty() ? L"—" : sum.bootSystemId.c_str()) << L"\r\n";
            txt << L"Boot Catalog LBA\t" << sum.bootCatalogLBA << L"\r\n";
        }
    }
    else {
        txt << L"Boot Record\t" << yesno(false) << L"\r\n";
    }
    if (sum.biosBoot && sum.uefiBoot) txt << tr(L"Тип загрузки", L"Boot type") << L"\tBIOS + UEFI\r\n";
    else if (sum.biosBoot)            txt << tr(L"Тип загрузки", L"Boot type") << L"\tBIOS\r\n";
    else if (sum.uefiBoot)            txt << tr(L"Тип загрузки", L"Boot type") << L"\tUEFI\r\n";
    else                               txt << tr(L"Тип загрузки", L"Boot type") << L"\t—\r\n";

    txt << tr(L"Загрузчик", L"Bootloader") << L"\t"
        << (sum.bootLoader.empty() ? tr(L"не обнаружен ❔", L"not detected ❔") : sum.bootLoader.c_str()) << L"\r\n";

    if (linuxInfo.detected) {
        txt << repeat(L'─', 90) << L"\r\n";
        txt << L"🐧 Linux\t\r\n";
        txt << tr(L"Тип образа", L"Image type") << L"\t"
            << (linuxInfo.imageType.empty() ? L"Linux ISO" : linuxInfo.imageType) << L"\r\n";
        txt << tr(L"Дистрибутив", L"Distro") << L"\t" << linuxInfo.distro << L"\r\n";
        if (!linuxInfo.version.empty())
            txt << tr(L"Версия", L"Version") << L"\t" << linuxInfo.version << L"\r\n";
        if (!linuxInfo.flavor.empty())
            txt << tr(L"Вариант", L"Flavor") << L"\t" << linuxInfo.flavor << L"\r\n";
        if (!linuxInfo.arch.empty())
            txt << tr(L"Архитектура", L"Architecture") << L"\t" << linuxInfo.arch << L"\r\n";
        if (!linuxInfo.diskInfoLine.empty())
            txt << L".disk/info\t" << linuxInfo.diskInfoLine << L"\r\n";
        if (!linuxInfo.kernelPath.empty())
            txt << tr(L"Ядро", L"Kernel") << L"\t" << linuxInfo.kernelPath << L"\r\n";
        if (!linuxInfo.squashfsPath.empty())
            txt << tr(L"Файловая система", L"Filesystem") << L"\t" << linuxInfo.squashfsPath << L"\r\n";
    }

    if (winInfo.detected) {
        txt << repeat(L'─', 90) << L"\r\n";
        txt << L"🪟 Windows\t\r\n";
        txt << tr(L"Тип образа", L"Image type") << L"\t"
            << (winInfo.imageType.empty() ? L"Windows" : winInfo.imageType) << L"\r\n";
        if (!winInfo.productVersion.empty())
            txt << tr(L"Версия", L"Version") << L"\t" << winInfo.productVersion << L"\r\n";
        if (!winInfo.buildNumber.empty())
            txt << tr(L"Сборка (build)", L"Build") << L"\t" << winInfo.buildNumber << L"\r\n";
        if (!winInfo.architecture.empty())
            txt << tr(L"Архитектура", L"Architecture") << L"\t" << winInfo.architecture << L"\r\n";
        if (!winInfo.channel.empty())
            txt << tr(L"Канал", L"Channel") << L"\t" << winInfo.channel << L"\r\n";
        if (!winInfo.defaultLanguage.empty())
            txt << tr(L"Язык (основной)", L"Language (primary)") << L"\t" << winInfo.defaultLanguage << L"\r\n";
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
        // editions already listed at top — skip duplicate table
        if (winInfo.editions.empty() && (winInfo.isInstallMedia || winInfo.bootImageSize)) {
            txt << tr(L"Редакции", L"Editions") << L"\t"
                << tr(L"не удалось прочитать XML из WIM/ESD", L"failed to read XML from WIM/ESD") << L"\r\n";
        }
        else if (winInfo.editions.empty() && sum.hasUDF && scan.totalFiles < 10) {
            txt << tr(L"Примечание", L"Note") << L"\t"
                << tr(L"файлы в UDF-разделе; install.wim не найден в ISO9660-дереве",
                      L"files are in UDF; install.wim not found in ISO9660 tree") << L"\r\n";
        }
    }

    if (!scan.largestFiles.empty()) {
        txt << repeat(L'─', 90) << L"\r\n";
        txt << L"📦 " << tr(L"Крупнейшие файлы", L"Largest files") << L"\t"
            << tr(L"топ-", L"top-") << (int)scan.largestFiles.size() << L"\r\n";
        txt << tr(L"Путь", L"Path") << L"\t" << tr(L"Размер", L"Size") << L"\t" << tr(L"Тип", L"Type") << L"\r\n";
        for (const auto& lf : scan.largestFiles) {
            txt << lf.path << L"\t" << FormatFileSize(lf.size) << L"\tFILE\r\n";
        }
    }

    if (g_optVerbose || !sum.configHits.empty()) {
        txt << repeat(L'─', 90) << L"\r\n";
        if (!sum.configHits.empty()) {
            txt << L"📝 " << tr(L"Конфигурационные файлы", L"Config files") << L"\t"
                << tr(L"найдено:", L"found:") << L" " << (int)sum.configHits.size() << L"\r\n";
            for (auto& p : sum.configHits) txt << L"\t" << p << L"\r\n";
        }
        else if (g_optVerbose) {
            txt << L"📝 " << tr(L"Конфигурационные файлы", L"Config files") << L"\t"
                << tr(L"не найдены", L"none found") << L"\r\n";
        }
    }

    if (g_optShowFileList && !scan.fileList.empty()) {
        txt << repeat(L'─', 90) << L"\r\n";
        txt << L"📁 " << tr(L"Содержимое", L"Contents") << L"\t"
            << tr(L"файлов:", L"files:") << L" " << scan.totalFiles << L", "
            << tr(L"каталогов:", L"dirs:") << L" " << scan.totalDirs;
        if ((int)scan.fileList.size() < scan.totalFiles + scan.totalDirs)
            txt << L" (" << tr(L"показано", L"shown") << L" " << (int)scan.fileList.size()
                << L" " << tr(L"из", L"of") << L" " << (scan.totalFiles + scan.totalDirs) << L")";
        txt << L"\r\n";
        txt << tr(L"Путь", L"Path") << L"\t" << tr(L"Размер", L"Size") << L"\t" << tr(L"Тип", L"Type") << L"\r\n";
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
            txt << L"📚 Boot Catalog — " << tr(L"все записи", L"all entries") << L"\r\n";
            txt << L"#\t" << tr(L"Платформа", L"Platform") << L"\tBootable\tMedia\tSegment\tSysType\tSectors\tLBA\r\n";
            int idx = 1;
            for (const auto& be : bootEntries2) {
                std::wstring boot = be.bootable ? yesno(true) : yesno(false);
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
    log_line(L"ListLoadW: file=\"%s\" flags=%d parent=%p", FileToLoad ? FileToLoad : L"(null)", ShowFlags, ParentWin);

    if (!ParentWin || !IsWindow(ParentWin)) {
        log_line(L"ListLoadW: invalid parent window");
        return nullptr;
    }

    // Re-read TC DarkMode each open (user may toggle cm_SwitchDarkMode without reload)
    {
        wchar_t wincmd[MAX_PATH]{};
        resolve_wincmd_ini(wincmd, MAX_PATH);
        recompute_theme(wincmd[0] ? wincmd : nullptr);
    }

    bool quickView = (ShowFlags & lcp_fittowindow) != 0;
    std::wstring text;
    try {
        text = generate_iso_report(FileToLoad, quickView);
    }
    catch (...) {
        log_line(L"ListLoadW: generate_iso_report exception");
        text = std::wstring(tr(L"Ошибка", L"Error")) + L"\t"
            + tr(L"Не удалось сформировать отчёт ❌", L"Failed to build report ❌") + L"\r\n";
    }
    sanitize_wstring_for_richedit(text);
    log_line(L"ListLoadW: report chars=%u quickView=%d", (unsigned)text.size(), quickView ? 1 : 0);

    bool wrapText = (ShowFlags & lcp_wraptext) != 0;
    DWORD reStyle = WS_CHILD | WS_VISIBLE | WS_TABSTOP | WS_VSCROLL |
        ES_MULTILINE | ES_AUTOVSCROLL | ES_READONLY | ES_WANTRETURN;
    if (!wrapText) reStyle |= WS_HSCROLL | ES_AUTOHSCROLL;

    HWND hRE = CreateRichEditView(ParentWin, reStyle);
    if (!hRE) {
        log_line(L"ListLoadW: CreateRichEditView FAILED");
        return nullptr;
    }

    FitWindowToParentClient(hRE, ParentWin);
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

// Detect: ISO/DMG — обычные файлы; IMG — MULTIMEDIA в TC, без этого флага плагин игнорируется.
// IMG: MULTIMEDIA required by TC; no bare EXT="IMG" (would steal GEM/picture .img).
// BIN: raw dumps; VHD/VHDX: Hyper-V images.
static const char kIsoListerDetectString[] =
    "EXT=\"ISO\" | EXT=\"DMG\" | EXT=\"VHD\" | EXT=\"VHDX\" | "
    "(EXT=\"BIN\" & [510]=85 & [511]=170) | "
    "(EXT=\"BIN\" & SIZE>50000000) | "
    "(MULTIMEDIA & EXT=\"IMG\" & [510]=85 & [511]=170) | "
    "(MULTIMEDIA & EXT=\"IMG\" & [32769]=67 & [32770]=68 & [32771]=48 & [32772]=48 & [32773]=49) | "
    "(MULTIMEDIA & EXT=\"IMG\" & SIZE>50000000)";

extern "C" void __stdcall ListGetDetectString(char* DetectString, int maxlen)
{
    StringCchCopyA(DetectString, (size_t)maxlen, kIsoListerDetectString);
    log_line(L"ListGetDetectString called: %hs", kIsoListerDetectString);
}

extern "C" void __stdcall ListCloseWindow(HWND ListWin)
{
    log_line(L"ListCloseWindow hwnd=%p", ListWin);
    if (!ListWin) return;
    if (!IsWindow(ListWin)) {
        g_richWndProcMap.erase(ListWin);
        return;
    }
    UnsubclassRichEdit(ListWin);
    DestroyWindow(ListWin);
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
    case lc_newparams: {
        wchar_t wincmd[MAX_PATH]{};
        resolve_wincmd_ini(wincmd, MAX_PATH);
        recompute_theme(wincmd[0] ? wincmd : nullptr);
        RichSetDefaultCharFormat(ListWin);
        InvalidateRect(ListWin, nullptr, TRUE);
        return LISTPLUGIN_OK;
    }
    default:
        break;
    }

    return LISTPLUGIN_ERROR;
}

extern "C" int __stdcall ListSearchTextW(HWND ListWin, WCHAR* SearchString, int SearchParameter)
{
    if (!IsWindow(ListWin) || !SearchString || !SearchString[0])
        return LISTPLUGIN_ERROR;

    CHARRANGE sel{};
    SendMessageW(ListWin, EM_EXGETSEL, 0, (LPARAM)&sel);

    FINDTEXTEXW ft{};
    ft.lpstrText = SearchString;
    if (SearchParameter & lcs_findfirst) {
        ft.chrg.cpMin = 0;
        ft.chrg.cpMax = -1;
    }
    else if (SearchParameter & lcs_backwards) {
        ft.chrg.cpMin = 0;
        ft.chrg.cpMax = sel.cpMin;
    }
    else {
        ft.chrg.cpMin = sel.cpMax;
        ft.chrg.cpMax = -1;
    }

    DWORD flags = 0;
    if (!(SearchParameter & lcs_backwards)) flags |= FR_DOWN;
    if (SearchParameter & lcs_matchcase) flags |= FR_MATCHCASE;
    if (SearchParameter & lcs_wholewords) flags |= FR_WHOLEWORD;

    LRESULT pos = SendMessageW(ListWin, EM_FINDTEXTEXW, flags, (LPARAM)&ft);
    if (pos < 0) return LISTPLUGIN_ERROR;

    SendMessageW(ListWin, EM_EXSETSEL, 0, (LPARAM)&ft.chrgText);
    SendMessageW(ListWin, EM_SCROLLCARET, 0, 0);
    return LISTPLUGIN_OK;
}

extern "C" int __stdcall ListSearchText(HWND ListWin, char* SearchString, int SearchParameter)
{
    if (!SearchString) return LISTPLUGIN_ERROR;
    int wlen = MultiByteToWideChar(CP_ACP, 0, SearchString, -1, nullptr, 0);
    if (wlen <= 0) return LISTPLUGIN_ERROR;
    std::wstring w((size_t)wlen, L'\0');
    MultiByteToWideChar(CP_ACP, 0, SearchString, -1, &w[0], wlen);
    if (!w.empty() && w.back() == L'\0') w.pop_back();
    return ListSearchTextW(ListWin, w.empty() ? (WCHAR*)L"" : &w[0], SearchParameter);
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
    std::wstring report = generate_iso_report(argv[1], false);
    fputws(report.c_str(), stdout);
    if (report.empty()) {
        fwprintf(stderr, L"VERIFY FAIL: empty report\n");
        return 1;
    }
    bool isIso = report.find(L"ISO 9660") != std::wstring::npos;
    bool isDisk = report.find(L"Образ диска") != std::wstring::npos;
    bool isDmg = report.find(L"Apple Disk Image") != std::wstring::npos;
    if (!isIso && !isDisk && !isDmg) {
        fwprintf(stderr, L"VERIFY FAIL: unknown report type\n");
        return 1;
    }
    if (isIso && report.find(L"ISO 9660") == std::wstring::npos &&
        report.find(L"FS type") == std::wstring::npos && report.find(L"Тип ФС") == std::wstring::npos) {
        fwprintf(stderr, L"VERIFY FAIL: missing ISO summary markers\n");
        return 1;
    }
    if (isDisk && report.find(L"Разметка диска") == std::wstring::npos) {
        fwprintf(stderr, L"VERIFY FAIL: missing disk layout section\n");
        return 1;
    }
    if (isDmg && report.find(L"UDIF") == std::wstring::npos) {
        fwprintf(stderr, L"VERIFY FAIL: missing UDIF section\n");
        return 1;
    }
    fwprintf(stderr, L"VERIFY OK\n");
    return 0;
}
#endif
