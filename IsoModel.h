// IsoModel.h — разбор текстового отчёта IsoLister в структуру для отрисовки.
// Отчёт (IsoLister.cpp) остаётся единственным источником данных: модель только
// раскладывает его строки на секции / пары ключ-значение / таблицы и вытаскивает
// ключевые факты для шапки и плиток. Исходный текст хранится целиком (копирование).
#pragma once
#include <string>
#include <vector>
#include <cstdint>

enum IsoTag { IsoTagNone, IsoTagOk, IsoTagBad, IsoTagWarn, IsoTagUnknown, IsoTagCount };

struct IsoItem {
    enum Kind { Section, KV, Line, Table, Blank };
    Kind kind = Line;
    int ind = 0;                     // отступ в исходной строке (пробелы)
    std::wstring key, value;         // текст для показа (без декоративных эмодзи)
    int tag = IsoTagNone;            // статус из ✅ ❌ ⚠️ ❔
    bool mono = false;               // путь / hex / UUID
    bool bullet = false;             // "  •\t..."
    bool strong = false;             // подзаголовок внутри секции ("UEFI bootloaders")
    bool header = false;             // Table: строка заголовка
    std::vector<std::wstring> cells; // Table
    std::vector<int> cellTags;       // Table: статус каждой ячейки
    std::wstring plain;              // исходная строка отчёта (для копирования)
};

enum IsoKind { IsoKindUnknown, IsoKindIso, IsoKindDisk, IsoKindVhd, IsoKindWim, IsoKindDmg, IsoKindError };

struct IsoFacts {
    IsoKind kind = IsoKindUnknown;
    std::wstring os, osFamily, distro; // "Alpine Linux 3.20.3", "alpine", "Alpine Linux"
    std::wstring created;            // ISO 9660 creation date
    std::wstring version, build, arch, bootType, bootloader, label, fsType, imageType;
    std::wstring layout, partitions, unallocated, diskType, virtualSize, format, error, release;
    std::wstring signerNote;         // предупреждение о подписи UEFI (Secure Boot)
    int bootable = -1;               // -1 неизвестно, 0 нет, 1 да
    int editions = -1, configFiles = -1, bypassRules = -1, files = -1;
    std::vector<std::wstring> fsList;
};

struct IsoModel {
    std::wstring text;               // отчёт как есть (CRLF), копируется по Ctrl+A/C
    std::wstring brand;              // "IsoLister v1.2.0.0"
    std::vector<IsoItem> items;      // секции: Section, затем её строки
    IsoFacts facts;
};

// ru — язык подписей для безымянных секций ("Сводка" / "Summary").
void IsoParseReport(const std::wstring& text, bool ru, IsoModel& m);

// Утилиты, общие с видом
std::wstring IsoTrim(const std::wstring& s);
bool IsoIsEmojiCp(uint32_t cp);
