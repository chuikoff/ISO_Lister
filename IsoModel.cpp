// IsoModel.cpp — разбор текстового отчёта IsoLister (см. IsoModel.h).
// Формат отчёта: строка бренда, линейки из '─' между блоками, строки "ключ<TAB>значение",
// заголовки секций начинаются с эмодзи (🗂 🚀 🪟 🐧 📀 🍎 🧱 📁 📚 📝 💾 💿 📦 ℹ️),
// подстроки с отступом в два пробела, таблицы — несколько TAB в строке.
#include "IsoModel.h"
#include <cwctype>
#include <algorithm>

static bool is_hi(wchar_t c) { return c >= 0xD800 && c <= 0xDBFF; }
static bool is_lo(wchar_t c) { return c >= 0xDC00 && c <= 0xDFFF; }

bool IsoIsEmojiCp(uint32_t cp) {
    if (cp == 0x200D || cp == 0xFE0F || cp == 0x20E3) return true;  // ZWJ / VS16 / keycap
    if (cp >= 0x1F300 && cp <= 0x1FAFF) return true;                 // pictographs
    if (cp >= 0x1F1E6 && cp <= 0x1F1FF) return true;                 // flags
    if (cp >= 0x2600 && cp <= 0x27BF) return true;                   // misc symbols, dingbats
    if (cp == 0x2139 || cp == 0x2B50 || cp == 0x2B55) return true;   // ℹ ⭐ ⭕
    if (cp >= 0x23E9 && cp <= 0x23FA) return true;                   // ⏩ … ⏺
    return false;
}

std::wstring IsoTrim(const std::wstring& s) {
    size_t a = 0, b = s.size();
    while (a < b && (s[a] == L' ' || s[a] == L'\t' || s[a] == L'\r')) ++a;
    while (b > a && (s[b - 1] == L' ' || s[b - 1] == L'\t' || s[b - 1] == L'\r')) --b;
    return s.substr(a, b - a);
}

static uint32_t cp_at(const std::wstring& s, size_t i, size_t& len) {
    if (i < s.size() && is_hi(s[i]) && i + 1 < s.size() && is_lo(s[i + 1])) {
        len = 2;
        return 0x10000u + (((uint32_t)s[i] - 0xD800u) << 10) + ((uint32_t)s[i + 1] - 0xDC00u);
    }
    len = 1;
    return i < s.size() ? (uint32_t)s[i] : 0;
}
static uint32_t cp_before(const std::wstring& s, size_t end, size_t& len) {
    if (end >= 2 && is_lo(s[end - 1]) && is_hi(s[end - 2])) return cp_at(s, end - 2, len);
    len = 1;
    return end ? (uint32_t)s[end - 1] : 0;
}

// Leading emoji (and the spaces after it) are decoration: drop them, return the first code point.
static uint32_t strip_lead(std::wstring& s) {
    size_t i = 0, len = 0;
    uint32_t first = 0;
    while (i < s.size()) {
        uint32_t cp = cp_at(s, i, len);
        if (!IsoIsEmojiCp(cp)) break;
        if (!first && cp != 0xFE0F && cp != 0x200D) first = cp;
        i += len;
    }
    if (!first) return 0;
    while (i < s.size() && s[i] == L' ') ++i;
    s.erase(0, i);
    return first;
}

static int tag_of(uint32_t cp) {
    switch (cp) {
    case 0x2705: case 0x2714: return IsoTagOk;          // ✅ ✔
    case 0x274C: case 0x2716: case 0x26D4: return IsoTagBad; // ❌ ✖ ⛔
    case 0x26A0: return IsoTagWarn;                      // ⚠
    case 0x2754: case 0x2753: return IsoTagUnknown;      // ❔ ❓
    default: return IsoTagNone;
    }
}

// Trailing status emoji (✅ ❌ ⚠️ ❔) become a tag; other trailing emoji (🐧, ⚙️) are dropped.
static int strip_trail(std::wstring& s) {
    s = IsoTrim(s);
    size_t end = s.size(), len = 0;
    uint32_t base = 0;
    bool any = false;
    while (end > 0) {
        uint32_t cp = cp_before(s, end, len);
        if (!IsoIsEmojiCp(cp)) break;
        if (cp != 0xFE0F && cp != 0x200D) base = cp;
        end -= len;
        any = true;
    }
    if (!any || end == 0) return IsoTagNone; // a value that is only an emoji stays as is
    s = IsoTrim(s.substr(0, end));
    return tag_of(base);
}

static bool is_header_cp(uint32_t cp) {
    switch (cp) {
    case 0x1F5C2: case 0x1F680: case 0x1FA9F: case 0x1F427: case 0x1F4C0: case 0x1F34E:
    case 0x1F9F1: case 0x1F4C1: case 0x1F4DA: case 0x1F4DD: case 0x1F4BE: case 0x1F4BF:
    case 0x1F4E6: case 0x2139:
        return true;
    default:
        return false;
    }
}

static bool is_rule(const std::wstring& s) {
    size_t box = 0;
    for (wchar_t c : s) {
        if (c == 0x2500) ++box;
        else if (c != L' ' && c != L'\t') return false;
    }
    return box >= 8;
}

static bool is_uuid(const std::wstring& s) {
    if (s.size() != 36) return false;
    for (size_t i = 0; i < 36; ++i) {
        bool dash = i == 8 || i == 13 || i == 18 || i == 23;
        if (dash ? s[i] != L'-' : !iswxdigit(s[i])) return false;
    }
    return true;
}
static bool looks_mono(const std::wstring& v) {
    if (v.empty()) return false;
    if (v[0] == L'/' || v[0] == L'\\') return true;
    if (v.size() > 2 && v[0] == L'0' && (v[1] == L'x' || v[1] == L'X')) return true;
    if (v.compare(0, 4, L"LBA ") == 0) return true;
    if (v.find(L":\\") != std::wstring::npos) return true;
    return is_uuid(v);
}

static std::vector<std::wstring> split_tabs(const std::wstring& s) {
    std::vector<std::wstring> out;
    size_t a = 0;
    for (;;) {
        size_t b = s.find(L'\t', a);
        out.push_back(s.substr(a, b == std::wstring::npos ? std::wstring::npos : b - a));
        if (b == std::wstring::npos) break;
        a = b + 1;
    }
    return out;
}

static IsoItem parse_line(const std::wstring& raw, uint32_t& leadValueCp) {
    IsoItem it;
    it.plain = raw;
    leadValueCp = 0;
    size_t ind = 0;
    while (ind < raw.size() && raw[ind] == L' ') ++ind;
    it.ind = (int)ind;
    std::wstring body = raw.substr(ind);
    size_t tab = body.find(L'\t');
    std::wstring key = tab == std::wstring::npos ? body : body.substr(0, tab);
    std::wstring rest = tab == std::wstring::npos ? std::wstring() : body.substr(tab + 1);

    // tables: two or more TABs (editions, largest files, file list, boot catalog)
    if (ind == 0 && tab != std::wstring::npos && tab > 0 && rest.find(L'\t') != std::wstring::npos) {
        it.kind = IsoItem::Table;
        for (auto c : split_tabs(body)) {
            strip_lead(c);
            int tg = strip_trail(c);
            it.cells.push_back(IsoTrim(c));
            it.cellTags.push_back(tg);
        }
        return it;
    }
    std::wstring k2 = key;
    uint32_t lead = strip_lead(k2);
    k2 = IsoTrim(k2);
    if (ind == 0 && lead && is_header_cp(lead) && !k2.empty()) {
        it.kind = IsoItem::Section;
        it.key = k2;
        it.value = rest;
        leadValueCp = strip_lead(it.value);
        it.tag = strip_trail(it.value);
        return it;
    }
    if (tab == std::wstring::npos) {               // "  ⚙️ text", "  🔓 text"
        it.kind = IsoItem::Line;
        it.value = k2;
        it.tag = strip_trail(it.value);
        if (lead == 0x1F513 && it.tag == IsoTagNone) it.tag = IsoTagWarn; // 🔓 bypass rule
        if (lead == 0x26A0) it.tag = IsoTagWarn;
        it.mono = looks_mono(it.value);
        return it;
    }
    if (k2.empty() || k2 == L"•") {               // "\t/path", "  •\t...", "  ⚠️\tnote", "📦\tname"
        it.kind = IsoItem::Line;
        it.bullet = k2 == L"•" || lead == 0x1F4E6;
        it.value = rest;
        strip_lead(it.value);
        it.tag = strip_trail(it.value);
        if (lead == 0x26A0) it.tag = IsoTagWarn;
        it.mono = looks_mono(it.value);
        return it;
    }
    it.kind = IsoItem::KV;
    it.key = k2;
    it.value = rest;
    leadValueCp = strip_lead(it.value);
    it.tag = strip_trail(it.value);
    if (lead == 0x26A0 && it.tag == IsoTagNone) it.tag = IsoTagWarn;
    if (IsoTrim(it.value).empty()) {               // "UEFI bootloaders\t" — subheader
        it.kind = IsoItem::Line;
        it.strong = true;
        it.value = it.key;
        it.key.clear();
        return it;
    }
    it.mono = looks_mono(it.value);
    return it;
}

struct Sec {
    IsoItem head;
    bool titled = false;
    std::vector<IsoItem> rows;
};

static bool key_is(const std::wstring& k, const wchar_t* ru, const wchar_t* en) { return k == ru || k == en; }

static int leading_int(const std::wstring& s) {
    size_t i = 0;
    while (i < s.size() && !iswdigit(s[i])) ++i;
    if (i == s.size()) return -1;
    long long v = 0;
    while (i < s.size() && iswdigit(s[i]) && v < 100000000) v = v * 10 + (s[i++] - L'0');
    return (int)v;
}

static std::wstring lower(std::wstring s) {
    for (auto& c : s) c = (wchar_t)towlower(c);
    return s;
}

static std::wstring os_family(const std::wstring& text) {
    std::wstring t = lower(text);
    struct { const wchar_t* needle; const wchar_t* fam; } map[] = {
        { L"windows", L"windows" }, { L"ubuntu", L"ubuntu" }, { L"debian", L"debian" }, { L"alpine", L"alpine" },
        { L"fedora", L"fedora" }, { L"arch linux", L"arch" }, { L"archlinux", L"arch" }, { L"mint", L"mint" },
        { L"opensuse", L"opensuse" }, { L"suse", L"opensuse" }, { L"manjaro", L"manjaro" }, { L"kali", L"kali" },
        { L"centos", L"centos" }, { L"rocky", L"rocky" }, { L"alma", L"alma" }, { L"red hat", L"rhel" },
        { L"rhel", L"rhel" }, { L"gentoo", L"gentoo" }, { L"nixos", L"nixos" }, { L"elementary", L"elementary" },
        { L"pop!_os", L"pop" }, { L"zorin", L"zorin" }, { L"proxmox", L"proxmox" }, { L"truenas", L"truenas" },
        { L"freebsd", L"freebsd" }, { L"macos", L"macos" }, { L"mac os", L"macos" }, { L"os x", L"macos" },
        { L"linux", L"linux" },
    };
    for (auto& e : map) if (t.find(e.needle) != std::wstring::npos) return e.fam;
    return L"";
}

static void extract_facts(IsoModel& m, IsoKind kindHint) {
    IsoFacts& f = m.facts;
    f.kind = kindHint;
    std::wstring distro, section;
    for (const IsoItem& it : m.items) {
        if (it.kind == IsoItem::Section) {
            section = it.key;
            if (key_is(it.key, L"Редакции (WIM)", L"WIM editions")) f.editions = leading_int(it.value);
            else if (key_is(it.key, L"Конфигурационные файлы", L"Config files")) f.configFiles = std::max(0, leading_int(it.value));
            else if (key_is(it.key, L"Содержимое", L"Contents")) f.files = leading_int(it.value);
            else if (key_is(it.key, L"Разметка диска", L"Disk layout")) f.layout = it.value;
            continue;
        }
        if (it.kind == IsoItem::Line) {
            if (it.tag == IsoTagWarn && it.ind > 0 && f.signerNote.empty() && !it.bullet && it.value.find(L"UEFI") != std::wstring::npos)
                f.signerNote = it.value;
            continue;
        }
        if (it.kind != IsoItem::KV) continue;
        const std::wstring& k = it.key;
        const std::wstring& v = it.value;
        auto set = [&](std::wstring& dst) { if (dst.empty() && v != L"—" && v != L"-") dst = v; };
        if (key_is(k, L"Ошибка", L"Error")) set(f.error);
        else if (key_is(k, L"Тип ФС", L"FS type")) set(f.fsType);
        else if (key_is(k, L"Тип образа", L"Image type")) set(f.imageType);
        else if (key_is(k, L"Метка ISO", L"ISO label")) {
            std::wstring l = v;
            if (l.size() >= 2 && l.front() == L'\'' && l.back() == L'\'') l = l.substr(1, l.size() - 2);
            if (f.label.empty()) f.label = IsoTrim(l);
        }
        else if (key_is(k, L"Обнаружено", L"Detected")) set(f.os);
        else if (key_is(k, L"Дистрибутив", L"Distro")) { if (distro.empty()) distro = v; }
        else if (key_is(k, L"Создан", L"Created")) set(f.created);
        else if (key_is(k, L"Имя релиза", L"Release name")) set(f.release);
        else if (key_is(k, L"Версия", L"Version")) set(f.version);
        else if (k == L"Build" || k == L"Сборка (build)") set(f.build);
        else if (key_is(k, L"Архитектура", L"Architecture")) set(f.arch);
        else if (key_is(k, L"Тип загрузки", L"Boot type")) set(f.bootType);
        else if (key_is(k, L"Загрузчик", L"Bootloader")) { if (it.tag != IsoTagUnknown) set(f.bootloader); }
        else if (key_is(k, L"Загрузочный ISO", L"Bootable ISO")) f.bootable = it.tag == IsoTagOk ? 1 : it.tag == IsoTagBad ? 0 : f.bootable;
        else if (key_is(k, L"Обход проверок Win11", L"Win11 checks bypass")) f.bypassRules = leading_int(v);
        else if (key_is(k, L"Число образов (XML)", L"Image count (XML)")) { if (f.editions < 0) f.editions = leading_int(v); }
        else if (key_is(k, L"Число образов (заголовок)", L"Image count (header)")) { if (f.editions < 0) f.editions = leading_int(v); }
        else if (key_is(k, L"Разметка диска", L"Disk layout")) set(f.layout);
        else if (key_is(k, L"Разделов", L"Partitions")) set(f.partitions);
        else if (key_is(k, L"Неразмечено", L"Unallocated")) set(f.unallocated);
        else if (key_is(k, L"Тип диска", L"Disk type")) set(f.diskType);
        else if (key_is(k, L"Виртуальный размер", L"Virtual size")) set(f.virtualSize);
        else if (key_is(k, L"Формат", L"Format")) set(f.format);
        else if (key_is(k, L"ФС", L"FS")) {
            if (std::find(f.fsList.begin(), f.fsList.end(), v) == f.fsList.end()) f.fsList.push_back(v);
        }
    }
    f.distro = distro;
    if (f.os.empty()) f.os = distro;
    if (f.kind == IsoKindUnknown) {
        if (!f.fsType.empty()) f.kind = IsoKindIso;
        else if (!f.error.empty()) f.kind = IsoKindError;
    }
    f.osFamily = os_family(f.os + L" " + distro + L" " + f.imageType + L" " + f.release);
}

void IsoParseReport(const std::wstring& text, bool ru, IsoModel& m) {
    m = IsoModel();
    m.text = text;
    std::vector<std::wstring> lines;
    {
        size_t a = 0;
        while (a <= text.size()) {
            size_t b = text.find(L'\n', a);
            std::wstring l = text.substr(a, b == std::wstring::npos ? std::wstring::npos : b - a);
            while (!l.empty() && l.back() == L'\r') l.pop_back();
            lines.push_back(l);
            if (b == std::wstring::npos) break;
            a = b + 1;
        }
        while (!lines.empty() && lines.back().empty()) lines.pop_back();
    }
    size_t start = 0;
    if (!lines.empty() && lines[0].compare(0, 10, L"IsoLister\t") == 0) {
        m.brand = L"IsoLister " + lines[0].substr(10);
        start = 1;
    }

    IsoKind kind = IsoKindUnknown;
    std::vector<Sec> secs;
    Sec* cur = nullptr;
    bool blank = false;
    for (size_t i = start; i < lines.size(); ++i) {
        const std::wstring& raw = lines[i];
        if (is_rule(raw)) { cur = nullptr; blank = false; continue; }
        if (IsoTrim(raw).empty()) { blank = true; continue; }
        uint32_t leadValue = 0;
        IsoItem it = parse_line(raw, leadValue);
        if (it.kind == IsoItem::KV && kind == IsoKindUnknown && key_is(it.key, L"Тип образа", L"Image type")) {
            if (leadValue == 0x1F4BD) kind = IsoKindDisk;      // 💽
            else if (leadValue == 0x1F4BE) kind = IsoKindVhd;  // 💾
            else if (leadValue == 0x1F34E) kind = IsoKindDmg;  // 🍎
            else if (leadValue == 0x1FA9F) kind = IsoKindWim;  // 🪟
        }
        if (it.kind == IsoItem::Section) {
            secs.push_back(Sec());
            secs.back().head = it;
            secs.back().titled = true;
            cur = &secs.back();
            blank = false;
            continue;
        }
        // "Unallocated" after the last partition block: a blank line, then an unindented row
        bool split = cur && cur->titled && blank && it.ind == 0 && !cur->rows.empty() && cur->rows.back().ind > 0;
        if (!cur || split) {
            secs.push_back(Sec());
            cur = &secs.back();
            blank = false;
        }
        if (blank && !cur->rows.empty()) {
            IsoItem b;
            b.kind = IsoItem::Blank;
            cur->rows.push_back(b);
        }
        blank = false;
        cur->rows.push_back(it);
    }

    // a titled header with a value and nothing under it ("🗂 FS type  ISO 9660", "ℹ️ Note  …") is a plain row
    for (size_t i = 0; i < secs.size(); ++i) {
        Sec& s = secs[i];
        if (!s.titled || !s.rows.empty() || IsoTrim(s.head.value).empty()) continue;
        IsoItem kv = s.head;
        kv.kind = IsoItem::KV;
        kv.mono = looks_mono(kv.value);
        if (i + 1 < secs.size() && !secs[i + 1].titled) {
            secs[i + 1].rows.insert(secs[i + 1].rows.begin(), kv);
            secs.erase(secs.begin() + (long)i);
            --i;
        }
        else if (i > 0 && !secs[i - 1].titled) {
            secs[i - 1].rows.push_back(kv);
            secs.erase(secs.begin() + (long)i);
            --i;
        }
        // otherwise it stays a header with its note ("📝 Config files  none found")
    }
    bool firstUntitled = true;
    for (Sec& s : secs) {
        if (!s.titled) {
            s.head.kind = IsoItem::Section;
            s.head.key = firstUntitled ? (ru ? L"Сводка" : L"Summary") : (ru ? L"Дополнительно" : L"More");
            s.head.plain.clear();
            firstUntitled = false;
        }
        bool prevTable = false;
        for (IsoItem& r : s.rows) {
            if (r.kind == IsoItem::Table) { r.header = !prevTable; prevTable = true; }
            else prevTable = false;
        }
        m.items.push_back(s.head);
        for (auto& r : s.rows) m.items.push_back(r);
    }
    extract_facts(m, kind);
}
