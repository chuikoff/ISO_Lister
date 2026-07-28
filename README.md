# IsoLister

WLX Lister plugin for [Total Commander](https://www.ghisler.com/) — fast disk image analysis in the viewer (F3 / Ctrl+Q), Rufus-style.

---

## Русский

### Назначение

**IsoLister** — плагин просмотра (Lister) для Total Commander. Анализирует образы дисков **без монтирования**: показывает тип ФС, загрузочность, редакции Windows, дистрибутив Linux, разметку raw-образов и структуру Apple DMG. Работает в полном Lister (**F3**) и в быстром просмотре (**Ctrl+Q**).

### Поддерживаемые форматы

| Расширение | Тип | Что определяется |
|------------|-----|------------------|
| `.iso` | ISO 9660 / UDF | Метка тома, Joliet, Rock Ridge, El Torito, UEFI/BIOS, Windows/Linux |
| `.img` | Raw-образ диска | MBR/GPT, разделы, FAT/NTFS, загрузочный код |
| `.bin` | Raw dump | То же, что `.img` (MBR/GPT по сигнатурам / размеру) |
| `.vhd` / `.vhdx` | Hyper-V | Метаданные VHD; fixed VHD — разбор MBR/GPT |
| `.dmg` | Apple UDIF | koly/blkx, GPT, HFS+/APFS, EFI, версия установщика macOS |

### Что показывает отчёт

**Сводка (как Rufus)** — в начале отчёта:
- тип файловой системы (ISO 9660, UDF, Joliet, Rock Ridge);
- Boot Marker, UEFI bootloaders и подписи bootmgr;
- **Detected** — Windows (версия, build), Linux (дистрибутив, архитектура);
- **Uses** — EFI, BIOS, install.wim/esd, live squashfs;
- таблица **редакций WIM** (имя, EditionID, версия, язык).

**Подробности** (полный Lister, F3):
- PVD/SVD ISO 9660, UDF NSR, El Torito Boot Catalog;
- раздел **Windows** — ei.cfg, канал, редакции из XML WIM/ESD;
- раздел **Linux** — `/.disk/info`, casper, ядро, initrd;
- крупнейшие файлы, конфиги, опционально — полный список файлов и Boot Catalog.

В **Ctrl+Q** выводится **компактная сводка** (без PVD/UDF и технических таблиц).

### Установка

1. Скачайте [последний релиз](https://github.com/chuikoff/ISO_Lister/releases): `ISO_Lister_v1.1.6.zip`.
2. Откройте архив в Total Commander — появится диалог автоустановки (`pluginst.inf`).
3. Путь по умолчанию: `%COMMANDER_PATH%\Plugins\ISO_Lister\`.
4. **Полностью перезапустите Total Commander.**
5. Откройте `.iso` / `.img` / `.dmg` → **F3** или **Ctrl+Q**.

В архиве оба варианта плагина: `IsoLister.wlx` (32-bit TC) и `IsoLister.wlx64` (64-bit TC); TC выбирает нужный автоматически.

**Рекомендуется:** поставить IsoLister на **позицию 0** в списке Lister-плагинов (*Конфигурация → Плагины → Lister-плагины (.WLX)*).

### Файлы после установки

```
%COMMANDER_PATH%\Plugins\ISO_Lister\
  IsoLister.wlx      — 32-bit
  IsoLister.wlx64    — 64-bit
  README.md
  LICENSE
```

### `.img` и конфликт с Imagine / IrfanView

Total Commander классифицирует `.img` как **MULTIMEDIA** (картинки). Плагины без `MULTIMEDIA` в detect для таких файлов **игнорируются**.

Detect-строка в DLL (v1.1.5+):

```
EXT="ISO" | EXT="DMG" | (MULTIMEDIA & EXT="IMG" & [510]=85 & [511]=170) | ... | (MULTIMEDIA & EXT="IMG" & SIZE>50000000)
```

Сигнатуры: MBR `55 AA`, ISO9660 `CD001`, либо размер > 50 МБ. Голый `EXT="IMG"` не используется (картинки GEM/Imagine).

Если `.img` не открывается:
1. Перезапустите TC, в настройках плагина нажмите **«По умолчанию»**.
2. У **Imagine** / **IrfanView** замените голый `MULTIMEDIA` на список расширений **без** `IMG`.
3. Проверьте лог: `%TEMP%\IsoLister.log` — должна быть строка `ListLoadW: file=...img`.

### Настройки

Секция `[IsoLister]` в `%APPDATA%\GHISLER\lsplugin.ini` (или `wincmd.ini`):

| Параметр | По умолчанию | Описание |
|----------|--------------|----------|
| `FullScan` | `0` | `1` — полный обход ISO9660 + UDF (медленно) |
| `Verbose` | `0` | `1` — подробный PVD/Path Table/UDF NSR и т.п. |
| `ShowFileList` | `0` | `1` — список файлов в отчёте |
| `ShowBootEntries` | `0` | `1` — все записи El Torito Boot Catalog |
| `ScanDepth` | `6` | Глубина каталогов при `FullScan=1` |
| `MaxNodes` | `40000` | Лимит узлов при полном скане |
| `MaxFileList` | `1000` | Макс. файлов в списке |

Язык UI: если в `wincmd.ini` `LanguageIni`/`LanguageDll` содержит **RUS** — русский отчёт; иначе **английский**.

Тёмная тема: по **`[Configuration] DarkMode`** (переключатель TC `cm_SwitchDarkMode`), **не** по теме Windows.  
Опционально `[IsoLister] Dark=0|1|2` — light / dark / auto (по умолчанию `2` = как TC).

Поиск в Lister: **Ctrl+F** / F7 (ListSearchText).

```ini
[IsoLister]
FullScan=0
Verbose=0
Dark=2
ShowFileList=0
ShowBootEntries=0
```

### Сборка из исходников

Visual Studio 2022, компонент «Разработка классических приложений на C++».

```bat
MSBuild IsoLister.sln /p:Configuration=Release /p:Platform=x64
MSBuild IsoLister.sln /p:Configuration=Release /p:Platform=x86
```

Упаковка ZIP: `.\installer\pack_release.ps1`

### Лицензия

MIT — см. [LICENSE](LICENSE).

---

## English

### Overview

**IsoLister** is a Total Commander Lister (WLX) plugin. It inspects disk images **without mounting**: filesystem type, boot capability, Windows editions, Linux distro metadata, raw partition layout, and Apple DMG structure. Works in full Lister (**F3**) and Quick View (**Ctrl+Q**).

### Supported formats

| Extension | Type | Detected information |
|-----------|------|----------------------|
| `.iso` | ISO 9660 / UDF | Volume label, Joliet, Rock Ridge, El Torito, UEFI/BIOS, Windows/Linux |
| `.img` | Raw disk image | MBR/GPT, partitions, FAT/NTFS, boot code |
| `.bin` | Raw dump | Same as `.img` (MBR/GPT by signature / size) |
| `.vhd` / `.vhdx` | Hyper-V | VHD metadata; fixed VHD — MBR/GPT layout |
| `.dmg` | Apple UDIF | koly/blkx, GPT, HFS+/APFS, EFI, macOS installer version |

### Report contents

**Summary (Rufus-style)** at the top:
- filesystem type (ISO 9660, UDF, Joliet, Rock Ridge);
- Boot Marker, UEFI bootloaders, bootmgr signatures;
- **Detected** — Windows (version, build), Linux (distro, architecture);
- **Uses** — EFI, BIOS, install.wim/esd, live squashfs;
- **WIM editions** table (name, EditionID, version, language).

**Details** (full Lister, F3):
- ISO 9660 PVD/SVD, UDF NSR, El Torito Boot Catalog;
- **Windows** — ei.cfg, channel, editions from WIM/ESD XML;
- **Linux** — `/.disk/info`, casper, kernel, initrd;
- largest files, config hits; optional full file list and Boot Catalog.

**Ctrl+Q** shows a **compact summary** only (no PVD/UDF technical blocks).

### Installation

1. Download the [latest release](https://github.com/chuikoff/ISO_Lister/releases): `ISO_Lister_v1.1.6.zip`.
2. Open the ZIP in Total Commander — auto-install dialog appears (`pluginst.inf`).
3. Default path: `%COMMANDER_PATH%\Plugins\ISO_Lister\`.
4. **Restart Total Commander completely.**
5. Open `.iso` / `.img` / `.dmg` → **F3** or **Ctrl+Q**.

The package includes both `IsoLister.wlx` (32-bit TC) and `IsoLister.wlx64` (64-bit TC); TC picks the correct one.

**Recommended:** place IsoLister at **position 0** in Lister plugins (*Configuration → Plugins → Lister plugins (.WLX)*).

### Installed files

```
%COMMANDER_PATH%\Plugins\ISO_Lister\
  IsoLister.wlx      — 32-bit
  IsoLister.wlx64    — 64-bit
  README.md
  LICENSE
```

### `.img` vs Imagine / IrfanView

Total Commander treats `.img` as **MULTIMEDIA** (images). Plugins without `MULTIMEDIA` in the detect string are **skipped** for such files.

Built-in detect (v1.1.5+):

```
EXT="ISO" | EXT="DMG" | (MULTIMEDIA & EXT="IMG" & [510]=85 & [511]=170) | ... | (MULTIMEDIA & EXT="IMG" & SIZE>50000000)
```

Signatures: MBR `55 AA`, ISO9660 `CD001`, or size > 50 MB. Bare `EXT="IMG"` is not used (GEM/Imagine pictures).

If `.img` does not open:
1. Restart TC; in plugin settings click **Default** to reload detect from DLL.
2. Narrow **Imagine** / **IrfanView** detect to image extensions **excluding** `IMG`.
3. Check log: `%TEMP%\IsoLister.log` — look for `ListLoadW: file=...img`.

### Settings

Section `[IsoLister]` in `%APPDATA%\GHISLER\lsplugin.ini` (or `wincmd.ini`):

| Option | Default | Description |
|--------|---------|-------------|
| `FullScan` | `0` | `1` — full ISO9660 + UDF tree walk (slow) |
| `Verbose` | `0` | `1` — full PVD/Path Table/UDF NSR details |
| `ShowFileList` | `0` | `1` — file list in report |
| `ShowBootEntries` | `0` | `1` — full El Torito Boot Catalog table |
| `ScanDepth` | `6` | Directory depth when `FullScan=1` |
| `MaxNodes` | `40000` | Node limit for full scan |
| `MaxFileList` | `1000` | Max files in list |

UI language: if `wincmd.ini` `LanguageIni`/`LanguageDll` contains **RUS** → Russian report; otherwise **English**.

Dark theme: follows **`[Configuration] DarkMode`** (TC `cm_SwitchDarkMode`), **not** Windows theme.  
Optional `[IsoLister] Dark=0|1|2` — light / dark / auto (default `2` = TC).

Search in Lister: **Ctrl+F** / F7 (`ListSearchText`).

```ini
[IsoLister]
FullScan=0
Verbose=0
Dark=2
ShowFileList=0
ShowBootEntries=0
```

### Build from source

Visual Studio 2022 with «Desktop development with C++».

```bat
MSBuild IsoLister.sln /p:Configuration=Release /p:Platform=x64
MSBuild IsoLister.sln /p:Configuration=Release /p:Platform=x86
```

Package ZIP: `.\installer\pack_release.ps1`

### Tests

```powershell
.\test\run_test.ps1
```

### License

MIT — see [LICENSE](LICENSE).