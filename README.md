# IsoLister

WLX Lister-плагин для [Total Commander](https://www.ghisler.com/) — быстрый анализ образов дисков прямо в панели просмотра (F3), в духе Rufus.

Показывает тип файловой системы, загрузочность (El Torito), UEFI/BIOS, метаданные Windows и Linux, версию install.wim/esd, издания, разметку raw-образов и структуру Apple UDIF — без полного монтирования.

## Поддерживаемые форматы

| Расширение | Тип | Что анализируется |
|------------|-----|-------------------|
| `.iso` | ISO 9660 / UDF | PVD/SVD, Joliet, Rock Ridge, El Torito, Windows/Linux-метаданные |
| `.img` | Raw disk image | MBR/GPT, FAT/NTFS, разделы, загрузочные записи |
| `.dmg` | Apple UDIF | koly, blkx, HFS+/APFS, GPT, версия установщика macOS |

## Возможности

- **Быстрый режим по умолчанию** — анализ ISO 2–4 ГБ за ~100–150 мс (точечный поиск путей вместо полного обхода дерева)
- **Windows** — UDF, install.wim/esd, boot.wim, ei.cfg, издания, build, архитектура, подпись UEFI bootmgr
- **Linux** — Ubuntu/Debian и др.: `/.disk/info`, casper, GRUB, ISOLINUX
- **macOS** — Apple UDIF `.dmg`: разделы GPT, Apple_HFS/APFS, EFI, версия установщика
- **Raw `.img`** — MBR/GPT, таблица разделов, сигнатуры FAT/NTFS, размер и смещения
- **ISO 9660** — Joliet, Rock Ridge, PVD/SVD, Boot Catalog
- **RichEdit** — цветной отчёт с переносом строк (исправлен «белый экран» на Win8.1+)

## Установка

1. Скачайте архив из [релизов](https://github.com/chuikoff/ISO_Lister/releases): `ISO_Lister_v1.1.5.zip` (32- и 64-bit TC в одном пакете).
2. Откройте архив в Total Commander — TC предложит автоматическую установку (`pluginst.inf`, нужный `.wlx`/`.wlx64` выбирается по разрядности TC).
   Либо вручную распакуйте в `%COMMANDER_PATH%\Plugins\ISO_Lister\`.
3. **Перезапустите Total Commander.**
4. Откройте `.iso`, `.img` или `.dmg` и нажмите **F3** (Lister).

Рекомендуется поставить IsoLister на **позицию 0** в списке Lister-плагинов (*Конфигурация → Плагины → Lister-плагины*).

## `.img` и конфликт с Imagine / IrfanView

Total Commander помечает `.img` как **MULTIMEDIA** (картинки). Плагины без `MULTIMEDIA` в detect-строке для таких файлов **не вызываются** — поэтому ISO/DMG могут работать, а IMG нет.

**В v1.1.5+** detect встроен в DLL:

```
EXT="ISO" | EXT="DMG" | (MULTIMEDIA & EXT="IMG" & [510]=85 & [511]=170) | ... | (MULTIMEDIA & EXT="IMG")
```

После обновления:

1. Перезапустите TC.
2. В настройках плагина нажмите **«По умолчанию»** (подтянет строку из DLL).
3. Если Imagine стоит с голым `MULTIMEDIA` — сузьте detect до списка расширений **без** `IMG`, иначе он перехватывает образы диска.
4. Лог: `%TEMP%\IsoLister.log` — строка `ListLoadW: file=...img` подтверждает вызов плагина.

## Настройки

Секция `[IsoLister]` в `%APPDATA%\GHISLER\lsplugin.ini` (или `wincmd.ini`):

| Параметр | По умолчанию | Описание |
|----------|--------------|----------|
| `FullScan` | `0` | `1` — полный BFS-обход ISO9660 + UDF (медленно, для отладки) |
| `ShowFileList` | `0` | `1` — список найденных файлов в отчёте |
| `ShowBootEntries` | `0` | `1` — таблица записей El Torito Boot Catalog |
| `ScanDepth` | `6` | Глубина обхода при `FullScan=1` |
| `MaxNodes` | `40000` | Лимит узлов при полном скане |
| `MaxFileList` | `1000` | Макс. файлов в списке |

Пример:

```ini
[IsoLister]
FullScan=0
ShowFileList=0
ShowBootEntries=0
```

## Сборка из исходников

Требуется Visual Studio 2022 с компонентом «Desktop development with C++».

```bat
REM 64-bit
MSBuild IsoLister.sln /p:Configuration=Release /p:Platform=x64

REM 32-bit
MSBuild IsoLister.sln /p:Configuration=Release /p:Platform=x86
```

Готовые плагины:

- `x64\Release\IsoLister.wlx64`
- `Release\IsoLister.wlx`

Версия и git SHA встраиваются автоматически через `gen_version.ps1` (Pre-Build).

Упаковка релизного ZIP:

```powershell
.\installer\pack_release.ps1
```

## Тесты

```powershell
.\test\run_test.ps1
```

## Лицензия

MIT — см. [LICENSE](LICENSE).