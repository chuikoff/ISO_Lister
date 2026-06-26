# IsoLister

WLX Lister-плагин для [Total Commander](https://www.ghisler.com/) — быстрый анализ ISO-образов прямо в панели просмотра (F3), в духе Rufus.

Показывает тип файловой системы, загрузочность (El Torito), UEFI/BIOS, метаданные Windows и Linux, версию install.wim/esd, издания и многое другое.

## Возможности

- **Быстрый режим по умолчанию** — анализ 2–4 ГБ ISO за ~100–150 мс (точечный поиск путей вместо полного обхода дерева)
- **Windows** — UDF (современные установочные ISO), install.wim/esd, boot.wim, ei.cfg, издания, build, архитектура, подпись UEFI bootmgr
- **Linux** — Ubuntu/Debian и др.: `/.disk/info`, casper, GRUB, ISOLINUX
- **macOS** — Apple UDIF `.dmg`: разделы GPT, Apple_HFS/APFS, EFI, версия установщика
- **ISO 9660** — Joliet, Rock Ridge, PVD/SVD, Boot Catalog
- **RichEdit** — цветной отчёт с переносом строк (исправлен «белый экран» на Win8.1+)

## Установка

1. Скачайте архив из [релизов](https://github.com/chuikoff/ISO_Lister/releases) под вашу разрядность TC:
   - **64-bit TC** → `ISO_Lister_*_wlx64.zip`
   - **32-bit TC** → `ISO_Lister_*_wlx.zip`  
   Поддерживаются расширения: `.iso`, `.img`, `.dmg`

### `.img` не открывается плагином (конфликт с Imagine / mthumbs)

Total Commander помечает `.img` как **MULTIMEDIA** (картинки IrfanView/Imagine). Для таких файлов TC **не вызывает** плагины без `MULTIMEDIA` в detect — поэтому ISO/DMG работают, а IMG нет (даже на позиции 0).

**Решение (v1.1.5+):** в DLL и в `0_detect` для IMG обязателен `MULTIMEDIA &` (без него TC игнорирует плагин для `.img`):

```
EXT="ISO" | EXT="DMG" | (MULTIMEDIA & EXT="IMG" & [510]=85 & [511]=170) | ... | (MULTIMEDIA & EXT="IMG")
```

1. **IsoLister** — позиция **0** в Lister-плагинах; перезапустите TC после обновления DLL.
2. В настройках плагина нажмите «По умолчанию» (подтянет строку из DLL) — **без кавычек** вокруг всей строки в INI.
3. **Imagine** (#8): замените голый `MULTIMEDIA` на список расширений **без** `IMG`, иначе перехватывает образы диска.
4. Лог плагина: `%TEMP%\IsoLister.log` — строка `ListLoadW: file=...Panasonic.img` означает, что плагин вызван.
2. Откройте архив в Total Commander — TC предложит автоматическую установку (`pluginst.inf`).
   Либо вручную распакуйте в `%TOTALCMD%\Plugins\wlx\ISO_Lister\`.
3. Перезапустите Total Commander.
4. Откройте любой `.iso` и нажмите **F3** (Lister).

## Настройки

Секция `[IsoLister]` в `%APPDATA%\GHISLER\wincmd.ini` или `lsplugin.ini`:

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

## Тесты

```powershell
.\test\run_test.ps1
```

## Лицензия

MIT — см. [LICENSE](LICENSE).