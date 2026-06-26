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

Total Commander считает `.img` **мультимедиа** (формат картинок в IrfanView/Imagine). Плагины с `MULTIMEDIA` в detect (mthumbs, Imagine, MMedia…) перехватывают F3 раньше, чем «голый» `EXT="IMG"`.

**Что сделать:**

1. Поднимите **IsoLister** в списке Lister-плагинов **выше** mthumbs/Imagine (лучше — на позицию 0).
2. Detect string (уже в плагине v1.1.4+):

   ```
   EXT="ISO" | EXT="DMG" | (EXT="IMG" & [510]=85 & [511]=170) | (EXT="IMG" & [32769]=67 & [32770]=68 & [32771]=48 & [32772]=48 & [32773]=49) | (EXT="IMG" & SIZE>50000000)
   ```

   Это ловит MBR (55 AA), ISO9660 (CD001) и крупные образы (>50 МБ), но не маленькие `.img`-картинки.

3. В **Imagine** / **mthumbs** сузьте detect — не используйте голый `MULTIMEDIA` без списка расширений, если мешает.
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