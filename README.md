# ISO Lister

WLX‑плагин для Total Commander, отображающий подробную информацию об ISO‑образах:

- поддерживает ISO 9660, Joliet, Rock Ridge, UDF, El Torito Boot Catalog;
- выводит данные в виде таблиц с цветными эмодзи (RichEdit 5.0);
- определяет популярные загрузчики (GRUB, ISOLINUX, systemd‑boot, Windows BootMgr);
- компилируется как Win32/Win64 DLL (статическая CRT, UNICODE, C++17).

## Сборка

1. Откройте `ISO_Lister.sln` в Visual Studio 2019 или новее.
2. Соберите проект (`ISO_Lister.dll`) в режимах x86/x64.
3. Скопируйте DLL в папку `Lister` Total Commander.

## Использование

В Total Commander откройте ISO‑образ клавишей `F3` — плагин покажет сводку,
Boot Catalog и (при включении опции) все записи каталога загрузки.

## Лицензия

