# Resource Studio 0.1.0 — Windows installer

## ملخص الإصدار

هذه أول حزمة Windows قابلة للتثبيت من Resource Studio بعد آخر نسخة مستقرة من المشروع. بُنيت الحزمة من شجرة المشروع التي تتضمن آخر MCP runtime وexternal integration gateway ووحدة MSIX/PRI، مع WPF shell مستقل وCLI محمول. رقم الإصدار المعروض هو `0.1.0`، والمنصة المستهدفة هي `win-x64`.

يُثبت installer التطبيق لكل مستخدم داخل `%LocalAppData%\Programs\Resource Studio` ولا يطلب صلاحيات administrator. يتضمن المعالج اتفاقية استخدام كاملة مبنية على `LICENSE`، وأيقونة Resource Studio، وأصول wizard متسقة مع لوحة الألوان الداكنة وSignal Cyan، واختصارًا في قائمة Start وخيارًا لاختصار سطح المكتب. يستطيع المستخدم إزالة التطبيق عبر uninstaller المرفق.

## مكونات الحزمة

| المكوّن | الغرض |
|---|---|
| `ResourceStudio.Windows.exe` | WPF shell self-contained لـWindows x64 |
| `ResourceStudioCli.exe` | CLI محمول مجمد من Python 3.12 مع تبعيات Resource Studio اللازمة |
| `EULA.txt` | اتفاقية التثبيت والنص الكامل لـApache License 2.0 |
| `INSTALLATION.txt` | معلومات الإصدار والمشروع والمطور |
| `resource-studio.ico` | الأيقونة الرسمية المستخدمة في التطبيق والاختصارات وinstaller |
| `unins000.exe` | أداة إزالة التثبيت التي يولدها installer |

لا تتطلب الحزمة تثبيت Python أو .NET Runtime منفصلًا. يبقى تشغيل plugin runtime معطلًا افتراضيًا داخل التطبيق وفق `SECURITY.md`، ولا يتحول وجود executable المحمول إلى تجاوز لسياسات MCP.

## artifact وchecksum

اسم artifact المنشور هو `resource-studio-windows-installer.zip`. يحتوي ZIP على `ResourceStudio-Setup-0.1.0-win-x64.exe`.

أُنشئ installer `v0.1.0` على clone Windows معزول، ثم اختُبر ونُقل إلى GitHub Release بعد التحقق من checksum. لم يكن Release workflow في ذلك الإصدار يبني installer داخل GitHub Actions؛ لذلك يُعد `v0.1.0` artifact مُختبرًا ومُحقق checksum، لكنه ليس ناتجًا عن pipeline قابل لإعادة البناء من الطرف إلى الطرف. ابتداءً من الإصدارات التالية، يتولى Release workflow بناء installer على `windows-latest` بعد نجاح CI لنفس commit، ثم يجري smoke test للتثبيت والإزالة قبل النشر.

```text
SHA-256: 15DA22FD8F22D1439B1C235C22653CC0313115069842D97E648CB963594A0C81
Size:    72,835,857 bytes
```

يُنصح بالتحقق من SHA-256 قبل تشغيل installer:

```powershell
Get-FileHash .\resource-studio-windows-installer.zip -Algorithm SHA256
```

## الاختبار

تم بناء WPF عبر `dotnet publish` بوضع Release و`win-x64` و`self-contained=true` و`PublishSingleFile=true`. جُمّد CLI عبر PyInstaller على Python 3.12. بعد البناء اجتاز installer اختبار تثبيت صامت داخل مجلد معزول، والتحقق من وجود WPF executable وCLI executable وEULA وuninstaller، وتشغيل CLI المحمول على `tests/fixtures/sample.dll`، وبدء WPF، ثم الإزالة الصامتة والتحقق من اختفاء مجلد التثبيت.

اجتازت كذلك اختبارات Resource Studio core وMCP وplugin runtime وexternal integrations وMSIX/PRI على Manus، واختبارات MCP وruntime وpackage integrations وWindows على clone Windows المعزول. لم تُلمس النسخة الأصلية المحمية أو تُستخدم كمسار build.

لم يكن `MakeAppx.exe` مثبتًا على حاسوب Windows المستخدم في هذه الجولة؛ لذلك بقيت إعادة بناء MSIX الفعلية محمية برسالة unavailable، ولم تُقدّم الحزمة ادعاءً بأن MakeAppx أو signing متاحان على كل جهاز.

## البناء من المصدر

يتطلب البناء Windows مع .NET SDK 8 وPython 3.12 وPyInstaller وInno Setup compiler. من PowerShell في جذر المشروع:

```powershell
py -3.12 -m pip install --user pyinstaller
.\installer\build-windows.ps1 -Version 0.1.0
```

ينتج السكربت stage مؤقتًا، ويولد أصول wizard من العلامة الحالية، ويبني WPF وCLI، ثم يستدعي `ISCC.exe` لإخراج installer داخل `dist\windows`. لا يُخزّن أي signing key أو secret في المستودع أو الحزمة.

## المراجع الرسمية

[1]: [Inno Setup Help](https://jrsoftware.org/ishelp/) — توثيق نظام بناء installer ومعالج Windows.

[2]: [Inno Setup Downloads](https://jrsoftware.org/isdl.php) — صفحة التنزيل الرسمية وإصدارات compiler.

[3]: [Inno Setup SetupIconFile](https://jrsoftware.org/ishelp/topic_setup_setupiconfile.htm) — توثيق استخدام أيقونة مخصصة للـinstaller وuninstaller.

[4]: [.NET 8 download](https://dotnet.microsoft.com/download/dotnet/8.0) — مصدر SDK المستخدم للبناء من المصدر.
