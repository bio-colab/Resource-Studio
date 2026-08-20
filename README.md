# Resource Studio

**Resource Studio** منصة مستقلة لتحليل وإدارة موارد ملفات Windows PE، مبنية حول نواة Python قابلة للاختبار وbackend يعتمد على [LIEF](https://lief.re/). المشروع لا ينسخ Resource Hacker ولا يضمّنه، ولا يكتب إلى نسخة Resource Hacker الأصلية.

> **قاعدة السلامة:** كل تعديل PE يتم عبر Workspace وSave As إلى ملف جديد، مع backup وround-trip verification وسجل Audit. لا تستخدم مجلد تثبيت Resource Hacker كمسار إخراج.

## ما الذي يوفره المشروع؟

| المجال | الوظائف الحالية |
|---|---|
| النواة | Project workspace، snapshots، Save As، Audit Log، Undo/Redo، rollback ذري، lockfile |
| PE | فهرسة الموارد، health checks، sections/imports/exports/TLS/debug، checksum، metadata وcompatibility profiles |
| الموارد | RES binary، RC text، Manifest، VersionInfo RC وPE binary، StringTable، Bitmap، Icon/Cursor، Menu |
| الكتابة الآمنة | Add/Replace/Delete/ChangeLanguage، typed validation، resource invariants، dry-run plan، منع تعديل PE موقع قبل strip/re-sign صريح |
| المقارنة والبحث | Diff Tree، image diff، HexViewer، بحث metadata/UTF-8/UTF-16/regex/hex |
| الأمان | Authenticode report، WinVerifyTrust native على Windows، PluginHost خارج العملية، limits وWindows Job Object |
| الواجهات | CLI JSON، Python GUI أولية، WPF shell مستقل في `windows/ResourceStudio.Windows` |
| الجودة | اختبارات core وCLI وQA، malformed corpus، golden round-trip، bounded fuzzing، SHA guards |

## المتطلبات

| المتطلب | الاستخدام |
|---|---|
| Python 3.12 | تشغيل النواة وCLI وPython GUI |
| `lief==1.0.0` | قراءة وكتابة PE resources |
| .NET SDK 8.0 أو أحدث | بناء WPF shell على Windows فقط |
| Windows Desktop Runtime 8.0 | تشغيل WPF shell المبني مسبقًا |

لتثبيت .NET SDK، استخدم [صفحة التنزيل الرسمية لـ .NET 8](https://dotnet.microsoft.com/download/dotnet/8.0). لا تُضمّن حزمة SDK أو runtime داخل مستودع المشروع.

## التثبيت على Windows

افتح PowerShell داخل مجلد المشروع وشغّل:

```powershell
py -3.12 -m pip install --user lief==1.0.0
```

بعد تثبيت .NET SDK، ابنِ واجهة WPF:

```powershell
dotnet restore windows\ResourceStudio.Windows\ResourceStudio.Windows.csproj
dotnet build windows\ResourceStudio.Windows\ResourceStudio.Windows.csproj --configuration Release
```

ثم شغّلها:

```powershell
windows\Run-ResourceStudio.cmd
```

يمكن تشغيل واجهة Python الأولية مباشرة:

```powershell
$env:PYTHONPATH = (Get-Location).Path
py -3.12 resource_studio_gui.py
```

## تشغيل CLI

من جذر المشروع:

```bash
python3 resource_studio_cli.py list tests/fixtures/sample.dll --json
python3 resource_studio_cli.py inspect tests/fixtures/sample.dll --json
python3 resource_studio_cli.py validate tests/fixtures/sample.dll --json
python3 resource_studio_cli.py search tests/fixtures/sample.dll MANIFEST --json
python3 resource_studio_cli.py plan add tests/fixtures/sample.dll --type RCDATA --name 1900 --language 1033 --data payload.bin --json
```

أمر `plan` لا ينشئ ملف الإخراج المطلوب؛ يعرض hashes والأحجام ونتيجة invariants قبل الكتابة.

## الاختبارات

بوابة الاختبارات لا تحتاج ResourceHacker.exe:

```bash
python3 -m py_compile core/*.py resource_studio_cli.py tests/core/*.py tests/test_cli.py tests/qa/*.py
for test in tests/core/test_*.py tests/test_cli.py tests/qa/test_*.py; do PYTHONPATH=. python3 "$test"; done
```

على Windows يمكن استخدام:

```powershell
$env:PYTHONPATH = (Get-Location).Path
py -3.12 -m compileall -q core tests resource_studio_cli.py
Get-ChildItem tests\core\test_*.py | ForEach-Object { py -3.12 $_.FullName }
py -3.12 tests\test_cli.py
Get-ChildItem tests\qa\test_*.py | ForEach-Object { py -3.12 $_.FullName }
```

## هيكل المشروع

```text
core/                         النواة والـ parsers والـ writer
resource_studio_cli.py        CLI موحد
resource_studio_gui.py        Python GUI أولية
windows/ResourceStudio.Windows WPF shell مستقل
windows/Run-ResourceStudio.cmd مشغل WPF
 tests/                       اختبارات core وCLI وQA
 docs/                        التقدم والتدقيق وتعليمات Windows
 TODO.md                     سجل المهام القابل للتتبع
```

## الحدود المقصودة

لا يضم المشروع `ResourceHacker.exe` أو أي ملف من مجلد تثبيته، ولا يطوّر MCP في هذه الدورة. ما يزال Dialog editor الكامل، PRI/MSIX، جداول .NET التفصيلية، strip/re-sign، العزل الكامل للشبكة وfilesystem للإضافات، وبعض عناصر UI المتقدمة ضمن TODO.

## الترخيص والاعتماديات

Resource Studio كود مستقل. يعتمد backend PE على LIEF المرخص تحت Apache-2.0، وتوجد إشعارات الطرف الثالث في [`THIRD-PARTY-NOTICES.md`](THIRD-PARTY-NOTICES.md). راجع شروط أي برنامج خارجي قبل إعادة توزيعه؛ ResourceHacker.exe ليس جزءًا من هذا المشروع.

## المراجع

[1]: https://dotnet.microsoft.com/download/dotnet/8.0 "تنزيل .NET 8 الرسمي"

[2]: https://lief.re/ "وثائق LIEF الرسمية"
