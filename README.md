# Resource Studio

**Resource Studio** منصة مستقلة لتحليل وإدارة موارد ملفات Windows PE، مبنية حول نواة Python قابلة للاختبار وbackend يعتمد على [LIEF](https://lief.re/). المشروع لا ينسخ Resource Hacker ولا يضمّنه، ولا يكتب إلى نسخة Resource Hacker الأصلية.

> **قاعدة السلامة:** كل تعديل PE يتم عبر Workspace وSave As إلى ملف جديد، مع backup وround-trip verification وسجل Audit. لا تستخدم مجلد تثبيت Resource Hacker كمسار إخراج.

## main-goal الحالي

الهدف الاستراتيجي هو تطبيق كل ما يمكن تطبيقه من دراسة Low-Level & Systems Programming على البنية الحالية، بحيث يصبح Resource Studio محرك PE يمكن إثباته من خلال Writer وPE invariants وWindows loader oracle وchecksum/signature diagnostics وdurable commit وround-trip contracts وPE corpus وfuzzing وJob Object isolation وWPF process-state reliability. لذلك تُجمّد إضافة الميزات الجديدة مؤقتًا؛ الأولوية لتقوية الصحة، وقابلية التشخيص، وإعادة الإنتاج، وعدم تغيير ما هو خارج نطاق العملية.

## ما الذي يوفره المشروع؟

| المجال | الوظائف الحالية |
|---|---|
| النواة | Project workspace، snapshots، Save As، Audit Log، Undo/Redo، rollback ذري، lockfile |
| PE | فهرسة الموارد، health checks، sections/imports/exports/TLS/debug، checksum، metadata وcompatibility profiles |
| الموارد | RES binary، RC text، Manifest، VersionInfo RC وPE binary، StringTable، Bitmap، Icon/Cursor مع JSON group model وpayload فردي قابل للتحويل إلى BMP/PNG، Menu، Dialog DIALOG/DIALOGEX binary وJSON |
| الكتابة الآمنة | Add/Replace/Delete/ChangeLanguage، typed validation، resource invariants، dry-run plan، rollback ذري حتى مع output موجود، منع تعديل PE موقع قبل strip/re-sign صريح |
| المقارنة والبحث | Diff Tree، image diff، HexViewer، بحث metadata/UTF-8/UTF-16/regex/hex |
| الأمان | Authenticode report وWinVerifyTrust native، Strip إلى ملف جديد، إنشاء Test PFX، Re-sign عبر `signtool.exe` عند توفر Windows SDK، PluginHost خارج العملية وWindows Job Object |
| الواجهات | CLI JSON، Python GUI أولية، WPF shell مستقل في `windows/ResourceStudio.Windows`، تبويبات Resources/Properties/Preview/Search/Diff/Batch Workspace/Localization، Dialog Editor WYSIWYG، StringTable Editor، Resource Wizards، Image Wizard، وAuthenticode Tools |
| الجودة | بوابة Python قابلة لإعادة التشغيل تشمل Writer rollback وPE corpus matrix وLoader/UpdateResource oracles وchecksum/signature diagnostics وround-trip contracts وbounded fuzzing وJob Object probes وDialog وAuthenticode وLocalization وBatch Workspace وStringTable وVersion/Manifest/Menu وImage وIcon/Cursor payload وPreviewEngine وgolden guards وSHA guards، إضافة إلى Windows UI automation وWPF build |

## المتطلبات

| المتطلب | الاستخدام |
|---|---|
| Python 3.12 | تشغيل النواة وCLI وPython GUI |
| `lief==1.0.0` | قراءة وكتابة PE resources |
| `Pillow>=10.0` | تحويل PNG الاختياري في payload الخاص بـICON/CURSOR؛ مسار DIB/BMP لا يعتمد عليه |
| .NET SDK 8.0 أو أحدث | بناء WPF shell على Windows فقط |
| Windows Desktop Runtime 8.0 | تشغيل WPF shell المبني مسبقًا |

لتثبيت .NET SDK، استخدم [صفحة التنزيل الرسمية لـ .NET 8](https://dotnet.microsoft.com/download/dotnet/8.0). لا تُضمّن حزمة SDK أو runtime داخل مستودع المشروع.

## التثبيت على Windows

افتح PowerShell داخل مجلد المشروع وشغّل:

```powershell
py -3.12 -m pip install --user -r requirements-backend.txt
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
python3 resource_studio_cli.py signature inspect tests/fixtures/sample.dll --json
python3 resource_studio_cli.py signature strip signed-input.dll --output unsigned-copy.dll --json
# على Windows فقط، بعد تثبيت Windows SDK:
$env:RS_PFX_PASSWORD = "test-only-password"
py -3.12 resource_studio_cli.py signature create-test-cert --output test-cert.pfx --password-env RS_PFX_PASSWORD --json
py -3.12 resource_studio_cli.py signature re-sign input.dll --output test-signed.dll --certificate test-cert.pfx --password-env RS_PFX_PASSWORD --json
python3 resource_studio_cli.py localization compare catalog.json --source-language en --target-language ar --json
python3 resource_studio_cli.py localization pseudo catalog.json --source-language en --target-language qps-ploc --output pseudo.json --json
python3 resource_studio_cli.py batch plan batch.json --json
python3 resource_studio_cli.py batch apply batch.json --report batch-report.json --json
python3 resource_studio_cli.py string-table export input.dll --name 1 --language 1033 --output strings.json --json
python3 resource_studio_cli.py version-resource export input.dll --language 1033 --output version.json --json
python3 resource_studio_cli.py manifest-resource export input.dll --language 1033 --output manifest.json --json
python3 resource_studio_cli.py menu-resource export input.dll --name 1 --language 1033 --output menu.json --json
python3 resource_studio_cli.py image-resource export input.dll --kind bitmap --name 1 --language 1033 --output image.bmp --json
python3 resource_studio_cli.py image-payload export input.dll --kind icon --resource-id 1 --language 1033 --output icon-1.bin --format raw --json
python3 resource_studio_cli.py image-payload export input.dll --kind icon --resource-id 1 --language 1033 --output icon-1.bmp --format bmp --json
python3 resource_studio_cli.py image-payload apply input.dll --kind icon --resource-id 1 --language 1033 --payload icon-1-edited.bmp --format bmp --output edited.dll --json
python3 resource_studio_cli.py preview input.dll --type MANIFEST --name 1 --language 1033 --length 4096 --json
```

أمر `plan` لا ينشئ ملف الإخراج المطلوب؛ يعرض hashes والأحجام ونتيجة invariants قبل الكتابة. وللتعامل مع Dialog يمكن استخدام `dialog export` لإخراج JSON و`dialog apply` لتطبيقه على نسخة Save As، مع تمرير `--language` و`--output` صراحة.

يفتح زر **Dialog Editor** في WPF محررًا مرئيًا مستقلًا. يدعم المحرر تحميل Dialog من PE عبر CLI، تعديل العنوان والأبعاد وعناصر التحكم ومواقعها ونصوصها، ثم الحفظ إلى JSON أو PE جديد؛ لا يكتب إلى ResourceHacker.exe الأصلي.

يفتح زر **Authenticode Tools** نافذة مدمجة لفحص التوقيع، ونزع certificate table إلى ملف PE جديد، وإنشاء شهادة Code Signing اختبارية محلية بصيغة PFX، وإعادة التوقيع إلى ملف جديد. كلمة مرور PFX لا تُمرر في سطر الأوامر؛ يستعمل المسار متغير بيئة مؤقتًا. إعادة التوقيع تحتاج `signtool.exe` من Windows SDK، ولذلك تعرض الأداة خطأً صريحًا إذا لم يكن SDK مثبتًا.

يفتح زر **StringTable Editor** جدولًا مرئيًا من 16 خانة مع String IDs، تحميل من PE، استيراد/تصدير JSON، وتطبيق Save As. ويفتح زر **Resource Wizards** تبويبات VersionInfo وManifest وMenu بصيغ JSON/XML قابلة للتحرير مع validation من النواة. يدعم MenuTree الآن سحب العقد إلى parent آخر، مع منع النقل أسفل descendant وإعادة بناء JSON قبل Save As. أما **Image Wizard** فيدعم BITMAP عبر BMP مع معاينة، وGROUP_ICON/GROUP_CURSOR عبر قائمة عناصر فردية وحقول width/height/resource ID وإجراءات Update/Add/Remove، إضافة إلى استخراج payload الفردي كـBMP، معاينته فور اختيار العنصر، واستبداله من BMP/PNG إلى PE جديد. كل عمليات الكتابة تمر عبر CLI وLIEF إلى ملف جديد.

يوفر WPF كذلك تبويبات **Resources** للفهرس والخصائص، و**Preview** الذي يستدعي PreviewEngine الموحد ويعرض Bitmap بصريًا، وMenu كقائمة مرئية، وDialog على Canvas، وVersionInfo كحقول وإصدارات وstrings، وManifest كـXML قابل للقراءة، وStringTable كسجل ID/text، وIcon/Cursor group كبطاقات أبعاد ومعرّفات، مع raw fallback عند تعذر التحليل. كما يوفر **Search** للبحث عبر النواة، و**Diff** لعرض شجرة المقارنة، و**Batch Workspace** لتشغيل manifest متعدد الملفات بوضع Plan أو Apply، و**Localization** لمقارنة اللغات وpseudo-localization. الاختصارات الأساسية هي `Ctrl+O` للفتح، و`Ctrl+F` للبحث، و`Ctrl+I` للفحص، و`F5` لإعادة تحميل الموارد. يوجد زر Dark mode مع اكتشاف Windows High Contrast. Image Wizard يعرض payload الفردي كـBMP فعليًا؛ أما cursor hotspot المتقدم وAccessibility automation الكامل فباقيان ضمن TODO.

يستخدم Batch Workspace صيغة `resource_studio.batch.v1`. يحتوي manifest على `jobs`، ولكل job `input` و`output` و`operations`. العمليات الحالية هي `add` و`replace` و`delete` و`change-language`. ينفذ `batch plan` staging مؤقتًا ويعرض hashes ونتيجة التحقق دون إنشاء المخرجات المطلوبة، بينما ينفذ `batch apply` كل العمليات في مساحة مؤقتة ثم يلتزم بها ذريًا إلى ملفات Save As، مع backup وسجل JSON وrollback عند فشل الالتزام. لا يسمح المسار بأن يكون output مساويًا لأي input.

## الاختبارات

بوابة الاختبارات لا تحتاج ResourceHacker.exe، ولا تتضمنه الحزمة. وتغطي `tests/qa/test_pe_corpus_matrix.py` سلسلة Save As حتمية تشمل RCDATA وBITMAP وICON وGROUP_ICON وSTRING وVERSION وتغيير اللغة والحذف، مع `PEHealth` و`PEInspector` وProject round-trip.

```bash
python3 -m py_compile core/*.py resource_studio_cli.py tests/core/*.py tests/test_cli.py tests/qa/*.py
for test in tests/core/test_*.py tests/test_cli.py tests/qa/test_*.py; do PYTHONPATH=. python3 "$test"; done
```

على Windows يمكن استخدام:

```powershell
$env:PYTHONPATH = (Get-Location).Path
py -3.12 tests\windows\create_ui_icon_fixture.py tests\fixtures\ui-icon.dll
dotnet build windows\ResourceStudio.Windows\ResourceStudio.Windows.csproj --configuration Release
powershell -NoProfile -ExecutionPolicy Bypass -File tests\windows\Invoke-ResourceStudioUIAutomation.ps1 -ApplicationPath windows\ResourceStudio.Windows\bin\Release\net8.0-windows\ResourceStudio.Windows.exe -PePath tests\fixtures\ui-icon.dll
```


```powershell
$env:PYTHONPATH = (Get-Location).Path
py -3.12 -m compileall -q core tests resource_studio_cli.py
Get-ChildItem tests\core\test_*.py | ForEach-Object { py -3.12 $_.FullName }
py -3.12 tests\test_cli.py
Get-ChildItem tests\qa\test_*.py | ForEach-Object { py -3.12 $_.FullName }
```

## دورة الاستقرار الحالية

توقفت إضافة الميزات الجديدة مؤقتًا للتركيز على صحة ما هو موجود. عولج مسار Writer بحيث يحتفظ بنسخة rollback مؤقتة من output الموجود حتى عندما يُطلب `backup_existing_output=False`؛ فإذا فشل LIEF أو validation أو invariant check يُستعاد الملف السابق ولا يُحذف. وأصبح commit على Windows يمر عبر flush ثم `ReplaceFileW`/`MoveFileExW` مع fallback معلن، بينما تعرض `inspect` مقارنة checksum بين LIEF وImageHlp وحالة certificate/signature مستقلة عن SHA-256.

كما أضيف resource-tree invariant graph، وWindows Loader Oracle، وUpdateResourceW differential oracle، وRoundTrip Contract Registry بعقود byte/semantic/canonical، وcorpus manifest hashes، وbounded parser fuzz harness، واختبار Job Object يثبت إنهاء child/grandchild. وفي WPF أصبحت قراءة stdout وstderr من CLI متوازية، وأضيف `CliStateText` بحالات Idle/Running/Completed/Failed واختبار UIA يثبت الحالة مع BMP preview فعلي.

تظل هذه دورة تثبيت وليست إعلانًا عن أنواع موارد جديدة؛ coverage-guided fuzzing الكامل، async cancellation وenabled-controls matrix، cursor hotspot، وAccessibility/screen-reader automation ما تزال فجوات مسجلة في TODO مع معايير مستقلة.

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

لا يضم المشروع `ResourceHacker.exe` أو أي ملف من مجلد تثبيته، ولا يطوّر MCP في هذه الدورة. ما تزال Accelerator/Font/MessageTable، وخصائص Win32 المتقدمة داخل Dialog، وPRI/MSIX، وجداول .NET التفصيلية، والتحقق الكامل من سلسلة الثقة لشهادات الاختبار، والعزل الكامل للشبكة وfilesystem للإضافات، وبعض عناصر UI المتقدمة ضمن TODO. لا تُعامل Test Certificates كشهادات إنتاج أو ثقة عامة.

## الترخيص والاعتماديات

Resource Studio كود مستقل. يعتمد backend PE على LIEF المرخص تحت Apache-2.0، وتوجد إشعارات الطرف الثالث في [`THIRD-PARTY-NOTICES.md`](THIRD-PARTY-NOTICES.md). راجع شروط أي برنامج خارجي قبل إعادة توزيعه؛ ResourceHacker.exe ليس جزءًا من هذا المشروع.

## المراجع

[1]: https://dotnet.microsoft.com/download/dotnet/8.0 "تنزيل .NET 8 الرسمي"

[2]: https://lief.re/ "وثائق LIEF الرسمية"


## Verification Engine Save Contract

تعمل دورة Save الآن كمسار تحقق قابل للتشخيص، لا كاستدعاء مباشر لـ`LIEF.write()`. يُبنى المرشح في temporary داخل نفس volume، ثم يُعاد فتحه ويُفحص عبر `PEHealth` و`DeepPEInvariantReport` و`ResourceGraph` وsemantic fingerprints وdifferential preservation checks قبل commit. على Windows يضاف loader resource oracle وWinVerifyTrust native، وبعد durable commit يعاد التحقق ويسجل التقرير في `WriteResult` وProject/Batch audit وCLI JSON.

التسلسل المثبت هو: **PLAN → MUTATE → SERIALIZE → REOPEN → STRUCTURAL VALIDATION → RESOURCE GRAPH VALIDATION → SEMANTIC DIFF → PRESERVATION CHECK → WINDOWS VALIDATION → AUTHENTICODE VERIFICATION → COMMIT → AUDIT**. تشمل preservation checks imports وexports وTLS وLoad Config وDebug وOverlay وdirectories وnon-resource sections. كما توجد structure-aware bounded fuzzing وcrash-consistency tests لمسار parser/writer وcommit/rollback.
