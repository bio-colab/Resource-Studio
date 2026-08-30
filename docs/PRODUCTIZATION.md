# Productization Backlog

## مبدأ المرحلة

مرحلة Productization لا تعني إضافة أكبر عدد من أنواع الموارد، بل تحويل النواة الحالية إلى أداة عملية يمكن للمطور أو الهاوي استخدامها بأمان وبأقل احتكاك. لذلك تأتي **قابلية التراجع، وضوح التقرير، وقابلية إعادة التشغيل** قبل توسيع المحررات.

تؤكد وثائق PE الرسمية أن الملف يتكون من headers وsection table وdata directories وموارد، وأن offsets وRVA وSizeOfOptionalHeader يجب التعامل معها بعقود تحقق صريحة.[1] كما أن أدوات تحرير الموارد العملية تجمع بين العرض المرئي، الاستخراج، التعديل، وسطر الأوامر والعمليات المتكررة.[2] وتُظهر أدوات PE التجارية أن وضوح شجرة الموارد والمعاينة والتراجع والحفظ الآمن عوامل مباشرة في سهولة الاستخدام.[3]

## ما اكتمل في هذه الدفعة

| المعرّف | الحالة | ما أصبح متاحًا |
|---|---|---|
| `PROD-01` | مكتمل جزئيًا | Batch Workspace متعدد الملفات مع `plan/apply` وSave As وrollback وbackup، وأضيف journal JSONL و`--resume` لتخطي العناصر الملتزم بها بعد التحقق من hash. فهرسة المجلد والـqueue التفاعلي ما زالا لاحقين. |
| `PROD-05` | مكتمل | `build_post_write_diagnostics` وأمر `report diagnostics` يقارنان before/after للأقسام والبنى المحمية وdirectories وimports وexports وTLS وLoad Config وdebug وoverlay وchecksum وsignature وresource graph وraw corroboration، ويخرجان findings قابلة للفهم. |
| `PROD-11` | مكتمل جزئيًا | journal لكل job بصيغة JSON Lines، resume آمن، hashes قبل/بعد، report artifact وexit code من CLI. يحتاج لاحقًا إلى استئناف تفاعلي ومراقبة تقدم WPF. |

## الاستخدام

لإنشاء خطة batch دون كتابة ملفات الناتج:

```bash
python3 resource_studio_cli.py batch plan batch.json --json
```

لتطبيق الدفعة مع سجل قابل للاستئناف:

```bash
python3 resource_studio_cli.py batch apply batch.json \
  --journal batch.journal.jsonl \
  --report batch-report.json \
  --json
```

إذا انقطع التنفيذ بعد إتمام بعض العناصر، يعاد تشغيله هكذا:

```bash
python3 resource_studio_cli.py batch apply batch.json \
  --journal batch.journal.jsonl \
  --resume \
  --json
```

يُعاد تنفيذ job إذا كان الناتج غير موجود أو لم يعد hash الناتج مساويًا للسجل. أما الناتج الموجود مع hash مطابق فيظهر `skipped: true` و`resumed: true` بدل الكتابة من جديد.

ولفحص ما تغير بين PE قبل وبعد الكتابة:

```bash
python3 resource_studio_cli.py report diagnostics before.dll after.dll \
  --format markdown \
  --output diagnostics.md
```

يمكن استخدام `json` للمعالجة الآلية، أو `markdown` للمراجعة البشرية، أو `csv/html` للتقارير العامة التي يدعمها محرك التقارير الحالي. لا يقوم diagnostics بأي تعديل؛ هو مسار قراءة ومقارنة فقط.

## ما يلي حسب الأولوية

| الأولوية | المعرّف | القرار |
|---|---|---|
| حرجة | `PROD-04` | Localization Workbench متعدد الملفات واللغات مع XLIFF/PO/RESX بعد تثبيت عقود التعليقات وplaceholders وplural rules. |
| عالية | `PROD-06` | توسيع UI automation وkeyboard/accessibility وscreen-reader smoke test على WPF. |
| عالية | `PROD-07` | Resource Transfer/Merge مع conflict resolver وdry-run فوق plan وdiagnostics الحاليين. |
| عالية | `PROD-08` | Accelerator/MessageTable/Font/RCData بعد fixtures وround-trip contracts، وليس قبلها. |
| عالية | `PROD-09` | MUI و.NET satellite workflow في مسار منفصل عن `.rsrc` العادي. |
| متوسطة | `PROD-10` | drag/drop وrecent/favorites وportable preferences بعد استقرار shell. |
| متوسطة | `PROD-12` | Plugin SDK sample pack وcontract tests قبل تنفيذ adapters جديدة. |

لن تُضاف disassembler أو unpacker أو runtime/network provider إلى النواة؛ أي adapter مستقبلي يجب أن يبقى اختياريًا وخارج العملية وبصلاحيات وتحذيرات صريحة.

## المراجع

[1]: https://learn.microsoft.com/en-us/windows/win32/debug/pe-format "Microsoft PE Format"


[3]: https://www.pe-explorer.com/peexplorer-tour-resource-editor.htm "PE Explorer Resource Viewer and Editor feature tour"
