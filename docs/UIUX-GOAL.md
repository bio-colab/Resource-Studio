# UI/UX-goal لـ Resource Studio

## الهدف الاستراتيجي

الهدف التالي ليس تحويل Resource Studio إلى معرض أزرار أو إعادة تصميم تجميلية، بل تحويله من واجهة تعرض **بنية PE وأدوات النواة** إلى تجربة عمل تجعل المستخدم يفهم أين هو، ماذا سيتغير، وما الدليل على سلامة الناتج.

> **UI/UX-goal:** عندما يفتح المستخدم Resource Studio، يجب أن يفهم خلال ثوانٍ: ما الملف المفتوح، ما الذي يمكنه فعله الآن، ما الذي سيُحفظ في ملف جديد، وما نتيجة التحقق بعد العملية — سواء كان هاويًا يريد معاينة مورد أو مطورًا يريد إثبات أن binary لم يتلف.

القاعدة الحاكمة هي: **نقوّي ما هو موجود، ولا نضيف ميزات إلا إذا أزالت ارتباكًا أو منعت فقدان بيانات أو جعلت حالة النظام قابلة للفهم والاختبار.**

## الفحص الحالي

واجهة WPF الحالية غنية وظيفيًا لكنها تعرض جميع الأوامر تقريبًا في `WrapPanel` واحد، فتجعل Open وValidate وAuthenticode وPython GUI متساوية في الوزن البصري. كما أن Resources وPreview وSearch وBatch وLocalization وInspect وDiff موجودة، لكن من دون نموذج تنقل يشرح متى يستخدم كل سطح.

مسار الحالة موجود عبر `StatusText` و`CliStateText`، واختبار UI automation يثبت فتح PE وتحميل الموارد وSearch وDark mode وImage Wizard وBMP preview. لكن الحالة لا تعرض مرحلة العملية أو سبب فشل قابلًا للتنفيذ، ولا تُظهر تقرير Verification Engine في سطح موجز. معظم الأوامر الثانوية والنوافذ لا تملك AutomationId أو Accelerator metadata، وبعض النوافذ تعتمد على تشغيل CLI متزامن مع رسالة حالة عامة.

المعاينة هي أقوى نقطة حالية: Resource Studio يستطيع عرض Bitmap وMenu وDialog وManifest وVersionInfo وStringTable وImage Group مع raw fallback. نقطة الضعف ليست غياب renderer، بل أن JSON/raw يظهر غالبًا كواجهة أولى بدل أن يكون طبقة التفاصيل للمطور.

## المستخدمون المستهدفون

| المستخدم | هدفه الواقعي | ما يحتاج أن يراه أولًا | معيار نجاحه |
|---|---|---|---|
| الهاوي أو المعدّل | فتح ملف، العثور على Icon/String/Manifest، معاينته، وحفظ نسخة | الملف الحالي، شجرة الموارد، معاينة واضحة، زر Save As آمن | لا يحتاج معرفة PE أو LIEF، ولا يلمس الأصل |
| المطور | فحص مورد أو binary وتعديل ضيق مع إثبات preservation | resource identity، diff، verification phases، hashes، preservation map | يستطيع تفسير لماذا نجح أو فشل Save |
| المترجم أو maintainer | مقارنة لغة، تعديل StringTable/VersionInfo/Manifest، وتصدير نسخة | language context، النصوص، preview، output path، audit | لا يضيع بين raw bytes وحقول تقنية لا تخصه |

## مبادئ التجربة

### 1. الهدف قبل التقنية

تستخدم الواجهة أفعالًا يفهمها المستخدم: **Open PE**, **Explore resources**, **Preview**, **Edit**, **Save As**, **Verify**. تبقى أسماء PE/LIEF/Authenicode في التفاصيل والمساعدة، لا كبديل عن وصف النتيجة.

### 2. الثقة قبل السرعة الزائفة

كل عملية لها حالة مرئية: `Ready`, `Running`, `Completed`, `Failed`, أو `Stopped`. عند Save يجب أن يظهر output path وملخص التحقق، مع إمكانية فتح التفاصيل. لا يكفي اللون أو كلمة `verified=true` وحدها.

### 3. progressive disclosure

المستخدم المبتدئ يرى ملخصًا وpreview؛ المطور يفتح `Details` ليرى JSON وhashes وinvariants؛ لا تُحذف raw/typed views، لكنها لا تكون نقطة الدخول الوحيدة.

### 4. Windows-native interaction

نحافظ على common controls وfocus indicators وkeyboard traversal وhigh contrast وDPI-aware resizing. لا يكون drag أو double-click الطريقة الوحيدة لتنفيذ فعل. كل نافذة تملك اسمًا واضحًا، وكل عنصر تفاعلي يملك automation name/id عندما يكون ذلك مفيدًا.

### 5. لا قرار خطير بلا سياق

Save As يعرض المصدر والهدف، وApply/Strip/Re-sign يشرح الأثر قبل التنفيذ. `Cancel` يعني لا أثر، و`Stop` يعني إيقاف عملية جارية، و`Close` يعني إغلاق نافذة بعد اكتمال العملية.

### 6. التشخيص لا يغرق المستخدم

الفشل يجيب: **ما الذي فشل؟ لماذا؟ ماذا يمكنني أن أفعل الآن؟**. التقرير التفصيلي يبقى متاحًا للنسخ والحفظ، لكن السطح الأول يعرض checklist مختصرة.

## information architecture المستهدفة

```text
Resource Studio
├── Workspace context: [PE path] [state] [output policy]
├── Primary actions
│   ├── Open PE
│   ├── Explore resources
│   ├── Inspect / Validate
│   └── Verify / Diff
├── Resource workbench
│   ├── Resources: tree/list → selected resource → properties
│   ├── Preview: visual summary → details/raw
│   └── Search
├── Editors and wizards
│   ├── Dialog
│   ├── StringTable
│   ├── VersionInfo / Manifest / Menu
│   ├── Image
│   └── Authenticode
├── Batch and Localization
└── Diagnostics
    ├── Verification summary
    ├── Full report
    └── Audit/output paths
```

لا يلزم إنشاء كل عقدة كميزة جديدة؛ معظمها موجود بالفعل. المطلوب هو إعادة ترتيب العرض، تسمية السياق، وإظهار العلاقات بين السطوح.

## user journeys ومعايير القبول

| المسار | الخطوات المتوقعة | معيار UI/UX-goal |
|---|---|---|
| فتح واستكشاف | Open → تحميل → Resources → اختيار leaf → Preview | يعرف المستخدم الملف والعدد والحالة والموضع المحدد دون قراءة log |
| تعديل آمن | اختيار editor → Load → تعديل → Save As | المصدر لا يتغير، الهدف واضح، حالة العملية مرئية، وتقرير verification قابل للنسخ |
| فحص مطور | Open → Inspect/Validate → Verification details | يرى PE validity وresource graph وpreservation وsignature state بلغة مختصرة ثم التفاصيل |
| فشل قابل للإصلاح | تنفيذ عملية بمدخل ناقص أو malformed | تظهر رسالة محددة مع الإجراء التالي، ولا تختفي النتيجة داخل modal عام أو exit code فقط |
| لوحة مفاتيح | Alt/access keys أو Tab → F6 بين المناطق → Enter/Space | جميع الأفعال الأساسية قابلة للوصول دون mouse، مع focus مرئي وترتيب منطقي |
| قارئ شاشة | التنقل بين action bar وresource list وpreview وstatus | لكل منطقة اسم، ولكل حالة تغيير announcement أو نص قابل للقراءة |
| نافذة صغيرة/high contrast | تصغير، تكبير DPI، High Contrast | لا truncation قاتل، ولا تعتمد الدلالة على اللون، وتبقى الأفعال الأساسية ظاهرة |

## الحالة المرئية الموحدة

كل عملية CLI/WPF تستخدم نموذجًا موحدًا:

```text
Ready
  → Running: <operation> — <phase>
  → Completed: <operation> — <output>
  → Failed: <operation> — <cause> — <next action>
  → Stopped: <operation> — output unchanged
```

وعند Save يظهر ملخص:

```text
✓ Output is valid PE
✓ Target resource changed (أو No-op preserved)
✓ Resource round-trip passed
✓ Non-target PE structures preserved
✓ Windows validation: passed / skipped / failed
✓ Signature state: ...
✓ Commit: same-volume durable replace
```

تظل القائمة الكاملة في VerificationReport، بينما يحصل المبتدئ على لغة مفهومة ويحصل المطور على JSON وhashes.

## خطة التنفيذ الجراحية

| المرحلة | التغيير | لا نضيفه |
|---|---|---|
| UX-01 | تجميع الأوامر في مناطق Workspace/Analyze/Edit/Tools وإظهار الملف والحالة كـcontext | لا نضيف backend أو resource type |
| UX-02 | surface موحد للحالة والـverification summary مع output path وcopy details | لا نكرر Verification Engine في WPF |
| UX-03 | أسماء وأوصاف وAutomationId وaccess keys وTabIndex وF6 للمناطق الأساسية | لا نبني custom control إذا كان common control يكفي |
| UX-04 | progressive disclosure للـraw JSON وadvanced fields، وتحسين preview header/empty/error states | لا نحذف raw view للمطور |
| UX-05 | responsiveness وStop/cancel ومسار error قابل للإصلاح في عمليات WPF الثقيلة | لا نضيف background service أو dependency جديدة بلا قياس |
| UX-06 | UI automation/accessibility/workflow matrix عبر resize، high contrast، keyboard، failure، Save As | لا نعد بتغطية قارئ شاشة كاملة قبل إثباتها |

## Definition of Done

يُعد UI/UX-goal محققًا عندما يستطيع مستخدم جديد فتح fixture، العثور على مورد، معاينته، تشغيل editor مناسب، حفظ Save As، وقراءة نتيجة التحقق دون معرفة Python أو LIEF؛ وعندما يستطيع المطور تنفيذ العملية ذاتها بالاختصارات ونسخ التقرير التفصيلي؛ وعندما تثبت UI automation أسماء المناطق، traversal الأساسي، الحالات، مسار الفشل، وعدم المساس بالأصل.

## مراجع البحث

[1]: https://learn.microsoft.com/en-us/windows/apps/get-started/best-practices "Windows application development — Best practices"

[2]: https://learn.microsoft.com/en-us/windows/apps/design/accessibility/keyboard-accessibility "Keyboard accessibility — Windows apps"

[3]: https://github.com/MicrosoftDocs/win32/blob/docs/desktop-src/uxguide/inter-accessibility.md "Accessibility design basics — Win32 UX guide"

[4]: https://learn.microsoft.com/en-us/dotnet/desktop/wpf/controls/ui-automation-of-a-wpf-custom-control "UI Automation of a WPF Custom Control"

[5]: https://learn.microsoft.com/en-us/windows/win32/uxguide/top-violations "UX checklist for desktop applications"

[6]: https://fluent2.microsoft.design/layout "Fluent 2 Layout"

[7]: https://www.nngroup.com/articles/visibility-system-status/ "Visibility of System Status — Nielsen Norman Group"

[8]: https://www.pe-explorer.com/peexplorer-tour-resource-editor.htm "PE Explorer resource editor feature tour"
