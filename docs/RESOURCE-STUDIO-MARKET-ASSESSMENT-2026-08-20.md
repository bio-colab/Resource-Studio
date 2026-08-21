# تقييم فائدة Resource Studio لمطوري Windows والهواة

**التاريخ:** 20 أغسطس 2026

## الخلاصة التنفيذية

نعم، **Resource Studio يمكن أن يفيد المطورين والهواة بوضوح**. فالمشروع الحالي لم يعد مجرد محرر موارد؛ بل أصبح أساسًا لـ **ورشة آمنة وقابلة للتكرار لتعديل موارد PE وتحليلها ومقارنتها وإدارتها ضمن مشروع**. قوته الأساسية هي الجمع بين Save As، snapshots، Undo/Redo، Audit Log، typed resource models، LIEF، الفحص، المقارنة، البحث، التقارير، CLI، WPF، وإضافات معزولة.

في المقابل، لا يزال المشروع أقرب إلى **نواة منصة قوية مع واجهة أولية متقدمة** منه إلى منتج نهائي ينافس الأدوات الناضجة في كل سيناريو. فالوظائف الأساسية التي اعتاد عليها المستخدمون موجودة جزئيًا أو عبر CLI، بينما تنقصه كثافة المحررات المرئية، اتساع أنواع الموارد، العمل الجماعي على عدة ملفات، دعم .NET/MUI الكامل، المعاينة الإعلامية، واختبارات UI قابلة للتكرار.

> **الحكم العملي:** Resource Studio مفيد الآن كأداة آمنة للمطور الذي يريد تعديل موارد PE مع خطة وتحقق وسجل، وكأداة بحث ومقارنة وتعريب أولية. ولكي يصبح أداة يومية للهواة والمترجمين، يجب أن ينتقل التركيز من إضافة نماذج داخلية جديدة إلى صقل سير العمل المرئي، وتوسيع التغطية الأكثر استخدامًا، وإضافة batch operations وpreview وlocalization workflow.

## 1. ما الذي يفعله المشروع حاليًا؟

جُردت القدرات من `TODO.md`، ومن ملفات `core/` وCLI وWPF الحالية. الجرد التالي يصف ما يمكن الاعتماد عليه حاليًا، مع التمييز بين المكتمل والمنجز جزئيًا.

| المجال | الوضع الحالي | القيمة العملية |
|---|---|---|
| إدارة المشروع | `Project`، `project.json`، فصل Original/Workspace، Save As، snapshots، recovery، lockfile، Audit Log | يمنع تخريب الأصل ويجعل التغيير قابلًا للمراجعة وإعادة البناء |
| الكتابة إلى PE | LIEF كـ backend، Add/Replace/Delete/ChangeLanguage، typed validation، invariants، plan/dry-run، backup وatomic output | مناسب لتعديلات موارد محافظة أكثر من patch خام غير قابل للتحقق |
| الموارد | RC/RES، Manifest، VersionInfo، StringTable، Bitmap، Icon/Cursor، Menu، Dialog DIALOG/DIALOGEX، JSON models | يغطي جزءًا مهمًا من Win32 resources ويعطي أساسًا لإضافات لاحقة |
| الحوار | parser/serializer ثنائي، JSON، validation، `Project.apply_dialog`، CLI، WPF WYSIWYG | ميزة قوية ومباشرة للهواة ومترجمي واجهات Win32 |
| الفحص | resource index، health، PE inspector، checksum، sections/imports/exports/TLS/debug/CLR/overlay hints، compatibility | يساعد المطور على فهم أثر التعديل قبل الحفظ |
| البحث والمقارنة | بحث metadata وUTF-8 وUTF-16 وregex وhex، Diff Tree، hex ranges، image diff model | يختصر البحث اليدوي ويجعل مراجعة نسختين ممكنة |
| التعريب | `LocalizationCatalog`، missing/extra/changed/untranslated، placeholder validation، pseudo-localization، CSV/JSON | أساس جيد للتعريب، لكنه ليس بعد بيئة مترجم متعددة الملفات كاملة |
| WPF | Resources/Properties/Preview/Search/Inspect/Diff/Localization tabs، Dialog Editor، Authenticode Tools، Dark mode، اختصارات، High Contrast detection | يثبت صلاحية shell مستقل فوق CLI، لكنه يحتاج صقلًا واختبارات UI |
| الأتمتة | CLI من النواة، build، validate، reports HTML/JSON/CSV/Markdown، Git-friendly export/import | مفيد لـ CI وعمليات batch، لكنه يحتاج queue ومعاينة وresume أفضل |
| الإضافات | manifest، registry، permissions، SDK، JSON-lines خارج العملية، timeout وquarantine وWindows Job Object | أساس جيد لمنصة قابلة للتوسع، مع بقاء parser execution الكامل مؤجلًا |
| التوقيع | inspect وstrip إلى ملف جديد، Test PFX، re-sign عبر `signtool` عند توفر SDK، writer يمنع signed PE | سياسة أمان جيدة، لكن re-sign الفعلي يحتاج fixture موقّع وWindows SDK |

## 2. ماذا يتوقع المستخدمون من هذا النوع من الأدوات؟

توضح الأدوات الناضجة أن الطلب لا يقتصر على فتح شجرة موارد وتعديل نص؛ بل يشمل preview، البحث متعدد الملفات، الفلاتر، الاستخراج الجماعي، المساعدة في Manifest، وسجل العمليات.

أما Visual Studio Resource Explorer فيؤكد أن المطورين يعتبرون البحث والفلاتر، عرض عدة ملفات ولغات معًا، التعديل متعدد الملفات، Dark mode، التحقق من placeholders، التحذيرات، التكبير، والتعليقات جزءًا من تجربة الموارد الحديثة [3]. وتظهر وثائق Winres أن المترجمين يحتاجون إلى محرر مرئي يغير النص والحجم والموقع، وينشئ ثقافات مشتقة، ويفحص hotkeys، مع فصل واضح بين ملف اللغة المحايد وملف الثقافة [4].

في الطرف المتقدم، يعرض CFF Explorer مجموعة مختلفة: PE32/PE64، حقول PE، دعم .NET الداخلي، rebuilder وrealigner، hex، imports، integrity checks، scripting، dependency walker، disassembler، ومدير توقيعات [5]. هذا لا يعني أن Resource Studio يجب أن يصبح IDA أو CFF Explorer؛ لكنه يحدد الحد الذي يبدأ عنده المطور المتقدم في طلب diagnostics وdependency context بدل الاقتصار على الموارد.

| احتياج المستخدم | لماذا يهم؟ | هل يغطيه Resource Studio؟ |
|---|---|---|
| تعديل سريع وآمن مع نسخة احتياطية | الهواة يخافون من إفساد EXE، والمطور يحتاج rollback | نعم، وهذه من أقوى نقاط المشروع |
| تغيير نصوص وأيقونات وVersion وManifest | أكثر المهام اليومية شيوعًا | نعم جزئيًا؛ بعض المسارات بلا محرر مرئي |
| Dialog/Menu WYSIWYG | الترجمة وتغيير التخطيط لا يمكن الاعتماد فيهما على hex | Dialog موجود؛ Menu يحتاج صقل UI، وباقي المحررات لاحقة |
| البحث في ملف أو عدة ملفات | العثور على نص أو ID داخل مشروع كبير | داخل PE موجود؛ multi-file batch غير مكتمل |
| مقارنة نسختين | معرفة ما تغير قبل التوزيع أو الترجمة | موجود في النواة وWPF، ويحتاج عرضًا وتصفية أقوى |
| تعدد اللغات | المنتج العالمي يحتاج رؤية اللغات في جدول واحد | الأساس موجود؛ comments وculture files وhotkeys لاحقة |
| استخراج واستيراد جماعي | مفيد للهواة وعمليات التحديث الكبيرة | CLI موجود، لكن UX queue وpreview غير مكتمل |
| دعم موارد غير معروفة | ألعاب قديمة وبرامج Delphi وRCData تعتمد على صيغ خاصة | raw/extension foundation موجود، parser coverage محدودة |
| فحص PE بعد التعديل | تعديل مورد قد يفسد directory أو checksum أو signature | health/invariants موجودة، وتحتاج diagnostics أكثر وضوحًا وcorpus أوسع |
| CI وbatch | المطور يريد تعديل عشرات الملفات دون واجهة | CLI وreports موجودة، وbatch transaction/resume لاحقان |
| .NET/MUI/PRI | مطورو .NET وWindows الحديثة لا يعملون على Win32 فقط | inspection أولي فقط، والتحرير/الربط غير مكتمل |
| دعم Windows shell | Drag/drop، Recent، file association، portable mode | غير مكتمل |

## 3. مقارنة مباشرة بالأدوات الموجودة

### الفجوة العملية

التفوق المطلوب لـResource Studio هو في طبقة المشروع الآمن: عدم الكتابة إلى الأصل، خطة قبل التنفيذ، invariants، audit، snapshots، diff، machine-readable reports، plugin permissions، وPE metadata. الفجوة العملية المتبقية هي سرعة العمليات اليومية ووضوحها داخل الواجهة.

### Resource Tuner وPE Explorer

Resource Tuner وPE Explorer يركزان على الاتساع والراحة: أنواع موارد كثيرة، preview، extraction batch، filters، manifest helpers، workspace preferences، ومحررات تلقائية حسب النوع [2] [6]. Resource Studio يتفوق في القابلية للتتبع والاختبار المفتوح والـdry-run، لكنه يتأخر في النضج المرئي والاتساع.

الاستنتاج هو أن Resource Studio يحتاج **محررًا مرئيًا واحدًا عالي الجودة لكل نوع شائع** بدل إنشاء عشرات parsers بلا تجربة مستخدم. الأولوية: StringTable، VersionInfo، Manifest، Menu، Icon/Bitmap، ثم Accelerator وMessageTable.

### Visual Studio Resource Explorer وWinres

Visual Studio يوضح معيار UX الحديث: multi-file، multi-locale، comments، search، filters، placeholders، theme، zoom، warnings، accessibility [3]. Winres يوضح أن localization ليس مجرد استبدال نصوص؛ يجب أن يكون هناك culture workflow، تغيير حجم وموقع، وفحص hotkeys [4].

لدى Resource Studio بالفعل missing/extra/changed/untranslated وplaceholder validation وpseudo-localization. لذلك فإن الاستثمار الأعلى عائدًا هو تحويل هذا الأساس إلى **لوحة تعريب عملية** بملفات متعددة، سياق وتعليقات، hotkey checks، side-by-side editing، وتصدير XLIFF/PO/RESX.

### CFF Explorer وPE-bear ونطاق التحليل

أدوات PE التحليلية تتعامل مع headers، sections، imports، exports، .NET، signatures، dependencies، disassembly، وscanning. وثائق Microsoft تذكر أن PE يتضمن data directories متعددة، وأن القراءة الصحيحة تحتاج احترام PE32/PE32+ و`SizeOfOptionalHeader` و`NumberOfRvaAndSizes` وRVA/file pointers [7]. كما يوضح LIEF أن شجرة الموارد نفسها متعددة المستويات TYPE/ID/LANGUAGE، وأن إعادة البناء يجب التعامل معها صراحة [8] [9].

لهذا لا أوصي الآن بجعل Resource Studio محرر headers عامًا أو disassembler. ما يحتاجه المطور أولًا هو **PE Diagnostics مفهومة**: ماذا تغير؟ هل checksum صحيح؟ هل resource directory ضمن الحدود؟ هل imports/exports/TLS/CLR/overlay تغيرت؟ هل signature أصبحت غير صالحة؟ ثم يمكن إضافة أدوات كتابة PE العامة بعد corpus واختبارات loader كافية.

## 4. التقييم حسب نوع المستخدم

| المستخدم | الفائدة الحالية | ما ينقصه كي يصبح مستخدمًا متكررًا |
|---|---:|---|
| مطور Win32 يملك المصدر | عالية | ربط أفضل مع RC/RES وVisual Studio، مقارنة generated outputs، manifest/version/string editors مرئية |
| مطور يصلح برنامجًا قديمًا بلا مصدر | متوسطة إلى عالية | دعم RCData/Delphi، preview أقوى، transfer/merge، diagnostics بعد الحفظ، backup/recovery ظاهر |
| مترجم أو localizer | متوسطة | multi-file/multi-locale grid، comments/context، hotkey check، XLIFF/PO/RESX، culture naming، visual layout fit |
| هاوٍ يريد تغيير icon أو text | متوسطة حاليًا | one-click common actions، drag/drop، image preview، wizard، recent/favorites، رسائل خطأ مبسطة |
| مهندس CI/build | عالية | batch transactions، resume، manifest outputs، deterministic logs، parallel safe queue، artifact verification |
| باحث PE أو reverse engineer | متوسطة | dependency scanner، deeper imports/exports/.NET، packer hints، signature manager، لكن هذه ليست أولوية المنتج الأساسية |
| مؤلف إضافة | متوسطة إلى عالية | SDK docs وأمثلة، stable versioned API، test harness، parser/viewer sample، capability discovery |

## 5. هل المشروع مفيد الآن؟

### للمطورين

نعم، وخاصة للمطور الذي يريد تعديل موارد برنامج موجود مع إبقاء العملية قابلة للمراجعة. الجمع بين `plan` وSave As وhealth وinvariants وaudit يجعل المشروع أكثر أمانًا من تعديل مباشر غير موثق. كما أن CLI وJSON والتقارير يجعلان استخدامه مناسبًا لخطوط البناء والاختبارات.

لكن لا يزال من المبكر تقديمه على أنه بديل كامل لـ Visual Studio Resource Explorer أو Resource Tuner. المطور الذي يعمل يوميًا على VersionInfo أو StringTable أو Manifest سيحتاج محررات مرئية أكثر اكتمالًا، والمطور الذي يحتاج .NET satellite assemblies أو MUI فعلية سيحتاج مسارات غير متوفرة بعد.

### للهواة

نعم، بشرط أن تكون الواجهة موجهة نحو المهام وليس نحو المصطلحات الداخلية. الهاوي يريد غالبًا: فتح ملف، رؤية ما يمكن تغييره، استبدال icon أو bitmap، تعديل نص، معاينة النتيجة، حفظ نسخة جديدة، والتراجع إن حدث خطأ. Resource Studio يملك الأمان وDialog Editor والبنية اللازمة، لكنه يحتاج wizards وdrag/drop وpreview ورسائل أخطاء عملية حتى لا يضطر الهاوي إلى فهم LIEF أو resource tree.

### للمترجمين

الأساس واعد، لكنه ليس منتجًا مكتملًا بعد. `LocalizationCatalog` وplaceholder validation وpseudo-localization تعطي قاعدة جيدة، إلا أن القيمة الحقيقية ستظهر عند دعم ملفات متعددة، comments، ثقافات، hotkeys، side-by-side editing، وvisual fit للحوارات والقوائم.

## 6. الإضافات التي ستزيد الفائدة أكثر

### أولوية P0: ما ينبغي بناؤه أولًا

| الإضافة | الأثر | سبب الأولوية | معيار الإنجاز المقترح |
|---|---|---|---|
| **Batch Workspace** | عالٍ جدًا | يفيد المطور والهاوي وCI في عملية واحدة | فتح مجلد أو manifest، فهرسة عدة PE، تحديد عملية، preview قبل التنفيذ، output لكل ملف، سجل وrollback لكل عنصر |
| **Common Resource Wizards** | عالٍ جدًا | يقلل منحنى التعلم | Wizards لـ icon/bitmap/string/version/manifest/menu، كل wizard يعرض plan ثم Save As |
| **إكمال المحررات المرئية** | عالٍ جدًا | raw JSON/CLI لا يكفي للمستخدم اليومي | StringTable وVersionInfo وManifest وMenu وImage editor بخصائص واضحة وpreview واختبار SHA |
| **Localization Workbench** | عالٍ جدًا | يميز المشروع عن محرر موارد تقليدي | multi-file/multi-locale grid، comments، placeholder/hotkey checks، diff، XLIFF/PO/RESX، export/import مع culture validation |
| **Preview Engine** | عالٍ | يقلل التجربة والخطأ | معاينة icon/cursor/bitmap، Dialog/Menu renderer، manifest summary، audio/video extraction، raw fallback |
| **UI Automation وAccessibility** | عالٍ | يثبت أن WPF قابل للاعتماد | اختبارات فتح/فهرسة/بحث/تعديل/Save As، keyboard navigation، AutomationProperties، High Contrast فعلي، screen-reader smoke test |
| **Diagnostics بعد الكتابة** | عالٍ | يمنع ملفات تبدو محفوظة لكنها غير صالحة | before/after report يوضح resource tree، directories، checksum، signature، overlay، PE32/PE32+/machine، مع فشل واضح عند الانحراف |

### أولوية P1: توسعة المنصة

| الإضافة | الأثر المتوقع | ملاحظة تنفيذية |
|---|---|---|
| **Resource Transfer/Merge** | عالٍ للهواة والتخصيص | نقل نوع/ID/لغة بين ملفين عبر plan، conflict resolver، وinvariants؛ يمكن البناء فوق `LIEF.set_resources` لكن مع safeguards [9] |
| **Accelerator وMessageTable وFont وRCData** | عالٍ للتغطية | ابدأ parser/serializer محافظًا وraw fallback، ثم editor متخصص عند وجود fixtures |
| **Delphi DFM / custom resource viewers** | متوسط إلى عالٍ | plugin خارج العملية، لا تضع parser غير موثوق داخل WPF |
| **MUI و.NET satellite assemblies** | عالٍ للمطورين | فتح المجموعة المرتبطة، مقارنة neutral/satellite، culture validation، وعدم خلط .NET resources مع Win32 `.rsrc` |
| **Signature Verification Center** | عالٍ للثقة | اكتشاف SDK، fixture موقّع، verify before/after، test certificate trust instructions، وعدم الادعاء بالثقة العامة |
| **Windows shell integration** | متوسط لكنه مؤثر | Drag/drop، recent files، favorites، file associations اختيارية، portable mode، context menu محلي لا يحتاج خدمة مقيمة |
| **Plugin SDK sample pack** | متوسط طويل الأمد | أمثلة Viewer/Parser/Exporter، contract tests، capability registry، documentation generator |
| **Batch reports وresume** | عالٍ لـCI | journal لكل عنصر، resume من آخر نجاح، exit codes، JSON Lines، artifacts hashes، parallelism اختياري بعد تثبيت العزل |

### أولوية P2: لا تُبنى قبل ثبات الأساس

تشمل هذه الفئة PE rebuilder العام، import editor، disassembler، unpacking شامل، memory/process viewer، وAI translation المباشر. هذه وظائف كبيرة لها أدوات متخصصة قوية، وقد توسع سطح المخاطر وتشتت هوية المنتج. إذا أُضيفت، فالأفضل أن تكون adapters أو plugins منفصلة، لا أن تتحول النواة الآمنة إلى مشروع reverse-engineering عام.

## 7. ترتيب عملي مقترح للدورات القادمة

### الدورة الأولى: تحويل النواة إلى أداة يومية

ينبغي أن تركز الدورة الأولى على Batch Workspace، إكمال محررات StringTable/VersionInfo/Manifest/Menu/Image، Preview Engine، وDiagnostics بعد الكتابة. هذه المجموعة تستثمر معظم ما هو موجود ولا تتطلب اختراع backend جديد.

### الدورة الثانية: جعل التعريب ميزة رئيسية

بعد استقرار المحررات، تُبنى Localization Workbench: multi-file، multi-locale، comments، placeholder/hotkey checks، XLIFF/PO/RESX، وvisual dialog fitting. هذه ميزة مهمة للمشاريع القديمة التي لا تملك source tree منظمًا.

### الدورة الثالثة: توسيع التغطية والامتدادات

يُضاف Accelerator وMessageTable وFont وRCData، ثم Resource Transfer/Merge، ثم MUI و.NET satellites. كل نوع يجب أن يمر عبر نفس العقد: parser، serializer، validation، JSON/RC إن كان مناسبًا، typed Project bridge، CLI، editor أو raw fallback، golden round-trip، malformed tests، وSHA guard.

### الدورة الرابعة: منصة إضافات ناضجة

يُستكمل SDK بالأمثلة والـcontract tests، ويضاف plugin marketplace محلي أو مجلد extensions موثق بدل خدمة مركزية. يجب أن تبقى الإضافات خارج العملية وبصلاحيات معلنة. MCP يظل مؤجلًا كما طلب المستخدم، ولا حاجة إلى إعادته قبل ثبات local SDK وbatch workflows.

## 8. قرارات ينبغي عدم اتخاذها الآن

لا أوصي بإضافة عشرات المحررات المرئية دفعة واحدة، ولا بدمج external executable داخل الحزمة، ولا بجعل Resource Studio محرر PE headers عامًا، ولا بتشغيل parsers خارجية داخل عملية WPF، ولا بإضافة خدمة Windows مقيمة من أجل وظائف يمكن تنفيذها محليًا.

كما لا أوصي بتقديم Test Certificate على أنه وسيلة لتجاوز ثقة Windows. يجب أن يبقى مسار التوقيع مخصصًا للاختبار المعزول، مع توضيح أن تعديل ملف موقع يبطل التوقيع السابق وأن الشهادة الاختبارية ليست ثقة إنتاجية.

## 9. النتيجة النهائية

**Resource Studio مفيد الآن، لكنه مفيد أكثر كمنصة آمنة قابلة للتوسع من كبديل نهائي شامل.** لديه أساس تقني أقوى من كثير من الأدوات الصغيرة: مشروع قابل للاستعادة، backend حقيقي، typed resources، invariants، تقارير، CLI، WPF، plugins معزولة، وتعريب قابل للاختبار. ما ينقصه ليس فكرة جديدة واحدة، بل تحويل هذا الأساس إلى سير عمل يومي أسرع.

إذا كان الهدف تعظيم الفائدة للمطورين والهواة، فالترتيب الأفضل هو: **Batch Workspace، محررات الموارد الشائعة، Preview، Localization Workbench، Diagnostics بعد الكتابة، ثم تغطية Accelerator/MessageTable/RCData وMUI/.NET**. أما disassembler وimport editor وPE rebuilder العام فتُترك كامتدادات متقدمة بعد نضج الأساس.

## المراجع

[2]: https://www.heaventools.com/resource-tuner-features.htm "Resource Tuner Feature List"
[3]: https://devblogs.microsoft.com/visualstudio/introducing-the-revamped-visual-studio-resource-explorer/ "Microsoft: Introducing the Revamped Visual Studio Resource Explorer"
[4]: https://learn.microsoft.com/en-us/dotnet/framework/tools/winres-exe-windows-forms-resource-editor "Microsoft Learn: Winres.exe"
[5]: https://ntcore.com/explorer-suite/ "NTCore Explorer Suite / CFF Explorer"
[6]: https://www.pe-explorer.com/peexplorer-tour-resource-editor.htm "PE Explorer Resource Viewer and Editor"
[7]: https://learn.microsoft.com/en-us/windows/win32/debug/pe-format "Microsoft PE Format"
[8]: https://lief.re/doc/latest/tutorials/07_pe_resource.html "LIEF: PE Resources Tutorial"
[9]: https://lief.re/doc/latest/formats/pe/modifications/resources.html "LIEF: Resources Modification"
[10]: https://github.com/katahiromz/RisohEditor "RisohEditor GitHub Repository"
