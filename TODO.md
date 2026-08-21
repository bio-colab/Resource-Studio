# Resource Studio — TODO قابل للتتبع

**آخر تحديث:** 2026-08-21
**النطاق الحالي:** تطوير الإضافات وطبقة المنصة فقط.  
**MCP:** مؤجل مؤقتًا؛ لا تُضاف وظائف MCP جديدة أثناء هذه الدورة.  
**الأصل:** `C:\Program Files (x86)\Resource Hacker\ResourceHacker.exe` محفوظ وغير قابل للكتابة.  
**نسخة الاختبار:** `C:\Users\Eylias\Desktop\Resource Hacker - Working Copy`.

## main-goal: تقوية Resource Studio إلى محرك PE يمكن إثباته

الهدف الاستراتيجي الحالي هو **تطبيق كل ما يمكن تطبيقه من الملخص التنفيذي لدراسة Low-Level & Systems Programming** على ما هو موجود بالفعل، لا فتح موجة ميزات جديدة. معيار النجاح هو أن يصبح كل تعديل PE قابلًا للإثبات من عدة زوايا مستقلة: Writer وPE invariant graph وWindows loader oracle وchecksum/signature diagnostics وdurable same-volume commit وround-trip contracts وPE corpus وparser fuzzing وJob Object containment وWPF process-state reliability.

هذا الهدف لا يسمح بتوسيع النطاق على حساب الأساس. أي عمل جديد يجب أن يحقق واحدًا من العقود التالية: يمنع تلف output، يكشف اختلافًا بين LIEF وWindows، يثبت round-trip أو invariant، يحسن العزل وقابلية الإيقاف، أو يجعل حالة UI/CLI قابلة للتشخيص وإعادة التشغيل. أما المحررات والأنواع والواجهات الجديدة فتظل مؤجلة ما لم تكن ضرورية لإثبات أحد هذه العقود.

| الحالة | المعرّف | المسار الاستراتيجي | معيار الإنجاز |
|---|---|---|---|
| [x] | SYS-01 | Windows Loader Oracle | مقارنة type/name/language/size/bytes بين LIEF وWin32 resource APIs دون تنفيذ PE الهدف؛ `core/windows_resource_oracle.py` و`test_windows_resource_oracle.py` نجحا على Windows |
| [x] | SYS-02 | Resource/PE Invariant Graph | حماية resource leaves type/name/language/offset/size/hash/codePage، كشف duplicate وbounds issues، ودمجها في `PEInvariantSnapshot`؛ Writer وcorpus وWindows regression نجحت |
| [x] | SYS-03 | Checksum and Signature Diagnostics | `core/pe_integrity.py` يقارن stored/LIEF/ImageHlp checksum ويدمج certificate/signature verification في `inspect`; نجح على Manus وWindows، مع تصنيف checksum غير المعبأ بدل اعتباره signature verdict |
| [x] | SYS-04 | Durable Same-Volume Commit | `commit_temporary` ينفذ fsync ثم ReplaceFileW/MoveFileExW مع same-volume detection وfallback؛ Writer يستخدمه قبل validation والrollback؛ tests نجحت محليًا وعلى Windows |
| [x] | SYS-05 | Round-trip Contract Registry | `core/roundtrip_contracts.py` يسجل raw byte وManifest canonical وMenu/VersionInfo semantic؛ اختبارات إعادة parse وnormalization نجحت محليًا وعلى Windows |
| [x] | SYS-06 | Differential Resource Oracle | `test_win32_update_resource_oracle.py` يطبق no-op raw update عبر UpdateResourceW على نسخة مؤقتة ثم يقارن LIEF/Win32 loader resource tree والbytes؛ نجح على Windows، وMUI/LN ما تزال policy مقيدة |
| [x] | SYS-07 | PE Corpus Taxonomy | `tests/corpus_manifest.json` يثبت hashes وتصنيف PE/negative/auxiliary وallowed normalization؛ corpus manifest test نجح محليًا وعلى Windows |
| [~] | SYS-08 | Parser Fuzz Harnesses | bounded harness يطبق على Manifest/Menu/VersionInfo ويصنف accepted/expected-rejected/crash/excessive-allocation/oversize؛ نجح محليًا وعلى Windows؛ coverage-guided engine مستقل ما يزال لاحقًا |
| [x] | SYS-09 | Job Object Containment Proof | `test_job_tree_containment.py` ينشئ child ثم grandchild داخل Job Object ويثبت انتهاء الشجرة عند إغلاق handle؛ نجح على Windows |
| [~] | SYS-10 | WPF Process-State Contract | إضافة `CliStateText` وحالات Idle/Running/Completed/Failed واختبار UIA يثبت Completed مع BMP preview؛ async cancellation وenabled-controls matrix الكاملة ما تزال لاحقة |

## دلالات الحالة

`[x]` مكتمل ومختبر، `[~]` قيد التنفيذ، `[ ]` مخطط، `[!]` محجوب أو يحتاج قرارًا، `[⏸]` مؤجل عمدًا.

## بوابة صفر: القرارات التي تمنع التعارض

| الحالة | المعرّف | القرار | السبب |
|---|---|---|---|
| [x] | DEC-01 | إبقاء Resource Hacker الأصلي وبيانات ترخيصه كما هي | منع خلط النسخة الأصلية مع المشروع الجديد |
| [x] | DEC-02 | تطوير Resource Studio كمشروع مستقل وطبقة خارجية | يسمح بالمقارنة ويقلل خطر خرق الترخيص |
| [x] | DEC-03 | تعليق MCP دون حذفه | المستخدم طلب تركه جانبًا؛ يبقى الكود موثقًا فقط |
| [x] | DEC-04 | لا تعديل PE خام قبل توفر writer حقيقي واختبارات round-trip | patch مساوي الحجم ليس منصة تحرير كاملة |
| [x] | DEC-05 | الإضافات الأولى خارج العملية الأساسية وبصلاحيات معلنة | عزل الانهيار وتقليل سطح الهجوم |
| [x] | DEC-06 | عدم بناء كل المحررات دفعة واحدة | String/Version/Manifest أعلى قيمة وأقل مخاطرة من Dialog المرئي |

## المرحلة 1: تثبيت خط الأساس

| الحالة | المعرّف | المهمة | الاعتماد | معيار الإنجاز |
|---|---|---|---|---|
| [x] | BASE-01 | نسخ Resource Hacker إلى Working Copy | لا شيء | تطابق SHA-256 وعدم تغير الأصل |
| [x] | BASE-02 | بناء مصفوفة الوظائف واختبار فتح/عرض/استخراج/إضافة/استبدال/حذف/لغة/RC/RES/سكربت | BASE-01 | تقرير نتائج محفوظ |
| [x] | BASE-03 | إنشاء حزمة ملفات PE/RC/RES/لغة مخصصة | BASE-01 | fixtures قابلة لإعادة التشغيل |
| [x] | BASE-04 | توثيق قدرات Resource Hacker والحدود والترخيص | BASE-01 | تقرير بحثي محفوظ |
| [x] | BASE-05 | إنشاء مشروع Resource Studio منفصل | BASE-04 | مجلد مشروع ووثائق أولية |

## المرحلة 2: نواة المشروع الآمن

| الحالة | المعرّف | المهمة | الاعتماد | معيار الإنجاز |
|---|---|---|---|---|
| [x] | CORE-01 | تعريف صيغة مشروع نصية `project.json` وملفات مصادر الموارد | BASE-05 | مشروع يفتح ويغلق دون فقد حالة |
| [x] | CORE-02 | إنشاء `Project`, `ResourceEntry`, وواجهة موارد داخلية | CORE-01 | schemas واختبارات تحقق |
| [x] | CORE-03 | فصل `Original`, `Workspace`, وبيانات المشروع مع منع الكتابة للأصل | CORE-01 | لا كتابة إلى Original في الاختبارات |
| [x] | CORE-04 | إضافة Save As وRevert وSnapshot واستعادة بعد الانهيار | CORE-03 | snapshot يحفظ project.json وworkspace ويستعيدهما ذريًا مع backup وPE verification |
| [x] | CORE-05 | إضافة فهرس type/name/language/size/hash/offset | CORE-02 | `ResourceIndex` في Core و`resourceIndex` داخل PEHealth مع اختبار |
| [~] | CORE-06 | إضافة صحة الملف Health Model للقراءة فقط | CORE-05 | PEHealth وresourceIndex منجزان؛ WinVerifyTrust الأصلي لاحق على Windows |
| [x] | CORE-07 | نقل منطق الأوامر إلى Core مستقل عن أي واجهة | CORE-02 | اختبارات النواة ناجحة |

## المرحلة 3: الأوامر والتراجع

| الحالة | المعرّف | المهمة | الاعتماد | معيار الإنجاز |
|---|---|---|---|---|
| [x] | CMD-01 | تعريف Command مع execute/undo/redo/description/timestamp | CORE-02 | أوامر قابلة للتراجع |
| [x] | CMD-02 | إنشاء Command History مع grouping وdirty state | CMD-01 | `CommandGroup` و`execute_group` مع execute/undo/redo وrollback ذري |
| [x] | CMD-03 | أوامر Replace/Delete/Add/ChangeLanguage/ChangeId/Rename | CMD-01 | `ChangeIdCommand` و`RenameResourceCommand` أضيفتا مع الاختبارات، وكل الأوامر الأساسية تعمل |
| [x] | CMD-04 | ربط الأوامر بالـ Snapshot وسجل التدقيق | CMD-02, CORE-04 | كل execute/undo/redo ينشئ snapshot ويسجل AuditLog |
| [x] | CMD-05 | اختبار فشل الأمر والتراجع الذري | CMD-02 | execute/undo الفاشلان يعيدان حالة المشروع وhistory كما كانت |

## المرحلة 4: backend موارد حقيقي

| الحالة | المعرّف | المهمة | الاعتماد | معيار الإنجاز |
|---|---|---|---|---|
| [x] | WRITER-01 | اختيار writer PE/Win32 حقيقي أو adapter موثق | CORE-07 | LIEF Apache-2.0 موثق، مع UpdateResource/Resource Hacker adapters مؤجلة |
| [~] | WRITER-02 | دعم Replace بمورد مختلف الحجم | WRITER-01 | `replace_typed_resource` يتحقق من Bitmap/Icon/Cursor/Menu/StringTable/Version؛ دعم أنواع PE الأوسع لاحق |
| [~] | WRITER-03 | دعم Add/Delete/ChangeLanguage | WRITER-01 | العمليات الأساسية وtyped Add/Replace و`ResRecord` bridge منجزة؛ دعم أنواع PE الأوسع لاحق |
| [~] | WRITER-04 | تحقق alignment/resource directory/size/checksum | WRITER-02 | PEInspector يحسب checksum ويقارن header عند وجوده، وPEHealth يتحقق من resource bounds؛ alignment العميق لاحق |
| [x] | WRITER-05 | Backup + Save As + atomic replace | CORE-04, WRITER-02 | output جديد، backup موجود عند التكرار، وatomic replace |
| [~] | WRITER-06 | كشف توقيع Authenticode والتحذير قبل الحفظ | CORE-06 | `core/windows_security.py` يمر عبر Get-AuthenticodeSignature وWinVerifyTrust native بلا UI؛ writer يمنع تعديل signed PE، ومسار strip/re-sign لاحق |

## المرحلة 5: واجهة الإضافات

| الحالة | المعرّف | المهمة | الاعتماد | معيار الإنجاز |
|---|---|---|---|---|
| [x] | PLUG-01 | تعريف plugin manifest: id/name/version/api/entry/permissions | CORE-07 | manifest صالح وغير صالح يختبران |
| [x] | PLUG-02 | تعريف أنواع Viewer/Editor/Importer/Exporter/Parser/Panel | PLUG-01 | registry يعرض النوع والصلاحيات |
| [x] | PLUG-03 | اختيار العزل: out-of-process JSON-lines في v1 | PLUG-01 | PluginHost وtimeout وJSON-lines منجزة ومختبرة |
| [x] | PLUG-04 | permission gate: project.read/modify/files.read/output.write/network | PLUG-01 | رفض الصلاحية غير المعلنة |
| [x] | PLUG-05 | تعطيل plugin المنهار وسجل أحداثه | PLUG-03 | PluginHost يعطل الإضافة تلقائيًا ويسجل الحدث ويمنع Context حتى التمكين |
| [x] | PLUG-06 | versioning وcompatibility للمكونات | PLUG-01 | Registry يقبل النطاق المدعوم ويرفض API أو host version غير المتوافق |
| [x] | PLUG-07 | SDK صغير: Project/ResourceTree/Entry/Data/Command/Logger | CORE-07, PLUG-01 | Context يوفر resources/read/put/log وexecute_command/undo_command مع History وصلاحيات |

## المرحلة 6: المحررات والإضافات الأعلى قيمة

| الحالة | المعرّف | المهمة | الاعتماد | معيار الإنجاز |
|---|---|---|---|---|
| [x] | EDIT-01 | Raw/Hex viewer مع offset وASCII وcopy formats | CORE-05 | `HexViewer.resource_slice` وCLI `hex` يستهلكان ResourceIndex offset مع اختبار |
| [~] | EDIT-02 | String Tables editor متعدد اللغات | CMD-03, WRITER-03 | Localization Catalog و`StringTableBlock` UTF-16 parser/serializer وProject bridge منجزة؛ واجهة متعددة اللغات لاحقة |
| [~] | EDIT-03 | Version Info editor | CMD-03, WRITER-03 | JSON وRC وPE VERSION binary parser/serializer وProject.apply_version_info وCLI `version-info` منجزة؛ واجهة مرئية لاحقة |
| [~] | EDIT-04 | Manifest XML editor مع validation | CMD-03, WRITER-03 | XML parse/validation/execution-level منجز؛ ربط PE لاحق |
| [~] | EDIT-05 | Icon/Cursor viewer/editor | WRITER-03 | parser/serializer وtyped writer و`Project.apply_typed_resource` منجزة؛ واجهة viewer المرئية لاحقة |
| [~] | EDIT-06 | Bitmap/image viewer | WRITER-03 | parser/serializer وtyped writer و`Project.apply_typed_resource` منجزة؛ واجهة viewer المرئية لاحقة |
| [~] | EDIT-07 | Menu editor | CMD-03, WRITER-03 | parser/serializer وtyped writer و`Project.apply_typed_resource` منجزة؛ واجهة editor المرئية لاحقة |
| [~] | EDIT-08 | Dialog editor مرئي | CMD-03, WRITER-03 | `DialogResource` يدعم DIALOG/DIALOGEX binary parser/serializer وJSON validation، و`Project.apply_dialog` وCLI `dialog export/apply` وWPF `DialogEditorWindow` WYSIWYG مع Load/Save/Save As؛ UI automation وخصائص Win32 المتقدمة لاحقة |

## المرحلة 7: الترجمة والمقارنة والأتمتة

| الحالة | المعرّف | المهمة | الاعتماد | معيار الإنجاز |
|---|---|---|---|---|
| [x] | LOC-01 | Localization Mode لغة مصدر/هدف | EDIT-02 | `mode_report` يعرض Missing/Extra/Changed/Untranslated بوضوح |
| [x] | LOC-02 | CSV/JSON أولًا ثم XLIFF/PO/RESX كإضافات | EDIT-02 | JSON وCSV export/import round-trip منجزان؛ XLIFF/PO/RESX لاحقة اختيارية |
| [x] | LOC-03 | placeholder validation وpseudo-localization | LOC-01 | validation موجود وpseudo-localization يحافظ على placeholders |
| [x] | DIFF-01 | Diff tree للنصوص والموارد والـ Hex | CORE-05, EDIT-01 | DiffNode يدعم النصوص والموارد ومقاطع hex وحالات Added/Removed/Modified/Unchanged |
| [~] | DIFF-02 | صور جنبًا إلى جنب وmerge انتقائي | EDIT-05, EDIT-06 | `diff_image_payloads` و`merge_selected_resources` وCLI `image-diff` منجزة؛ واجهة العرض المرئية لاحقة |
| [x] | AUTO-01 | CLI من نفس Core | CORE-07 | list/extract/diff/build/validate تعمل باختبار تكاملي |
| [x] | AUTO-02 | Build pipeline project.json | CORE-01, CMD-02 | `Project.build` يتحقق من workspace والموارد وPE round-trip ويستخدم Save As |
| [x] | AUTO-03 | تقارير HTML/JSON/CSV/Markdown | DIFF-01, CORE-06 | أمر report يولد الصيغ الأربع من health وDiff Tree مع اختبارات |
| [x] | AUTO-04 | Git-friendly export/import | CORE-01, LOC-02 | `Project.export_git/import_git` وCLI `export/import` ينسخان metadata/resources/workspace مع تحقق |

## المرحلة 8: تجربة المستخدم والتحليل المتقدم

| الحالة | المعرّف | المهمة | الاعتماد | معيار الإنجاز |
|---|---|---|---|---|
| [x] | UI-01 | اختيار shell Windows: WPF أولًا، WinUI 3 لاحقًا إن ثبتت الحاجة | CORE-07 | `windows/ResourceStudio.Windows` مبني بـ .NET 8 WPF ويشغل shell مستقلًا فوق CLI؛ UI التفصيلية لاحقة |
| [~] | UI-02 | Tree/Tabs/Properties/Preview/Search/Diff | UI-01, DIFF-01 | WPF الآن يوفر Tabs للموارد وInspect/Diff/Localization، DataGrid للفهرس والخصائص والبحث، Preview خام عبر CLI `hex` وDiff Tree مبني من `diff`؛ UI automation وعمليات التحرير المرئية المتخصصة لاحقة |
| [~] | UI-03 | Command palette/keyboard/dark mode/high contrast | UI-02 | مفاتيح `Ctrl+O/Ctrl+F/Ctrl+I/F5`، زر Dark mode، واكتشاف Windows High Contrast أضيفت؛ command palette وaccessibility automation وpersisted theme لاحقة |
| [~] | UI-04 | Localization dashboard | LOC-01, UI-02 | تبويب WPF للمقارنة وpseudo-localization، وCLI `localization compare/pseudo` فوق `LocalizationCatalog`؛ ربط التعديل مباشرة بموارد STRINGTABLE وCSV/XLIFF workflow المتقدم لاحق |
| [~] | PE-01 | PE inspector sections/imports/exports/relocs/TLS/debug | CORE-05 | `PEInspector` وCLI `inspect` وchecksum fields منجزة؛ توسعة exports/TLS حسب توفر LIEF لاحقة |
| [~] | PE-02 | MUI support | PE-01, LOC-01 | كشف `.mui` وlanguage hint وsatellite hint قراءة فقط منجز؛ فتح/ربط/مقارنة فعلية لاحقة |
| [~] | PE-03 | .NET resources/satellite assemblies قراءة محدودة | PE-01 | كشف CLR directory وتحذير metadata غير المفكوكة منجز؛ جداول .NET التفصيلية لاحقة |
| [ ] | PE-04 | PRI/MSIX منفصلًا | PE-01 | لا يخلط مع `.rsrc` |
| [~] | EXT-01 | Custom type definitions/parsers/viewers/serializers | PLUG-07, PE-01 | `ResourceTypeDefinition` وregistry declarative وentrypoint gate منجزة؛ تنفيذ parser الخارجي عبر host لاحق |
| [~] | EXT-02 | Scripting بعد استقرار SDK والصلاحيات | PLUG-07, AUTO-01 | `PluginHost.dry_run_registered` يتحقق من المسار والطلب دون تشغيل؛ sandbox تنفيذ كامل لاحق |

## المرحلة 9: فجوات عالية الأثر اكتُشفت في المراجعة المعمارية

هذه المرحلة لا تعني أن العناصر الحالية ناقصة بالضرورة؛ بل تسجل القدرات التي تغيّر مستوى الأمان والاعتمادية أو توسع الاستخدام بشكل واضح، ولم تكن ممثلة كمهام مستقلة في الخطة السابقة.

| الحالة | المعرّف | المهمة | الأولوية | معيار الإنجاز |
|---|---|---|---|---|
| [x] | GAP-01 | ضمان التغيير الجراحي ومقارنة PE خارج الموارد | حرجة | `core/invariants.py` يقارن الأقسام غير المرتبطة بالموارد وdirectories/imports/exports/TLS/debug/overlay، وwriter يرفض التغير الجانبي |
| [~] | GAP-02 | دورة حياة التوقيع Authenticode كاملة | حرجة | أضيف `signature.py` وCLI/WPF لمسار Inspect/Strip وCreate Test Certificate وRe-sign عبر `signtool.exe`، مع Save As وbackup ومنع الأصل وكلمة مرور عبر environment؛ strip ورفض الحالات غير الموقعة وإنشاء PFX اختبِرت على Windows، أما re-sign الفعلي فيحتاج Windows SDK/signtool غير المثبت حاليًا، والتحقق الكامل من الثقة/strip-re-sign الإنتاجي لاحق |
| [~] | GAP-03 | مصفوفة توافق PE حقيقية | عالية | `core/compatibility.py` وCLI inspect يخرجان profiles وnamed resources وoverlay وARM64X/CLR/delay imports؛ corpus PE32/PE32+/SYS/ARM64X موسع لاحق |
| [x] | GAP-04 | خطة تنفيذ قبل الكتابة ومعاينة قابلة للمقارنة | عالية | `LiefPEWriter.plan_add_resource/plan_replace_resource` وCLI `plan` ينفذان dry-run داخليًا ويعرضان hashes وresource sizes وinvariants دون output خارجي |
| [~] | GAP-05 | قفل المشروع والتعافي من الانقطاع | عالية | `Project.acquire_lock/release_lock/locked` تمنع التشغيل المتزامن؛ transaction journal والاستعادة التلقائية الكاملة لاحقان |
| [~] | GAP-06 | حدود أمان الإضافات خارج العملية | حرجة | `PluginLimits` وWindows Job Object process/memory cap تعمل؛ filesystem/network isolation الكامل لاحق |
| [x] | GAP-07 | بحث موحد متقدم | عالية | `core/search.py` وCLI `search` يدعمان metadata وUTF-8 وUTF-16 وregex وhex وفلترة type/language مع offset |
| [~] | GAP-08 | تغطية Dialog وAccelerator وFont وMessageTable | عالية | Dialog مكتمل جزئيًا: DIALOG/DIALOGEX parser/serializer، JSON model، malformed/round-trip tests، Project/CLI bridge وWPF WYSIWYG؛ Accelerator/Font/MessageTable وخصائص Win32 المتقدمة لاحقة |
| [ ] | GAP-09 | تعريب تبادلي كامل | متوسطة | XLIFF/PO/RESX مع حفظ التعليقات والسياق وplural rules وplaceholder validation، دون خلطه بمحرر الموارد الأساسي |
| [~] | GAP-10 | حفظ provenance والإصدارات والتراخيص | عالية | `core/provenance.py` ينشئ manifest للبناء يحوي LIEF/version/input/output hashes/resources/licenses؛ SBOM وreproducible metadata الكاملان لاحقان |
| [~] | GAP-11 | اختبار PE خارج الموارد وخصائص loader | عالية | invariants وcompatibility وPEInspector تغطي directories/imports/exports/TLS/debug/CLR/overlay؛ corpus loader profiles الأوسع لاحق |
| [~] | GAP-12 | قابلية التشغيل الآلي الموثوقة | متوسطة | CLI `plan` وmachine-readable reports وexit codes موجودة؛ batch transactions والاستئناف الكامل لاحق |

## بوابة الجودة قبل كل إصدار

| الحالة | المعرّف | الفحص |
|---|---|---|
| [x] | QA-01 | Unit tests للـ PE parser وresource serializers | اختبارات parser وManifest/VersionInfo RC+binary/Localization serializers وgolden ناجحة |
| [x] | QA-02 | Golden files وround-trip فتح/تعديل/حفظ/إعادة فتح | `tests/golden/sample_resources.json` واختبار `test_golden_roundtrip.py` |
| [~] | QA-03 | Fuzzing للملفات التالفة وحدود الذاكرة | corpus deterministic وbounded bit-flip fuzzing لمدخلات PE/image/menu/VERSION؛ fuzzing property-based موسع لاحق |
| [x] | QA-04 | Integration tests للـ CLI والplugins | اختبار cross-feature يربط Project/Build/CLI/Health/Diff مع حماية الأصل |
| [~] | QA-08 | دورة Authenticode على Windows | اختبار inspect/رفض strip غير الموقّع/إنشاء PFX وSave As؛ اختبار re-sign الفعلي ينتظر توفر `signtool.exe` وfixture موقّع |
| [x] | QA-09 | Batch Workspace على ملفات PE متعددة | اختبارات core وCLI تغطي plan/apply، replace/delete، التقرير، backup، رفض in-place، وحماية SHA للـfixture |
| [x] | QA-10 | StringTable/Version/Manifest/Menu typed workflows | اختبار CLI export/apply وround-trip وvalidation ورفض Manifest غير الصالح وJSON menu model |
| [x] | QA-11 | Image resource workflow | اختبار BITMAP BMP↔DIB export/apply وJSON model للمجموعات مع حماية fixture |
| [x] | QA-12 | PreviewEngine typed/raw contract | اختبار Manifest/Version/Menu/StringTable/Bitmap وraw fallback وmalformed fallback وBMP output |
| [x] | QA-13 | PreviewEngine golden contract | `tests/golden/preview_models.json` يثبت kind/title/summary/raw fields للـManifest/Menu/raw preview |
| [x] | QA-14 | Menu tree mutation contract | اختبار move/reparent/reorder/update ورفض نقل العقدة أسفل descendant مع round-trip |
| [x] | QA-15 | WPF visual rendering smoke | بناء WPF وتشغيل العملية، fixture ICON، تحميل العنصر الفردي، تحويله إلى BMP، وإثبات `BMP preview` عبر `tests/windows/Invoke-ResourceStudioUIAutomation.ps1`؛ اختبارات Accessibility وscreen reader الأوسع ما تزال لاحقة |
| [x] | QA-16 | Individual Icon/Cursor payload round-trip | `image-payload export/apply` بصيغ raw وBMP، تحويل DIB↔BMP، PNG اختياري عبر Pillow، Save As و`verified=true`؛ اختبار نجح على Manus وWindows |
| [x] | QA-17 | PE corpus matrix round-trip | `tests/qa/test_pe_corpus_matrix.py` ينفذ سلسلة Save As حتمية تغطي RCDATA وBITMAP وICON وGROUP_ICON وSTRING وVERSION وتغيير اللغة والحذف، مع PEHealth وPEInspector وProject verification؛ نجح محليًا وعلى Windows |
| [x] | QA-18 | Existing-output rollback | إجبار validation failure مع output موجود و`backup_existing_output=False` يثبت بقاء bytes الأصلية وعدم ترك rollback temporary files؛ `test_pe_writer.py` نجح |
| [ ] | QA-05 | UI automation وAccessibility keyboard/screen reader |
| [~] | QA-06 | مقارنة SHA-256 للأصل قبل وبعد كل اختبار | SHA guards تشمل Project/writer/editors/inspector؛ تعميم helper على كل اختبار قديم لاحق |
| [x] | QA-07 | لا تشغيل MCP أو نقل بعيد في هذه الدورة | MCP بقي مؤجلًا ولم تُضف وظائف جديدة أثناء الدورة |

## سجل التنفيذ

| التاريخ | المهمة | الحالة | الدليل |
|---|---|---|---|
| 2026-08-19 | نسخة عمل واختبارات Resource Hacker | مكتمل | تقرير التقييم ومصفوفة الوظائف |
| 2026-08-19 | تأسيس Resource Studio وMCP | مكتمل ثم مؤجل | `docs/MCP-LOCAL-README.md` |
| 2026-08-20 | قراءة الخطة المرفقة وفض التعارضات | مكتمل | `docs/PLAN-RECONCILIATION.md` |
| 2026-08-20 | إنشاء TODO قابل للتتبع | مكتمل | هذا الملف |
| 2026-08-20 | تنفيذ Project/ResourceEntry/Save/Load/Snapshot | مكتمل جزئيًا | `core/project.py` واختبار النواة |
| 2026-08-20 | تنفيذ Commands وUndo/Redo | مكتمل جزئيًا | `core/commands.py` واختبار النواة |
| 2026-08-20 | تنفيذ Plugin Manifest/Registry/Permissions | مكتمل جزئيًا | `core/plugins.py` واختبار الإضافات |
| 2026-08-20 | تنفيذ Localization Catalog والمقارنة والتصدير | مكتمل جزئيًا | `core/localization.py` واختبار التعريب |
| 2026-08-20 | تنفيذ ManifestDocument وVersionInfo كنماذج مستقلة | مكتمل جزئيًا | `core/manifest.py`, `core/version_info.py` واختباران |
| 2026-08-20 | اختيار LIEF وتنفيذ Save-As PE writer أولي | مكتمل جزئيًا | `core/pe_writer.py` واختبار round-trip |
| 2026-08-20 | توسيع LIEF writer إلى Add/Delete/ChangeLanguage | مكتمل جزئيًا | اختبار PE writer شامل |
| 2026-08-20 | تنفيذ PEHealth للتوقيع والموارد والتحذيرات | مكتمل جزئيًا | `core/health.py` واختبار Health |
| 2026-08-20 | تنفيذ HexViewer للعرض والبحث وصيغ النسخ | مكتمل جزئيًا | `core/hex_view.py` واختبار Hex |
| 2026-08-20 | ربط Project بملف PE وSave As وAuditLog | مكتمل جزئيًا | `core/project.py` واختبار `test_project_pe.py` |
| 2026-08-20 | تنفيذ PluginHost خارج العملية عبر JSON-lines | مكتمل جزئيًا | `core/plugin_host.py` واختبار `test_plugin_host.py` |
| 2026-08-20 | ربط CommandHistory بالـ snapshots وAuditLog وrollback الذري | مكتمل ومختبر | `core/commands.py` واختبار `test_command_atomic.py` |
| 2026-08-20 | إضافة quarantine للإضافات الفاشلة وسجل enabled/disabled | مكتمل ومختبر | `core/plugins.py` واختبار `test_plugin_quarantine.py` |
| 2026-08-20 | تنفيذ CLI من نفس Core | مكتمل ومختبر | `resource_studio_cli.py` واختبار `tests/test_cli.py` |
| 2026-08-20 | إضافة التقارير واختبار golden/round-trip | مكتمل جزئيًا | `core/reports.py`, `tests/golden/`, `tests/qa/test_golden_roundtrip.py` |
| 2026-08-20 | تقوية PluginHost بتعطيل تلقائي عند crash | مكتمل ومختبر | `run_registered` واختبار `test_plugin_quarantine.py` |
| 2026-08-20 | إضافة plugin API/host compatibility checks | مكتمل ومختبر | `core/plugins.py` واختبار `test_plugin_compatibility.py` |
| 2026-08-20 | تنفيذ Build Pipeline آمن من `project.json` | مكتمل ومختبر | `Project.build`, CLI `build`, واختبار `test_project_build.py` |
| 2026-08-20 | تنفيذ Diff Tree للنصوص والموارد والـ Hex وربطه بالتقارير وCLI | مكتمل ومختبر | `core/diff.py`, `test_diff.py`, `resource_studio_cli.py` |
| 2026-08-20 | إضافة cross-feature integration test مع SHA guard | مكتمل ومختبر | `tests/qa/test_cross_feature.py` |
| 2026-08-20 | إكمال Localization Mode وCSV/JSON وpseudo-localization | مكتمل ومختبر | `core/localization.py` واختبار `test_localization.py` |
| 2026-08-20 | توسيع PluginContext إلى SDK للموارد والصلاحيات والسجل | مكتمل جزئيًا ومختبر | `core/plugins.py` واختبار `test_plugin_sdk.py` |
| 2026-08-20 | إكمال recovery من snapshot مع نسخة workspace وbackup | مكتمل ومختبر | `Project.restore_snapshot` واختبار `test_project_restore.py` |
| 2026-08-20 | تنفيذ ResourceIndex ودمجه في PEHealth | مكتمل ومختبر | `core/resource_index.py`, `core/health.py`, `test_resource_index.py` |
| 2026-08-20 | تشديد PE writer validation وإضافة validate_output | مكتمل جزئيًا ومختبر | `core/pe_writer.py`, `test_pe_writer.py` |
| 2026-08-20 | إضافة Plugin Command adapters إلى SDK | مكتمل ومختبر | `PluginContext.execute_command/undo_command`, `test_plugin_sdk.py` |
| 2026-08-20 | إضافة resource bounds validation لمسار PE writer | مكتمل جزئيًا ومختبر | `PEHealth` و`LiefPEWriter.validate_output`, `test_pe_writer.py` |
| 2026-08-20 | تنفيذ Bitmap وIcon/Cursor وMenu resource models | مكتمل جزئيًا ومختبر | `core/image_resources.py`, `core/menu_resources.py`, واختبارات parser/serializer |
| 2026-08-20 | ربط typed image/menu payloads بـ LIEF writer | مكتمل جزئيًا ومختبر | `replace_typed_resource`, `add_typed_resource`, `test_image_resources.py`, `test_menu_resources.py` |
| 2026-08-20 | إضافة editor SHA/malformed QA guards | مكتمل ومختبر | `tests/qa/test_editor_sha_guard.py`, `test_editor_malformed.py` |
| 2026-08-20 | تنفيذ image diff وPEInspector وربطهما بالـ CLI/report | مكتمل جزئيًا ومختبر | `core/diff.py`, `core/pe_inspector.py`, `resource_studio_cli.py` واختباراتهما |
| 2026-08-20 | إضافة checksum inspection المحلي إلى PEInspector | مكتمل ومختبر | `checksum`, `computedChecksum`, `checksumValid` واختبار PEInspector |
| 2026-08-20 | إضافة MUI/.NET metadata inspection القراءة فقط وربطه بالـ CLI | مكتمل جزئيًا ومختبر | `core/pe_metadata.py`, CLI `inspect/report inspect`, `test_pe_metadata.py` |
| 2026-08-20 | إضافة custom resource type registry declarative مع quarantine gate | مكتمل جزئيًا ومختبر | `ResourceTypeDefinition`, `PluginRegistry`, `test_custom_resource_types.py` |
| 2026-08-20 | إضافة PluginHost scripting dry-run دون تشغيل كود | مكتمل جزئيًا ومختبر | `dry_run_registered`, `test_plugin_dry_run.py` |
| 2026-08-20 | إضافة bounded bit-flip fuzz corpus للمدخلات المحلية | مكتمل ومختبر | `tests/qa/test_bounded_fuzz.py` |
| 2026-08-20 | إكمال Command grouping وChangeId/Rename | مكتمل ومختبر | `core/commands.py`, `test_command_grouping.py` |
| 2026-08-20 | ربط typed editors مباشرة بـ Project workspace وAuditLog | مكتمل ومختبر | `Project.apply_typed_resource`, `test_project_typed.py` |
| 2026-08-20 | إضافة VersionInfo RC parser/serializer مع escaping وround-trip | مكتمل ومختبر | `VersionInfo.to_rc/from_rc`, `test_version_info.py` |
| 2026-08-20 | إضافة StringTableBlock UTF-16 parser/serializer وID mapping | مكتمل ومختبر | `core/string_table.py`, `test_string_table.py` |
| 2026-08-20 | ربط StringTable typed payload بـ LIEF writer | مكتمل ومختبر | `validate_resource_payload`, `add_typed_resource`, `test_pe_writer.py` |
| 2026-08-20 | تنفيذ RES binary parser/serializer محافظ | مكتمل ومختبر | `core/res_format.py`, `test_res_format.py` |
| 2026-08-20 | ربط ResRecord مباشرة بـ Project وLIEF writer | مكتمل ومختبر | `replace_res_record`, `add_res_record`, `Project.apply_res_record`, `test_project_typed.py` |
| 2026-08-20 | إضافة PE VERSION binary parser/serializer وProject bridge وCLI conversion | مكتمل ومختبر | `VersionInfo.to_bytes/from_bytes`, `Project.apply_version_info`, CLI `version-info`, `test_version_info.py`, `test_project_typed.py` |
| 2026-08-20 | ربط HexViewer بـ ResourceIndex وCLI `hex` | مكتمل ومختبر | `HexViewer.resource_slice`, `resource_studio_cli.py`, `test_hex_view.py`, `test_cli.py` |
| 2026-08-20 | إضافة VERSION إلى bounded fuzz corpus | مكتمل ومختبر | `tests/qa/test_bounded_fuzz.py` |
| 2026-08-20 | توسيع CLI باختبارات inspect وimage-diff وreport inspect | مكتمل ومختبر | `tests/test_cli.py` |
| 2026-08-20 | إضافة inspector/image diff SHA guard وتشغيل البوابة الكاملة | مكتمل ومختبر | `tests/qa/test_inspector_sha_guard.py` وجميع اختبارات core/CLI/QA |
| 2026-08-20 | توسيع بوابة QA بالـ serializers وmalformed corpus وSHA guard | مكتمل جزئيًا ومختبر | `tests/qa/test_serializers.py`, `test_malformed_inputs.py`, `test_sha_guard.py` |
| 2026-08-20 | تنفيذ Git-friendly project export/import وCLI | مكتمل ومختبر | `Project.export_git/import_git`, CLI `export/import`, واختبار `test_project_portable.py` |
| 2026-08-20 | مراجعة TODO لاكتشاف فجوات عالية الأثر | مكتمل كتحليل وتنفيذ جزئي | `docs/TODO-AUDIT-2026-08-20.md`, GAP-01 إلى GAP-12 |
| 2026-08-20 | تنفيذ GAP-01/04/05/06/07/10/11/12 محليًا | مكتمل جزئيًا ومختبر | `invariants.py`, `plan`, `Project.locked`, `PluginLimits`, `search.py`, `provenance.py`, `compatibility.py`, `test_gap_features.py` |
| 2026-08-20 | تنفيذ Authenticode report وسياسة منع تعديل signed PE | مكتمل جزئيًا ومختبر | `signature.py`, CLI inspect/report، وحظر writer قبل strip/re-sign |
| 2026-08-20 | تنفيذ RC text parser/serializer | مكتمل ومختبر | `core/rc_format.py` وround-trip STRINGTABLE/MENU/VERSIONINFO |
| 2026-08-20 | إضافة اختبارات صيغ التقارير ومدخلات PE التالفة | مكتمل جزئيًا | `test_reports.py`, `test_malformed_inputs.py` |
| 2026-08-20 | إغلاق بوابة Manus وتجهيز حزمة Windows | مكتمل ومختبر | 33 core + 9 QA + CLI، `docs/TRANSFER-TO-WINDOWS.md`, `resource-studio-manus-bundle.tar.gz` |
| 2026-08-20 | Windows Python/LIEF وAuthenticode gate | مكتمل ومختبر | Python 3.12، LIEF 1.0.0، Get-AuthenticodeSignature وWinVerifyTrust native، جميع core/CLI/QA نجحت، وSHA الأصل محفوظ |
| 2026-08-20 | بناء وتشغيل WPF shell وJob Object | مكتمل ومختبر | .NET SDK 8.0.424، `windows/ResourceStudio.Windows`, WPF process، `core/windows_isolation.py`, `PluginHost` |
| 2026-08-20 | تنفيذ DialogResource وDIALOG/DIALOGEX parser/serializer وProject bridge | مكتمل ومختبر | `core/dialog_resources.py`, `Project.apply_dialog`, `test_dialog_resources.py`, `test_dialog_project.py`, CLI `dialog` |
| 2026-08-20 | إضافة WPF Dialog Editor والتحقق من بوابة Windows | مكتمل ومختبر | `DialogEditorWindow.xaml/.cs`, WPF build بلا تحذيرات أو أخطاء، و45 اختبار Python ناجحة على Windows |
| 2026-08-20 | إضافة Authenticode Inspect/Strip/Re-sign وTest Certificate workflow | مكتمل جزئيًا ومختبر | `core/signature.py`, CLI `signature`, `SignatureToolsWindow.xaml/.cs`, اختبار `test_signature_operations.py`، إنشاء PFX و46 اختبار Python ناجحة؛ re-sign الفعلي ينتظر Windows SDK/signtool |
| 2026-08-20 | تنفيذ متطلبات المرحلة الثامنة UI-02/UI-03/UI-04 | مكتمل جزئيًا ومختبر | WPF Resources/Properties/Preview/Search/Diff/Localization tabs، اختصارات Dark/High Contrast، CLI localization، اختبار `test_phase8_localization_cli.py`، وبناء WPF ناجح بلا تحذيرات |
| 2026-08-20 | بدء Productization بـ Batch Workspace | مكتمل جزئيًا ومختبر | `core/batch.py`, CLI `batch plan/apply`, تبويب WPF Batch Workspace، اختبارات `test_batch.py` و`test_batch_cli.py`، وWPF build ناجح على Windows |
| 2026-08-20 | تنفيذ Common Resource Wizards لـStringTable/Version/Manifest/Menu/Image | مكتمل جزئيًا ومختبر | `StringTableEditorWindow`, `ResourceWizardsWindow`, `ImageResourceWindow`, أوامر `string-table`, `version-resource`, `manifest-resource`, `menu-resource`, `image-resource`، 52 اختبارًا مسجلًا، وبناء WPF ناجح بـ0 تحذيرات و0 أخطاء |
| 2026-08-20 | تنفيذ PreviewEngine الموحد وربطه بـWPF | مكتمل جزئيًا ومختبر | `core/preview.py`, CLI `preview`, WPF Preview tab typed summary/raw fallback، اختبار `test_preview_engine.py`، وأمر preview الفعلي على Windows نجح |
| 2026-08-20 | توسيع Menu Wizard وإضافة Preview golden contract | مكتمل جزئيًا ومختبر | Menu TreeView حي من JSON، `preview_models.json`, `test_preview_golden.py`، وبناء WPF النهائي نجح بـ0 أخطاء و0 تحذيرات |
| 2026-08-20 | تنفيذ Menu drag-and-drop وIcon/Cursor group editor وvisual Preview | مكتمل جزئيًا ومختبر | `MenuResource.move_item/update_item`, WPF drag/drop، قائمة Icon/Cursor وعناصر Update/Add/Remove، Bitmap/Menu/Dialog visual rendering، `test_menu_editing.py` نجح على Windows، وبناء WPF بـ0 أخطاء و0 تحذيرات |
| 2026-08-20 | إضافة Individual Icon/Cursor payload export/apply | مكتمل ومختبر | CLI `image-payload export/apply`، Save As عبر LIEF، `tests/core/test_image_payload_cli.py` نجح على Manus وWindows، دون المساس بالأصل |
| 2026-08-20 | إضافة WPF payload actions ومعاينات الموارد المتخصصة | مكتمل ومختبر | Image Wizard يصدّر ويطبّق raw `.bin` للعنصر المحدد؛ Preview يعرض VersionInfo وManifest وStringTable وIcon/Cursor group بشكل متخصص؛ WPF build بـ0 أخطاء و0 تحذيرات وتشغيل مستجيب |
| 2026-08-20 | تنفيذ ICON/CURSOR DIB↔BMP وPNG الاختياري | مكتمل ومختبر | `icon_cursor_payload_to_bmp` و`icon_cursor_bmp_to_payload`، CLI `image-payload --format bmp/raw/auto`، اختبار round-trip وPNG اختياري، وPillow موثق في requirements/notices |
| 2026-08-20 | تنفيذ WPF BMP preview وUI automation | مكتمل ومختبر | Image Wizard يحمّل selected ICON/CURSOR payload إلى BMP ويضع Automation Name ديناميكيًا؛ `--open` و`--image-kind` لتشغيل اختبار ثابت؛ fixture ICON و`Invoke-ResourceStudioUIAutomation.ps1` نجحا على Windows |
| 2026-08-20 | Stability pass: Writer rollback وPE corpus matrix | مكتمل ومختبر | Writer يحفظ rollback مؤقتًا حتى دون backup معلن، وcorpus matrix يغطي raw/typed resources واللغة والحذف، مع بقاء SHA-256 للأصل ثابتًا |
| 2026-08-20 | Stability pass: Windows CLI plumbing | مكتمل ومختبر | MainWindow وImage Wizard يقرآن stdout/stderr بالتوازي عبر `ReadToEndAsync`، وبناء WPF وUI smoke نجحا بـ0 أخطاء و0 تحذيرات |
| 2026-08-20 | تنفيذ SYS-01 Windows Loader Oracle | مكتمل ومختبر | تحميل PE كـimage/data resource عبر Win32، enumeration type/name/language، `FindResourceEx` و`SizeofResource` و`LoadResource`، ومقارنة SHA-256 للbytes مع LIEF؛ نجح `windows-resource-oracle-tests` على Windows |
| 2026-08-20 | تنفيذ SYS-02 Resource/PE Invariant Graph | مكتمل ومختبر | `PEInvariantSnapshot` يتضمن resource leaves و`resourceIssues`، و`compare_surgical_change` يرفض issues جديدة؛ `invariant-tests` و`pe-writer-tests` و`pe-corpus-matrix-tests` نجحت محليًا وعلى Windows |
| 2026-08-20 | تنفيذ SYS-03 Checksum and Signature Diagnostics | مكتمل ومختبر | `PEIntegrityReport` يربط LIEF `compute_checksum` وWindows `MapFileAndCheckSumW` و`inspect_signature`؛ CLI `inspect` يعرض integrity، و`pe-integrity-tests` نجح على Manus وWindows |
| 2026-08-20 | تنفيذ SYS-04 Durable Same-Volume Commit | مكتمل ومختبر | `core/durable_commit.py` يفرض flush قبل commit، وWindows يستخدم ReplaceFileW/MoveFileExW مع same-volume contract؛ `durable-commit-tests` و`pe-writer-tests` و`pe-corpus-matrix-tests` نجحت محليًا وعلى Windows |
| 2026-08-20 | تنفيذ SYS-05 RoundTrip Contract Registry | مكتمل ومختبر | عقود `byte/semantic/canonical` مع إعادة parse وnormalization للنماذج الحالية؛ `roundtrip-contract-tests` نجح محليًا وعلى Windows |
| 2026-08-20 | تنفيذ SYS-06 Differential Resource Oracle | مكتمل ومختبر | UpdateResourceW no-op update على نسخة مؤقتة ثم `compare_with_lief`؛ `win32-update-resource-oracle-tests` نجح على Windows |
| 2026-08-20 | تنفيذ SYS-07 PE Corpus Taxonomy | مكتمل ومختبر | manifest deterministic مع SHA-256 وتصنيف parse/negative/auxiliary وnormalization؛ `corpus-manifest-tests` نجح محليًا وعلى Windows |
| 2026-08-20 | تنفيذ SYS-08 bounded Parser Fuzz Harnesses | مكتمل جزئيًا ومختبر | `run_parser_cases` يصنف parser outcomes و`test_parser_fuzz_harness.py` يغطي valid/malformed seeds؛ coverage-guided fuzzing الكامل بقي لاحقًا بوضوح |
| 2026-08-20 | تنفيذ SYS-09 Job Object Containment Proof | مكتمل ومختبر | child/grandchild probe داخل `WindowsJob`، و`JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` أنهى الشجرة؛ اختبار Windows نجح |
| 2026-08-20 | تنفيذ SYS-10 WPF Process-State baseline | مكتمل جزئيًا ومختبر | `CliStateText` وAutomationId وحالات Idle/Running/Completed/Failed؛ build WPF بـ0 أخطاء و0 تحذيرات وUI automation مع fixture ICON نجح |

## المرحلة 10: Productization backlog وفق احتياجات المطورين والهواة

هذه البنود مستخلصة من تقييم الاستخدام العملي ومقارنة أدوات الموارد وPE، وليست بديلًا عن المرحلة 8 أو 9.

| الحالة | المعرّف | المهمة | الأولوية | معيار الإنجاز |
|---|---|---|---|---|
| [~] | PROD-01 | Batch Workspace متعدد الملفات | حرجة | `core/batch.py` وCLI `batch plan/apply` يدعمان manifest متعدد الملفات، add/replace/delete/change-language، dry-run، staging، atomic Save As، backup، rollback عند فشل commit، report JSON، وWPF Batch Workspace؛ فهرسة المجلد والـqueue التفاعلي وresume الكامل لاحقة |
| [~] | PROD-02 | Common Resource Wizards والمحررات المرئية | حرجة | StringTable Editor WPF بجدول 16 خانة وCLI export/apply؛ Resource Wizards WPF لـVersionInfo/Manifest/Menu مع JSON/XML وSave As؛ Menu يدعم drag-and-drop إلى parent وإعادة بناء JSON؛ Image Wizard يحرر عناصر Icon/Cursor الفردية ويزامن group JSON، مع export/apply BMP/PNG وpreview بصري؛ multi-image payload editing وAccessibility automation اللاحقة |
| [~] | PROD-03 | Preview Engine موحد | عالية | `core/preview.py` وCLI `preview` يدعمان Manifest/Version/Menu/Dialog/StringTable/Bitmap/Icon/Cursor مع summary typed وraw fallback وBMP output اختياري؛ WPF Preview يرسم Bitmap وMenu وDialog، ويعرض VersionInfo كحقول وstrings، Manifest كـXML، StringTable كسجل ID/text، وIcon/Cursor group كبطاقات؛ Image Wizard يعرض payload الفردي بصيغة BMP، بينما golden screenshots ومعاينة cursor hotspot المتقدمة لاحقة |
| [ ] | PROD-04 | Localization Workbench | حرجة | multi-file/multi-locale grid، comments/context، placeholder وhotkey checks، XLIFF/PO/RESX، side-by-side editing |
| [ ] | PROD-05 | Post-write Diagnostics Center | حرجة | تقرير before/after للأقسام وdirectories وchecksum وsignature وoverlay وresource bounds مع تفسير قابل للفهم |
| [ ] | PROD-06 | UI Automation وAccessibility | عالية | اختبارات WPF قابلة لإعادة التشغيل للفتح/البحث/التعديل/Save As، keyboard navigation، AutomationProperties، High Contrast وscreen-reader smoke test |
| [ ] | PROD-07 | Resource Transfer/Merge | عالية | نقل نوع/ID/لغة بين PE مع conflict resolver وdry-run وinvariants وحماية signature/overlay |
| [ ] | PROD-08 | Accelerator/MessageTable/Font/RCData | عالية | parser/serializer محافظ، raw fallback، typed bridge، CLI، fixtures malformed وgolden round-trip، ثم editor عند ثبات الصيغ |
| [ ] | PROD-09 | MUI و.NET satellite workflow | عالية | فتح المجموعة المرتبطة، مقارنة neutral/satellite، culture validation، ومسار منفصل لموارد .NET |
| [ ] | PROD-10 | Windows shell وworkspace convenience | متوسطة | drag/drop، recent/favorites، portable mode، file association اختيارية، context menu محلي، وتفضيلات theme محفوظة |
| [ ] | PROD-11 | Batch reports وresume | عالية | journal لكل عنصر، resume من آخر نجاح، JSON Lines، exit codes، hashes وartifacts قابلة للتحقق |
| [ ] | PROD-12 | Plugin SDK sample pack | متوسطة | أمثلة Viewer/Parser/Exporter، contract tests، capability discovery، وثائق API مولدة وإصدار SDK متوافق |
| [ ] | PROD-13 | PE diagnostics المتقدمة | متوسطة | dependency scanner وimports/exports/TLS/CLR/packer hints وتقارير واضحة، دون كتابة headers قبل اكتمال corpus |
| [ ] | PROD-14 | Adapters للأدوات المتقدمة | منخفضة | adapters اختيارية لـ disassembler/import editor/PE rebuilder أو unpacker خارج النواة وبصلاحيات وتحذيرات صريحة |

**الدليل التحليلي:** `docs/RESOURCE-STUDIO-MARKET-ASSESSMENT-2026-08-20.md` و`docs/research_competitors_notes.md`.


## سجل بوابة main-goal النهائية

| التاريخ | البوابة | الحالة | الدليل |
|---|---|---|---|
| 2026-08-20 | Manus full Python gate | مكتمل ومختبر | `compileall` ناجح؛ جميع اختبارات `tests/core` و`tests/test_cli.py` و`tests/qa` نجحت، مع تخطي Windows-only بأمان خارج Windows |
| 2026-08-20 | Windows core/CLI gate | مكتمل ومختبر | compileall وجميع اختبارات `tests/core` و`tests/test_cli.py` نجحت |
| 2026-08-20 | Windows QA gate | مكتمل ومختبر | جميع اختبارات `tests/qa/test_*.py` نجحت، بما فيها Win32 loader وUpdateResourceW وintegrity وdurable commit وcorpus وfuzz وround-trip |
| 2026-08-20 | Windows WPF Release build | مكتمل ومختبر | `dotnet build -c Release --no-restore`: 0 warnings و0 errors |
| 2026-08-20 | Windows Job Object gate | مكتمل ومختبر | `job-tree-containment-tests: passed` مع child وgrandchild |
| 2026-08-20 | Windows UI automation gate | مكتمل ومختبر | `ui-automation-tests: passed`؛ `CliStateText=Completed` وindividual `BMP preview` عبر fixture ICON |

تبقى **SYS-08** في حالة مكتمل جزئيًا لأن harness bounded/deterministic فقط؛ coverage-guided engine طويل التشغيل يحتاج دورة مستقلة وأدوات تشغيل مناسبة. وتبقى **SYS-10** في حالة مكتمل جزئيًا لأن baseline الحالة واختبار UIA مكتملان، بينما async cancellation وenabled-controls matrix وscreen-reader/accessibility coverage الأوسع لم تُدّعَ ولم تُنفذ ضمن main-goal pass.


## main-goal extension: Verification Engine — دورة التحقق قبل الميزات

الدورة التالية لا تضيف محررات أو أنواع موارد جديدة. هدفها جعل Save عملية قابلة للإثبات والتشخيص، بحيث لا يكون `LIEF.write()` هو العقد النهائي، بل pipeline صريحًا يبدأ بالتخطيط وينتهي بتقرير تدقيق بعد commit.

| الحالة | المعرّف | الطبقة | معيار الإنجاز |
|---|---|---|---|
| [x] | VE-01 | Resource Graph canonical model | `core/verification.py` يبني leaves مستقرة ومفاتيح type/name/language وsemantic/layout fingerprints، ويصدر graph diff |
| [x] | VE-02 | Deep PE invariants | `core/deep_invariants.py` يفحص headers وsection raw/virtual geometry وalignment وdirectory bounds وoverlaps |
| [x] | VE-03 | Semantic fingerprints | raw resources تستخدم byte fingerprint، وManifest/Menu/Version تستخدم العقود canonical/semantic القائمة |
| [x] | VE-04 | Differential verification | التحقق يقارن before/after ويثبت target changed وresource round-trip وnon-target preservation |
| [x] | VE-05 | Windows resource oracle | على Windows يقارن before/after loader resources ثم يطابق candidate مع LIEF؛ خارج Windows الحالة SKIPPED صراحة |
| [x] | VE-06 | Structure-aware fuzzing | `structure_aware_cases` يغير PE headers/section/data-directory offsets ضمن حدود، مع parser/writer outcome classifier |
| [x] | VE-07 | Crash consistency | commit failure وpost-commit verification failure يعيدان output السابق دون rollback temporary؛ اختبارات قابلة لإعادة التشغيل |
| [x] | VE-08 | Authenticode verification | candidate يمر عبر WinVerifyTrust native قبل وبعد commit؛ NOT_SIGNED مقبول للملف غير الموقع وVALID/INVALID موثق |
| [x] | VE-09 | Save verification pipeline | Writer ينفذ PLAN → MUTATE → SERIALIZE → REOPEN → STRUCTURAL_VALIDATION → RESOURCE_GRAPH_VALIDATION → SEMANTIC_DIFF → PRESERVATION_CHECK → WINDOWS_VALIDATION → AUTHENTICODE_VERIFICATION → COMMIT → AUDIT، ويعيد report قابلًا للآلة |

### عقد Save الناتج

كل WriteResult ناجح يحمل `verification` report يتضمن `phases` و`targetChanged` و`resourceRoundTrip` و`preservation` و`deepInvariants` و`resourceGraph` و`windows` و`signature` و`integrity`. تعرض أوامر CLI typed/image/dialog والمشروع وBatch Workspace هذا التقرير بدل الاكتفاء بـ`verified=true`.

| النتيجة الظاهرة | مصدر الإثبات |
|---|---|
| Output is valid PE | reopen + PEIntegrity + DeepPEInvariantReport |
| Target resource changed | canonical ResourceGraph differential |
| Resource round-trip passed | target payload/hash بعد reopen وsemantic fingerprint |
| Non-target PE structures preserved | imports/exports/TLS/load config/debug/overlay/directories/sections |
| Imports/Exports/TLS/Load Config/Debug/Overlay preserved | deep preservation map في VerificationReport |
| Signature state | WinVerifyTrust native على Windows، أو SKIPPED خارج Windows |
| Commit atomic | durable commit بعد نجاح candidate verification وpost-commit verification مع rollback |
| Audit | report مضمن في WriteResult وProject/Batch audit payload |

الفجوة المتبقية في هذه الدورة هي **coverage-guided fuzzing طويل التشغيل** و**مصفوفة Windows أوسع للـsigned corpus وMUI/LN**؛ لم تُدعَ ضمانات غير مختبرة في البيئات التي لا يتوفر فيها Windows oracle.


## سجل تنفيذ Verification Engine

| التاريخ | المهمة | الحالة | الدليل |
|---|---|---|---|
| 2026-08-20 | بناء ResourceGraph وsemantic/layout fingerprints | مكتمل ومختبر | `core/verification.py` و`tests/core/test_verification.py` |
| 2026-08-20 | تعميق PE invariants | مكتمل ومختبر | `core/deep_invariants.py` يفحص headers/sections/directories/geometry؛ fixture وSave candidates نجحت |
| 2026-08-20 | دمج differential/preservation verification | مكتمل ومختبر | Writer يثبت target/no-op semantics وimports/exports/TLS/Load Config/Debug/Overlay/non-resource sections |
| 2026-08-20 | دمج Windows loader وWinVerifyTrust stages | مكتمل ومختبر | Windows QA و`windows-resource-oracle-tests` و`pe-integrity-tests` و`win32-update-resource-oracle-tests` نجحت |
| 2026-08-20 | structure-aware fuzzing وcrash consistency | مكتمل ومختبر | `structure_aware_cases` و`test_crash_consistency.py`؛ commit وpost-commit failure يعيدان output السابق |
| 2026-08-20 | Save pipeline وCLI/Project/Batch audit | مكتمل ومختبر | WriteResult يحمل `verification` report، وCLI/Project/Batch يمررونه؛ جميع بوابات Manus وWindows نجحت |
| 2026-08-20 | WPF/Job final gate | مكتمل ومختبر | WPF Release: 0 warnings/0 errors؛ Job Object وUI automation نجحا مع `CliStateText=Completed` و`BMP preview` |


## main-goal extension: UI/UX-goal — من أداة تفهمها الآلة إلى تجربة يفهمها الإنسان

هذه الدورة لا تعيد بناء النواة ولا تضيف أنواع موارد جديدة. هدفها جعل الواجهة الحالية مفهومة وآمنة وقابلة للتعلم والاختبار للهاوي والمطور والمترجم، مع إبقاء Verification Engine مصدر الحقيقة الوحيد.

| الحالة | المعرّف | الطبقة | معيار الإنجاز |
|---|---|---|---|
| [x] | UX-00 | Research and audit | فحص MainWindow والنوافذ الثانوية وعقد UI automation؛ حفظ مصادر البحث في `docs/UIUX-RESEARCH-NOTES-2026-08-20.md` |
| [x] | UX-01 | UI/UX-goal | `docs/UIUX-GOAL.md` يحدد personas وjourneys وIA وstate model وDefinition of Done |
| [x] | UX-02 | Workspace context | تجميع الأفعال الرئيسية وإظهار PE path/output policy/current state كسياق واحد |
| [x] | UX-03 | Action hierarchy | فصل primary Explore/Analyze/Edit/Verify عن الأدوات الثانوية دون حذف الوظائف الموجودة |
| [x] | UX-04 | Verification summary | VerificationSummary formatter يظهر checklist مفهومة في Dialog/Image/Wizards/StringTable/Signature، وraw JSON يبقى متاحًا |
| [x] | UX-05 | Responsive operation state | MainWindow وكل النوافذ الثانوية تستخدم CliProcessRunner async مع Stop وStopped/input unchanged؛ اختبار الضغط الطويل ما يزال منفصلًا |
| [~] | UX-06 | Accessibility contract | أضيفت names/ids/tooltips/automation surfaces وsystem gray brushes للـhigh contrast؛ TabIndex/F6/reader matrix الأوسع لاحقة |
| [~] | UX-07 | Progressive disclosure | أضيفت hierarchy وtooltips وcontext؛ جعل raw/JSON طبقة details كاملة في كل المحررات ما يزال لاحقًا |
| [~] | UX-08 | Workflow reliability | UI automation يثبت context/status/Stop disabled/workbench/Preview/Image Wizard/BMP preview بعد runner الموحد؛ failure/keyboard/resize matrix لاحقة |
| [~] | UX-09 | Documentation and packaging | UI/UX-GOAL وresearch notes وREADME محدثة؛ الحزمة النهائية ستُعاد بعد إكمال دورة UX الحالية |

### قاعدة UI/UX-goal

لا يُقبل أي تعديل UI جديد إلا إذا حسّن واحدًا من: **الفهم الفوري للسياق، قابلية اكتشاف الفعل، وضوح الحالة، منع فقدان البيانات، الوصول بلوحة المفاتيح/التقنيات المساعدة، أو قابلية تشخيص النتيجة**. لا يضاف backend موازي، ولا custom control إذا كان WPF common control يحقق الغرض.


## سجل تنفيذ UI/UX-goal — الدفعة الأولى

| التاريخ | التنفيذ | الحالة | الدليل |
|---|---|---|---|
| 2026-08-20 | فحص UX الحالي والبحث المرجعي | مكتمل | `docs/UIUX-GOAL.md` و`docs/UIUX-RESEARCH-NOTES-2026-08-20.md` مع مصادر Microsoft/Fluent/NN/g ومرجع PE Explorer |
| 2026-08-20 | Workspace context وAction hierarchy | مكتمل | MainWindow أصبح مقسمًا إلى Workspace/Editors/Tools، ويعرض Current PE وSave As only وtooltips |
| 2026-08-20 | Status visibility | مكتمل جزئيًا | `CliStateText` بقي متوافقًا، وأضيف `StatusDetailText` يعرض Running/Completed/Failed ومدة العملية وnext action |
| 2026-08-20 | Accessibility surface | مكتمل جزئيًا ومختبر | AutomationId/Name لعناصر العمل والتبويبات والجداول والـpreview، وفرش system للـhigh contrast |
| 2026-08-20 | UI automation | مكتمل ومختبر | WPF build: 0 warnings/0 errors؛ UI automation نجح مع context/status/workbench/Preview/Image Wizard/BMP preview |

الفجوات المتبقية عمدًا: async cancellation وStop الكامل لكل النوافذ، checklist Verification summary مرئية موحدة بعد Save، F6/TabIndex matrix، screen-reader verification الأوسع، واختبارات resize/failure لكل editor.


## سجل تنفيذ UI/UX-goal — الدفعة الثانية

| التاريخ | التنفيذ | الحالة | الدليل |
|---|---|---|---|
| 2026-08-20 | Verification summary في النوافذ الثانوية | مكتمل ومختبر بالبناء | `VerificationSummary.cs` يستهلك `verification` من CLI دون تكرار النواة، ويعرض checklist مع raw output |
| 2026-08-20 | MainWindow async CLI runner | مكتمل ومختبر | `RunCliCaptureAsync` يستخدم `WaitForExitAsync` وقراءة stdout/stderr غير حاجبة |
| 2026-08-20 | Stop contract | مكتمل ومختبر جزئيًا | Stop يقتل process tree ويعرض `Stopped — input unchanged`؛ UIA يثبت وجود الزر وتعطيله بعد النجاح |
| 2026-08-20 | WPF regression gate | مكتمل ومختبر | `dotnet build -c Release --no-restore`: 0 warnings و0 errors؛ UI automation: passed |

الفجوات المتبقية: async/Stop موحد في النوافذ الثانوية، اختبار فعلي لإيقاف عملية طويلة أثناء التشغيل، F6 وTabIndex/access-key matrix، screen-reader checks، وSave failure/resize workflows.


## سجل تنفيذ UI/UX-goal — الدفعة الثالثة

| التاريخ | التنفيذ | الحالة | الدليل |
|---|---|---|---|
| 2026-08-20 | CliProcessRunner مشترك | مكتمل ومختبر | runner واحد للنوافذ الثانوية يستخدم CancellationToken وWaitForExitAsync وقتل process tree عند الإيقاف |
| 2026-08-20 | Dialog/Image/Wizards/StringTable/Signature async | مكتمل ومختبر بالبناء | كل Save/Apply/Export/Inspect يمر عبر runner المشترك، مع Stop وحالة input unchanged |
| 2026-08-20 | WPF build | مكتمل ومختبر | 0 أخطاء و0 تحذيرات بعد إضافة runner وتحويل النوافذ الثانوية |
| 2026-08-20 | UI automation regression | مكتمل ومختبر | MainWindow وStop disabled after completion وImage Wizard وBMP preview: passed |

الفجوة المتبقية بدقة: اختبار UIA يضغط Stop أثناء عملية طويلة متعمدة، ومصفوفة keyboard/accessibility/failure/resize الأوسع. لم تُضاف آلية delay إلى الإنتاج فقط لتسهيل الاختبار؛ يجب أن يستخدم اختبار الضغط fixture أو process test معزولًا.


## سجل إغلاق فجوات UI/UX — الدفعة الرابعة

| التاريخ | التنفيذ | الحالة | الدليل |
|---|---|---|---|
| 2026-08-20 | Stop موحد في النوافذ الثانوية | مكتمل ومختبر بالبناء | Dialog/Image/Resource Wizards/StringTable/Authenticode تستخدم `CliProcessRunner` وStop وinput unchanged |
| 2026-08-20 | Keyboard discoverability | مكتمل جزئيًا | HelpText وAcceleratorKey لـCtrl+O وCtrl+I وStop؛ F6/TabIndex/access-key matrix الأوسع لاحقة |
| 2026-08-20 | Image Wizard workflow | مكتمل ومختبر | Stop button idle assertion وindividual BMP preview: passed |
| 2026-08-20 | WPF regression gate | مكتمل ومختبر | dotnet build: 0 warnings/0 errors؛ UI automation: passed |

الفجوات المتبقية: اختبار إيقاف عملية طويلة فعلية عبر fixture معزول، F6/TabIndex/access-key matrix كاملة، screen-reader verification، واختبارات failure/resize الشاملة لكل نافذة.


## main-goal extension: Forensic-goal — Forensic integrity of PE transformation

هذه الدورة تعمّق البنية الحالية ولا تنشئ Forensics Module مستقلًا. الأولوية 70% forensic depth، و20% UX-06/07/08 لعرض الأدلة، و10% testing infrastructure.

| الحالة | المعرّف | الطبقة | معيار الإنجاز |
|---|---|---|---|
| [x] | FR-00 | Goal definition | `docs/FORENSIC-GOAL.md` يحدد الهوية والحدود وDefinition of Done اعتمادًا على Resource Graph وVerification الحاليين |
| [x] | FR-01 | PE forensic baseline | `ForensicBaseline.from_path/save/load` يجمع hash/size/PE snapshot/Resource Graph/deep invariants/integrity ويحفظ artifact ذريًا قبل mutation؛ provenance طويل المدى في Project ما يزال لاحقًا |
| [x] | FR-02 | Canonical graph evidence | `ForensicEvidence` يستخدم graph diff الحالي ويحسب targeted/unintended وbefore/result hashes وresource-tree attribution ضمن schema ثابت |
| [x] | FR-03 | Deep preservation evidence | `_preservation_evidence()` مستقل عن `VerificationReport` ويثبت sections/directories/imports/exports/TLS/Load Config/Debug/Overlay |
| [~] | FR-04 | Forensic difference | `forensicDifference` يخرج targeted/resourceTree/pePreservation/bytePreservation/rawResource/richHeader/integrity/signature/windows/pureLoader ويميز passed عن verified؛ التقرير متعدد الصيغ لاحق |
| [x] | FR-05 | Mutation attribution | `ForensicEvidence` يربط operationId/operation/target بالفرق المرصود، وWriteResult/Project Audit/Batch payload تحمل الدليل |
| [~] | FR-06 | Independent corroboration | baseline/result يُعاد بناؤهما خارج Writer باستخدام LIEF وinvariants وgraph وintegrity، وpure loader وraw parser يقدمان corroboration مستقلة؛ Windows loader corroboration المسمى ما زال مرجع Windows-only |
| [~] | FR-07 | Evidence report | machine-readable evidence في WriteResult وProject/Audit وBatch وCLI، مع chain/env fingerprint وEvidenceLedger اختياري يكشف العبث عبر hash-chain/Ed25519؛ التقرير متعدد الصيغ وprovenance Project الطويل لاحقان |
| [~] | FR-08 | Forensic UX | VerificationSummary يعرض Technical evidence من التقرير دون إعادة الحساب؛ viewer تفاعلي منفصل وkeyboard/accessibility matrix الأوسع لاحقان |
| [~] | FR-09 | Forensic regression | baseline/no-op/writer/corpus/crash وpure-loader/raw-parser/preservation/ledger/readback/determinism gates تغطي العقود الأساسية؛ Atheris corpus طويل التشغيل وfixtures malformed/policy-difference الأوسع لاحقة |

### قواعد Forensic-goal

لا timeline عام، ولا malware scanner، ولا IOC/YARA/PEiD، ولا entropy maps، ولا hex forensic viewer، ولا redesign navigation. لا تعتبر Writer نفسه دليلًا. لا تعاد كتابة Verification Engine داخل WPF؛ الواجهة تعرض evidence report وتسمح بالـprogressive disclosure فقط.

### السؤال المركزي

> ماذا تغير في هذا الملف، وهل نستطيع إثبات أن التغيير كان مقصودًا وأن كل شيء آخر بقي محفوظًا؟


## سجل تنفيذ Forensic-goal — الدفعة الأولى

| التاريخ | التنفيذ | الحالة | الدليل |
|---|---|---|---|
| 2026-08-20 | تعريف Forensic-goal والحدود | مكتمل | `docs/FORENSIC-GOAL.md`؛ لا timeline/malware/IOC/YARA/entropy/hex module |
| 2026-08-20 | ForensicBaseline | مكتمل جزئيًا ومختبر | `core/forensics.py` يجمع SHA-256 وsize وPEInvariantSnapshot وResourceGraph وDeepPEInvariantReport وPEIntegrityReport |
| 2026-08-20 | ForensicEvidence | مكتمل جزئيًا ومختبر | `resource_studio.forensic_evidence.v1` يربط operationId/target/baseline/result وforensicDifference وVerificationReport |
| 2026-08-20 | no-op attribution contract | مكتمل ومختبر | `tests/core/test_forensics.py` يثبت target unchanged و0 unintended changes وpassed evidence |
| 2026-08-20 | core API | مكتمل ومختبر | `ForensicBaseline` و`ForensicEvidence` و`verify_transformation` مصدّرة من `core` دون import cycle |

أُنجزت في هذه الدفعة FR-01 وFR-03 وFR-05 وجزء جوهري من FR-06 وFR-07 وFR-08: baseline artifact persistence، preservation مستقل، attribution عبر WriteResult وProject/Audit وBatch، CLI `forensic-baseline` وTechnical evidence في WPF. تبقى report formats/viewer التفاعلي وWindows corroboration المسمى ضمن الدفعات التالية.


## سجل تنفيذ Forensic-goal — الدفعة الثانية

| التاريخ | التنفيذ | الحالة | الدليل |
|---|---|---|---|
| 2026-08-21 | ربط forensic evidence بـWriteResult | مكتمل ومختبر | `WriteResult.forensic_evidence` يُبنى بعد commit مستقلًا عن `VerificationReport`؛ `tests/core/test_pe_writer.py` يثبت schema و`passed` |
| 2026-08-21 | ربط evidence بـProject Audit وBatch | مكتمل ومختبر | `Project.apply_typed_resource/apply_res_record/apply_manifest` و`Batch` تحمل `forensicEvidence` في payload |
| 2026-08-21 | Manus full gate | مكتمل ومختبر | compileall وجميع `tests/core/test_*.py` و`tests/test_cli.py` و`tests/qa/test_*.py` نجحت؛ Windows-only skipped بأمان خارج Windows |
| 2026-08-21 | Windows Python/Win32 gate | مكتمل ومختبر | compileall وجميع core/CLI/QA نجحت، بما فيها `forensic-baseline-tests` و`pe-writer-tests` وcorpus/integrity/oracle/crash gates |
| 2026-08-21 | Windows WPF/UI gate | مكتمل ومختبر | `dotnet build -c Release --no-restore`: 0 warnings و0 errors؛ `ui-automation-tests: passed` |
| 2026-08-21 | Original SHA guard | مكتمل ومختبر | `ResourceHacker.exe` بقي SHA-256: `14A44FE31B04FBCC65E94E80016138A2E9FC9BB6DFCEA09B98DE57F8A22A1240` |

الدفعة التالية تركز على baseline artifact persistence، وإظهار forensic evidence في CLI وواجهة Summary → Details → Technical evidence، مع توسيع Windows corroboration وforensic regression fixtures دون إنشاء Forensics Module مستقل أو إعادة Verification Engine داخل WPF.


## سجل تنفيذ Forensic-goal — الدفعة الثالثة

| التاريخ | التنفيذ | الحالة | الدليل |
|---|---|---|---|
| 2026-08-21 | Baseline artifact persistence | مكتمل ومختبر | `ForensicBaseline.save/load` يكتبان JSON ذريًا؛ Writer يحفظ baseline قبل mutation ويرجع `forensicBaselinePath` |
| 2026-08-21 | CLI forensic surface | مكتمل ومختبر | أمر `forensic-baseline INPUT --output ARTIFACT --json`، ومخرجات apply تحمل `forensicEvidence` و`forensicBaselinePath`؛ `tests/test_cli.py` نجح |
| 2026-08-21 | WPF Technical evidence | مكتمل جزئيًا ومختبر | `VerificationSummary` يعرض attribution وSHA وunintended changes وPE preservation من JSON دون إعادة الحساب؛ viewer التفاعلي الكامل لاحق |
| 2026-08-21 | Manus full gate | مكتمل ومختبر | compileall وجميع اختبارات core/CLI/QA نجحت، مع تخطي Windows-only خارج Windows |
| 2026-08-21 | Windows Forensic/WPF gate | مكتمل ومختبر | Forensic baseline وWriter وCLI نجحت؛ WPF Release: 0 warnings و0 errors؛ UI automation: passed |
| 2026-08-21 | Original SHA guard | مكتمل ومختبر | `ResourceHacker.exe` بقي SHA-256: `14A44FE31B04FBCC65E94E80016138A2E9FC9BB6DFCEA09B98DE57F8A22A1240` |

الدفعة التالية يجب أن تعالج التقرير forensic متعدد الصيغ أو viewer تفاعلي مخصص، مع corroboration Windows مسمى واختبارات malformed/policy-difference، دون إدخال نظام forensic مستقل أو إعادة Verification Engine داخل WPF.


## سجل مراجعة توصية الخبير — 2026-08-21

| البند | القرار | الدليل |
|---|---|---|
| فصل `passed` عن `verified` | مكتمل ومختبر | `VerificationReport` يعلن `platformLimited` عند SKIPPED/UNAVAILABLE، وتثبت Verification regression الفرق خارج Windows |
| post-commit readback | مكتمل ومختبر | `CommitResult.verified_sha256` و`durable-commit-tests` يثبتان hash الهدف بعد الاستبدال |
| pure loader corroboration | مكتمل جزئيًا ومختبر | `core/pure_loader_oracle.py` يختبر exact/primary/neutral/first على canonical leaves؛ لا يدعي أنه Win32 replacement |
| evidence ledger | مكتمل جزئيًا ومختبر | `EvidenceLedger` append-only JSONL وhash-chain وEd25519 اختياري، مع CLI append/verify/keygen؛ لا ادعاء قانوني أو chain of custody تلقائي |
| Atheris coverage-guided fuzzing | مؤجل عمدًا | يتطلب corpus دائمًا وcrash minimization ووقت تشغيل وسياسة دعم Windows/Manus؛ bounded deterministic harness باقٍ كما هو |
| `similarityHash` | مؤجل عمدًا | لا يُضاف قبل contract يحدد normalization والتشابه المقبول ويقيس false positives؛ integrity الحالي يبقى SHA-256 حتميًا |

المرجع التحليلي الكامل: `docs/FORENSIC-EXPERT-REVIEW-2026-08-21.md`.


## سجل تنفيذ Forensic-goal — مراجعة الخبير الثانية

| التاريخ | التنفيذ | الحالة | الدليل |
|---|---|---|---|
| 2026-08-21 | Evidence chain metadata | مكتمل ومختبر | `ForensicEvidence` يحمل `prevSha256` وenvironment fingerprint وcommand line وsha256 قابلًا لإعادة البناء |
| 2026-08-21 | Byte-range preservation | مكتمل ومختبر | `PreservationMap` يصنف target/resource container/header recalc/UNEXPECTED، وأي unexpected يجعل evidence failed؛ regression مستقل يغطي byte خارج النطاق |
| 2026-08-21 | Raw resource corroboration | مكتمل جزئيًا ومختبر | parser خام يقرأ PE resource directory وdata entries ويطابق keys/SHA مع ResourceGraph؛ التوسعات غير القياسية لاحقة |
| 2026-08-21 | Rich Header وdeterminism | مكتمل جزئيًا ومختبر | Rich Header hash/preservation signal، تثبيت COFF timestamp، وتكرار نفس mutation ينتج نفس SHA؛ checksum/signature policy الحالية محفوظة |
| 2026-08-21 | WPF Technical evidence | مكتمل ومختبر | عرض byte budget وraw corroboration وRich Header وevidence/environment hashes دون إعادة تنفيذ الحكم |
| 2026-08-21 | Manus full gate | مكتمل ومختبر | compileall وجميع core/CLI/QA نجحت؛ Windows-only skipped خارج Windows بصورة صريحة |
| 2026-08-21 | Windows Python/Win32/WPF gate | مكتمل ومختبر | جميع core/CLI/QA نجحت، Windows Resource Oracle وUpdateResourceW نجحا، WPF Release: 0 warnings و0 errors، UI automation: passed |
| 2026-08-21 | Original SHA guard | مكتمل ومختبر | `ResourceHacker.exe` بقي SHA-256: `14A44FE31B04FBCC65E94E80016138A2E9FC9BB6DFCEA09B98DE57F8A22A1240` |

الحدود المقصودة لهذه الدفعة: لا Job Object/named-pipe telemetry إضافي لنداء Win32 غير المنفذ، ولا entropy/ssdeep/TLSH ولا recursive MZ/steganography analytics. هذه البنود خارج نطاق Forensic-goal الحالي ومثبتة في تقرير المراجعة.
