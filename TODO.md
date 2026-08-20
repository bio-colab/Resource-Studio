# Resource Studio — TODO قابل للتتبع

**آخر تحديث:** 2026-08-20  
**النطاق الحالي:** تطوير الإضافات وطبقة المنصة فقط.  
**MCP:** مؤجل مؤقتًا؛ لا تُضاف وظائف MCP جديدة أثناء هذه الدورة.  
**الأصل:** `C:\Program Files (x86)\Resource Hacker\ResourceHacker.exe` محفوظ وغير قابل للكتابة.  
**نسخة الاختبار:** `C:\Users\Eylias\Desktop\Resource Hacker - Working Copy`.

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

## المرحلة 10: Productization backlog وفق احتياجات المطورين والهواة

هذه البنود مستخلصة من تقييم الاستخدام العملي ومقارنة أدوات الموارد وPE، وليست بديلًا عن المرحلة 8 أو 9.

| الحالة | المعرّف | المهمة | الأولوية | معيار الإنجاز |
|---|---|---|---|---|
| [~] | PROD-01 | Batch Workspace متعدد الملفات | حرجة | `core/batch.py` وCLI `batch plan/apply` يدعمان manifest متعدد الملفات، add/replace/delete/change-language، dry-run، staging، atomic Save As، backup، rollback عند فشل commit، report JSON، وWPF Batch Workspace؛ فهرسة المجلد والـqueue التفاعلي وresume الكامل لاحقة |
| [~] | PROD-02 | Common Resource Wizards والمحررات المرئية | حرجة | StringTable Editor WPF بجدول 16 خانة وCLI export/apply؛ Resource Wizards WPF لـVersionInfo/Manifest/Menu مع JSON/XML وSave As؛ Image Wizard WPF لمعاينة BMP وJSON Icon/Cursor؛ typed CLI وround-trip tests مكتملة، بينما tree editing المتقدم للـMenu وmulti-image editing المتقدم لاحق |
| [ ] | PROD-03 | Preview Engine موحد | عالية | معاينة icon/cursor/bitmap/dialog/menu/manifest، raw fallback، واختبارات golden للعرض والتحويل |
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
