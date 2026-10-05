# تقرير مراجعة الكود — رصد ومعالجة الديون التقنية

> نطاق المراجعة: Python كامل (`core/` + CLI + Tkinter GUI + `tools/` + `installer/`) — أغسطس 2026.
> المنهجية: vulture (عتبة ثقة 60% و80%)، تحليل AST لرسم بياني للاستيراد، مقارنة أجسام الدوال بعد تطبيع AST، فحص ساكن للاستثناءات الصامتة، تدقيق مطابقة عقود MCP JSON مع الخادم، ومراجعة يدوية لكل موضع مشتبه قبل القرار.
> التحقق النهائي: **102/102 اختبارًا ينجح** (Linux، Python 3.12) بعد كل التعديلات.

## الخلاصة

المستودع في حالة صحية عالية جدًا: لا وحدات يتيمة، لا أخطاء تركيب، لا TODO/FIXME داخل الكود، لا كود معلّق مطفأ، وعقود MCP متطابقة مع الخادم بالكامل (22 أداة). الديون المرصودة محدودة ومعالَجة أدناه.

## 1) الكود الميت — مرصود ومعالَج (حذف)

كل عنصر تحقق منه صفر مراجع في المستودع كاملًا (يشمل الاختبارات) قبل الحذف:

| الموقع | العنصر المحذوف | ملاحظة |
|---|---|---|
| `core/audit.py` | `AuditLog.latest()` | لا مستدعٍ في أي مكان |
| `core/case_lifecycle.py` | `CaseLifecycle.add_note()` | سجل الملاحظات يمر عبر `add_annotation` والـ CLI |
| `core/case_lifecycle.py` | `CaseLifecycle.timeline()` | الوصول للـ timeline يتم عبر `payload` مباشرة |
| `core/case_lifecycle.py` | `CaseLifecycle.state_hash()` | لا مستدعٍ |
| `core/dialog_resources.py` | `dword_after()` | مساعد بلا مستدعٍ |
| `core/menu_resources.py` | `MenuItem.flag_labels` + `_MENU_FLAG_LABELS` | أزيلا معًا لأن القاموس لا يستعمل سواها |
| `core/evidence_graph.py` | `EvidenceGraph.neighbors()` | لا مستدعٍ |
| `core/project.py` | `Project.find_resources()` | لا مستدعٍ؛ الفهرسة عبر `ResourceIndex` |
| `core/verification.py` | `_resource_bytes()` | دالة خاصة ميتة من refactor سابق |
| `core/signature.py` | `import getpass` | استيراد ميت |
| `core/pe_writer.py` | `import hashlib` | أصبح ميتًا بعد توحيد `_sha256` |

## 2) الكود المكسور — لا يوجد، مع ملاحظتين

- **لا يوجد كود مكسور فعليًا**: كل الملفات تترجم، والـ 102 اختبارًا ينجحون، ولا مراجع لرموز غير موجودة.
- **مرجع مكسور في README (أُصلح)**: قسم «بوابة Windows الأساسية» كان يستدعي `tests\windows\Invoke-ResourceStudioUIAutomation.ps1` وfixture باسم `tests\fixtures\ui-icon.dll` — الاول حُذف في تنظيف سابق والثاني غير موجود أصلًا في المستودع. استُبدل الاستدعاء بوصف للمسار الصحيح (مهمة Windows في CI).
- **فشل بيئي سابق (أُصلح في commit سابق)**: `test_durable_commit` كان يفشل لأن `_same_volume` يقارن `st_dev` لملف بمجلد، وتفصل على أنظمة الملفات مثل overlayfs؛ عولج بمقارنة المجلدين الأبوين.

## 3) التعارض — مرصود ومعالَج (توثيق)

- **README يقول «MCP مؤجل في هذه الدورة» بينما MCP منفذ ومختبر**: طبقة MCP كاملة موجودة (خادم stdio/HTTP بعقود 22 أداة، persistence، plugins، observability) ومربوطة ببوابة CI بعشرة ملفات اختبار. عولج التعارض بتحديث فقرة «حدود مقصودة» لتعكس الواقع مع روابط `MCP-ARCHITECTURE` و`MCP-CONTRACT`.
- **TODO CMD-03 يزعم اختبارات لـ `RenameResourceCommand`**: التحقق أظهر أنه alias من سطر واحد لـ `ChangeIdCommand` بلا أي مرجع آخر. الاسم يختبر ضمنيًا عبر الكيان نفسه؛ أُبقي كـ alias توافقي غير مفعل (انظر §5) — إزالته ستكسر أي مستورد خارجي محتمل بلا مقابل.
- **صفوف تاريخية في TODO تشير لملفات حذفت** (سجلات تنفيذ مؤرخة): أُبقيت كما هي لأنها سجل تاريخي وليست مراجع نشطة؛ حذفها يعيد كتابة التاريخ.
- **عقود MCP مقابل الخادم**: مطابقة كاملة 22/22 — لا تعارض.
- **قسم «الحالة» في PLUGIN-API.md قديم (أُصلح في جولة تصريف §5)**: كانت الوثيقة تدعي أن entrypoint غير مشغّل وأن registry هو المنفذ وحده، بينما `PluginHost` يشغّل الإضافات خارج العملية فعليًا (JSON-lines مع staging وحدود timeout/ذاكرة/CPU وتعطيل تلقائي عند الانهيار) وأدوات MCP الإدارية الأربع منفذة ومختبرة، وقائمة «ما تم تأجيله» عدّت Python مؤجلة وهي مدعومة فعليًا كـ entrypoint JSON-lines. عولج بتحديث الوثيقة لتعكس الواقع المنفذ مع بقاء المؤجل الحقيقي (WASM/ABI الأصلية/.NET/Lua/JavaScript وsandbox adapters) موثقًا.

## 4) الكود المكرر بدون فائدة — مرصود ومعالَج (توحيد)

المسح بـ AST (تطبيع السلاسل والأرقام) رصد 5 مجموعات؛ وحّد الثلاث ذات القيمة، واستثني اثنتين:

| المجموعة | القرار |
|---|---|
| `_sha256` في `resource_studio_cli` و`batch` و`pe_writer` و`signature` (4 نسخ متطابقة) | وحّدت في `core/util.py::sha256_file`؛ الـ CLI يستوردها كسولًا داخل الدوال حفاظًا على عقد سرعة الإقلاع (`test_cli_startup_contract`) |
| `_numeric` في `pe_inspector` و`invariants` (نسختان متطابقتان) | وحّدت في `core/util.py::numeric_value` |
| `_unescape` في `rc_format` و`_rc_unescape` في `version_info` | وحّدت في `core/util.py::unescape_rc_string` |
| `to_dict` في `windows_resource_oracle` و`raw_resource_parser` | استثني: تشابه شكلي على أنواع بيانات مختلفة (false positive) |
| `RenameResourceCommand = ChangeIdCommand` | استثني: alias مقصود لا تكرار منطق |

`core/util.py` جديدة عن قصد لا تستورد شيئًا من باقي core حتى يمكن استيرادها من أي طبقة دون دورات استيراد.

## 5) الكود غير المفعل — قرار مصيرفي منفذ: إبقاء مدعوم بالأدلة

خضع كل بند لتحليل استخدام معمق: خريطة مواضع استدعاء عبر core/ وCLI وMCP وtools/ مقابل الاختبارات (سكربت AST/نصي)، مع فحص الاستدعاء الديناميكي والتوثيق وسجلات TODO. النتيجة النهائية: **إبقاء جميع البنود** — كل بند إما عقد موثق، أو مخرج مرحلي مسجل في TODO كمكتمل، أو نصف بنية حية. حذفها كان سيعيد كسر توثيق-كود من نوع §3 ويعطل معالم خارطة الطريق معلقة، مقابل وفر خطي غير مادّي:

| البند | القرار | الأدلة الحاسمة |
|---|---|---|
| Tkinter GUI (`resource_studio_gui.py`) | إبقاء | fallback موثق في README؛ كلفة صيانة صفرية ودخول طوارئ عابر للمنصات |
| Project typed API (`apply_typed_resource`/`apply_manifest`/`apply_dialog`/`apply_version_info`/`apply_res_record`) | إبقاء | مسار الكتابة الجنسي الوحيد المُدار بمشروع (عزل workspace + audit + backup + إعادة فهرسة) فوق Writer الخام؛ مخرجات مراحل EDIT-03/05/06/07/08 وربط forensicEvidence (TODO سطر 517)؛ الاختبارات عبرها تحرس ضمانات sha-guard وcross-feature؛ المستهلكون المصممون: المحررات البصرية المعلقة وكتابة MCP بمشروع. لاحظ أن CLI ينفذ كتاباته عبر Writer مباشرة (input→output) فلا ازدواج وظيفي |
| `Project.restore_snapshot`/`snapshot` | إبقاء | نصف استعادة ما بعد الانهيار — معلم CORE-04 مسجل منجزًا (TODO سطرا 60 و215) |
| `Project.locked`/`acquire_lock`/`release_lock` | إبقاء | أداة أمان متماسكة مع كشف القفل اليتيم (GAP-01، TODO سطر 244)؛ موقعها الطبيعي جلسة WPF (P4) وتزامن MCP persistence |
| `CommandHistory.can_undo`/`can_redo`/`redo`/`execute_group` | إبقاء | `execute`/`undo` حيتان فعليًا عبر `PluginContext` (core/plugins.py)؛ redo النصف التبادلي لعقد التراجع الذري وتغطية CMD-02/03/05 |
| Plugin SDK surface (`PluginContext.read_resource`/`put_resource`/`execute_command`/`undo_command`، `PluginHost.dry_run_registered`) | إبقاء | عقد موثق في PLUGIN-API.md (بوابة `require`)؛ PLUG-07 وEXT-03؛ PROD-12 (حزمة أمثلة SDK) يعتمد عليه؛ «غير مستعمل داخليًا» طبيعي لواجهة خارجية |
| محررات typed (`add_item`/`remove_item`/`move_item`/`update_item`/`class_label`/`is_checked`/`is_disabled`/`set_execution_level`/`to_csv`/`from_csv`) | إبقاء | طبقة النموذج للمحررات المرئية المعلقة (EDIT-07، PROD-08)؛ مغطاة بQA-10/12 |
| `RenameResourceCommand` | إبقاء | alias توافقي (انظر §3) |

تثبيت القرار داخل الكود: أضيفت docstrings تصريفية إلى أسطح Project أعلاه وإلى `CommandHistory` توثق الوضع (مستهلكو اليوم مقابل المستهلكين المصممين) حتى لا يُعاد فتح القرار عرضًا في مراجعات قادمة. ملاحظتان من التحليل: مواضع `read_resource` في اختبارات MCP إيجابيات كاذبة (طريقة `ClientSession.read_resource` من مكتبة mcp نفسها، لا علاقة لها بسطح الإضافات)، واكتشاف تعارض PLUGIN-API.md الموثق في §3.

## 6) القمامة التقنية — مرصودة ومعالَجة وفق أولوية «الاستثناءات الصامتة»

المسح رصد 10 مواضع ابتلاع أخطاء؛ عولجت كالتالي:

**أ) موثقة بتعليق يشرح جدوى الصمت (8 مواضع)** — الصمت نفسه مقصود وسليم، لكن كان غير موثق:

| الموقع | الجدوى الموثقة |
|---|---|
| `core/commands.py:145` | undo بالجهد الممكن أثناء rollback؛ الفشل الأصلي يعاد رفعه |
| `core/version_info.py:112` | تخطي مفاتيح لغة غير سداسية عشرية (تحليل متسامح) |
| `core/evidence_ledger.py` | chmod قد يفشل على منصات/أنظمة ملفات لا تدعمه |
| `core/security_workspace.py` ×2 | تنظيف staging وإذن chmod بالجهد الممكن |
| `core/windows_security.py` | إغلاق جلسة WinVerifyTrust لا يجب أن يطمر نتيجة التحقق |
| `core/pe_writer.py` | كتابة تشخيصات الفشل لا يجب أن تنهار فوق فشل قائم |
| `core/p0_telemetry.py` | telemetry اختيارية يجب ألا تغير نتائج التحليل |
| `core/case_lifecycle.py` | تنظيف ملف مؤقت بالجهد الممكن |

**ب) موثق مسبقًا (1)**: `core/commands.py` في `_record` — لديه تعليق أصلي يشرح أن وجهة audit المعطلة يجب ألا تحول تعديلًا مكتملًا إلى نصف تاريخ.

**ملاحظات إضافية**:
- `external_integrations.redirect_request(msg, newurl)`: إيجابية كاذبة من vulture — توقيع override إلزامي لـ urllib.
- **صفر TODO/FIXME/HACK** في كود الإنتاج، وصفر كود معطل بتسلسلات `if False`، وصفر كود معلّق خارج الخدمة.
- **دين معماري مقصود خارج نطاق الإصلاح الآمن**: الاختبارات سكربتات مستقلة بدل pytest. أما `mcp/server.py` (1732 سطرًا) فقد فُكّك لاحقًا — انظر §7.

## 7) تفكيك mcp/server.py — منفّذ (جذر تركيب نحيف + حزمة rs_mcp)

جولة لاحقة فكّت أكبر ملف في المستودع دون أي تغيير منطقي أو في السطح المكشوف (نفس الأدوات والموارد والـprompts، والأجسام منقولة حرفيًا بنطاقات أسطر):

- **القيد المُوجِّه**: مجلد `mcp/` المحلي بلا `__init__.py` عمدًا حتى تفوز حزمة SDK المنصبة بـ`import mcp`؛ لذلك وُضعت الوحدات الجديدة في حزمة عليا مستقلة **`rs_mcp/`**، وبقي `mcp/server.py` نقطة الدخول (سكربت stdio + يُحمّل بالمسار عبر importlib في http_server والاختبارات).
- **البنية**: `mcp/server.py` جذر تركيب (~85 سطرًا: bootstrap + استيراد الوحدات لتسجيل الأدوات + `_load_state`/`_discover_plugins` + تشغيل stdio). داخل rs_mcp: `state.py` (كل الحالة الجلسية والأحداث والمثابرة)، `pemodel.py` (تحليل PE الخالص)، `files.py` (تسجيل الملفات وفحصها)، `workspaces.py` (مساعدات workspace/التأكيد)، `plugins.py` (اكتشاف الإضافات وبوابات التأكيد)، `integrations.py`، `app.py` (كائن الخادم)، وسبع وحدات `handlers_*` حسب المجال (discovery/workspace/package/integrations/plugins/live/readonly).
- **خطران خفيان عولجا أثناء التفكيك** (قاعدة عامة: الاسم الذي يعاد ربطه عبر `global` يجب الوصول إليه عبر وحدته لا عبر from-import):
  - `PLUGIN_REGISTRY` يُعاد ربطه في `_discover_plugins` — وحدات handlers تصل إليه عبر `rs_mcp.plugins.PLUGIN_REGISTRY`.
  - `EVENT_SEQUENCE` عدد صحيح يُعاد ربطه في `_record_event` — مورد session_state يقرأه عبر `rs_mcp.state.EVENT_SEQUENCE` (القيمة المفردة من-الاستيراد تتجمد). المخازن القاموسية (FILES/PLANS/…) لا تتأثر لأنها تُعدّل في المكان.
- **التحقق**: مدقّق symtable (استيراد بلا أسماء غير محلولة ولا استيرادات ميتة في كل وحدة) + compileall + **102/102 اختبارًا** أخضر، وci.yml يفحص rs_mcp في compileall على المنصتين.

## 8) جولة الأداء المعماري — منفّذة (واجهة كسولة + مضيف CLI دائم)

مراجعة معمارية كمية (رسم استيرادات، fan-in/fan-out، دورات SCC، قياس إقلاع) حددت ثقلين غير مبررين وعنق زجاجة تشغيلي، ونفذ إصلاحاهما عالي العائد:

- **`core/__init__.py` كسول (PEP 562)**: الترويسة المتحمسة كانت تجعل أي `from core.X import Y` يسحب 261 وحدة/365ms منها `lief`=252ms عبر `batch → pe_writer`. الواجهة الجديدة خريطة 152 اسمًا + فرع submodule، مع تطابق حرفي لـ`__all__` وسلوك `dir`/AttributeError. القياس (min من 7): `cli --help` 472→53ms، `import core.project` 365→44ms، `import core.reports` 338→28ms؛ وأُزيل استيراد `FORMATS` من أعلى `parser()` إلى موعده الوحيد.
- **مضيف CLI دائم عديم الحالة (`tools/wpf_cli_host.py`)**: WPF كانت تشغل عملية Python لكل نقرة تحرير (8 مواضع عبر `CliProcessRunner`) بكلفة موثقة في P0 (~459ms خارجي مقابل ~7ms داخلي). المضيف الجديد يلتزم بروتوكول `wpf_read_host` حرفيًا مع حقل `env` لكل طلب (يُطبق ويُستعاد)، وينفذ `cli.main(argv)` من الصفر في كل طلب — فلا حالة ولا مشكلة إبطال، و`lief` يبقى ساخنًا. `CliProcessRunner.cs` يوجّه عبر `CliHostConnection` مشترك مع fallback تلقائي للspawn عند فشل البدء، وخطأ صريح بلا إعادة تلقائية عند فشل بروتوكولي (حالة الطلب غير معلومة). القياس (تسلسل 4 نقرات على fixture ثقيل): مجموع ~1743ms → ~456ms، والنداء الدافئ ~393ms → ~6ms.
- **خلل حي أصلح أثناء الجولة**: `wpf_read_host.py` كان لا يستطيع استيراد `resource_studio_cli` في وضع الإطلاق الفعلي من WPF (sys.path[0]=tools/)؛ كلا المضيفين يشفيان `sys.path` ذاتيًا مع اختبار انحدار بلا PYTHONPATH.
- **قرارات عدم-تدخل موثقة**: الدورة المنطقية السباعية (`project/pe_writer/health/verification/forensics/windows_resource_oracle/resource_index`) مطفأة وقت الاستيراد وتعكس حلقة المجال (كتابة←تحقق←إثبات) — تُوثق ولا تُفكك؛ طبقة service مشتركة CLI/MCP مؤجلة (اللاصق رقيق ومغطى بالاختبارات)؛ حالة `rs_mcp/state.py` العمومية مقصودة وتفرض جلسة-واحدة لوضع HTTP.

## 9) جولة التقليم والعبء الأيضي — منفّذة (مسح دقيق + جراحتان مقيسة)

فحص فسلجي وظيفي كامل (جرد 783 وظيفة، قياس حي، تعداد تفكيكات، تغطية كاملة) ثم تقليم بلا رحمة لكن بإثبات لكل قطع:

- **المسح الدقيق وحصيلته**: 6 استيرادات ميتة (forensics ×3 — كانت أيضًا حواف دورة زائدة، audit ×2، rc_format ×1، build_pe_corpus ×1)، ثابت `_OPERATORS` الميت في evidence_query، شظية `docs/CHANGELOG.md` المجمّدة (تكرار قديم لسجل الجذر الحي)، وإضافة `.coverage` إلى `.gitignore`. ما فُحص وابقاءه موثقًا: مستوردات `mcp/server.py` حاملة-تحميل (التسجيل وقت الاستيراد بnoqa مقصود)، `_NoRedirect` و`windows_isolation` بروتوكولية، Tkinter GUI fallback وProject typed API مخرجات مراحل موثقة، C# بلا أنواع يتيمة، وكود غير قابل للوصول: صفر. أربع وثائق مرجعية كانت يتيمة الوصل (CORE-ARCHITECTURE/ROADMAP/BATCH-MANIFEST/HEX-TEMPLATES) أُوصلت من README بدل بترها.
- **جراحة العضو الأثقل `preservation._diff_ranges`**: كانت تمشي بايت-ببايت بحلقة بايثون على كامل الملف (~245ms/MB؛ 15.7s لملف 64MB — أبطأ من محلل LIEF الـC++ بـ~190× لكل بايت). الصيغة الجديدة تقارن مجزأة 64KB بسرعة C وتماشي بايتي داخل المقاطع غير المتساوية فقط (×742 عند 64MB: 15.7s → 21ms). **وإصلاح عمى طرفي مكتشف أثناء الفحص**: الصيغة القديمة كانت تُسقط أي نطاق تغيّر يصل إلى نهاية الملف (1522 من 4000 حالة تفاضلية عشوائية) — البايتات الملحقة/المقتطعة عند EOF لم تكن تظهر أبدًا في خريطة الحفظ؛ الصيغة الجديدة تُبلغ عنها، واختبار الانحدار `tests/core/test_diff_ranges_regression.py` يثبت التكافؤ التفاضلي (600 حالة) ورؤية الذيل وبلغ الملحق غير المتوقع عن خريطة حفظ حقيقية.
- **جراحة التفكيك المتكرر `core/parse_cache.py`**: التعداد المُسند للمستدعي أثبت 11 تفكيكًا كاملًا لنفس البايتات في كتابة واحدة و8 في `inspect` للقراءة فقط. كاش محلي-الخيط محدود (4 مداخيل/256MB، keyed بـpath+size+mtime_ns) للقراءة-فقط عبر 13 موقعًا (health/pe_inspector/signature/pe_integrity/verification ×2/pe_metadata/compatibility/deep_invariants/invariants/static_code_analysis/project.open_pe/resource_reader)؛ التفكيكات المتحولة بقيت خاصة (writer `_parse`، `_strip_to_path`، أوراكل Windows) والاستدعاءات الديناميكية لـlief.parse تحفظ تيليمتري P0. النتيجة (عملية منفصلة لكل أمر): `inspect` 8→1، كتابة 11→5، وكتابة 64MB كاملة ~4.8s (كانت ~17s بالمكونات المقيسة).

## التحقق بعد المعالجة

- `python -m compileall`: نظيف لكل الملفات.
- مجموعة الاختبارات كاملة: **102/102 PASS** (core + CLI + QA + MCP + golden).
- vulture بعد المعالجة (ثقة 90%): صفر نتائج غير الإيجابيات الكاذبة الموثقة أعلاه.
- جولة تصريف §5: تحليل معمق لكل بند، docstrings تصريفية على Project/CommandHistory، إصلاح PLUGIN-API.md، وإعادة تشغيل كاملة: **102/102 PASS**.
- جولة تفكيك MCP: حزمة rs_mcp (14 وحدة) + جذر تركيب نحيف، مدقق symtable نظيف، و**102/102 PASS**.
- جولة الأداء المعماري: واجهة كسولة + مضيف CLI دائم + شفاء sys.path للمضيفين، compileall نظيف، و**103/103 PASS** (102 سابقة + `tests/qa/test_wpf_cli_host.py`).
- جولة التقليم والأيض: مسح vulture-100%/AST/C#/وثائق + جراحتا `_diff_ranges` و`parse_cache`، compileall نظيف، و**104/104 PASS** (103 سابقة + `tests/core/test_diff_ranges_regression.py`)، وقياسات مذكورة في §9.
