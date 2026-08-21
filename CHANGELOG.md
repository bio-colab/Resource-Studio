# Changelog

تتبع هذه الوثيقة التغييرات القابلة للملاحظة في Resource Studio. لا تُسجل فيها وعود مستقبلية على أنها منجزة؛ الأعمال غير المكتملة تبقى في [`TODO.md`](TODO.md) بحالة ومعيار إنجاز.

## [Unreleased]

### الاتجاه النشط

تتركز الدفعة التالية على **Security-goal** فوق Forensic-goal وVerification Engine: تحليل PE ساكن، تصنيف الفساد والوصول والقفل، مؤشرات العبث والتمويه، وفصل نتائج Defender/YARA الخارجية عن verdict الداخلي. لا تشمل تشغيل الملفات أو unpacking أو decryption أو process injection أو dynamic malware engine داخل النواة.

### أُضيف

- تنفيذ P0 من خطة إصلاح الأداء: telemetry اختياري لمسارات CLI وWriter وWPF runner، مع قياس الزمن وLIEF parses والقراءات الكاملة وtemporary I/O وprocess-per-action، دون تغيير السلوك الافتراضي. وثقت النتائج في `docs/P0-PERFORMANCE-BASELINE.md`.
- تنفيذ P1 عبر `core/resource_reader.py`: أصبحت `list` و`extract` و`search` وقراءة طرفي `diff` تستخدم parse واحدًا دون `Project` workspace أو audit؛ baseline أثبت إزالة temporary I/O والقراءات الكاملة من هذه المسارات. التفاصيل في `docs/P1-READONLY-READER.md`.
- تنفيذ P2 عبر `VerificationContext`: إعادة استخدام binary وsnapshot وResourceGraph وdeep/integrity/signature داخل Writer، مع انخفاض `writer.replace_manifest` من 49 إلى 11 LIEF parses ومن 14 إلى 12 full reads دون حذف مراحل التحقق. التفاصيل في `docs/P2-VERIFICATION-CONTEXT.md`.
- تنفيذ P3 عبر Python JSONL read host طويل العمر و`ReadHostClient.cs`؛ أزيل process-per-action من مسارات القراءة الساخنة مع session cache لـ`list/search` وfallback آمن. أبقى القياس Rust وC++ خارج المسار حتى يثبت Windows baseline حاجة حقيقية. التفاصيل في `docs/P3-READ-HOST.md`.
- تنفيذ P4 في WPF: request generation و`CliResult.IsStale` لمنع النتائج القديمة، وowned process/cancellation لمنع تداخل الطلبات. التفاصيل في `docs/P4-WPF-SESSION.md`.
- تقييم Rust جراحيًا لمسار byte-search عبر FFI؛ تطابقت accuracy، لكن `bytes.find` كان أسرع من prototype Rust، لذلك لم يُضف أي dependency أو artifact Rust إلى المشروع. التفاصيل في `docs/RUST-EVALUATION.md`.
- إضافة `Evidence annotations` و`evidence_selection.v1` بعد مراجعة أنماط Wireshark وOxygen: annotations append-only مربوطة بـartifact SHA-256 وgraph hash، وCLI/WPF لتصدير selection manifest انتقائي دون تعديل PE. الدراسة في `docs/FORENSIC-ANALYTICS-RESEARCH.md`.

- Apache-2.0 في `LICENSE` مع توضيح نطاق كود Resource Studio واعتماديات الطرف الثالث.
- GitHub Actions CI لـPython وWindows/WPF، وRelease workflow لإنتاج source bundle عند tags دون ملفات الأسرار أو البناء.
- community files: `CODE_OF_CONDUCT.md` و`SUPPORT.md` و`SECURITY.md` وIssue templates.
- توسيع `hex` CLI ليعرض raw file slices أو resource slices مع hex/ASCII/base64/C-array JSON.
- إضافة `rc compile` و`rc decompile` لـSTRINGTABLE وMENU/MENUEX وVERSIONINFO ضمن RC subset حتمي قابل للاختبار.
- `core/forensics.py` مع `ForensicBaseline` الذي يلتقط hash والحجم وPE invariant snapshot وResource Graph وdeep invariants وintegrity diagnostics.
- `ForensicEvidence` و`verify_transformation` لإنتاج `resource_studio.forensic_evidence.v1` وربط operation ID وoperation وtarget بالفرق المرصود.
- ربط `forensic_evidence` بـ`WriteResult` بعد commit مستقل، وتمريره إلى Project Audit وBatch operation payload.
- حفظ `ForensicBaseline` كـartifact JSON ذري قبل mutation، مع `ForensicBaseline.save/load` وأمر CLI `forensic-baseline`.
- إضافة `forensicBaselinePath` إلى WriteResult وProject Audit وBatch payload.
- فصل `passed` عن `verified` وإضافة `platformLimited` عندما تكون Windows Resource Oracle أو WinVerifyTrust متخطاة.
- إضافة `CommitResult.verified_sha256` مع post-commit readback بعد الاستبدال.
- إضافة `core/pure_loader_oracle.py` لاختبار اختيار اللغة على canonical ResourceGraph دون الادعاء بأنه بديل Win32.
- إضافة `EvidenceLedger` اختياريًا كسجل JSONL append-only مع hash-chain وتوقيع Ed25519 عند توفر `cryptography`، دون ادعاء chain of custody قانونية.
- إضافة `resource_studio.evidence_graph.v1` بعقد evidence nodes وعلاقات `corroborates` و`contradicts` و`derives-from` و`supports` و`references` مع graph hash حتمي.
- إضافة Query Engine آمن وأوامر `evidence-query` و`evidence-graph`، مع namespaces محددة وoperators مقارنة و`contains` و`and/or` دون `eval`.
- إضافة `resource_studio.case.v1` وأوامر `case create/analyze/transition/show` مع lifecycle وtimeline وaudit event hash-chain وتقارير قابلة لإعادة التحميل.
- إضافة تبويب WPF Security Center يعرض static security report وEvidence Graph ونتائج Query وcase path فوق CLI/Core الحالية، دون إعادة تنفيذ Verification Engine.
- نجاح GitHub Actions run `32478276207` على commit `f81b2bd`، مع اجتياز Python 3.12 وWindows/WPF وبناء Security Center بنجاح.
- إضافة evidence chain metadata القابل لإعادة البناء: `prevSha256` وenvironment fingerprint وcommand line وevidence sha256.
- إضافة `PreservationMap` بخريطة byte ranges وتصنيف `EXPECTED_TARGET_RESOURCE` و`EXPECTED_RESOURCE_CONTAINER` و`EXPECTED_HEADER_RECALC` و`UNEXPECTED`، مع ميزانية unexpected تساوي صفرًا.
- إضافة raw resource parser مستقل محدود يقارن موارد `IMAGE_RESOURCE_DIRECTORY` مع canonical ResourceGraph.
- إضافة Rich Header hash/preservation signal وتثبيت COFF timestamp الأصلي وdeterminism regression لنفس mutation.
- forensic difference أولي يميز target وresource tree unintended changes وPE preservation وintegrity وsignature وWindows status.
- اختبار `tests/core/test_forensics.py` الذي يثبت baseline contract وno-op attribution وغياب unintended changes.
- `FORENSIC-GOAL.md` الذي يحدد الهوية والحدود ومعايير FR-00 إلى FR-09.
- `CONTRIBUTING.md` الذي يشرح السلامة والاختبارات والتوثيق وقواعد المساهمات.
- إنشاء `docs/SECURITY-GOAL.md` كخطة دفاعية للتحليل الساكن، وفصل المؤشرات عن verdicts، وتحديد حدود Defender/YARA وruntime telemetry.
- إضافة `core/security_analysis.py` وأوامر CLI `security` و`report security` لإنتاج `resource_studio.security_report.v1` مع access/parse state وPEHealth وdeep invariants وsignature/integrity وResource Graph/raw corroboration وstatic indicators وEvidence Summary؛ لا يشغّل الملف ولا يفك payloadات.
- نجاح GitHub Actions run `32444514351` على commit `3dc383b`، مع اجتياز Python 3.12 وWindows/WPF وفحص الملفات المحظورة.
- توسيع Security-goal بنتائج بحث دفاعي عن T1486 وT1219 وT1573: إضافة static indicators للـoverlay وentrypoint وexecutable+writable sections وcrypto/network/persistence imports وstrings محدودة، مع إبقاء RAT/ransomware/C2 attribution خارج الحكم الساكن.
- توثيق طبقات التكامل الآمنة المستقبلية: YARA وDefender على staged copies وSysmon/EDR telemetry كأدلة خارجية، مع منع تشغيل أو unpacking أو decryption أو process injection داخل النواة.
- إضافة عقد `resource_studio.external_scan.v1` في `core/security_providers.py` واستيراد النتائج السابقة عبر `security --external-result` مع provider/status/target SHA/ruleset/exit code؛ لا يشغّل أي موفر.
- نجاح GitHub Actions run `32445879114` على commit `8f3c2db`، مع اجتياز Python 3.12 وWindows/WPF وفحص artifacts المحظورة.
- إضافة `security --stage-root` لإنشاء نسخة read-only ذات SHA-256 ثابتة، و`security --ledger` لربط التقرير بـEvidenceLedger المحلي وإعادة entry/evidence hashes.
- إبقاء تشغيل YARA وMicrosoft Defender مؤجلًا كما طلب المستخدم؛ لا يوجد external provider runner أو تشغيل عينة داخل هذه الدفعة.
- نجاح GitHub Actions run `32446796151` على commit `8e3a19f`، مع اجتياز Python 3.12 وWindows/WPF وفحص artifacts المحظورة.
- `core/evidence_model.py` بصيغة `resource_studio.evidence_summary.v1` لتطبيع observations وraw ranges وstatistics وprovenance وExpert Findings.
- إضافة `evidence` و`evidenceHash` و`rawResourceComparison` إلى CLI `inspect --json`، وإضافة Evidence Summary إلى `ForensicEvidence`.
- وثيقة `docs/PE-EVIDENCE-MODEL.md` التي تحدد المصادر والـconfidence والحدود وعدم تحويل entropy إلى verdict.

### تحسّن

- توحيد README ليعرض هوية المشروع والحالة الحالية ومسار Save/Verification/Forensic والتثبيت والتشغيل والاختبار والحدود وروابط التوثيق.
- توسيع TODO بسجل Forensic-goal وحالات baseline/evidence الحالية والفجوات المتبقية.
- إضافة regression لـbaseline save/load وWriter sidecar وCLI `forensic-baseline`، مع إبقاء UI/UX improvements السابقة: Verification summary وasync CLI وStop وaccessibility surfaces وUI automation.
- توسيع VerificationSummary في WPF ليعرض `Technical evidence` من التقرير دون إعادة تنفيذ Verification Engine.
- إغلاق بوابة Manus الكاملة، وبوابة Windows Python/Win32/WPF/UI automation؛ SHA-256 للنسخة الأصلية بقي `14A44FE31B04FBCC65E94E80016138A2E9FC9BB6DFCEA09B98DE57F8A22A1240`.
- نجاح GitHub Actions run `32439414719` على Python 3.12 وWindows/WPF بعد إصلاح فحص PDB الناتج الطبيعي داخل `bin/obj` في commit `506ee11`.
- نجاح أحدث CI run `32441785614` على commit `3c7d783`، مع اجتياز Python 3.12 وWindows/WPF وبدون ملفات محظورة.
- نجاح release workflow السابق `32440078729` في إنشاء source bundle وSHA-256 مع اجتياز فحص الملفات المحظورة.
- نشر screenshot حقيقي لنافذة WPF في `assets/screenshots/resource-studio-main.png`، وإنشاء Issue المجتمع الأول [#1](https://github.com/bio-colab/Resource-Studio/issues/1). Discussion بقيت اختيارية بسبب رفض صلاحية `createDiscussion` من GitHub integration.
- إضافة regression لنموذج Evidence وCLI inspect وForensicEvidence، مع إبقاء RSQL وMutation Timeline مخططين لا منفذين في هذه الدفعة.
- تنفيذ `core/diagnostics.py` وأمر `report diagnostics` لتفسير before/after للأقسام والبنى المحمية وdirectories وchecksum وsignature وoverlay وresource graph وraw corroboration، مع findings وصيغ التقارير الحالية.
- إضافة journal JSONL لكل Batch job وخيار `--resume` الذي يتحقق من hash الناتج ويخطي العناصر المكتملة بأمان، مع اختبارات core وCLI.
- إضافة `docs/PRODUCTIZATION.md` وتحديث المرحلة 10 لتحديد ما اكتمل وما بقي مؤجلًا حسب احتياجات المطورين والهواة.
- نجاح GitHub Actions run `32442901962` على commit `60ffe5d`، مع اجتياز Python 3.12 وWindows/WPF وفحص الملفات المحظورة.
- نجاح release workflow run `32443264983` على commit `c5ec854` في إنشاء source bundle وSHA-256، مع اجتياز فحص غياب الملفات المحظورة.

### ما يزال قيد التنفيذ

- provenance طويل المدى يربط كل mutation تلقائيًا بledger واحد داخل Project.
- تقرير forensic متعدد الصيغ وviewer تفاعلي كامل للأدلة.
- operation ID persistence عبر كل مسارات mutation غير Writer/Project/Batch الحالية.
- raw parser coverage للامتدادات غير القياسية، coverage-guided fuzzing دائم عبر Atheris مع corpus وcrash minimization، وsimilarity hashing بعد تعريف contract وfalse-positive tests.
- التحليل السلوكي وentropy وssdeep وTLSH وrecursive payload/steganography خارج نطاق Forensic-goal عمدًا.
- اختبار Stop أثناء عملية طويلة فعلية، ومصفوفة keyboard/accessibility/failure/resize الأوسع.

## [2026-08-20] — Verification and UI/UX foundation

### أُضيف

- Resource Graph canonical model وsemantic fingerprints وdeep PE invariants.
- Windows Resource Oracle وUpdateResourceW differential oracle.
- checksum/signature diagnostics وWinVerifyTrust وdurable same-volume commit.
- round-trip contract registry وPE corpus taxonomy وbounded/structure-aware fuzz harnesses.
- Job Object containment proof وWPF process-state contract وUI automation مع BMP preview.
- UI/UX-goal مع Workspace context وVerification summary وasync Stop وprogressive disclosure.

### تم التحقق منه

- نجاح بوابات Python وWindows core/CLI/QA ذات الصلة.
- WPF Release build بـ0 أخطاء و0 تحذيرات في آخر بوابات موثقة.
- نجاح Job Object containment وUI automation مع بقاء الأصل دون تغيير.

### الحدود المعلنة

بقي coverage-guided fuzzing طويل التشغيل، وsigned/MUI/LN corpus الأوسع، وscreen-reader وF6/TabIndex matrix، واختبار Stop أثناء عملية طويلة فعلية، ضمن TODO ولم تُدّعَ كتغطية مكتملة.

## [2026-08-19] — Project and resource foundations

### أُضيف

- Project workspace وsnapshots وAudit Log وUndo/Redo وCommand Pattern.
- LIEF PE writer مع Save As وbackup وrollback وresource operations.
- parsers وserializers للموارد المدعومة، وCLI JSON، وWPF shell مستقل.
- خطط MCP المحلية ووثائقها، مع إبقاء النقل البعيد والمصادقة والإضافات المؤجلة.

### ملاحظة السلامة

لم تُضمّن ملفات خارجية مملوكة أو مواد من بيئة المستخدم في المستودع أو أي حزمة.

[Unreleased]: https://github.com/bio-colab/Resource-Studio/compare/main...HEAD
