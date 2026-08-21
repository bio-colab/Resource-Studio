# Changelog

تتبع هذه الوثيقة التغييرات القابلة للملاحظة في Resource Studio. لا تُسجل فيها وعود مستقبلية على أنها منجزة؛ الأعمال غير المكتملة تبقى في [`TODO.md`](TODO.md) بحالة ومعيار إنجاز.

## [Unreleased]

### الاتجاه النشط

تتركز الدورة النشطة على **Forensic-goal**: إثبات سلامة تحويل PE عبر baseline وindependent differential verification وmutation attribution وevidence report. لا تشمل هذه الدورة إعادة بناء navigation أو إضافة malware/IOC/YARA/PEiD أو timeline عام أو hex forensic viewer.

### أُضيف

- Apache-2.0 في `LICENSE` مع توضيح الفصل القانوني بين Resource Studio وResource Hacker واعتماديات الطرف الثالث.
- GitHub Actions CI لـPython وWindows/WPF، وRelease workflow لإنتاج source bundle عند tags دون `ResourceHacker.exe` أو ملفات الأسرار والبناء.
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
- إضافة evidence chain metadata القابل لإعادة البناء: `prevSha256` وenvironment fingerprint وcommand line وevidence sha256.
- إضافة `PreservationMap` بخريطة byte ranges وتصنيف `EXPECTED_TARGET_RESOURCE` و`EXPECTED_RESOURCE_CONTAINER` و`EXPECTED_HEADER_RECALC` و`UNEXPECTED`، مع ميزانية unexpected تساوي صفرًا.
- إضافة raw resource parser مستقل محدود يقارن موارد `IMAGE_RESOURCE_DIRECTORY` مع canonical ResourceGraph.
- إضافة Rich Header hash/preservation signal وتثبيت COFF timestamp الأصلي وdeterminism regression لنفس mutation.
- forensic difference أولي يميز target وresource tree unintended changes وPE preservation وintegrity وsignature وWindows status.
- اختبار `tests/core/test_forensics.py` الذي يثبت baseline contract وno-op attribution وغياب unintended changes.
- `FORENSIC-GOAL.md` الذي يحدد الهوية والحدود ومعايير FR-00 إلى FR-09.
- `CONTRIBUTING.md` الذي يشرح السلامة والاختبارات والتوثيق وقواعد المساهمات.

### تحسّن

- توحيد README ليعرض هوية المشروع والحالة الحالية ومسار Save/Verification/Forensic والتثبيت والتشغيل والاختبار والحدود وروابط التوثيق.
- توسيع TODO بسجل Forensic-goal وحالات baseline/evidence الحالية والفجوات المتبقية.
- إضافة regression لـbaseline save/load وWriter sidecar وCLI `forensic-baseline`، مع إبقاء UI/UX improvements السابقة: Verification summary وasync CLI وStop وaccessibility surfaces وUI automation.
- توسيع VerificationSummary في WPF ليعرض `Technical evidence` من التقرير دون إعادة تنفيذ Verification Engine.
- إغلاق بوابة Manus الكاملة، وبوابة Windows Python/Win32/WPF/UI automation؛ SHA-256 للنسخة الأصلية بقي `14A44FE31B04FBCC65E94E80016138A2E9FC9BB6DFCEA09B98DE57F8A22A1240`.

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

لم تُعدل نسخة Resource Hacker الأصلية ولم تُضمّن في المستودع أو أي حزمة.

[Unreleased]: https://github.com/bio-colab/Resource-Studio/compare/main...HEAD
