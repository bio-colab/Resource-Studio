# Changelog

تتبع هذه الوثيقة التغييرات القابلة للملاحظة في Resource Studio. لا تُسجل فيها وعود مستقبلية على أنها منجزة؛ الأعمال غير المكتملة تبقى في [`TODO.md`](TODO.md) بحالة ومعيار إنجاز.

## [Unreleased]

### الاتجاه النشط

تتركز الدورة النشطة على **Forensic-goal**: إثبات سلامة تحويل PE عبر baseline وindependent differential verification وmutation attribution وevidence report. لا تشمل هذه الدورة إعادة بناء navigation أو إضافة malware/IOC/YARA/PEiD أو timeline عام أو hex forensic viewer.

### أُضيف

- `core/forensics.py` مع `ForensicBaseline` الذي يلتقط hash والحجم وPE invariant snapshot وResource Graph وdeep invariants وintegrity diagnostics.
- `ForensicEvidence` و`verify_transformation` لإنتاج `resource_studio.forensic_evidence.v1` وربط operation ID وoperation وtarget بالفرق المرصود.
- ربط `forensic_evidence` بـ`WriteResult` بعد commit مستقل، وتمريره إلى Project Audit وBatch operation payload.
- forensic difference أولي يميز target وresource tree unintended changes وPE preservation وintegrity وsignature وWindows status.
- اختبار `tests/core/test_forensics.py` الذي يثبت baseline contract وno-op attribution وغياب unintended changes.
- `FORENSIC-GOAL.md` الذي يحدد الهوية والحدود ومعايير FR-00 إلى FR-09.
- `CONTRIBUTING.md` الذي يشرح السلامة والاختبارات والتوثيق وقواعد المساهمات.

### تحسّن

- توحيد README ليعرض هوية المشروع والحالة الحالية ومسار Save/Verification/Forensic والتثبيت والتشغيل والاختبار والحدود وروابط التوثيق.
- توسيع TODO بسجل Forensic-goal وحالات baseline/evidence الحالية والفجوات المتبقية.
- إضافة Writer regression assertion يثبت schema وpassed forensic difference، مع إبقاء UI/UX improvements السابقة: Verification summary وasync CLI وStop وaccessibility surfaces وUI automation.
- إغلاق بوابة Manus الكاملة، وبوابة Windows Python/Win32/WPF/UI automation؛ SHA-256 للنسخة الأصلية بقي `14A44FE31B04FBCC65E94E80016138A2E9FC9BB6DFCEA09B98DE57F8A22A1240`.

### ما يزال قيد التنفيذ

- persistence مستقل للـbaseline وartifact provenance الكامل.
- human-readable forensic report في Summary → Details → Technical evidence.
- CLI surface موحد يعرض forensic evidence الكامل.
- operation ID persistence عبر كل مسارات mutation غير Writer/Project/Batch الحالية.
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
