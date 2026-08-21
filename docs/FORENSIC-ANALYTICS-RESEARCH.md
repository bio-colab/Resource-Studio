# Forensic Analytics Research — Wireshark وOxygen Forensic Detective

## الخلاصة التنفيذية

تقدم الأداتان درسين مناسبين لـResource Studio، لكن ليسا دعوة لنسخ وظائفهما. الدرس الأول من Wireshark هو أن التحليل القوي يبدأ بنموذج حقول موحد، ثم يضع فوقه لغة تصفية آمنة، وواجهة تفاصيل، ومؤشرات شدة، وتصديرًا قابلًا لإعادة الإنتاج. توضح وثائق Wireshark أن display filters أساس لميزات أخرى مثل coloring rules، وأن Expert Information نقطة بداية للتحقيق لا حكمًا نهائيًا [1] [2].

الدرس الثاني من Oxygen هو ربط **الأثر، السياق، الملاحظة، الوسم، الزمن، والتقرير** في دورة واحدة. تعرض صفحات Oxygen الرسمية Timeline وLink Analysis، وKey Evidence، وtags، وnotes، وCLI job automation، مع تتبع المستخدم والزمن في annotation workflows [3] [4] [5] [6]. النقل المناسب هنا هو طبقة مراجعة أدلة محلية وحتمية فوق الموجود، لا استخراج أجهزة أو تجاوز تشفير أو منصة تعاون شبكية.

## مصفوفة النقل

| الفكرة الأصلية | نظيرها داخل PE forensics | حالة Resource Studio | القرار |
|---|---|---|---|
| Wireshark display filters | Query على resource/finding/evidence/observation fields | موجود Query Engine آمن | لا نعيد بناء اللغة؛ نضيف selection/presets فقط عند الحاجة |
| Wireshark Expert Information | findings بدرجات severity/confidence مع corroboration | موجود Security Report وEvidence Graph | تحسين العرض والسياق، لا verdict تلقائي |
| Wireshark list/details/bytes/diagram | resource list + typed details + hex/raw + graph | موجودة في CLI/WPF بدرجات مختلفة | توحيد selection state هو الفجوة، لا parser جديد |
| Wireshark profiles | profile للاستعلام والأعمدة والعتبات | غير موجود بشكل واضح | مؤجل حتى تظهر حاجة UI متكررة |
| Oxygen Timeline | timeline لتحليل/تحقق/حالة القضية وcontext window | Case timeline موجود | إضافة annotation/context selection فوقه، لا schema timeline جديد |
| Oxygen Link/Social Graph | ResourceGraph/EvidenceGraph | موجود Evidence Graph | إعادة استخدام graph مع views، لا graph ثالث |
| Oxygen Key Evidence / tags / notes | annotations مربوطة بـartifact SHA وtarget ثابت | Case note عام موجود، annotation target غير موجود | **تنفيذ جراحي**: annotations append-only وselection export |
| Oxygen smart filters | context around selected evidence/tag/time range | غير موجود | مؤجل بعد تثبيت annotations؛ يعتمد على timeline semantics |
| Oxygen CLI jobs | JSON job manifest وdry-run/resume | CLI وBatch Workspace موجودان | توثيق pattern فقط؛ لا job runner جديد الآن |
| Oxygen selective export | manifest للأدلة المختارة مع hashes/provenance | exports موجودة لكن لا selection manifest موحد | **تنفيذ جراحي** مع annotations |
| Oxygen collaboration/RBAC | reviewer artifact read-only وaudit | audit chain موجود، collaboration غير موجود | لا multi-user service؛ نضيف actor/timestamp فقط |

## ما سيُنفذ

سيُضاف إلى `CaseFile` مسار annotations صغير: كل annotation ترتبط بـtarget ثابت، وartifact SHA-256، وactor، وUTC timestamp، وtag/note، وتدخل audit hash-chain. الإضافة append-only؛ لا يوجد حذف صامت ولا replace افتراضي. هذا يحافظ على مبدأ أن الملاحظة لا تعدل PE ولا تغير evidence graph.

سيُضاف كذلك `evidence_selection.v1` لتصدير annotations المختارة أو targets/tags المختارة في manifest مستقل يحوي case ID وartifact hash وgraph hash وselection hash. هذا يمنح المستخدم وحدة قابلة للمشاركة والمراجعة دون نسخ الملف الأصلي أو كامل case directory.

## ما لن يُنفذ

لن تُنقل live capture أو protocol dissectors أو packet reassembly من Wireshark. ولن تُنقل mobile/cloud acquisition أو password recovery أو OCR أو face categorization أو maps أو online collaboration من Oxygen. هذه وظائف صحيحة في سياقها، لكنها لا تعالج مشكلة PE الحالية.

## معايير القبول

يجب أن يرفض النظام annotation بلا target أو بلا tag/note، ويثبت أن إضافة annotation لا تغير SHA-256 للـartifact. يجب أن يفشل export عند عدم تطابق artifact hash، وأن يكون selection manifest قابلًا للتحقق بحقل hash مستقل. كما يجب أن تبقى كل اختبارات Writer وVerification Engine دون تغيير.

## المراجع

[1]: https://www.wireshark.org/docs/wsug_html/ "Wireshark User’s Guide — Expert Information, display filters, panes, and export"

[2]: https://www.wireshark.org/docs/dfref/ "Wireshark Display Filter Reference"

[3]: https://www.oxygenforensics.com/products/oxygen-forensic-detective/ "Oxygen Forensic Detective — collection, import, analysis, and export"

[4]: https://www.oxygenforensics.com/features/analysis/timeline-and-link-analysis/ "Oxygen Forensics — Timeline and Link Analysis"

[5]: https://www.oxygenforensics.com/technical-resources/smart-filters-key-evidence-timeline/ "Oxygen Forensics — Smart Filters and Key Evidence"

[6]: https://www.oxygenforensics.com/technical-resources/transfer-annotations-from-review-center-to-detective/ "Oxygen Forensics — annotation transfer, tags, notes, users, timestamps, and activity history"
