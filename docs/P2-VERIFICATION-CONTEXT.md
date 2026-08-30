# P2 VerificationContext

## التنفيذ

أضيف `VerificationContext` إلى `core/verification.py`. يبني السياق من parse واحد لكل ملف ويحمل `PEInvariantSnapshot` و`ResourceGraph` وdeep PE invariants وintegrity وsignature state. أضيفت أيضًا مداخل اختيارية إلى `snapshot` و`inspect_deep` و`inspect_integrity` و`inspect_signature` و`compare_surgical_change` لقبول النتائج الجاهزة مع إبقاء الاستدعاءات القديمة متوافقة.

يستخدم Writer السياق نفسه خلال candidate pre-verification وpost-commit verification وforensic evidence. بعد commit يعاد فتح output من القرص كما كان مطلوبًا؛ الذي أزيل هو إعادة بناء نفس البيانات داخل الطبقات المتتالية، لا post-commit readback ولا أي preservation gate.

## القياس

شُغّل نفس baseline على نفس fixture PE المستخدم في P0 وP1:

| العملية | P0 | P2 | التغير |
|---|---:|---:|---:|
| `writer.replace_manifest` — LIEF parses | 49 | 11 | -38 |
| `writer.replace_manifest` — full reads | 14 | 12 | -2 |
| `writer.replace_manifest` — temporary files | 1 | 1 | ثابت |
| `writer.replace_manifest` — الزمن الداخلي ms | 92.186 | 76.582 | -15.604 |

لم تتغير counters لمسارات P1 القرائية: `list` و`extract` ما زالا عند parse واحد وبدون temporary I/O، بينما `security` و`evidence-query` انخفضا من 9 إلى 8 parses نتيجة إزالة إعادة parsing داخل ResourceGraph. لا يُعامل هذا كbenchmark عام؛ corpus الحالي يحتوي PE واحدًا.

## الحواجز التي بقيت

بقيت مراحل `STRUCTURAL_VALIDATION` و`RESOURCE_GRAPH_VALIDATION` و`SEMANTIC_DIFF` و`PRESERVATION_CHECK` وWindows validation وAuthenticode state وdurable commit وpost-commit verification وforensic evidence. اختبارات Writer وVerification وForensic وcrash consistency وجميع بوابات Core/CLI/QA هي معيار القبول.

## قرار النطاق

لم يُبنَ cache عالمي ولم تُخفّض دقة التحقق ولم يُستبدل LIEF بـraw-surgical writer. P3 الخاص بـWPF host طويل العمر يبقى منفصلًا، وP5 لا يبدأ إلا إذا أثبتت قياسات corpus أوسع أن P2 غير كافٍ.
