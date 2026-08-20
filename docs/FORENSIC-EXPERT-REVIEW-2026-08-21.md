# مراجعة توصية الخبير — Forensic-goal

**التاريخ:** 2026-08-21

## الخلاصة التنفيذية

التوصية قوية لأنها ركزت على فجوات داخل العقود الموجودة بدل اقتراح ميزات أفقية جديدة. بعد مطابقة البنود مع الكود والاختبارات، اعتُمدت أربعة تحسينات ذات أثر مباشر: فصل `passed` عن `verified` عند تخطي Windows أو Authenticode، إضافة post-commit readback hash، إضافة pure loader language corroboration على canonical ResourceGraph، وإضافة ledger محلي مقاوم للعبث مع توقيع Ed25519 اختياري.

لا يُوصف ledger بأنه **سلسلة حيازة قانونية** أو ضمان عدم الإنكار. التوقيع يثبت أن artifact لم يتغير بالنسبة إلى المفتاح العام، بينما تعريف NIST لسلسلة الحيازة يتطلب تتبع الحركة والحفظ ومن تعامل مع الدليل والتاريخ والغرض من النقل [1]. لذلك سُميت الطبقة `tamper-evident local evidence chain`، وبقيت مسؤوليات التخزين وإدارة المفاتيح والسياسات التشغيلية خارج ادعاء المشروع.

## القرارات والتنفيذ

| البند | القرار | التنفيذ أو الحد |
|---|---|---|
| `SKIPPED` مقابل `PASSED` | مقبول وعاجل | `VerificationReport` يحتفظ بـ`passed` كنجاح pipeline، ويضيف `verified` و`platformLimited`. خارج Windows لا يُدعى أن Windows Resource Oracle أو WinVerifyTrust قد اشتغلا. |
| post-commit readback | مقبول وعاجل | `CommitResult.verified_sha256` يُحسب من الهدف بعد `os.replace` أو `ReplaceFileW/MoveFileExW`، ويُرفع `DurableCommitError` عند اختلافه. |
| pure loader oracle | مقبول بحدود واضحة | `core/pure_loader_oracle.py` يطبق اختيار اللغة deterministic على canonical resource leaves: exact ثم primary ثم neutral ثم أول متاح. هو corroboration لخوارزمية الاختيار، وليس بديلًا عن Win32 loader. |
| evidence ledger | مقبول كطبقة provenance اختيارية | `EvidenceLedger` يستخدم JSONL hash-chain، وتوقيع Ed25519 اختياري عند توفر `cryptography`. ledger لا يغير schema الأساسي ولا يجعل الدليل قانونيًا بذاته. |
| Atheris coverage-guided fuzzing | مؤجل | سيُضاف فقط مع corpus دائم وسياسة crash minimization ووقت تشغيل مستقل وقرار دعم Windows/Manus؛ لا يُخلط bounded deterministic harness مع coverage claim. |
| `similarityHash` | مؤجل | لا يُضاف قبل وجود contract مُثبت واختبارات false-positive/normalization؛ لا قيمة لإدخال fuzzy similarity إلى integrity verdict دون معيار قبول واضح. |

## سبب الحدود

توثيق Microsoft لـ`FindResourceEx` يوضح أن `wLanguage` يحدد لغة المورد، وأن `MAKELANGID(LANG_NEUTRAL, SUBLANG_NEUTRAL)` يستعمل لغة الخيط الحالية [2]. لذلك لا يحق للنسخة النقية أن تدعي أنها أعادت تنفيذ كل سلوك Windows أو MUI policy؛ ما نملكه هنا هو resolver حتمي قابل للمقارنة والاختبار، بينما يبقى Win32 oracle المرجع على Windows.

توضح وثائق `cryptography` أن Ed25519 يوفر `sign` و`verify` ومفاتيح عامة وخاصة قابلة للتسلسل [3]. وهذا مناسب لتثبيت artifact محليًا، لكنه لا يحل وحده إدارة المفتاح أو صلاحيات الوصول أو النقل أو الاحتفاظ أو التوقيت الموثوق. كما يعرّف NIST سلسلة الحيازة بأنها عملية تتبع دورة الدليل والحفظ والتحويل والأشخاص والتواريخ والأغراض [1].

## أثر التغييرات على Forensic-goal

أصبح التقرير أكثر صدقًا في البيئات غير Windows: يمكن أن ينجح pipeline البنيوي، مع بقاء `verified=false` و`platformLimited=true` عندما تكون مراحل خارج البيئة متخطاة. وأصبح commit قابلًا للتحقق بعد الاستقرار على القرص بدل الاكتفاء بالتحقق من الملف المؤقت. كما أصبح pure loader corroboration قادرًا على اختبار fallback مستقل عن Win32، وأصبح ledger قادرًا على كشف تعديل سجل الأدلة بعد إنتاجه.

تظل هذه التحسينات محافظة على قاعدة المشروع الأساسية: **Writer ينتج output، ولا يصنع الحكم وحده؛ الأدلة تُبنى من reopen وLIEF وinvariants وResource Graph وintegrity وWindows حيث يتوفر oracle**.

## المراجع

[1]: https://csrc.nist.gov/glossary/term/chain_of_custody "NIST CSRC — Chain of custody"
[2]: https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-findresourceexa "Microsoft Learn — FindResourceExA function"
[3]: https://cryptography.io/en/latest/hazmat/primitives/asymmetric/ed25519/ "PyCA cryptography — Ed25519 signing"
