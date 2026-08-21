# P4 — WPF Session Identity

## التنفيذ

أضيفت هوية monotonic لكل طلب في `MainWindow` عبر `_requestGeneration`. يبدأ كل طلب جديد بهوية مختلفة ويلغي cancellation الخاص بالطلب السابق. بعد اكتمال الطلب، لا يحدّث النتيجة القديمة أي عنصر UI؛ كل handler يتوقف عند `CliResult.IsStale`.

أضيفت ملكية واضحة للعملية في fallback one-shot. يحتفظ كل طلب بـ`ownedProcess` الخاص به، لذلك لا يستطيع cleanup أو cancellation لطلب قديم قتل process تابعًا لطلب أحدث. وبالمثل لا يمسح الطلب القديم `_cliCancellation` الجديد في `finally` إلا إذا كان المرجع ما يزال مملوكًا له.

يحافظ `ReadHostClient` على serialization عبر `SemaphoreSlim`، ويقتل host الذي يملكه عند cancellation أو فشل البروتوكول. إغلاق النافذة يتخلص من host. بقيت عمليات الكتابة خارج read host.

## الاختبار

أضيف `tests/qa/test_p4_wpf_session_contract.py` ليثبت وجود request generation وstale guards ومرجعية cancellation وprocess ownership. كما بقي اختبار `wpf_read_host` وCLI ناجحًا. التحقق النهائي من بناء WPF يتم عبر Windows CI.

## حدود المرحلة

لا يدعي P4 أنه نفذ UI scheduler كاملًا أو priority queue أو multi-file workspace. الهدف المحدد هو منع stale UI updates وcross-request process cancellation فوق P3. أي توسعة لاحقة يجب أن تبدأ بقياس تفاعلي على Windows وباختبار UI automation.
