# P3 — Long-lived Read Host

## ما نُفذ

أضيف `tools/wpf_read_host.py` كعملية Python طويلة العمر تعمل عبر JSON Lines على stdin/stdout. يستقبل host طلبًا واحدًا في كل سطر ويعيد response واحدًا، مع إبقاء diagnostics خارج stdout. أضيف `ReadHostClient.cs` إلى WPF لإدارة العملية، ترتيب الطلبات، cancellation، telemetry، وإغلاق العملية عند إغلاق النافذة.

تستخدم MainWindow host للأوامر القرائية الساخنة: `list` و`search` و`inspect` و`validate` و`security` و`evidence-graph` و`evidence-query` و`diff` و`preview` و`localization compare`. تبقى أوامر الكتابة والمحررات الثانوية على المسار الحالي، كما يبقى one-shot CLI fallback إذا تعذر بدء host.

يحافظ host على `ResourceReader` داخل جلسة واحدة. لذلك تعيد `list` و`search` استخدام parse الذاكرة نفسه عندما يكون الملف وحجمه ووقت تعديله ثابتًا. أما `inspect` وبقية الأوامر التي تحتاج نماذج أعمق فتستدعي dispatcher الحالي داخل العملية نفسها؛ لم تُنسخ عقود JSON الخاصة بها ولم يُعاد تنفيذ منطقها في C#.

ملاحظتان لاحقتان: (1) الموزّع المشترك `dispatch_cli(argv)` في `wpf_read_host.py` أصبح دالة وحدة يعيد استخدامها `tools/wpf_cli_host.py` (المضيف الدائم لمسار الكتابة) دون تغيير البروتوكول؛ (2) المضيفان يشفيان `sys.path` ذاتيًا عند الإقلاع بوضع script — بدون هذا كان استيراد `resource_studio_cli` يفشل في وضع إطلاق WPF الفعلي (`py.exe -3.12 tools/wpf_read_host.py`) لأن `sys.path[0]` يشير إلى `tools/` لا جذر المستودع، والاختبار القديم كان يمر فقط لأنه يضبط PYTHONPATH يدويًا.

## القياس المحلي

شُغل `tools/p3_baseline.py` على `tests/fixtures/sample.dll`. المقارنة تقيس process startup في Linux، وليست benchmark لزمن WPF على Windows:

| العملية | Python CLI مستقل ms | الطلب في host ms |
|---|---:|---:|
| `list` — أول طلب وparse الجلسة | 467.994 | 435.050 |
| `search` — طلب دافئ على الجلسة نفسها | 467.936 | 8.177 |
| `inspect` — داخل العملية نفسها | 495.105 | 34.875 |

أنشأ القياس عملية host واحدة فقط (`hostProcessCount=1`). لا ندعي أن هذه الأرقام تمثل latency Windows النهائية؛ قيمتها أنها تثبت إزالة process startup من الطلبين اللاحقين، وأن session cache يعمل فعليًا في `list/search`.

## قرار Rust وC++

لا يُنقل core إلى Rust أو C++ في P3. عنق الزجاجة المثبت كان process-per-action، وقد عالجه host دون ABI جديد. نقل Rust إلى Python عبر PyO3/maturin ممكن، لكنه يضيف بناء wheels، توافق OS/architecture/Python، وقرار `abi3` أو ABI خاص؛ توثق PyO3 هذه المقايضات صراحة [1]. كما أن Python Stable ABI يقلل مشاكل الربط عبر الإصدارات لكنه يفرض حدودًا وقد يخفض بعض التحسينات [2].

أما C++/CLI فيحتاج مشروعًا مختلطًا و`/clr` وتقسيمًا خاصًا لـXAML؛ توثق Microsoft أن WPF managed code لا يستدعيه C++ غير المُدار مباشرة، وأن التداخل يضيف تعقيدًا على مستوى المشاريع [3]. لذلك لا يبرر P3 إدخال C++/CLI.

القرار القابل للمراجعة هو: **Python host الآن، Rust مرشح لاحقًا فقط إذا أثبت Windows baseline أن host الدافئ نفسه ما زال عنق زجاجة، وC++/CLI غير مخطط حاليًا**. إذا جاء ذلك الدليل، يكون النقل محصورًا في native host أو parser بعقد C ABI/JSON واضحة، وليس إعادة كتابة Writer وVerification Engine دفعة واحدة.

## حدود السلامة

لم يتغير Writer أو Verification Engine في P3، ولم تُنقل عمليات الكتابة إلى host. كل طلب كتابة يظل على المسار الحالي مع Save As والتحقق. قتل host عند cancellation يفقد الجلسة فقط ولا يلمس ملف الإدخال.

## المراجع

[1]: https://pyo3.rs/main/building-and-distribution "PyO3 — Building and distribution"

[2]: https://docs.python.org/3/c-api/stable.html "Python — C API Stability and Stable ABI"

[3]: https://learn.microsoft.com/en-us/dotnet/desktop/wpf/advanced/wpf-and-win32-interoperation "Microsoft Learn — WPF and Win32 Interoperation"
