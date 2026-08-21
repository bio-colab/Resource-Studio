# Rust Evaluation — قرار عدم الدمج في هذه النقطة

## السؤال

اختُبر استخدام Rust جراحيًا في أكثر مسار قابل للعزل وضوحًا: البحث عن byte sequence داخل resource payload، مع إبقاء parsing وWriter وVerification Engine خارج التجربة.

## التجربة

بُني prototype Rust كـ`cdylib` صغير بدالة C ABI واحدة، ثم استُدعِي عبر `ctypes` من Python. استخدم الاختبار buffer حجمه 16 MiB وneedle ثابتة، وكرر العملية 200 مرة. قارنت النتيجة `bytes.find` الحالية بمسار Rust FFI، وتطابقت النتيجتان عند offset `8388608`.

| المسار | الزمن لـ200 تكرار | النتيجة |
|---|---:|---:|
| Python `bytes.find` | 1204.482ms | offset 8388608 |
| Rust FFI prototype | 3251.989ms | offset 8388608 |

كان prototype Rust يستخدم scan بسيطًا عبر `windows`، بينما `bytes.find` الحالية تنفذ في C محسّن. لذلك لم يظهر تحسن سرعة؛ ظهر العكس، مع بقاء accuracy متطابقة في هذه العينة.

## القرار

**لم يُدمج Rust في المشروع.** إدخاله هنا سيضيف ABI وartifact/build matrix وfallback وصيانة، دون فائدة أداء مثبتة. لم نلمس `core/search.py` ولا CLI ولا WPF ولا Writer.

سيُعاد فتح تقييم Rust فقط إذا أثبت corpus حقيقي على Windows أن هناك حلقة CPU داخلية لا تغطيها عمليات Python/C الحالية، وعندها يجب أن يكون النقل إلى خوارزمية متخصصة فعلية مع benchmark before/after وdifferential tests، لا مجرد استبدال لغة التنفيذ.

هذا القرار لا يرفض Rust كخيار عام؛ بل يرفض **هذه النقطة المحددة** لأن القياس لم يثبت فائدتها.
