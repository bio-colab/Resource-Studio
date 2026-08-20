# Backend research notes

## Microsoft UpdateResource

المصدر الرسمي: https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-updateresourcea

تؤكد Microsoft أن UpdateResource تضيف وتحذف وتستبدل موردًا داخل ملف PE. لكن الصفحة توثق قيودًا خاصة بملفات LN وMUI التي تحتوي RC Config؛ خصوصًا أن إضافة لغة جديدة غير مسموحة، وأن بعض عمليات الإضافة/التعديل/الحذف تعتمد على بيانات RC Config ونوع المورد. لذلك لا يجوز اعتبار API عملية عامة بلا سياسة ملف.

## LIEF

المصدر الرسمي: https://lief.re/doc/latest/formats/pe/modifications/resources.html

توثق LIEF تعديل موارد PE على مستويين: شجرة الموارد منخفضة المستوى عبر ResourceNode، وResourcesManager عالي المستوى. تشمل الواجهة إضافة وحذف العقد وتغيير بيانات مورد، وإسناد Manifest، ونقل شجرة الموارد بين binaryين، ثم كتابة ناتج جديد. هذا يلائم Resource Studio كخيار أولي مستقل عن Resource Hacker، مع ضرورة اختبار round-trip والتوقيع والأنواع الخاصة قبل اعتماده.

## القرار المبدئي

سنفصل واجهة `ResourceWriter` عن التنفيذ. سيكون LIEF backend اختياريًا قابلًا للاختبار في بيئة Python، بينما يبقى Windows UpdateResource adapter مسارًا أصليًا لاحقًا. لا يُستخدم Resource Hacker إلا كـ adapter محلي اختياري في نسخة المستخدم، ولا يُضمّن أو يُعاد توزيعه. يمر كل writer عبر Save As إلى ملف output جديد، ثم إعادة فتح وفهرسة ومقارنة قبل إعلان النجاح.

## Resource Hacker CLI

المصدر الرسمي: https://www.angusj.com/resourcehacker/

تؤكد الصفحة الرسمية أن Resource Hacker يوفر عبر CLI عمليات `add`, `addoverwrite`, `addskip`, `compile`, `delete`, `extract`, `modify`, و`changelanguage`، كما يدعم scripts متعددة الأوامر. لذلك سيكون Resource Hacker adapter مفيدًا على Windows لاختبار التوافق مع النسخة القديمة، لكن لا يُستخدم كاعتمادية موزعة داخل Resource Studio قبل مراجعة الترخيص.

## ترخيص LIEF

المصدر الرسمي: https://github.com/lief-project/LIEF/blob/main/LICENSE

يعرض مستودع LIEF ترخيص Apache License 2.0، مع شروط حفظ إشعارات حقوق النشر والترخيص وبيان التغييرات. هذا يجعله مرشحًا قابلًا للدمج كاعتمادية مفتوحة المصدر، بشرط تضمين إشعاراته في الحزمة ومراجعة تراخيص التبعيات.
