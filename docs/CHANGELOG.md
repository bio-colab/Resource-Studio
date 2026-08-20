# سجل التغييرات

## [Unreleased] — 2026-08-19

### أُضيف

- اعتماد MCP كواجهة من الدرجة الأولى في معمارية Resource Studio.
- توثيق معمارية MCP ومسارات stdio وStreamable HTTP المؤجلة.
- فصل أدوات القراءة والتخطيط والتعديل.
- عقد أولي للأدوات والموارد والقوالب.
- ملف عقد JSON قابل للاستخدام كأساس للتوليد والاختبار.
- سياسة مسارات معزولة، تأكيد بشري، هاشات، إعادة فتح والتحقق، وسجل تدقيق.
- خارطة طريق تتضمن مراحل MCP، محلل PE، التوطين، MSIX/PRI، ونظام الإضافات.
- ADR يثبت قرار MCP-first.
- خطة اختبارات للبروتوكول والنواة والتعديل والأمان والتوافق.
- خادم MCP محلي عبر stdio للقراءة والفهرسة.
- أدوات إنشاء workspace والمقارنة وإنشاء الخطط وقراءة الخطة.
- تعديل معزول محدود متساوي الحجم بعد confirmation token وتحقق إعادة الفتح.
- سجل تدقيق منظم للعملية ومنع إعادة استخدام الخطة.
- اختبار تكاملي محفوظ يغطي التهيئة، اكتشاف الأدوات والموارد، فحص PE، فهرسة الموارد، workspace، diff، plan، رفض التطبيق دون تأكيد، apply، audit، رفض المسارات الخارجية، والتعامل مع ملف غير PE.

### أُضيف في دورة الإضافات 2026-08-20

- ملف TODO قابل للتتبع وفض تعارضات الخطة.
- Project/ResourceEntry مع project.json وresources الخارجية وSnapshot.
- Command Pattern مع Replace/Add/Delete/ChangeLanguage وUndo/Redo.
- Plugin Manifest/Registry/Permissions دون تشغيل كود خارجي.
- Localization Catalog للمقارنة والتصدير والتحقق من placeholders.
- ManifestDocument وVersionInfo وHexViewer كنماذج مستقلة قابلة للاختبار.
- اختبارات نواة منفصلة نجحت بالكامل.

### أُضيف في دورة backend 2026-08-20

- بحث موثق في Microsoft UpdateResource وLIEF وResource Hacker CLI والتراخيص.
- LIEFPEWriter مع Save As وbackup وatomic replace.
- Replace بمورد مختلف الحجم، Add، Delete، وChangeLanguage مع إعادة فتح والتحقق.
- PEHealth لتقرير PE والموارد والتوقيع والتحذيرات.
- اختبارات round-trip للكتابة مع إثبات بقاء fixture الأصلي ثابتًا.

### لم يُنفذ بعد

- ربط writer بنظام Project/Workspace مباشرة.
- واجهة مستخدم لتأكيد الخطط بصريًا بدل تمرير confirmation عبر عميل الاختبار.
- محرك Resource Studio الكامل.
- تكامل فعلي مع Resource Hacker Adapter.
- Streamable HTTP والمصادقة البعيدة.
- وحدة MSIX/PRI.
- نظام plugins.

### ملاحظة حماية

لم تُعدل نسخة Resource Hacker الأصلية، ولم تُنشأ أي إعدادات اتصال خارجية أو موصل MCP في جلسة المستخدم؛ ما تم إنشاؤه هو أساس مشروع ووثائق وعقد تصميمي محلي، وليس تفعيل خدمة خارجية.
