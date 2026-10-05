# معمارية النواة — الإصدار الأول

## المبدأ

النواة لا تعرف الواجهة الرسومية ولا MCP ولا أدوات خارجية غير مملوكة. تستقبل نموذج مشروع، وتنفذ أوامر على الذاكرة، وتحفظ صيغة مشروع مستقلة عند طلب الحفظ. بهذا يمكن لاحقًا استخدام النواة من واجهة Windows أو CLI أو plugin host دون تكرار المنطق.

```text
Project
 ├── Original metadata: path + SHA-256
 ├── ResourceEntry map: type/name/language/data/metadata
 ├── resources/*.bin: بيانات الموارد خارج project.json
 └── snapshots/*.json: حالات قابلة للاستعادة

CommandHistory
 ├── execute
 ├── undo
 └── redo
```

## صيغة المشروع

الملف `project.json` يحمل رقم الصيغة، بيانات الأصل، وقائمة أوصاف الموارد. البيانات الثنائية تحفظ في `resources/` ويُثبت لكل ملف SHA-256. هذا يمنع تضخم JSON ويحافظ على إمكانية تخزين المشروع في Git، مع بقاء تحسينات deduplication وmanifest versioning للعمل اللاحق.

## الأمان

عمليات `Project.put` و`Project.remove` تغير النموذج في الذاكرة فقط وتحدد `dirty=True`. الحفظ يستخدم ملفًا مؤقتًا ثم استبدالًا ذريًا، ولا يكتب المسار الأصلي. لا توجد في هذه الطبقة وظيفة `save_to_original`.

## الأوامر

المرحلة الحالية تنفذ Replace وAdd وDelete وChangeLanguage وChangeId. كل أمر يحتفظ بما يكفي لعكسه. `CommandHistory` يمسح redo بعد أمر جديد، ويعيد الأمر إلى القائمة السابقة إذا فشل undo أو redo. التجميع (`CommandGroup`) وسجل التدقيق (`AuditLog` المربوط بـProject) والاستعادة بعد الانهيار (`restore_snapshot` عبر snapshots) منفذة ومختبرة؛ أما الأسطح غير المفعلة ومبررات إبقائها فموثقة في `CODE-REVIEW.md`.

## حد مقصود

النواة لا تحوّل `ResourceEntry` إلى PE تلقائيًا خارج مسار الكتابة الموثق. الكتابة الفعلية تمر عبر `core/pe_writer.py` (خلفية LIEF) مع durable commit وإعادة فتح وتحقق مستقل وعقود round-trip على ملفات مرجعية — ولا يعيد أي مسار كتابة الملف الأصلي مباشرة (Save As فقط). بهذا بقيت القاعدة الأصلية قائمة: لا تحويل ضمني، ولا كتابة إلى input، ولا منطق تحقق داخل النموذج نفسه.

## واجهة الحزمة الكسولة

`core/__init__.py` واجهة إعادة تصدير كسولة (PEP 562): كل اسم عام مربوط بوحدته في خريطة `_EXPORTS` ولا يُستورد إلا عند أول وصول. لذلك يستدعي `from core.X import Y` كلفة `core.X` وتبعياته فقط — لم يعد يسحب الحزمة كاملة عبر استيرادات ترويسة الحزمة المتحمسة القديمة التي كانت تجعل أي استيراد يسحب `lief` (~250ms) عبر سلسلة `batch → pe_writer`، مع بقاء `from core import Project` و`from core import verification` و`dir(core)` و`core.__all__` كما هي.

ملاحظة معمارية معلنة: توجد دورة اعتماد منطقية بين `project/pe_writer/health/verification/forensics/windows_resource_oracle/resource_index` تعكس حلقة المجال نفسها (كتابة ← تحقق ← إثبات)؛ وهي مطفأة وقت الاستيراد لأن وحداتها تستورد كسولًا داخل الدوال، والقرار هو إبقاؤها موثقة بدل تفكيكها بالقوة (التفاصيل في `CODE-REVIEW.md`).

## كاش التفكيك للقراءة فقط

`core/parse_cache.py` كاش thread-local محدود (4 مداخيل/256MB) بمفتاح `(path, size, mtime_ns)` تشاركه أجهزة التقارير للقراءة فقط (health وintegrity وmetadata وcompatibility وsignature inspection وverification context وinvariants وdeep وstatic analysis وresource reader) داخل عمر الأمر الواحد، فلا يعاد فك نفس الملف لكل عضو. قاعدة المشاركة الصارمة: أي مستهلك يُحوّل الـBinary (writer `_parse` و`_strip_to_path` وأوراكل Windows) يبقى على تفكيك خاص — المشاركة للقراءة فقط، والاستدعاء الديناميكي لـ`lief.parse` يحفظ سلوك تيليمتري P0.
