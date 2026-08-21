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

المرحلة الحالية تنفذ Replace وAdd وDelete وChangeLanguage. كل أمر يحتفظ بما يكفي لعكسه. `CommandHistory` يمسح redo بعد أمر جديد، ويعيد الأمر إلى القائمة السابقة إذا فشل undo أو redo. التجميع، سجل التدقيق، والتراجع بعد الانهيار ما زالت مراحل لاحقة.

## حد مقصود

هذه النواة نموذج مشروع وأوامر، وليست بعد PE resource writer. لا تُحوّل `ResourceEntry` إلى PE تلقائيًا. writer الحقيقي سيأتي بعد اختيار backend موثق واختبارات round-trip على ملفات مرجعية.
