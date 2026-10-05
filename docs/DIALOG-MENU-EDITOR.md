# DIALOG وMENU Editor

## النتيجة

أصبح Resource Studio يملك مسارًا typed حقيقيًا لتحرير DIALOG وMENU بدل الاعتماد على raw bytes أو JSON فقط. يقرأ CLI المورد إلى نموذج منظم، ويعيد serializer البنية القياسية، ثم يمرر الناتج إلى Writer وVerification Engine المعتادين. لا تتم الكتابة فوق ملف الإدخال؛ كل Apply يطلب مخرجًا جديدًا عبر Save As.

## DIALOG

يدعم النموذج standard وDIALOGEX، وحقول الإطار والخط، و`helpId`، و`creationData`، والـordinal/string fields، ومجموعة controls كاملة مع `controlId` وgeometry وstyle وexstyle وclass وtitle. أضيفت معاينة WYSIWYG تميز BUTTON وSTATIC وEDIT وLISTBOX وCOMBOBOX، مع خصائص قابلة للتعديل للـID والـHelp ID والـclass والـstyle والـexstyle والنص والموقع والحجم.

يمكن للمستخدم إضافة Button وLabel وEdit وList وCombo، ونسخ control أو حذفه، وسحب العناصر داخل مساحة التصميم. وتبقى القيود الثنائية مفروضة قبل serializer: حدود signed WORD، حدود IDs، متطلبات `DS_SETFONT`، وصحة ordinal/string fields.

## MENU

يحتفظ النموذج بكل `flags` الخام مع عرض typed للعنصر باعتباره ITEM أو POPUP أو SEPARATOR. أضيفت خصائص ID والنص وflags بصيغة decimal أو hexadecimal، وإجراءات إضافة root item أو child item أو separator، والحذف، وإعادة الترتيب، والتحقق من duplicate IDs وبنية الشجرة. يظل drag/drop متاحًا لتحريك العقد، بينما يمنع المسار typed نقل عنصر تحت أحد أحفاده.

يدعم CLI الآن:

```text
python resource_studio_cli.py dialog validate INPUT --name 1 --language 1033 --json
python resource_studio_cli.py menu-resource validate INPUT --name 1 --language 1033 --json
python resource_studio_cli.py dialog export INPUT --name 1 --language 1033 --output dialog.json --json
python resource_studio_cli.py dialog apply INPUT --name 1 --language 1033 --model dialog.json --output OUTPUT.exe --json
python resource_studio_cli.py menu-resource export INPUT --name 1 --language 1033 --output menu.json --json
python resource_studio_cli.py menu-resource apply INPUT --name 1 --language 1033 --model menu.json --output OUTPUT.exe --json
```

أوامر `validate` لا تنشئ output ولا تغير الملف. أما `apply` فيستخدم Save As ويمر عبر writer verification والـforensic evidence الموجودين مسبقًا.

## الاختبارات

أضيفت عقود تغطي `DialogResource.validate`، وأنواع controls القياسية، وMENU flags، وduplicate IDs، وadd/remove operations، إضافة إلى round-trip binary contracts القائمة. لم يُخفّف أي preservation gate، ولم تُضف مكتبة خارجية أو parser بديل.

## الحدود الحالية

لا يدّعي المحرر أنه يعيد بناء كل semantics الخاصة بمكتبات custom controls أو owner-draw rendering أو layout manager ديناميكي. هذه القيم تُحفظ كـclass/style/exstyle/creationData، وتظهر في النموذج، لكن معاينتها البصرية الدقيقة تحتاج Windows control oracle، ولذلك بقيت خارج هذه الدفعة.
