# GitHub Foundation

## الهدف

تجعل هذه الدفعة مستودع Resource Studio قابلًا للاستخدام والمساهمة العامة دون خلط كود المشروع بملفات خارجية أو اعتماديات الطرف الثالث أو ملفات المستخدمين.

## الترخيص

كود المستودع مرخص تحت Apache License 2.0 في [`../LICENSE`](../LICENSE). اختير هذا الترخيص لأنه permissive وOSI-approved وله SPDX identifier ثابت `Apache-2.0`، مع احتفاظ المساهمين والمستخدمين بشروط الإشعارات والضمانات والقيود الواردة في النص الرسمي. لا يغطي الترخيص `external executable` أو علامته أو أصوله أو أي ملف خارجي غير مملوك للمشروع.

هذا قرار ترخيص للمستودع، وليس استشارة قانونية. يجب مراجعة المحامي عند دمج الكود في منتج أو عند جمعه مع ملفات أو اعتماديات ذات شروط مختلفة.

## Discoverability

تم ضبط وصف المستودع وhomepage وإضافة topics مرتبطة مباشرة بالوظائف الحالية: `pe` و`windows` و`resource-editor` و`lief` و`wpf` و`dotnet` و`reverse-engineering` و`localization` و`hex-editor`. لا تستخدم topics ادعاءات غير موجودة في الكود.

## CI/CD

يقوم `.github/workflows/ci.yml` بتشغيل compileall واختبارات Python وCLI وQA على Ubuntu، ثم يعيد تشغيل الاختبارات ذات الصلة على Windows مع Python 3.12 و.NET 8 ويبني WPF Release. يتحقق workflow أيضًا من غياب `external executable` وPDBs.

يقوم `.github/workflows/release.yml` ببناء source bundle عند tags من نمط `vX.Y.Z` أو يدويًا، ويحذف `.git` و`.github` وملفات البناء والـartifacts المؤقتة والمفاتيح و`external executable` قبل النشر. لا ينتج workflow binary يتضمن الأصل.

## Community health

توجد `CONTRIBUTING.md` و`CODE_OF_CONDUCT.md` و`SUPPORT.md` و`SECURITY.md` وIssue forms للـbug والـfeature. أُنشئ [Issue #1](https://github.com/bio-colab/Resource-Studio/issues/1) كبوابة أولى للمساهمات حول Hex Viewer وRC coverage وCI. حاولت الأتمتة إنشاء Discussion افتتاحي، لكن GitHub integration رفض mutation `createDiscussion`؛ يبقى إنشاؤه يدويًا من واجهة Discussions أو بعد منح الصلاحية المناسبة.

## المواد المرئية

تحتوي [`assets/screenshots/resource-studio-main.png`](../assets/screenshots/resource-studio-main.png) على لقطة حقيقية لنافذة WPF بعد فتح fixture عام بمسار عام `C:\ResourceStudio`. لا تمثل الصورة اختبارًا وظيفيًا ولا تُغني عن UI automation؛ وظيفتها إظهار Workspace وSave As policy وفهرس الموارد للمستخدم الجديد.
