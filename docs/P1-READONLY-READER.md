# P1 Read-only ResourceReader

## التغيير

أضيف `core/resource_reader.py` لمسار القراءة فقط. يقوم `ResourceReader` بعمل `lief.parse` مرة واحدة، ويعيد استخدام نموذج `ResourceEntry` ومحول الموارد الموجودين في `core.project`، ولا ينشئ `Project` أو workspace أو `project.json` أو audit.

استُبدلت نقطة `_entries()` في CLI بالـreader. لذلك أصبحت الأوامر التي تعتمد عليها، وهي `list` و`extract` و`search` وقراءة طرفي `diff`، منفصلة عن مسار إدارة المشروع والكتابة. بقي `Project.open_pe` وWriter وVerification Engine دون تعديل سلوكي في هذه المرحلة.

## التحقق

شُغّلت نفس أداة baseline على نفس fixture المستخدم في P0، من دون تغيير الملف الأصلي. النتيجة داخل العملية:

| العملية | قبل P1: parses | بعد P1: parses | قبل: full reads | بعد: full reads | قبل: temp dirs/files | بعد: temp dirs/files |
|---|---:|---:|---:|---:|---|---|
| `cli.list` | 1 | 1 | 2 | 0 | 1 / 3 | 0 / 0 |
| `cli.extract` | 1 | 1 | 2 | 0 | 1 / 3 | 0 / 0 |
| `cli.security` | 9 | 9 | 6 | 6 | 0 / 0 | 0 / 0 |
| `cli.evidence-query` | 9 | 9 | 6 | 6 | 0 / 0 | 0 / 0 |
| `writer.replace_manifest` | 49 | 49 | 14 | 14 | 0 / 1 | 0 / 1 |

انخفض الزمن الداخلي المقاس لـ`list` من `7.020ms` إلى `0.881ms`، ولـ`extract` من `5.422ms` إلى `1.132ms` في هذه الجولة. أما زمن العملية الخارجية فبقي في نطاق بدء Python، ولذلك لا يُعد نتيجة تحسين مستقلة للـreader.

اختبارات `ResourceReader` وCLI وtelemetry نجحت، كما بقيت بوابة compile و`git diff --check` سليمتين. لا يدّعي هذا القياس أداءً عامًا لملفات أكبر؛ corpus الحالي يحتوي fixture PE واحدًا فقط.

## حدود P1

لم يُنقل `command_hex` resource mode في هذه المرحلة، لأنه يحتاج إلى offset/index خاص بـ`HexViewer` وليس مجرد entries. ولم تُمس مسارات الكتابة أو `security` أو `evidence-query` أو WPF؛ هذه الأعمال تبقى في مراحلها المحددة حتى لا تختلط نتيجة P1.
