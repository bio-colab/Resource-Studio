# P0 Performance Baseline

## نطاق القياس

أُضيفت قياسات اختيارية لا تعمل افتراضيًا، وتُفعّل فقط عند ضبط `RESOURCE_STUDIO_P0_TELEMETRY_PATH`. لا تغير القياسات مخرجات CLI أو verdicts أو سلوك Writer. يسجل CLI `elapsedMs` و`liefParse` و`fullFileReads` و`temporaryDirectories` و`temporaryFiles`، بينما يسجل benchmark زمن العملية الخارجية وعدد processes التي أنشأها.

شُغّل القياس في 21 أغسطس 2026 على fixture الحقيقي `tests/fixtures/sample.dll`، حجمه `271872` بايت، وSHA-256 هو `d1a71f9ac1728082c1b276392725c3e010b98714888579b99152e401abedbf11`. هذا checkout يحتوي PE واحدًا فقط؛ لذلك لا يدّعي التقرير شيئًا عن ملفات 50MB أو corpus واسع.

## النتائج

| العملية | زمن العملية الخارجية ms | زمن داخل CLI ms | LIEF parses | full reads | temp dirs | temp files | processes |
|---|---:|---:|---:|---:|---:|---:|---:|
| `cli.list` | 459.226 | 7.020 | 1 | 2 | 1 | 3 | 1 |
| `cli.extract` | 437.677 | 5.422 | 1 | 2 | 1 | 3 | 1 |
| `cli.security` | 456.101 | 20.883 | 9 | 6 | 0 | 0 | 1 |
| `cli.evidence-query` | 479.694 | 20.917 | 9 | 6 | 0 | 0 | 1 |
| `writer.replace_manifest` | 533.645 | 92.186 | 49 | 14 | 0 | 1 | 1 |

زمن العملية الخارجية يتضمن بدء Python وتحميل imports. لذلك يظهر فرق واضح بين `cli.list` الخارجي (~459ms) وداخل الأمر (~7ms) على هذا النظام؛ هذا **دليل قياسي على كلفة process-per-action**، وليس حكمًا عامًا على كل جهاز Windows.

أما `list` و`extract` فهما يثبتان كلفة workspace القرائي الحالية: parse واحد، قراءتان كاملتان، TemporaryDirectory واحد، وثلاثة temporary files. هذا يتطابق مع مرور `_entries()` عبر `Project.open_pe`، الذي ينسخ PE ويكتب metadata وaudit رغم أن العملية لا تعدل الملف.

مسار `writer.replace_manifest` أعاد فتح/تحليل العينة 49 مرة وقرأ bytes كاملة 14 مرة داخل العملية المقاسة. هذا لا يثبت أن كل هذه القراءات غير ضرورية، لكنه يثبت أن P2 يجب أن يبدأ بـ`VerificationContext` وقياس مراحل منفصل قبل أي تخفيف للضمانات.

## WPF telemetry

أضيف إلى `CliProcessRunner` تسجيل اختياري باسم `resource_studio.p0_wpf_telemetry.v1` عند ضبط المتغير نفسه. يسجل كل استدعاء `py.exe` و`processSpawned` وarguments وexit code والزمن. لم يُشغّل WPF تفاعليًا داخل بيئة Linux؛ بوابة Windows/WPF في GitHub هي gate البناء، أما قياس latency التفاعلي فيحتاج تشغيل التطبيق على Windows مع المتغير مفعلاً.

## القيود

القياس الحالي baseline وليس benchmark إحصائيًا. لم تُستخدم بيانات مصطنعة لتضخيم الحجم، ولم تُقرأ النسخة الأصلية Resource Hacker. لا يجوز استنتاج عشرات الثواني لملفات كبيرة من هذه العينة الصغيرة، كما لا يجوز استنتاج أن كل parse في Writer يمكن حذفه قبل مقارنة verdicts وevidence hashes.

## حالة ما بعد P1

نُفذ P1 عبر `core/resource_reader.py`. بعد الإصلاح أصبحت `list` و`extract` و`search` وقراءة طرفي `diff` تستخدم parse واحدًا دون `Project.open_pe`. على نفس fixture انخفضت counters لمسارات القراءة إلى `fullFileReads=0` و`temporaryDirectories=0` و`temporaryFiles=0`، مع بقاء `liefParse=1`. النتيجة التفصيلية محفوظة في [`P1-READONLY-READER.md`](P1-READONLY-READER.md).

القرار التالي هو P2: دراسة إعادة استخدام snapshots وgraphs داخل Writer دون تغيير Writer أو Verification Engine قبل ظهور قياس جديد. أما Python host طويل العمر لـWPF فيبقى P3، وraw-surgical writer يبقى قرارًا مؤجلًا حتى يثبت القياس الحاجة إليه.
