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

### المضيف الدائم (wpf_cli_host)

بدل spawn لكل عملية، يوجّه `CliProcessRunner` استدعاءات وضع source عبر `tools/wpf_cli_host.py`: عملية Python دائمة تنفذ `cli.main(argv)` داخل نفسها بلا أي حالة محفوظة بين الطلبات، فتبقى الدلالات مطابقة لـprocess-per-action (كل طلب يعيد قراءة المدخلات من القرص) مع إزالة كلفة بدء العملية والاستيراد. عند فشل بدء المضيف (أدوات مفقودة مثلًا) يعود المسار القديم تلقائيًا (spawn)، وعند فشل بروتوكولي أثناء طلب يُعاد خطأ صريح بلا محاولة تلقائية ثانية لأن حالة العملية تصبح غير معلومة. حقل التيليمتري `mode` (`host` أو `spawn`) و`processSpawned` (0 عند إعادة الاستخدام) يميزان المسار المُستعمل؛ أول استدعاء يدفع كلفة الاستيراد مرة واحدة. نفس بروتوكول `wpf_read_host` حرفيًا مع حقل `env` اختياري لكل طلب (يُطبق ويُستعاد)، والذي ينقل أسرارًا مثل `RS_PFX_PASSWORD` دون بقائها في بيئة المضيف.

## القيود

القياس الحالي baseline وليس benchmark إحصائيًا. لم تُستخدم بيانات مصطنعة لتضخيم الحجم، ولم تُقرأ ملفات خارج نطاق المشروع. لا يجوز استنتاج عشرات الثواني لملفات كبيرة من هذه العينة الصغيرة، كما لا يجوز استنتاج أن كل parse في Writer يمكن حذفه قبل مقارنة verdicts وevidence hashes.

## حالة ما بعد P1

نُفذ P1 عبر `core/resource_reader.py`. بعد الإصلاح أصبحت `list` و`extract` و`search` وقراءة طرفي `diff` تستخدم parse واحدًا دون `Project.open_pe`. على نفس fixture انخفضت counters لمسارات القراءة إلى `fullFileReads=0` و`temporaryDirectories=0` و`temporaryFiles=0`، مع بقاء `liefParse=1`. النتيجة التفصيلية محفوظة في [`P1-READONLY-READER.md`](P1-READONLY-READER.md).

القرار التالي هو P2: دراسة إعادة استخدام snapshots وgraphs داخل Writer دون تغيير Writer أو Verification Engine قبل ظهور قياس جديد. أما Python host طويل العمر لـWPF فيبقى P3، وraw-surgical writer يبقى قرارًا مؤجلًا حتى يثبت القياس الحاجة إليه.

## جولة الأيض (2026-08-30)

قنّص مُسند للمستدعي (إطار على `lief.parse` مع تتبع المكدس) أثبت أن كتابة واحدة تفك نفس البايتات 11 مرة (writer ×1 متحول، signature ×1، verification-before ×1، snapshot+deep على input ×2، tmp ×2، output ×5) وأن `inspect` يفكك الملف 8 مرات (عضو تقارير لكل لقطة). جرحتان:

- **كاش تفكيك للقراءة فقط** (`core/parse_cache.py`): thread-local، حد 4 مداخيل/256MB، مفتاح `(path, size, mtime_ns)`؛ التفكيكات المتحولة تبقى خاصة. النتيجة بعملية منفصلة لكل أمر: `inspect` 8→1 تفكيكات، كتابة 11→5 (writer المتحول + shared لكل من input/output + tmp)، وإعادة `list` كما هي (1).
- **إعادة كتابة `preservation._diff_ranges`**: كان يمشي بايت-ببايت على كامل الملف (قياس مباشر: 245ms/MB، أي 15.7s عند 64MB)، والصيغة الجديدة مجزأة 64KB (21ms عند 64MB، ×742). أصلح معها عمى طرفي كان يُسقط نطاق التغيّر الواصل إلى نهاية الملف من خريطة الحفظ؛ اختبر تفاضليًا ضد مشي مرجعي (600 حالة seeded + حالات حدية) في `tests/core/test_diff_ranges_regression.py`.

قياس طرفي لنهاية إلى نهاية على ملف 64MB (fixture + overlay أصفار): كتابة `string-table apply` كاملة 4.8s بـ5 تفكيكات؛ المكونات المكافئة قبل الجولة (~15.7s مشي بايتي + ~0.95s تفكيكات زائدة) تجعل التقدير المضاد ~17s+. القياس على Linux/Python 3.12 وليس benchmark Windows.
