# خطة إصلاح المعمارية والأداء

## الحكم التنفيذي

التقييم الخارجي **مصيب في جوهرين مهمين**: مسار WPF الحالي process-per-action، ومسارات القراءة في CLI تمر عبر `Project.open_pe` الذي ينشئ workspace ويكتب metadata وaudit رغم أن `list` و`extract` وقراءة البحث لا تحتاج إلى ذلك. أما وصف Verification Engine بأنه «برمجة طقسية» أو الجزم بأن كل عملية تستغرق عشرات الثواني، فهما **استنتاجان غير مثبتين بعد**. الكود يثبت وجود إعادة تحليل متعددة في مسار الكتابة، لكنه لا يثبت رقمًا زمنيًا عامًا أو أن كل اختلاف ناتج عن LIEF غير مقصود.

القرار الحكيم ليس حذف التحقق ولا القفز مباشرة إلى raw patcher. القرار هو فصل مسارات القراءة عن مسارات التحرير، إبقاء التحقق الصارم كحاجز أمان، ثم إزالة العمل المكرر منه بواسطة context/cache حتمي، وبعد ذلك فقط دراسة writer جراحي محدود فوق corpus واقعي وWindows oracle.

## ما يثبته الكود حاليًا

| الادعاء | الحكم | الدليل | القرار |
|---|---|---|---|
| WPF ينشئ Python جديدًا لكل عملية | صحيح | [`CliProcessRunner.RunAsync`](../windows/ResourceStudio.Windows/CliProcessRunner.cs) ينشئ `py.exe -3.12` وينتظر انتهاء العملية لكل استدعاء | استبدال المسار الساخن بمضيف Python طويل العمر لكل جلسة PE، مع الإبقاء على CLI المستقل للتشغيل اليدوي |
| لا توجد حالة مستمرة بين نقرات WPF | صحيح عمليًا | `MainWindow` يعتمد على `RunCliCaptureAsync`، بينما cache الحالي محصور في بيانات موارد WPF ولا يحتفظ بـLIEF session أو parsed graph | إنشاء `PeSession` مشتركة للتصفح والبحث والتقارير |
| `list` و`extract` ينسخان PE إلى workspace مؤقت | صحيح | `_entries` في `resource_studio_cli.py` يستعمل `TemporaryDirectory` ثم `Project.open_pe`؛ و`Project.open_pe` ينسخ الملف ويكتب project/audit | إضافة read-only `ResourceReader` لا يستعمل Project workspace |
| LIEF قد يعيد ترتيب أو إعادة بناء أجزاء PE | خطر واقعي يحتاج قياسًا | `binary.write()` يعيد serialization من النموذج، وWriter يضع preservation checks صريحة | لا نحذف LIEF الآن؛ نقيس byte/structure drift ونفصل writer profiles |
| التحقق يقرأ الملف عدة مرات | صحيح نوعيًا | `_write` يمر عبر baseline وcandidate verification وpost-commit verification وsurgical comparison وforensic verification، وكل طبقة قد تعيد parse/snapshot | إدخال `VerificationContext` يعيد استخدام snapshots وgraphs والتقارير المتوافقة دون تخفيف معايير القبول |
| كل عملية تستغرق عشرات الثواني لملف 50MB | غير مثبت | لا توجد benchmark trace أو corpus performance report تثبت الرقم | يمنع اعتماد هذا الرقم؛ نضيف قياسًا قبل أي تحسين أو ادعاء |
| verification مجرد غطاء شكلي | غير منصف كحكم تقني | `verify_candidate` يختبر structural validation وresource graph وsemantic diff وpreservation وWindows/signature phases؛ لكنه قد يكرر العمل | نصلح التكرار، لا نحذف الضمانات |

## المبادئ غير القابلة للتفاوض

يجب أن يبقى Save As فقط، ويجب ألا يكتب أي مسار سريع فوق الأصل. لا يجوز تحويل cache أو host إلى مصدر ثقة وحيد؛ النتيجة النهائية للكتابة تعاد قراءتها من bytes الموجودة على القرص. ولا يجوز استبدال writer الحالي بكتابة raw غير مختبرة قبل توفر corpus وround-trip وWindows validation.

> **القاعدة:** القراءة يمكن أن تكون سريعة ومستمرة؛ الكتابة يجب أن تبقى ذرية، قابلة للتراجع، وقابلة لإعادة الفحص.

## خطة الإصلاح المرحلية

### المرحلة A — القياس أولًا، بلا تغيير سلوكي

نضيف trace داخليًا لا يغير النتائج ويسجل لكل عملية: الزمن، حجم الملف، عدد عمليات `lief.parse`، عدد قراءات bytes الكاملة، حجم temporary I/O، عدد عمليات Python الفرعية، وعدد مرات بناء Resource Graph وPE snapshots. تُشغل القياسات على corpus حقيقي من الملفات الصغيرة والمتوسطة والكبيرة، وعلى موارد مختلفة، مع baseline hash محفوظ.

معيار الخروج هو تقرير يمكنه الإجابة عن سؤالين: كم كلفت القراءة قبل الإصلاح؟ وكم مرة أعيد التحليل أثناء الكتابة؟ لا نضع أرقام latency مصطنعة قبل ظهور baseline.

### المرحلة B — إصلاح القراءة في CLI

نستخرج reader مشتركًا منطقُه هو: parse واحد، استخراج entries/index مرة واحدة، ثم تنفيذ `list` و`extract` و`search` وقراءة جانب diff منه. هذا reader لا ينشئ `Project` ولا workspace ولا audit ولا outputs. يبقى `Project.open_pe` لمسار التحرير وإدارة المشروع فقط.

معايير القبول هي أن `list` و`extract` لا ينشئان مجلدًا مؤقتًا أو `project.json` أو audit، وأن النتيجة وSHA-256 وتعدد اللغات تطابق المسار القديم، وأن الملف الأصلي لا يتغير. نُفذت هذه المرحلة في commit `P1` عبر `core/resource_reader.py`، وأثبت baseline بعد الإصلاح أن `list` و`extract` أصبحا عند `temporaryDirectories=0` و`temporaryFiles=0` و`fullFileReads=0` مع `liefParse=1`. بقي زمن process startup الخارجي قائمًا، لذلك لا ننسب انخفاضه إلى reader.

### المرحلة C — جلسة WPF طويلة العمر

بدل تشغيل `py.exe` لكل زر، ينشئ WPF مضيفًا واحدًا `resource_studio_host.py` لكل PE مفتوح، عبر stdio وJSON Lines. يحتفظ المضيف بـ`PeSession` تحتوي parsed binary وresource index وgraph وhash، وتستخدمها أوامر list/search/inspect/preview/query/graph. يرسل WPF request ID ويدعم cancellation وإغلاق المضيف عند تغيير الملف.

لن يسمح المضيف في نسخته الأولى بالكتابة. أوامر mutation تبقى عبر Save As الحالي حتى يثبت protocol القراءة. بذلك نحصل على state persistence من دون إدخال HTTP أو database أو خدمة خلفية دائمة.

معايير القبول هي عدم ظهور process جديد عند كل عملية قراءة، وإعادة استخدام session داخل الملف نفسه، وإبطال cache عند تغير SHA-256 أو تبديل الملف، وإظهار خطأ واضح عند تعطل المضيف مع fallback اختياري إلى CLI المستقل.

### المرحلة D — تقليل التكرار داخل Verification Engine

نعرّف `VerificationContext` داخليًا يحمل `before_snapshot` و`candidate_snapshot` و`before_graph` و`candidate_graph` و`integrity` و`deep_invariants` وsignature state. يمرر هذا السياق إلى `verify_candidate` و`compare_surgical_change` و`verify_transformation` عندما تكون البيانات نفسها صالحة.

لا نلغي pre-commit verification أو post-commit readback؛ فالأول يحمي من commit لمرشح سيئ، والثاني يثبت bytes الهدف بعد `os.replace`. الذي يُزال هو إعادة حساب نفس snapshot أو graph بلا داعٍ. إذا تغير الملف أو لم تتطابق identity/hash، يبطل السياق ويعاد التحليل.

معايير القبول هي تطابق verdicts وerrors وevidence hashes مع baseline، انخفاض عدد parses المقاسة، وبقاء اختبارات preservation وdeterminism وcrash consistency وWindows gates ناجحة. نُفذ P2 عبر `VerificationContext`: انخفض `writer.replace_manifest` من 49 إلى 11 LIEF parses ومن 14 إلى 12 full reads في fixture baseline، مع نجاح اختبارات Writer وVerification وForensic وcrash consistency. بقيت pre-commit وpost-commit وforensic gates دون حذف.

### المرحلة E — تصنيف writer بدل اتهامه أو استبداله دفعة واحدة

يُفصل writer إلى profile واضح: `LIEF-compatible` للوظائف الحالية، و`strict` للتحقق الكامل، و`raw-surgical` لا يُفتح إلا لاحقًا لأنواع عمليات محددة ثبت أنها آمنة. لا يسمح هذا التصنيف بتجاوز الحواجز؛ هو فقط يحدد serializer والعقود اللازمة.

قبل بناء raw-surgical writer، يجب إثبات ثلاثة أمور: أن LIEF يسبب drift قابلًا للتكرار في حالات محددة، وأن التعديل الجراحي يمكنه تحديث resource directory وheaders والalignment بصورة صحيحة، وأن Windows loader وAuthenticode وround-trip لا تتضرر. إذا لم تثبت القياسات الحاجة، يبقى LIEF مع context optimization هو الحل الأبسط.

### المرحلة F — تحسين WPF بعد ثبات المضيف

بعد ثبات host protocol، تُحوّل واجهة WPF إلى نموذج جلسة حقيقي: `CurrentPeSession`، resource collection واحدة، report cache، query results، وحالة عملية واحدة قابلة للإلغاء. لا تُضاف طبقة MVVM أو dependency framework ما لم تظهر حاجة فعلية؛ يمكن تنفيذ session service صغير فوق الموجود.

تُظهر الواجهة الفرق بين `Loading`, `Ready`, `Stale`, `Failed`، ولا تعرض نتيجة قديمة بعد تبديل الملف. ويجب أن تبقى UI automation IDs الحالية مستقرة.

## ترتيب التنفيذ المقترح

| الأولوية | التغيير | المخاطر | القيمة |
|---|---|---:|---:|
| P0 | benchmark/trace بلا تغيير سلوك | منخفضة | يزيل الجدل ويحدد عنق الزجاجة الحقيقي |
| P1 | read-only ResourceReader للـCLI | منخفضة | مكتمل؛ أزال workspace وtemporary I/O من list/extract/search |
| P2 | VerificationContext وإزالة إعادة التحليل المكرر | متوسطة | مكتمل؛ خفض إعادة parsing في Writer دون تقليل الضمانات |
| P3 | Python host طويل العمر للقراءة في WPF | متوسطة | مكتمل؛ host JSONL واحد وsession cache لـlist/search، وfallback آمن |
| P4 | WPF session/cache/cancellation | متوسطة | مكتمل جزئيًا؛ session identity وstale protection وowned cancellation، بينما UI automation الكامل مؤجل |
| P5 | دراسة raw-surgical writer لنطاق ضيق | عالية | لا يبدأ إلا بعد القياس وcorpus وWindows oracle |

## ما يجب ألا نفعله

لا نحذف `verify_candidate` أو `verify_transformation` لمجرد أن LIEF قد يسبب drift؛ ذلك يخفي العيب بدل عزله. لا نقرر أن أي أداة خارجية تثبت أن raw patching بسيط لكل أنواع الموارد؛ هذا افتراض غير آمن. لا نضيف database أو HTTP service أو MCP إلى مسار الأداء قبل أن نحل process-per-action وProject materialization. ولا نضع cache عالميًا بلا invalidation صارم، لأن stale PE evidence أخطر من البطء.

## معايير النجاح النهائية

يُعتبر الإصلاح ناجحًا عندما تصبح القراءة المتكررة داخل WPF session واحدة بلا process جديد لكل زر، وعندما لا تمر `list` و`extract` عبر workspace، وعندما ينخفض عدد التحليلات الكاملة في Save دون اختلاف في verdict أو evidence، وعندما تبقى سلامة الأصل وSave As وrollback وWindows/WPF CI وround-trip tests سليمة. أما raw-surgical writer فليس شرطًا للمرحلة الأولى؛ هو قرار لاحق تحسمه القياسات لا الانطباعات.

## القرار المقترح

أوصي بالانتقال إلى **P2** بعد تثبيت P1. عولجت كلفة materialization القرائية المؤكدة بأقل تغيير، ولا يزال Writer وVerification Engine دون تعديل. لا يبدأ P2 بإزالة فحوص؛ يبدأ بقياس وإعادة استخدام snapshots متطابقة فقط، مع إبقاء verdict وevidence hashes بوابة قبول.
