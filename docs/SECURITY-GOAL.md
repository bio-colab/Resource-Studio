# Security-goal: PE Security and Safe Reverse-Engineering

## الملخص التنفيذي

يضيف **Security-goal** طبقة أمنية دفاعية فوق Verification Engine وForensic Evidence الموجودين في Resource Studio. هدفها ليس تحويل البرنامج إلى مضاد فيروسات أو منصة تفجير عينات، بل جعل كل ملف PE قابلًا للفحص الساكن، والتصنيف، والحفظ، والمقارنة، مع إظهار حدود الدليل بوضوح.

القاعدة المركزية هي:

> **المؤشر ليس إثباتًا، وغياب المؤشر ليس شهادة أمان.**

تفرض بنية PE التعامل مع headers وsections وdata directories وRVA وfile offsets بعقود تحقق صريحة؛ لذلك يبني Security-goal على structural validation وhashes وAuthenticode وResource Graph بدل الحكم من heuristic واحدة.[1] أما NIST فيربط التعامل مع البرمجيات الخبيثة بالوقاية والاستجابة وسلامة المعلومات وحفظ الأدلة، لا بمجرد إظهار لون أحمر في الواجهة.[2]

## النطاق الدفاعي

| المحور | ما سيقدمه Resource Studio | الحالة التي يجب عرضها |
|---|---|---|
| **سلامة PE** | فحص headers وsections وdirectories وbounds وoverlaps وchecksum وResource Graph | `VALID`، `INVALID`، أو `UNKNOWN` مع السبب |
| **العبث والحقن داخل الملف** | مقارنة hashes وsections وoverlay وresources وsignature، ورصد section غير معتادة أو payload خارج البنية المتوقعة | `INDICATOR` وليس verdict malware |
| **الهندسة العكسية الساكنة** | imports/exports/TLS/debug/CLR/resources/strings/hex وsemantic diff وraw corroboration | observations قابلة للإحالة إلى offset أو resource key |
| **الضغط والتمويه والتشفير** | مؤشرات entropy/opaque bytes/section layout/encoded strings/embedded archives أو payloads | `OBFUSCATION_INDICATOR` مع limitation؛ لا unpack أو decrypt تلقائي |
| **التوقيع والثقة** | WinVerifyTrust على Windows، certificate state، Authenticode hash، وسجل قبل/بعد | فصل `SIGNATURE_PRESENT` و`SIGNATURE_VALID` و`TRUST_CHAIN_VALID` |
| **الفحص المضاد للبرمجيات الخبيثة** | موفر اختياري لـMicrosoft Defender وموفر اختياري لـYARA على نسخة staged | `EXTERNAL_SCAN_RESULT` يحفظ tool/version/ruleset/hash/exit code |
| **الملفات المقفولة** | اختبار وصول للقراءة، حالة Windows sharing إن أمكن، وسبب الفشل | `READABLE`، `SHARING_VIOLATION`، `ACCESS_DENIED`، `UNKNOWN` |
| **الملفات المعطوبة** | parse outcome، deep invariant issues، malformed corpus، وعدم الكتابة عند الغموض | `CORRUPT_OR_UNSUPPORTED` مع قائمة issues |
| **الملفات المشفرة** | رصد opaque/encrypted-looking regions وامتدادات/حاويات معروفة دون فكها | `ENCRYPTED_OR_OPAQUE_INDICATOR`، لا `MALWARE` تلقائيًا |

## نموذج التهديد

يشمل Security-goal ملفًا قد يكون معدّلًا أو ملوثًا أو ناقصًا أو محميًا أو غير مدعوم. المقصود بالحقن هنا نوعان منفصلان. الأول **حقن داخل الملف**، مثل إضافة section أو overlay أو resource أو تغيير entrypoint أو import directory بصورة غير متوقعة. الثاني **Process Injection**، وهو تنفيذ كود داخل مساحة عنوان عملية أخرى؛ هذا دليل runtime ولا يمكن إثباته من PE ساكن على القرص وحده.[4]

كما يشمل النموذج ملفات تستخدم الضغط أو التشفير أو encoding أو تقسيم payload لجعل التحليل أصعب. يصف MITRE ذلك ضمن T1027، لكنه لا يجعل كل ملف packed أو encrypted ملفًا خبيثًا.[3] لذلك لا يستخدم المشروع entropy أو وجود section executable وحده لإطلاق حكم أمني.

لا يشمل النطاق تنفيذ الملف، تحميله كصورة قابلة للتشغيل، إنشاء process، emulation، unpacking تلقائي، memory dumping، DLL injection، أو الاتصال بخدمة سمعة خارجية دون موافقة صريحة. يستطيع Windows loader oracle الحالي تحميل الموارد بصيغة data/image resource دون تشغيل الكود، ويظل هذا هو الحد الأقصى المسموح به في المسار الساكن.

## دورة الفحص الآمنة

```text
ACQUIRE PATH
    ↓
READ-ONLY ACCESS PROBE
    ↓
SHA-256 + SIZE + FILE METADATA
    ↓
PE PARSE / MALFORMED CLASSIFICATION
    ↓
DEEP STRUCTURAL INVARIANTS
    ↓
RESOURCE GRAPH + RAW CORROBORATION
    ↓
SIGNATURE / CHECKSUM / OVERLAY
    ↓
STATIC INDICATORS
    ↓
OPTIONAL EXTERNAL SCANNERS ON STAGED COPY
    ↓
EVIDENCE SUMMARY + FINDINGS + LIMITATIONS
    ↓
AUDIT LEDGER
```

يجب أن يكون كل فحص read-only افتراضيًا. عند طلب Defender أو YARA، ينسخ التطبيق الملف إلى staging مع hash معلوم، ويعرض نتيجة الأداة الخارجية كدليل مستقل. توثق Microsoft أن `MpCmdRun.exe` أداة سطر أوامر للفحص والأتمتة، وقد تحتاج إلى نافذة مرتفعة الصلاحيات وقد توجد في مسارات مختلفة على Windows؛ لذلك لا يجوز افتراض وجودها أو اعتبار فشلها نتيجة نظيفة.[5] أما YARA فهو محرك مطابقة وتصنيف يعتمد على rules، ونتيجته مرتبطة بقاعدة القواعد المستخدمة وليست حكمًا عالميًا.[6]

## عقد الحالة والنتيجة

كل نتيجة أمنية يجب أن تحتوي على `schema` و`targetSha256` و`toolVersion` و`capturedAt` و`observations` و`findings` و`externalScans` و`limitations`. ويجب أن يميز التقرير بين الحالات التالية:

| الحالة | المعنى |
|---|---|
| `DETECTED` | تحقق شرط محدد في طبقة معلومة، مثل directory خارج الحدود أو signature invalid |
| `NOT_DETECTED` | لم يظهر المؤشر الذي يبحث عنه الفاحص المحدد فقط |
| `UNKNOWN` | تعذر الفحص أو لا تكفي الأدلة |
| `NOT_SCANNED` | لم يُشغّل الموفر أو رفضه المستخدم أو غير متاح |
| `RUNTIME_NOT_ASSESSED` | لا يوجد telemetry عن سلوك وقت التشغيل |
| `EXTERNAL_RESULT` | نتيجة Defender/YARA/موفر آخر مع هوية الإصدار والقواعد |

لا يجوز تحويل `NOT_DETECTED` إلى `SAFE`، ولا تحويل `HIGH_ENTROPY` إلى `MALWARE`. عند وجود finding، يجب حفظ `severity` و`confidence` و`category` و`evidenceRefs` و`limitations`.

## خارطة التنفيذ

| الحالة | المعرّف | المهمة | معيار الإنجاز |
|---|---|---|---|
| [x] | `SEC-01` | تعريف Security-goal وحدود الأمان | هذه الوثيقة، مع منع التشغيل التلقائي وفصل المؤشر عن verdict |
| [x] | `SEC-02` | Static Security Report | `core/security_analysis.py` وأمرا CLI `security` و`report security` يعيدان PEHealth وPEInspector وdeep invariants وEvidence Summary وsignature/integrity وResource Graph/raw corroboration ومؤشرات ساكنة. |
| [~] | `SEC-03` | Read-only access and lock probe | read/access classification وWindows sharing probe مضافة؛ remediation UI وmatrix أوسع للقفل لاحقان |
| [ ] | `SEC-04` | Safe malformed/corrupt classification | parse ladder، bounded reads، corpus للتلف والامتدادات غير المدعومة، ورفض الكتابة عند ambiguity |
| [ ] | `SEC-05` | Static injection/tamper indicators | sections/overlay/entrypoint/import/resource anomalies مع references وfalse-positive limits |
| [ ] | `SEC-06` | Obfuscation/encryption indicators | مؤشرات typed لا verdict، مع عدم فك أو تشغيل payload |
| [ ] | `SEC-07` | External scanner providers | Defender وYARA كموفرين اختياريين على staged copies، مع provider contracts وtimeouts وexit codes |
| [ ] | `SEC-08` | Security evidence ledger | ربط نتيجة الفحص بـEvidenceLedger، hash-chain، provider metadata، وreproducible JSON |
| [ ] | `SEC-09` | Safe reverse-engineering workspace | read-only project mode، extracted artifacts directory، deny-by-default execution، وحماية الملفات الأصلية |
| [ ] | `SEC-10` | Windows/WPF Security Center | عرض findings والحدود ومصدر الدليل وطلب المستخدم قبل أي external scan |
| [ ] | `SEC-11` | Runtime telemetry adapter | adapter اختياري لنتائج خارجية فقط؛ لا dynamic engine داخل النواة |

## ما سيُنفذ أولًا

الدفعة الأولى الآمنة هي `SEC-02` مع جزء صغير من `SEC-03`: أُنشئ تقرير ساكن قابل للآلة، ويظهر access/parse state، ويعاد استخدام Evidence Summary وdeep invariants وsignature الحالية. بعد تثبيت contract والاختبارات، تأتي مؤشرات التلاعب والتمويه. أما Defender وYARA فيأتيان بعد provider contract يمنع الخلط بين `NOT_SCANNED` و`NOT_DETECTED`.

## ضوابط عدم إساءة الاستخدام

يُمنع في النواة إضافة وظائف تستخرج payloadات أو تفك تشفيرها أو تشغلها أو تحقنها في عمليات. ويُمنع الادعاء بأن Resource Studio يثبت أن الملف «مصاب بفيروس» من PE وحده. عند وجود اشتباه، يجب أن يوصي التقرير بعزل الملف، الاحتفاظ بـSHA-256، فحصه بأداة حماية مستقلة، وعدم فتحه أو تشغيله على جهاز الإنتاج. لا يرفع المشروع عينات المستخدم إلى خدمات خارجية تلقائيًا.

## المراجع

[1]: https://learn.microsoft.com/en-us/windows/win32/debug/pe-format "Microsoft PE Format"

[2]: https://csrc.nist.gov/pubs/sp/800/83/r1/final "NIST SP 800-83 Rev. 1: Guide to Malware Incident Prevention and Handling"

[3]: https://attack.mitre.org/techniques/T1027/ "MITRE ATT&CK T1027: Obfuscated Files or Information"

[4]: https://attack.mitre.org/techniques/T1055/ "MITRE ATT&CK T1055: Process Injection"

[5]: https://learn.microsoft.com/en-us/defender-endpoint/command-line-arguments-microsoft-defender-antivirus "Microsoft Defender MpCmdRun command-line tool"

[6]: https://virustotal.github.io/yara/ "YARA official overview"

[7]: https://learn.microsoft.com/en-us/windows/win32/api/wintrust/nf-wintrust-winverifytrust "Microsoft WinVerifyTrust"
