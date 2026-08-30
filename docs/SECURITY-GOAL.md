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
| **الهندسة العكسية الساكنة** | imports/exports/TLS/debug/CLR/resources/strings/hex، bounded disassembly، basic CFG، semantic diff وraw corroboration | observations قابلة للإحالة إلى RVA وfile offset أو resource key |
| **الضغط والتمويه والتشفير** | مؤشرات entropy/opaque bytes/section layout/encoded strings/embedded archives أو payloads، مع executable section expansion وentrypoint anomalies | `OBFUSCATION_INDICATOR` أو `UNPACKING_INDICATOR` مع limitation؛ لا runtime unpack أو decrypt تلقائي |
| **التوقيع والثقة** | WinVerifyTrust على Windows، certificate state، Authenticode hash، وسجل قبل/بعد | فصل `SIGNATURE_PRESENT` و`SIGNATURE_VALID` و`TRUST_CHAIN_VALID` |
| **الفحص المضاد للبرمجيات الخبيثة** | موفر اختياري لـMicrosoft Defender وموفر اختياري لـYARA على نسخة staged | `EXTERNAL_SCAN_RESULT` يحفظ tool/version/ruleset/hash/exit code |
| **الملفات المقفولة** | اختبار وصول للقراءة، حالة Windows sharing إن أمكن، وسبب الفشل | `READABLE`، `SHARING_VIOLATION`، `ACCESS_DENIED`، `UNKNOWN` |
| **الملفات المعطوبة** | parse outcome، deep invariant issues، malformed corpus، وعدم الكتابة عند الغموض | `CORRUPT_OR_UNSUPPORTED` مع قائمة issues |
| **الملفات المشفرة** | رصد opaque/encrypted-looking regions وامتدادات/حاويات معروفة دون فكها | `ENCRYPTED_OR_OPAQUE_INDICATOR`، لا `MALWARE` تلقائيًا |

## نموذج التهديد

يشمل Security-goal ملفًا قد يكون معدّلًا أو ملوثًا أو ناقصًا أو محميًا أو غير مدعوم. المقصود بالحقن هنا نوعان منفصلان. الأول **حقن داخل الملف**، مثل إضافة section أو overlay أو resource أو تغيير entrypoint أو import directory بصورة غير متوقعة. الثاني **Process Injection**، وهو تنفيذ كود داخل مساحة عنوان عملية أخرى؛ هذا دليل runtime ولا يمكن إثباته من PE ساكن على القرص وحده.[4]

كما يشمل النموذج ملفات تستخدم الضغط أو التشفير أو encoding أو تقسيم payload لجعل التحليل أصعب. يصف MITRE ذلك ضمن T1027، لكنه لا يجعل كل ملف packed أو encrypted ملفًا خبيثًا.[3] لذلك لا يستخدم المشروع entropy أو وجود section executable وحده لإطلاق حكم أمني.

لا يشمل النطاق تنفيذ الملف، تحميله كصورة قابلة للتشغيل، إنشاء process، emulation، runtime unpacking، memory dumping، DLL injection، أو الاتصال بخدمة سمعة خارجية دون موافقة صريحة. يدعم المسار الحالي disassembly وCFG ساكنين bounded من entrypoint، ويستورد behavioral telemetry وmemory analysis وAPI traces كـartifacts خارجية مطابقة للـSHA-256 فقط. يستطيع Windows loader oracle الحالي تحميل الموارد بصيغة data/image resource دون تشغيل الكود، ويظل هذا هو الحد الأقصى المسموح به في المسار الساكن.

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

يجب أن يكون كل فحص read-only افتراضيًا. عند طلب Defender أو YARA مستقبلًا، ينسخ التطبيق الملف إلى staging مع hash معلوم، ويعرض نتيجة الأداة الخارجية كدليل مستقل. حاليًا يتيح `security --stage-root` إنشاء النسخة المعزولة، بينما يظل تشغيل أي موفر خارجي خارج المشروع ومؤجلًا.
 توثق Microsoft أن `MpCmdRun.exe` أداة سطر أوامر للفحص والأتمتة، وقد تحتاج إلى نافذة مرتفعة الصلاحيات وقد توجد في مسارات مختلفة على Windows؛ لذلك لا يجوز افتراض وجودها أو اعتبار فشلها نتيجة نظيفة.[5] أما YARA فهو محرك مطابقة وتصنيف يعتمد على rules، ونتيجته مرتبطة بقاعدة القواعد المستخدمة وليست حكمًا عالميًا.[6]

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
| [~] | `SEC-05` | Static injection/tamper indicators | sections/overlay/entrypoint/import/resource anomalies مع references وfalse-positive limits؛ جزء من static indicators وunpacking indicators، مع توسيع corpus لاحقًا |
| [~] | `SEC-06` | Obfuscation/encryption indicators | entropy وopaque/layout indicators وbounded static-code report؛ لا فك أو تشغيل payload |
| [~] | `SEC-07` | External scanner providers | عقد `resource_studio.external_scan.v1` وCLI `--external-result` منجزان لاستيراد نتيجة مسبقة مع SHA/provider/status/ruleset/exit code؛ تشغيل Defender/YARA الفعلي وtimeouts وstaged-copy runner لاحقة |
| [~] | `SEC-08` | Security evidence ledger | أمر `security --ledger` يضيف التقرير إلى EvidenceLedger ويعيد entry/evidence hashes؛ signed ledger وcase lifecycle لاحقان |
| [~] | `SEC-09` | Safe reverse-engineering workspace | `security --stage-root` ينشئ نسخة staged ذات hash ثابت وقراءة فقط دون استبدال الموجود؛ read-only project mode وartifact policy الأوسع لاحقان |
| [ ] | `SEC-10` | Windows/WPF Security Center | عرض findings والحدود ومصدر الدليل وطلب المستخدم قبل أي external scan؛ لا تغيير في WPF بهذه الدفعة |
| [~] | `SEC-11` | Runtime telemetry adapter | استيراد behavioral telemetry وmemory analysis وAPI call trace كـruntime evidence خارجي مع target SHA-256؛ لا dynamic engine داخل النواة |

## ما سيُنفذ أولًا

أصبحت الدفعة الأساسية تشمل `SEC-02` وامتدادات `SEC-05` و`SEC-06` و`SEC-11`: تقرير ساكن قابل للآلة، access/parse state، PE invariants، مؤشرات التلاعب والتمويه، bounded disassembly وCFG، واستيراد runtime evidence خارجي مطابق للـSHA-256. يبقى جمع telemetry الحي، memory dumping، runtime unpacking، Defender/YARA runner، وواجهة WPF الكاملة مراحل منفصلة؛ ويجب أن يمنع provider contract الخلط بين `NOT_SCANNED` و`NOT_DETECTED`.

## نتائج البحث الدفاعي: الأنماط المشتركة

لا توجد «أداة واحدة» أو بصمة واحدة تجمع كل ransomware وRAT والحمولات المشفرة والحقن. النمط المشترك هو **تراكم قدرات** قد تكون شرعية أو ضارة بحسب السياق: مناطق opaque أو مضغوطة، استخدام APIs للتشفير أو تغيير حماية الذاكرة، imports مرتبطة بالوصول البعيد أو الذاكرة بين العمليات، مؤشرات persistence أو service، strings لعناوين أو بروتوكولات، وتغييرات في sections أو overlay أو resources.

| فئة القدرة | أمثلة على ما يمكن ملاحظته ساكنًا | ما لا يثبته ذلك |
|---|---|---|
| **Payload encryption/obfuscation** | entropy مرتفعة، strings encoded، blobs غير معروفة، crypto APIs، key/config-like regions | لا يثبت أن payload خبيث أو أنه سيُفك أثناء التشغيل |
| **Ransomware impact** | crypto capability، file-marker/ransom-note strings، امتدادات مستهدفة، مؤشرات الوصول إلى drives أو backups | لا يثبت تشفير ملفات الضحية أو أثرًا على نظام حي؛ ذلك يحتاج telemetry |
| **RAT/remote access** | remote-access strings، service/persistence clues، network endpoints، TLS/crypto capability، signed publisher context | لا يثبت أن الأداة استُخدمت للوصول غير المصرح به؛ أدوات الإدارة المشروعة قد تشترك في المؤشرات |
| **Process injection** | remote-memory/thread imports، executable+writable section، entrypoint أو staging غير معتاد | لا يثبت Process Injection؛ MITRE يعرّفه كسلوك داخل process حي |
| **Encrypted C2** | TLS/crypto imports، protocol/endpoint strings، key-like material، opaque configuration | لا يثبت إنشاء قناة C2 أو اتصالًا فعليًا |
| **Tamper/implantation** | overlay، section geometry، entrypoint، resource directory، signature/hash mismatch، raw/canonical discrepancy | لا يثبت مصدر التعديل أو هوية من أجراه |

تؤكد MITRE أن `T1486` يتعلق بتشفير بيانات النظام لإيقاف إتاحتها، وهو مختلف عن `T1027` الذي يصف التمويه لتصعيب التحليل.[8] كما تذكر MITRE أن أدوات الوصول البعيد قد تكون مشروعة ثم تُساء الاستفادة منها، وأن القنوات المشفرة قد تستخدم مفاتيحًا موجودة أو مولدة داخل العينة.[9] لذلك يجب أن يقدم Security-goal **capability indicators** لا أسماء اتهامية مثل `RAT` أو `RANSOMWARE` إلا عندما تأتي من external provider أو runtime evidence مستقل.

### طبقات الأدوات التي يمكن توظيفها بأمان

| الطبقة | الاستخدام الآمن داخل المشروع | القرار |
|---|---|---|
| **PE parser/invariant engine** | structural parse، bounds، sections، directories، resources، hashes | جزء من النواة ومطلوب لكل تقرير |
| **YARA provider** | مطابقة rules على staged copy مع rule-set hash/version وmatch evidence | اختياري، read-only، خارج writer |
| **Microsoft Defender provider** | on-demand scan لنسخة staged مع tool path/version/exit code | اختياري، Windows-only، لا يفترض وجوده |
| **Sysmon/EDR/runtime provider** | استيراد telemetry موجودة مسبقًا عن process/network/file activity | خارج النواة؛ لا تشغيل أو injection من Resource Studio |
| **Sandbox/dynamic analysis** | لا تُنفذ داخل Resource Studio؛ يقتصر التكامل على استيراد تقرير خارجي موثق | مؤجل، external-only |
| **Disassembler/CFG** | bounded Capstone disassembly وCFG ساكن من entrypoint مع RVA/file offsets وحدود صريحة | مطبق في `core/static_code_analysis.py`؛ لا recursive discovery شامل |
| **Unpacker/decryptor** | مؤشرات unpacking ساكنة فقط؛ runtime unpacking أو decryptor خارج النواة | لا يُنفذ داخل Resource Studio |
| **Telemetry/memory/API evidence** | استيراد JSON خارجي موثق ومطابق للـSHA-256 | مطبق كـexternal evidence؛ لا live collection داخل النواة |

### القرار الهندسي

أُنجزت static multi-signal indicators وtyped limitations، ثم أضيف `core/static_code_analysis.py` لـbounded disassembly وCFG ومؤشرات unpacking الساكنة، وأضيف `runtime_evidence.v1` لاستيراد telemetry وmemory/API artifacts المطابقة للـSHA-256. يبقى جمع telemetry الحي وruntime unpacking وmemory dumping خارج النواة، ويأتي عرض هذه النتائج في Security Center لاحقًا.
 لن يضيف المشروع أدوات هجومية أو kits أو samples أو تعليمات تشغيلية لصناعة ransomware/RAT أو حقن process.

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

[8]: https://attack.mitre.org/techniques/T1486/ "MITRE ATT&CK T1486: Data Encrypted for Impact"

[9]: https://attack.mitre.org/techniques/T1219/ "MITRE ATT&CK T1219: Remote Access Tools"

[10]: https://attack.mitre.org/techniques/T1573/ "MITRE ATT&CK T1573: Encrypted Channel"

[11]: https://www.cisa.gov/stopransomware/ransomware-guide "CISA StopRansomware Guide"

[12]: https://www.cisa.gov/resources-tools/resources/guide-securing-remote-access-software "CISA Guide to Securing Remote Access Software"
