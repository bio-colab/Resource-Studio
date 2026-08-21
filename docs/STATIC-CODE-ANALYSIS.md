# Static Code Analysis

أضيفت إلى Security Layer طبقة `resource_studio.static_code_analysis.v1` للتحليل الساكن المحدود. تستخدم هذه الطبقة Capstone لفك تعليمات تبدأ من PE entrypoint ضمن حد أقصى للبايتات والتعليمات، ثم تبني basic blocks وحواف CFG من فروع مباشرة قابلة للاستخراج. لا تُحمّل العينة كصورة قابلة للتشغيل، ولا تنشئ process، ولا تتصل بعملية حية.

> نتيجة disassembly أو CFG هي وصف ساكن لما أمكن فكّه من نقطة البداية، وليست إثباتًا أن كل الكود قابل للاكتشاف أو أن السلوك المتوقع سيحدث وقت التشغيل.

يحفظ التقرير لكل تعليمة `rva` و`fileOffset` و`size` وbytes وmnemonic وoperands. هذا الفصل ضروري لأن RVA هو عنوان نسبي بعد التحميل، بينما file offset موضع داخل الملف؛ لا يجوز استخدام أحدهما بدل الآخر.[1]

| الطبقة | ما تنفذه | الحد المقصود |
|---|---|---|
| **Disassembly** | x86/x64 وARM64 عندما يدعمها Capstone، بدءًا من entrypoint وبحدود قابلة للضبط | لا recursive code discovery شامل ولا decoding للـindirect targets |
| **CFG** | basic blocks وحواف branch/fallthrough للفروع المباشرة | الفروع غير المباشرة وopaque predicates وself-modifying code تبقى unresolved |
| **Unpacking indicators** | executable section expansion، entropy مرتفعة، executable+writable section، entrypoint غير تنفيذي، وoverlay | مؤشرات احتمالية لا تثبت packer أو unpacking runtime |
| **Runtime evidence** | استيراد JSON خارجي للـbehavioral telemetry وmemory analysis وAPI call trace مع target SHA-256 | Resource Studio لا ينفذ الملف ولا يقرأ live memory ولا يربط debugger |

تعمل أوامر التحليل الساكن عبر:

```bash
python3 resource_studio_cli.py security sample.dll --json
```

ويظهر في التقرير `staticCode` و`unpackingIndicators`. إذا كانت Capstone غير متاحة، يعيد التقرير `DECODER_UNAVAILABLE` بوضوح بدل إسقاط نتيجة وهمية؛ وفي التثبيت القياسي للمشروع أصبحت `capstone>=5.0,<6` ضمن `requirements-backend.txt`.

يمكن استيراد الأدلة الديناميكية الملتقطة خارجيًا، بشرط أن يكون كل ملف JSON معلنًا `targetSha256` مطابقًا للـPE:

```bash
python3 resource_studio_cli.py security sample.dll \
  --behavioral-telemetry process-trace.json \
  --memory-evidence memory-report.json \
  --api-trace api-trace.json --json
```

صيغة كل artifact خارجية هي JSON تحتوي `targetSha256` و`events`، ويمكنها تحديد `provider` و`capturedAtUtc` و`limitations`. يخزن التقرير `sourceSha256` و`evidenceSha256` و`executedByResourceStudio: false`. هذا يجعل telemetry وmemory وAPI tracing **أدلة مستوردة** وليست وظائف تشغيلية داخل النواة.

تُستخدم ETW على Windows كأحد المصادر الممكنة لإنشاء trace خارجي؛ فهي توفر أحداثًا منظمة مثل إنشاء وانتهاء العمليات وتخصيص الذاكرة، لكن جمعها ومعالجتها يبقى مسارًا مستقلًا عن static Security Layer.[2] كما أن Capstone نفسه إطار disassembly متعدد المعماريات مع Python bindings وSKIPDATA mode للحالات التي تختلط فيها البيانات بالتعليمات.[3]

## حدود السلامة

لا يضيف هذا المسار unpacker أو decryptor أو emulator أو memory dumper أو API hook. لا يحاول المشروع استخراج payload أو فك تشفيره أو تشغيله. عند الحاجة إلى dynamic analysis، يجب تشغيل العينة في مختبر منفصل مع snapshot وnetwork containment وسياسة حفظ أدلة، ثم استيراد التقرير الناتج فقط.

## المراجع

[1]: https://learn.microsoft.com/en-us/windows/win32/debug/pe-format "Microsoft PE Format"
[2]: https://learn.microsoft.com/en-us/windows/apps/trace-processing/overview "Process ETW traces in .NET"
[3]: https://www.capstone-engine.org/documentation.html "Capstone documentation"
