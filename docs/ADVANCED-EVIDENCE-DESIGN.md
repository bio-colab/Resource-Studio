# تصميم طبقات الأدلة المتقدمة

## الغرض

تضيف هذه الدفعة ثلاث طبقات فوق `resource_studio.evidence_summary.v1` دون تغيير عقده: رسم أدلة قابل للتتبع، محرك استعلام محدود وآمن، ودورة حالة تربط الدليل بالنتائج والتقرير.

## Evidence Graph

العقدة هي كيان قابل للإحالة، مثل observation أو finding أو artifact أو external scan. تحمل كل عقدة `id` و`kind` و`value` و`sourceRef` و`confidence` اختياريًا. الحواف موجهة ومحدودة إلى `corroborates` و`contradicts` و`derives-from` و`supports` و`references`.

لا يُستنتج من وجود edge وحده أن الملف ضار. العلاقة تصف provenance أو توافقًا أو تناقضًا بين الأدلة. وتُرفض self-edge والعلاقات المكررة غير المتطابقة، وتُحفظ العقد والحواف بترتيب ثابت حتى يكون hash قابلاً للمقارنة.

## Query / Filtering Engine

يستخدم المحرك grammar صغيرة لا تنفذ Python ولا تستدعي دوال أو ملفات. الصيغة المدعومة هي:

```text
resource.type == "ICON"
resource.size > 10000
finding.severity == "HIGH"
evidence.confidence >= 0.8
```

يُحوّل المحرك القيم إلى أنواع محدودة، ويدعم `==`, `!=`, `>`, `>=`, `<`, `<=`، و`contains`، مع `and` و`or` والأقواس. الكلمات التشغيلية غير حساسة لحالة الأحرف، لذلك تعمل الصيغتان `and` و`AND`، وكذلك `contains` و`CONTAINS`. مثال مركب:

```text
(resource.type == "ICON" OR resource.type == "CURSOR") AND resource.size > 10000
```

أسماء الحقول تقع ضمن namespace صريح: `resource`, `finding`, `observation`, `evidence`, `artifact`، و`externalScan`. عندما يحتوي `evidence_summary.v1` على نتائج مستوردة من `external_scan.v1`، تُحفظ في `externalScans` وتصبح حقولها قابلة للاستعلام مثل `externalScan.status` و`externalScan.provider` و`externalScan.targetSha256`. أي حقل أو عامل غير معروف يسبب خطأ واضحًا بدل نتيجة ناقصة.

## Case lifecycle

يستخدم case ملف JSON قابلًا لإعادة البناء:

```text
OPEN → TRIAGED → ANALYZED → REPORTED → CLOSED
```

تحتوي الحالة على artifact references وevidence graph وfindings وtimeline وreports وaudit metadata. كل انتقال يسجل event زمنيًا مع hash للحالة السابقة، ولا يسمح بالانتقال العكسي أو إغلاق حالة بلا artifact ودليل واحد على الأقل. لا يغيّر case الملف الأصلي ولا يشغّل أي external provider.

## Security boundaries

يبقى YARA وMicrosoft Defender مؤجلين. يمكن استيراد نتائجهما لاحقًا من خلال `external_scan.v1`، لكن هذه الطبقات لا تشغّل أدوات أو عينات. ولا يوجد في graph أو query engine أي unpacking أو decryption أو emulation أو process injection.

## مبررات الترتيب

يُنفذ graph وquery أولًا لأنهما يضيفان قيمة مباشرة إلى CLI والتقارير، ثم case lifecycle لأنه يحتاج graph IDs مستقرة. أما WPF Security Center فيُبنى بعد ثبات هذه العقود حتى يكون سطح عرض رقيقًا فوق النواة ولا يعيد تنفيذ Verification Engine.
