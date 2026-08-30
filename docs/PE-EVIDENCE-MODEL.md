# PE Evidence Model

## الغرض

يضيف Resource Studio طبقة تطبيع مستقلة فوق تقارير PE الموجودة، بحيث لا تُعرض نتيجة التحليل كقيمة Boolean منفردة فقط. كل ملاحظة تحمل معرّفًا ومصدرًا ومحللًا ودرجة ثقة، ويمكن ربطها بمورد أو قسم أو جزء من الملف وبمدى خام عندما يكون ذلك متاحًا.

> **المبدأ:** observation قابلة لإعادة الفحص، وfinding قابلة للتفسير، وcorroboration لا تُستنتج إلا عند اتفاق مصادر مستقلة.

## البنية

| المكوّن | الوظيفة | مصدر البيانات الحالي |
|---|---|---|
| `artifact` | SHA-256 والحجم والمسار المطلق | bytes وfilesystem |
| `observations` | حقائق PE والموارد والأقسام والتوقيع والتكامل | `PEInspector` و`ResourceGraph` و`PEIntegrity` |
| `rawRange` | offset وlength للمورد أو القسم عند توفرهما | resource index / raw parser |
| `corroboration` | نتيجة مقارنة canonical graph مع raw resource directory | `LIEF` مقابل parser مستقل |
| `statistics` | عدد الموارد والأنواع واللغات وأكبر مورد وعدد الأقسام والواردات والصادرات | التقارير الحالية |
| `findings` | رسائل قابلة للقراءة مع severity وconfidence وlimitations | invariants وintegrity وsignature وcorroboration |

الصيغة الحالية هي `resource_studio.evidence_summary.v1`. ولضمان المقارنة الحتمية، يوفر `evidence_summary_hash` hashًا يستبعد وقت الالتقاط ويعتمد على بقية المحتوى المطبّع.

## مصادر الثقة والحدود

لا تُحوّل الإحصاءات مثل entropy أو حجم المورد إلى حكم أمني. كما أن وجود certificate table لا يساوي ثقة Authenticode؛ لذلك يظهر كـfinding محدود يطلب التحقق عبر WinVerifyTrust على Windows. أما نتيجة `CORROBORATED` فتُستخدم فقط عندما تتطابق بصمات resource leaves بين `ResourceGraph` وparser الخام المستقل.

يظهر النموذج في أمر `inspect` عبر `evidence` و`evidenceHash`، ويُضمّن كذلك داخل `ForensicEvidence` الناتج بعد إعادة فتح candidate. لا يعيد هذا المسار تنفيذ Verification Engine ولا يغيّر قواعد الكتابة أو الحفظ.

## ما لم يُفعّل بعد

لم تُضف لغة استعلام مستقلة أو runtime/network providers أو timeline عام أو graph بصري جديد في هذه الدفعة. يمكن بناء هذه الطبقات لاحقًا فوق schema الحالي، بعد تثبيت عقود query وcase lifecycle واختبارات false-positive، دون خلط الملاحظات الساكنة بالتحليل السلوكي.
