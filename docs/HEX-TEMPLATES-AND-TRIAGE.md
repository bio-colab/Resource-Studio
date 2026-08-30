# Hex Templates and Evidence Triage

أصبح Preview contract قادرًا على إرفاق خريطة هيكلية محدودة بالـraw hex. لا يعرض Hex Viewer bytes فقط؛ فعند توفر layout معروف يضيف `raw.template` من schema `resource_studio.hex_template.v1`، وفيه اسم القالب وقائمة الحقول و`offset` و`length` و`value` وhex bytes الخاص بكل حقل.

## القوالب الحالية

| Resource kind | Template | Fields |
|---|---|---|
| `BITMAP` وpayloadات `ICON/CURSOR` ذات DIB header | `BITMAPINFOHEADER` | `biSize`، `biWidth`، `biHeight`، `biPlanes`، `biBitCount`، compression وimage metrics |
| `VERSION` | `VS_VERSIONINFO` | `wLength`، `wValueLength`، `wType`، key، والقيمة النصية عند توفرها |
| `DIALOG` و`DIALOGEX` | `DIALOG_HEADER` | style وexStyle وitem count وgeometry، مع كشف extended signature |
| `MENU` و`MENUEX` | `MENU_HEADER` | `wVersion` و`cbHeader` |

التنفيذ في `core/hex_templates.py` **read-only ومحدود**. إذا كان payload قصيرًا أو layout غير معروف، يعود العقد بقائمة fields فارغة وتحذير صريح بدل التخمين. اختيار field في `PreviewFieldsGrid` يحدد byte range المطابق له في `PreviewHexBox`؛ وهذا تمييز بصري للقراءة ولا يفتح مسار كتابة جديدًا.

## Evidence triage coloring

أضيف schema `resource_studio.evidence_triage.v1` عبر `core/evidence_triage.py`، ويظهر في Security report تحت `resourceTriage`. القواعد لا تعيد حساب evidence ولا تغير verdict؛ إنها تلخص الإشارات الموجودة إلى `level` و`color` و`reasons` و`sources`.

| Signal | Triage level |
|---|---|
| `CORRUPT_OR_UNSUPPORTED` أو category `CORRUPTION/ACCESS` | `HIGH`، أحمر |
| finding severity `HIGH/MEDIUM` | `MEDIUM` أو `HIGH` بحسب confidence/category |
| `confidence == LOW` على observation أو finding | `HIGH` للمحافظة على visibility، لا كإثبات maliciousness |
| category/kind يتضمن `OBFUSCATION` أو `PACK` أو `ENTROPY` | `MEDIUM`، كهرماني |
| لا توجد إشارة | `NONE`، رمادي |

تعرض WPF banner للحالة العامة، وتلون Resource Grid rows عندما يملك التقرير resource reference مباشرًا أو observation منخفض الثقة مربوطًا بالمورد. الـtooltip يذكر السبب ويؤكد أن اللون **visual cue only**. لا يعني اللون الأحمر أن الملف malware، ولا يعني غياب اللون أن الملف موثوق.

## اختبار وبناء Windows

```bash
python3 tests/core/test_hex_templates_and_triage.py
python3 tests/core/test_preview_engine.py
python3 tests/core/test_security_analysis.py
```

عقد WPF النصي السابق (`tests/qa/test_hex_triage_wpf_contract.py`) أُزيل ضمن تنظيف الفحوص الزائدة لأنه كان يؤكد نصوص XAML/C# دون تنفيذ كود؛ غطاء السلوك المتبقي هو اختبارات core أعلاه وبوابة بناء WPF في CI (السياق في `CODE-REVIEW.md`).

على Windows:

```powershell
dotnet build windows\ResourceStudio.Windows\ResourceStudio.Windows.csproj --configuration Release --no-restore
```

يظل فتح الملف للقراءة فقط، وتبقى الكتابة محكومة بـSave As وVerification Engine. لا تستخدم القوالب أو الألوان أي binary mutation، ولا تعتمد على تشغيل العينة أو telemetry حي.
