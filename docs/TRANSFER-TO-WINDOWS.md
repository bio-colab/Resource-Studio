# انتقال Resource Studio إلى Windows

## قاعدة الانتقال

تُنقل حزمة Resource Studio فقط. لا تُنسخ ملفات خارجية إلى الحزمة، ولا تُكتب المخرجات إلى مجلدات التثبيت المحمية.

تبقى النسخة الأصلية مرجعًا للقراءة والمقارنة فقط.

## فحوص Manus المنجزة قبل النقل

تم تشغيل:

```bash
cd /home/ubuntu/resource-studio
python3 -m py_compile core/*.py resource_studio_cli.py tests/core/*.py tests/test_cli.py tests/qa/*.py
for test in tests/core/test_*.py tests/test_cli.py tests/qa/test_*.py; do PYTHONPATH=. python3 "$test"; done
```

نجحت 33 اختبارات core و9 اختبارات QA واختبار CLI. كما بقي SHA-256 للأصل على Windows مساويًا للقيمة المحفوظة:

```text
14A44FE31B04FBCC65E94E80016138A2E9FC9BB6DFCEA09B98DE57F8A22A1240
```

## خطوات Windows اللاحقة

يُنسخ المجلد المستقل إلى مسار عمل مثل:

```text
C:\Users\<User>\Documents\ResourceStudio
```

ثم يُنشأ virtual environment ويُثبت `lief==1.0.0` من `requirements-backend.txt`. لا تُستخدم مجلدات التثبيت المحمية كـ workspace، ولا تُحفظ المخرجات فيها.

بعد ذلك تُنفذ فحوص البيئة التالية:

```powershell
python --version
python -m pip show lief
python resource_studio_cli.py inspect tests\fixtures\sample.dll --json
python -m unittest discover
```

إذا كان المشروع يستخدم أسلوب الاختبارات الحالي، يُعاد تشغيل بوابة الاختبارات عبر Python لكل ملف `tests\core\test_*.py` و`tests\qa\test_*.py` كما في تعليمات Manus.

## الأولويات الخاصة ببيئة Windows

تبدأ الدورة التالية بتنفيذ WinVerifyTrust/Authenticode verification، ثم Job Object للإضافات وحدود filesystem والشبكة، ثم shell UI. بعدها تُنشأ fixtures حقيقية لـ PE32 وPE32+ وEXE وDLL وSYS وملفات موقعة وMUI وARM64X عند توفرها.

لا يُطلب تسجيل الدخول أو تعديل ملفات النظام. إذا احتاجت إعادة التوقيع إلى شهادة أو مفتاح، يبقى ذلك خارج المشروع ويُطلب من المستخدم تحديد أداة Windows وسياسة المفاتيح قبل أي تنفيذ.

## ما لا يُنقل

لا تُنقل ملفات من مجلدات التثبيت، ولا تُضمّن الأسرار أو الشهادات أو مفاتيح التوقيع، ولا تُفعّل وظائف MCP أو النقل البعيد ضمن هذه الدورة.
