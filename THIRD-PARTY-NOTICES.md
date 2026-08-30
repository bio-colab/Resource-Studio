# Third-party notices

## LIEF

Resource Studio يستخدم LIEF كاعتمادية اختيارية للـ PE resource writer.

- المشروع: https://github.com/lief-project/LIEF
- الترخيص: Apache License 2.0
- نص الترخيص: https://github.com/lief-project/LIEF/blob/main/LICENSE
- الإصدار المثبت في بيئة الاختبار: `1.0.0`

عند توزيع نسخة تحتوي LIEF، يجب تضمين نص Apache License 2.0 وإشعارات حقوق النشر المطلوبة، وتسجيل أي تغييرات محلية على الاعتمادية. هذا الملف لا يغني عن مراجعة قانونية لتجميعة التوزيع النهائية أو تراخيص تبعيات LIEF الأخرى.


## Pillow

يُستخدم Pillow اختياريًا لتحويل PNG المضمّن داخل ICON/CURSOR payload إلى BMP أو DIB.

- المشروع: https://python-pillow.org/
- الترخيص: HPND (Historical Permission Notice and Disclaimer)
- الترخيص: https://github.com/python-pillow/Pillow/blob/main/LICENSE
- الاستخدام: `Pillow>=10.0` في `requirements-backend.txt`

لا يُستخدم Pillow في مسار DIB/BMP الأساسي، لكن تثبيته مطلوب لدعم PNG بصورة كاملة.

## Capstone

يُستخدم Capstone اختياريًا داخل `core/static_code_analysis.py` لفك تعليمات bounded disassembly وبناء CFG ساكن من نقطة الدخول. لا يشغّل Capstone الملف ولا يتصل بعملية حية.

- المشروع: https://github.com/capstone-engine/capstone
- التوثيق: https://www.capstone-engine.org/documentation.html
- الترخيص: BSD 3-Clause License
- الاستخدام: `capstone>=5.0,<6` في `requirements-backend.txt`

عند توزيع نسخة تحتوي Capstone، يجب تضمين نص BSD 3-Clause والإشعارات المطلوبة ضمن حزمة التوزيع.
