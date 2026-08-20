# Third-party notices

## LIEF

Resource Studio يستخدم LIEF كاعتمادية اختيارية للـ PE resource writer.

- المشروع: https://github.com/lief-project/LIEF
- الترخيص: Apache License 2.0
- نص الترخيص: https://github.com/lief-project/LIEF/blob/main/LICENSE
- الإصدار المثبت في بيئة الاختبار: `1.0.0`

عند توزيع نسخة تحتوي LIEF، يجب تضمين نص Apache License 2.0 وإشعارات حقوق النشر المطلوبة، وتسجيل أي تغييرات محلية على الاعتمادية. هذا الملف لا يغني عن مراجعة قانونية لتجميعة التوزيع النهائية أو تراخيص تبعيات LIEF الأخرى.

## Resource Hacker

Resource Hacker برنامج مملوك لصاحبه. لا يُضمّن Resource Studio `ResourceHacker.exe` أو ملفاته أو بيانات ترخيصه. أي adapter محلي له يجب أن يعتمد على تثبيت المستخدم ووفق شروط الترخيص، وتبقى النسخة الأصلية ونسخة العمل خارج هذه الحزمة.

## Pillow

يُستخدم Pillow اختياريًا لتحويل PNG المضمّن داخل ICON/CURSOR payload إلى BMP أو DIB.

- المشروع: https://python-pillow.org/
- الترخيص: HPND (Historical Permission Notice and Disclaimer)
- الترخيص: https://github.com/python-pillow/Pillow/blob/main/LICENSE
- الاستخدام: `Pillow>=10.0` في `requirements-backend.txt`

لا يُستخدم Pillow في مسار DIB/BMP الأساسي، لكن تثبيته مطلوب لدعم PNG بصورة كاملة.
