# Contributing to Resource Studio

شكرًا لاهتمامك بالمساهمة في Resource Studio. المشروع يتعامل مع ملفات PE حساسة، ولذلك تُقاس جودة المساهمة بسلامة الدليل وقابلية إعادة الإنتاج بقدر ما تُقاس بكمية الكود.

## قبل البدء

اقرأ [`README.md`](README.md)، ثم [`TODO.md`](TODO.md)، وراجع الهدف النشط في [`docs/FORENSIC-GOAL.md`](docs/FORENSIC-GOAL.md). ابحث عن مهمة ذات معرّف واضح أو أنشئ اقتراحًا يشرح أي هدف من أهداف المشروع يخدمه التغيير: منع تلف output، كشف اختلاف بين LIEF وWindows، إثبات round-trip أو invariant، تحسين العزل، أو جعل حالة CLI/WPF قابلة للتشخيص.

لا تبدأ بإضافة Feature جديدة إذا كان المطلوب يمكن تحقيقه بتقوية contract موجود. طبقة MCP المحلية منفذة ومختبرة ومربوطة بCI؛ أي توسعة جديدة لها تتبع نسخ العقد في [`docs/MCP-CONTRACT.md`](docs/MCP-CONTRACT.md) ولا تضيف أدوات خارج العقد. يرحب المشروع بإضافات Security-goal الدفاعية الساكنة فقط وفق [`docs/SECURITY-GOAL.md`](docs/SECURITY-GOAL.md)؛ لا تضف malware/IOC engine أو تشغيلًا أو unpacking أو decryption أو process injection داخل النواة. أي Defender/YARA integration يجب أن يكون موفرًا اختياريًا على staged copy مع evidence وlimitations واضحة.

## بيئة التطوير

يتطلب backend Python 3.12 و`lief==1.0.0`، ويُستحسن استخدام virtual environment:

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements-backend.txt
```

يتطلب WPF على Windows .NET SDK 8.0 أو أحدث. لا تُضاف ملفات SDK أو runtime أو `external executable` إلى المستودع.

## قواعد السلامة

يجب ألا يكتب أي اختبار أو أداة إلى `protected installation directory` أو إلى ملف الإدخال الذي يختبره. كل تعديل PE يستخدم Save As إلى مسار output جديد، ويجب أن يمر عبر reopen وstructural validation وresource graph validation وpreservation checks قبل commit.

لا تستخدم ملفات مستخدم حقيقية أو شهادات إنتاج في الاختبارات. استخدم fixtures داخل `tests/fixtures` أو ملفات مؤقتة، واحذف المخرجات المؤقتة في `finally`. يجب ألا تحتوي السجلات أو pull requests على كلمات مرور PFX أو مفاتيح خاصة أو مسارات شخصية غير لازمة.

## أسلوب التغيير

اجعل التغيير أصغر ما يحقق العقد. حافظ على فصل النواة عن CLI وعن WPF؛ لا تعِد تنفيذ Verification Engine داخل الواجهة. إذا احتاجت الواجهة إلى عرض نتيجة، استهلك `verification` أو evidence report الصادر من النواة بدل إعادة تفسير PE.

كل مهمة جديدة يجب أن تحمل معرّفًا في `TODO.md` وحالة ومعيار إنجاز. حدّث `CHANGELOG.md` وREADME فقط بما تم اختباره فعليًا. استخدم أسماء دوال وحقول مستقرة، واحتفظ بالتوافق مع JSON schemas القائمة ما لم توجد ضرورة موثقة لتغييرها.

## الاختبارات المطلوبة

قبل فتح pull request شغّل الاختبارات المتأثرة ثم البوابات الكاملة (نفس تغطية `ci.yml`):

```bash
python3 -m compileall -q core rs_mcp mcp tools tests resource_studio_cli.py resource_studio_gui.py
for test in tests/core/test_*.py tests/test_cli.py tests/qa/test_*.py \
            tests/test_mcp_*.py tests/golden/test_*.py; do
  PYTHONPATH=. python3 "$test" || exit 1
done
```

على Windows شغّل compileall والبوابة نفسها، وأضف بناء WPF (`dotnet build windows\\ResourceStudio.Windows\\ResourceStudio.Windows.csproj -c Release`) وأوراكل Windows الحقيقية (`test_windows_resource_oracle` و`test_win32_update_resource_oracle`) عندما يمس التغيير Windows أو WPF. إذا كان الاختبار Windows-only أو يحتاج توقيعًا أو loader oracle، اذكر البيئة والنتيجة صراحة بدل تحويل التخطي إلى نجاح مضلل.

كل parser أو writer change يحتاج اختبار malformed أو round-trip أو regression مناسب. كل Forensic change يحتاج baseline/result أو differential assertion، ويجب أن يثبت target وunintended changes وpreservation حيثما ينطبق. لا يكفي فحص `ExitCode == 0`.

## Pull requests

استخدم فرعًا قصير العمر باسم يصف الهدف، مثل `forensic/baseline-evidence` أو `docs/contributing`. اجعل كل pull request مركزًا على هدف واحد، واكتب وصفًا يجيب عن الأسئلة التالية:

| السؤال | ما يجب توضيحه |
|---|---|
| لماذا؟ | المشكلة أو فجوة contract التي يعالجها التغيير |
| ماذا؟ | الملفات والطبقات التي تغيرت |
| الدليل؟ | الاختبارات والأوامر والبيئة والنتيجة |
| السلامة؟ | كيف ثبت عدم لمس الأصل وعدم استبدال input وعدم تسريب secrets |
| الحدود؟ | ما لم يُختبر أو ما بقي Windows-only أو policy-dependent |

لا ترفع `bin/` أو `obj/` أو `__pycache__/` أو ملفات `.pyc` أو PDB أو outputs أو snapshots أو `external executable`. لا تعدّل التاريخ أو hash للأصل؛ يجب أن يبقى الهاش المرجعي `14A44FE31B04FBCC65E94E80016138A2E9FC9BB6DFCEA09B98DE57F8A22A1240`.

## التوثيق

استخدم GitHub-flavored Markdown. أضف العناوين والجداول عند الحاجة، وحافظ على العربية المهنية المستخدمة في وثائق المشروع مع إبقاء أسماء APIs والحقول والأوامر بالإنجليزية. لا تكتب ادعاءات أوسع من الاختبارات. حدّث `CHANGELOG.md` ضمن قسم `[Unreleased]`، وأضف المهمة أو نتيجتها إلى `TODO.md`.

## الترخيص

بإرسال مساهمة، تؤكد أن لك الحق في إرسالها وأنها لا تنسخ موادًا مملوكة لطرف آخر. يخضع كود هذا المستودع إلى Apache-2.0 كما هو موضح في [`LICENSE`](LICENSE)، مع الاحتفاظ بإشعارات LIEF والطرف الثالث في [`THIRD-PARTY-NOTICES.md`](THIRD-PARTY-NOTICES.md). لا ينبغي للمساهمة أن تفترض أن ترخيص Resource Studio يغطي اعتماديات أو موادًا خارجية.
