# خادم MCP المحلي — المرحلة الأولى

## الحالة

الخادم المحلي يعمل عبر `stdio` باستخدام Python MCP SDK 2.0.0. يدعم الإصدار الحالي القراءة والفهرسة، إنشاء مساحة عمل معزولة، المقارنة، خطط التغيير الجاف، وتعديلًا محدودًا متساوي الحجم بعد تأكيد صريح. لا توجد أداة تنفيذ أوامر عامة.

## التشغيل

من جذر المشروع:

```bash
cd /home/ubuntu/resource-studio
RESOURCE_STUDIO_ROOT=/home/ubuntu/resource-studio python3 mcp/server.py
```

في تشغيل MCP المعتاد، يطلق العميل العملية ويقرأ JSON-RPC من stdout. لذلك لا تكتب الخادمات أي رسائل تشخيص إلى stdout؛ السجلات تذهب إلى stderr. يمكن تغيير جذر القراءة عبر `RESOURCE_STUDIO_ROOT`، لكن كل مسار خارج هذا الجذر مرفوض.

## الأدوات المتاحة

| الأداة | الوظيفة |
|---|---|
| `resource_studio.inspect_file` | قراءة هاش الملف، PE headers، المعمارية، الأقسام، وعدد الموارد |
| `resource_studio.index_resources` | فهرسة النوع والاسم واللغة والحجم وRVA وoffset وSHA-256 لكل مورد |
| `resource_studio.create_workspace` | إنشاء نسخة عمل داخل `.resource-studio/workspaces` مع هاش المصدر |
| `resource_studio.diff_files` | مقارنة ملفين أو نسخة العمل بالمصدر دون كتابة |
| `resource_studio.plan_resource_change` | إنشاء خطة add/replace/delete دون تنفيذ |
| `resource_studio.get_plan` | قراءة خطة محفوظة في جلسة الخادم |
| `resource_studio.apply_plan` | استبدال محدود متساوي الحجم داخل نسخة العمل بعد التأكيد |
| `resource_studio.read_audit` | قراءة سجل العملية بعد التحقق |

كما يعرض الخادم المورد الثابت `resource://workspace/info`، الذي يعلن جذر القراءة وحالة الخادم وحدود حجم الملف.

## نتائج الاختبار

اختبار التكامل `tests/test_mcp_stdio.py` شغّل الخادم كعملية فرعية عبر `stdio` ثم نفذ التهيئة، واكتشاف الأدوات، واكتشاف الموارد، وقراءة مورد workspace، وفحص ملف PE، وفهرسته. النتيجة الأخيرة:

```json
{
  "status": "passed",
  "tools": [
    "resource_studio.index_resources",
    "resource_studio.inspect_file"
  ],
  "resources": ["resource://workspace/info"],
  "resourceCount": 1
}
```

يشمل الاختبار رفض مسار `/etc/hosts` لأنه خارج الجذر، وقبول ملف نصي غير PE مع تحذير منظم، وإنشاء workspace، ومقارنة المصدر بالنسخة، وإنشاء خطة لا تكتب، ورفض التطبيق دون تأكيد، وتطبيق استبدال متساوي الحجم، وإعادة فتح الناتج والتحقق من الهاش، ومنع إعادة استخدام الخطة، وتسجيل audit. تم فحص صياغة Python وملف JSON قبل تشغيل اختبار التكامل.

## حدود المرحلة

المحلل الحالي يقرأ بنية PE ويدرج شجرة الموارد الأساسية، والتعديل الحالي محدود عمدًا باستبدال raw resource متساوي الحجم داخل نسخة العمل. لا يعرض بعد معاينات الصور، ولا يفك النصوص أو الحوارات إلى نموذج تحريري، ولا يدعم add/delete أو تغيير الحجم، ولا يتحقق من Authenticode. كما أن fixture الحالي ملف PE تجريبي محلي.

## الخطوة التالية

الخطوة التالية هي استبدال backend التجريبي المتساوي الحجم بمحول موارد حقيقي يدعم add/delete/modify وتغيير الحجم على نسخة العمل، مع الحفاظ على بوابة التأكيد وإعادة الفهرسة وسجل التدقيق. بعد ذلك تضاف المعاينات المتخصصة والتحقق من التوقيع.

## المرجع

يعتمد الخادم على [Python SDK الرسمي لـ MCP](https://modelcontextprotocol.io/docs/2026-07-28/sdk) وعلى [دليل بناء خادم MCP](https://modelcontextprotocol.io/docs/2026-07-28/develop/build-server).
