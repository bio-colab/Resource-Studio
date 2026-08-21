# Resource Studio MCP — Local stdio

## الحالة

خادم MCP المحلي في **Phase 1** يعمل عبر `stdio` باستخدام Python MCP SDK `2.0.0`. يوفّر تسجيل الملفات إلى `fileId` محدود الجلسة، القراءة والفهرسة، موارد MCP ثابتة وديناميكية، Prompts للمراجعة والفرز، مساحة عمل معزولة، خطط تغيير جافة، تطبيقًا مؤكدًا عبر `LiefPEWriter`، إعادة فتح وتحقيق، وتصديرًا إلى ملف جديد تحت الجذر المحلي. لا يوجد transport بعيد أو أداة أوامر عامة.

## التشغيل

من جذر المشروع:

```bash
RESOURCE_STUDIO_ROOT=/home/ubuntu/resource-studio python3 mcp/server.py
```

في التشغيل المعتاد يطلق العميل العملية ويقرأ JSON-RPC من stdout. لذلك يكتب الخادم السجلات إلى stderr فقط. يحدد `RESOURCE_STUDIO_ROOT` الجذر المسموح؛ كل مسار خارجه مرفوض، والأصل لا يُكتب إليه.

## تدفق الاستخدام

يبدأ العميل باستدعاء `resource_studio.register_file` للحصول على `fileId` وSHA-256. تستخدم الأدوات التالية ذلك المعرّف في الاستدعاءات اللاحقة:

| الفئة | الأدوات |
|---|---|
| التسجيل | `resource_studio.register_file` |
| القراءة | `resource_studio.inspect_file`، `resource_studio.index_resources`، `resource_studio.diff_files`، `resource_studio.read_audit` |
| التخطيط | `resource_studio.create_workspace`، `resource_studio.plan_resource_change`، `resource_studio.get_plan` |
| التعديل والتصدير | `resource_studio.apply_plan`، `resource_studio.export_workspace`، `resource_studio.cancel_plan` |

تتطلب كل عملية تعديل خطة و`confirmationToken` صالحًا وتأكيدًا صريحًا. صلاحية رمز التأكيد عشر دقائق. يمر الاستبدال عبر `LiefPEWriter` ومسار التحقق المشترك، ولا يكتب فوق المصدر. الناتج المرحلي يبقى داخل مساحة العمل، ثم يحتاج التصدير إلى تأكيد مستقل ومسار Save As جديد تحت الجذر.

## Resources وPrompts

يعرض الخادم المورد الثابت `resource://workspace/info`. كما يعلن القوالب التالية:

| URI | المحتوى |
|---|---|
| `resource://workspace/{workspace_id}` | بيانات مساحة العمل المعزولة |
| `resource://file/{file_id}/manifest` | PE health وresource manifest وwarnings |
| `resource://file/{file_id}/resource/{resource_key}` | مورد محدد مع payload base64 محدود الحجم عند الإمكان؛ `resource_key` هو `type/name/language` بعد URI encoding |
| `resource://plan/{plan_id}` | الخطة الحالية وحالة التأكيد |
| `resource://operation/{operation_id}/audit` | سجل العملية والتحقق |

الـPrompts المنفذة هما `review_change` و`pe_triage`. لا يمنح أي Prompt صلاحية كتابة.

## حدود Phase 1

التعديل المنفذ حاليًا هو **replace** لمورد موجود عبر writer المشترك. أُبقي add/delete وتغيير اللغة وأدوات المعاينة المتخصصة خارج هذه الدفعة حتى تُعرّف عقودها فوق نفس writer والـVerification Engine، بدل إعادة إدخال raw patcher موازٍ. حالة الخادم ومسجل `fileId` داخل الذاكرة ومحدودان بجلسة stdio؛ لا توجد بعد قاعدة حالة دائمة أو Streamable HTTP أو مصادقة بعيدة.

## الاختبارات

يشغّل `tests/test_mcp_stdio.py` الخادم كعملية فرعية عبر stdio ويثبت التهيئة، اكتشاف الأدوات، Resources وResource Templates وPrompts، تسجيل fileId، قراءة manifest وresource URI، فحص وفهرسة PE، إنشاء workspace، diff، plan، رفض التطبيق دون تأكيد، apply عبر writer، منع إعادة استخدام الخطة، export بتأكيد مستقل، cancel_plan، وقراءة audit. كما يثبت رفض المسارات خارج الجذر وعدم تغيير fixture المصدر.

يُثبت CI اعتماد `mcp==2.0.0`، ويدخل `mcp` في compileall، ويشغل اختبار stdio على Python وWindows.

## المراجع

يعتمد الخادم على [Python SDK الرسمي لـ MCP](https://modelcontextprotocol.io/docs/2026-07-28/sdk) وعلى [دليل بناء خادم MCP](https://modelcontextprotocol.io/docs/2026-07-28/develop/build-server).
