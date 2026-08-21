# Resource Studio MCP

## الحالة الحالية

يوفّر Resource Studio خادم MCP محليًا عبر **stdio**، كما يوفّر طبقة **Streamable HTTP** اختيارية. الخادم ليس واجهة أوامر عامة؛ فهو يقرأ الملفات الواقعة تحت `RESOURCE_STUDIO_ROOT`، ويعزل التعديلات داخل workspace، ولا يكتب فوق المصدر الأصلي. كل تغيير يمر بمسار الخطة والتأكيد والكتابة المشتركة وإعادة الفتح والتحقق.

تدعم الدفعة الحالية تسجيل الملفات إلى `fileId` محدود الجلسة، القراءة والفهرسة، موارد MCP ثابتة وديناميكية، Prompts للمراجعة والفرز، خطط التغيير، `replace` و`add` و`delete` و`change-language`، الحالة الدائمة المحدودة، التصدير إلى ملف جديد، وقراءة سجل التدقيق. كما تضيف **plugin discovery للقراءة فقط**؛ حيث تُقرأ ملفات manifests وتُفحص صلاحيتها، ولا تُشغّل entrypoints أو تمنح الإضافات صلاحية تنفيذ عبر MCP.

## التشغيل عبر stdio

من جذر المشروع:

```bash
RESOURCE_STUDIO_ROOT=/home/ubuntu/resource-studio python3 mcp/server.py
```

يحدد `RESOURCE_STUDIO_ROOT` الجذر المسموح. يرفض الخادم المسارات الخارجة عنه، ويكتب السجلات إلى stderr حتى يبقى stdout مخصصًا لـ JSON-RPC. لا تُلمس ملفات المصدر؛ الناتج المرحلي والتصدير يظلان تحت الجذر وبمسار جديد.

## التشغيل عبر Streamable HTTP

يتطلب تشغيل HTTP رمزًا صريحًا، ويستمع افتراضيًا على `127.0.0.1:8765` وبمسار MCP هو `/mcp`:

```bash
RESOURCE_STUDIO_ROOT=/home/ubuntu/resource-studio \
RESOURCE_STUDIO_MCP_TOKEN='ضع-رمزًا-محليًا-طويلًا' \
python3 mcp/http_server.py
```

تتوفر نقطة فحص بسيطة على `/healthz`. كل طلب MCP يحتاج `Authorization: Bearer ...`. تُرفض Origins غير المدرجة، ويُتحقق من Host عبر `TrustedHostMiddleware`. الإعداد الافتراضي محلي؛ لا يُسمح بالربط البعيد إلا عند ضبط `RESOURCE_STUDIO_MCP_ALLOW_REMOTE=true`. عند تفعيل الربط البعيد يجب أن يكون الرمز بطول 32 محرفًا على الأقل، ويُفرض HTTPS عبر `X-Forwarded-Proto: https`.

يمكن تخصيص الإعدادات عبر `RESOURCE_STUDIO_MCP_HOST` و`RESOURCE_STUDIO_MCP_PORT` و`RESOURCE_STUDIO_MCP_PATH` و`RESOURCE_STUDIO_MCP_ALLOWED_HOSTS` و`RESOURCE_STUDIO_MCP_ALLOWED_ORIGINS`. لا تُفتح socket عند استدعاء `create_app()`؛ وهذا يتيح اختبار ASGI دون تشغيل خدمة فعلية.

## تدفق الاستخدام والتعديلات

يبدأ العميل باستدعاء `resource_studio.register_file` للحصول على `fileId` وSHA-256. بعد ذلك يُنشئ workspace ويخطط لتغيير مورد. كل عملية كتابة تتطلب `confirmationToken` صالحًا وتأكيدًا صريحًا؛ مدة الرمز عشر دقائق.

| المجال | الأدوات |
|---|---|
| التسجيل | `resource_studio.register_file` |
| القراءة | `resource_studio.inspect_file`، `resource_studio.index_resources`، `resource_studio.diff_files`، `resource_studio.read_audit` |
| الإضافات | `resource_studio.list_plugins` |
| التخطيط | `resource_studio.create_workspace`، `resource_studio.plan_resource_change`، `resource_studio.get_plan` |
| التعديل والتصدير | `resource_studio.apply_plan`، `resource_studio.export_workspace`، `resource_studio.cancel_plan` |

تقبل `plan_resource_change` العمليات التالية فوق writer المشترك:

| العملية | المعنى | المتطلبات |
|---|---|---|
| `replace` | استبدال payload لمورد موجود | `resource_key` و`payloadBase64` |
| `add` | إضافة مورد جديد | `resource_type` و`resource_name` و`target_language` و`payloadBase64` |
| `delete` | حذف مورد موجود | `resource_key` |
| `change-language` | نقل payload إلى لغة أخرى مع حذف النسخة القديمة | `resource_key` و`target_language` |

تُكتب كل نتيجة إلى ملف جديد داخل workspace، ثم يُعاد فتح الناتج ويُتحقق من PE والموارد والتغيير المستهدف. التصدير يحتاج تأكيدًا مستقلًا ومسار Save As جديدًا تحت الجذر.

## الحالة الدائمة

يحفظ الخادم حالة MCP محدودة في `.resource-studio/mcp-state.json` داخل الجذر، باستخدام كتابة ذرية وقفل داخل العملية. تشمل الحالة file registrations وworkspaces وplans وaudit records اللازمة لاستكمال جلسة محلية بعد إعادة تشغيل العملية. لا تُحفظ payloads خارج الملفات الناتجة، ولا يتحول هذا الملف إلى قاعدة بيانات أو قناة تنفيذ.

## Resources وPrompts

| URI | المحتوى |
|---|---|
| `resource://workspace/info` | حدود الجذر وإعدادات الخادم |
| `resource://plugins` | manifests المكتشفة وحالة validation، للقراءة فقط |
| `resource://workspace/{workspace_id}` | بيانات workspace المعزولة |
| `resource://file/{file_id}/manifest` | PE health وresource manifest وwarnings |
| `resource://file/{file_id}/resource/{resource_key}` | مورد محدد مع payload base64 محدود الحجم عند الإمكان |
| `resource://plan/{plan_id}` | الخطة وحالة التأكيد |
| `resource://operation/{operation_id}/audit` | سجل العملية والتحقق |

الـPrompts المنفذة هما `review_change` و`pe_triage`. لا يمنح أي Prompt صلاحية كتابة.

## Plugin discovery

يقرأ الخادم manifests من `.resource-studio/plugins/<plugin-id>/plugin.json`. يعرض `resource_studio.list_plugins` و`resource://plugins` الاسم والإصدار وAPI والـkind والصلاحيات وentrypoint وحالة التوافق. هذه مرحلة discovery فقط: لا تُستورد ملفات Python ولا تُنفذ entrypoints ولا تُمنح الإضافة صلاحيات عبر MCP. يفشل manifest غير الصالح بحالة `rejected` مع سبب قابل للتشخيص، بينما يبقى الخادم مستمرًا في خدمة بقية الأدوات.

## الاختبارات

تشغّل اختبارات MCP الخادم كعمليات مستقلة أو كـASGI app حسب الحالة:

```bash
PYTHONPATH=. python3 tests/test_mcp_stdio.py
PYTHONPATH=. python3 tests/test_mcp_http.py
PYTHONPATH=. python3 tests/test_mcp_persistence.py
PYTHONPATH=. python3 tests/test_mcp_mutations.py
PYTHONPATH=. python3 tests/test_mcp_plugins.py
```

يثبت الاختبار الأساسي التسجيل والقراءة والفهرسة وResources وPrompts والخطة والتأكيد والتصدير. ويثبت اختبار HTTP رفض bearer token المفقود وOrigin الخاطئ وHost الخاطئ، بينما يثبت اختبار persistence الاستعادة بين عمليتين منفصلتين. ويغطي اختبار mutations الإضافة والحذف وتغيير اللغة، ويثبت اختبار plugins اكتشاف manifest صالح ورفض manifest غير صالح وعدم تنفيذ entrypoint.

## المراجع

يعتمد الخادم على [Python SDK الرسمي لـ MCP](https://modelcontextprotocol.io/docs/2026-07-28/sdk) وعلى [دليل بناء خادم MCP](https://modelcontextprotocol.io/docs/2026-07-28/develop/build-server).
