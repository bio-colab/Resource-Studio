# Resource Studio MCP

## الحالة الحالية

يوفّر Resource Studio خادم MCP محليًا عبر **stdio**، كما يوفّر طبقة **Streamable HTTP** اختيارية. الخادم يقرأ الملفات الواقعة تحت `RESOURCE_STUDIO_ROOT`، ويعزل تعديلات PE وMSIX داخل مساحات عمل، ولا يكتب فوق المصدر الأصلي. كل عملية تغيير تمر بخطة وتأكيد وإعادة فتح وتحقيق.

تدعم الدفعة الحالية تسجيل الملفات إلى `fileId`، القراءة والفهرسة، Resources وPrompts، خطط PE وMSIX، عمليات PE الأساسية، plugin discovery، تشغيل plugin منخفض الصلاحية خارج العملية، external integration gateway محدودًا، والحالة الدائمة المحدودة. لا تُمنح الصلاحيات الحساسة لمجرد إعلانها في manifest؛ `network` و`process.execute` و`files.write.project-output` وclipboard تبقى مرفوضة حتى إضافة sandbox adapter متخصص لها.

## التشغيل عبر stdio وHTTP

```bash
RESOURCE_STUDIO_ROOT=/home/ubuntu/resource-studio python3 mcp/server.py
```

ولـStreamable HTTP:

```bash
RESOURCE_STUDIO_ROOT=/home/ubuntu/resource-studio \
RESOURCE_STUDIO_MCP_TOKEN='رمز-محلي-طويل' \
python3 mcp/http_server.py
```

يستمع HTTP افتراضيًا على `127.0.0.1:8765` وبمسار `/mcp`. يتطلب Bearer token، ويفحص Host وOrigin، ويمنع الربط البعيد إلا مع `RESOURCE_STUDIO_MCP_ALLOW_REMOTE=true`. عند الربط البعيد يلزم رمز بطول 32 محرفًا على الأقل ويُفرض HTTPS. توجد نقطة `/healthz` للفحص فقط.

## أدوات PE والتعديلات

| المجال | الأدوات |
|---|---|
| القراءة | `resource_studio.register_file`، `inspect_file`، `index_resources`، `diff_files`، `read_audit` |
| التخطيط | `create_workspace`، `plan_resource_change`، `get_plan` |
| التعديل | `apply_plan`، `export_workspace`، `cancel_plan` |

تدعم خطة PE عمليات `replace` و`add` و`delete` و`change-language`. يمر الناتج عبر `LiefPEWriter` والتحقق المشترك وإعادة الفتح، ولا يُستخدم هذا المسار لتعديل PRI أو MSIX.

## Plugin runtime

تقرأ manifests من `.resource-studio/plugins/<plugin-id>/plugin.json`. تعرض الأدوات `resource_studio.list_plugins` و`resource_studio.inspect_plugin` الاسم والإصدار وAPI والصلاحيات وحالة quarantine، للقراءة فقط.

يبدأ تشغيل plugin عبر `resource_studio.plan_plugin_execution` ثم `resource_studio.apply_plugin_execution`. التنفيذ يحدث خارج عملية الخادم، داخل staging مؤقت، مع رفض symlinks، Python isolated mode، JSON-lines response واحد، حدود request/output/time/memory، وWindows Job Object عند توفر Windows. يحتاج كل تشغيل إلى تأكيد بشري قصير العمر وadmin authorization. وهو **معطل افتراضيًا**؛ لا يُفعّل إلا بعد مراجعة المستخدم مع `RESOURCE_STUDIO_MCP_ALLOW_PLUGIN_EXECUTION=true` و`RESOURCE_STUDIO_MCP_ADMIN_TOKEN`. الصلاحيات الممنوحة في الخطة يجب أن تكون معلنة في manifest، ولا تُعتبر permission env بديلًا عن sandbox OS.

النسخة الحالية تسمح فعليًا بـ`project.read` فقط. الصلاحيات الحساسة التالية تُرفض حتى مع admin token إلى أن يتوفر adapter عزل فعلي لها:

| الصلاحية | الحالة الحالية |
|---|---|
| `project.read` | مدعومة في runtime المحدود |
| `project.modify` | تحتاج admin وcontext mutation مستقل؛ غير مفعلة |
| `files.write.project-output` | غير مفعلة |
| `network` | غير مفعلة؛ استخدم integration gateway المقيد |
| `process.execute` | غير مفعلة |
| clipboard | غير مفعلة |

تحتاج إعادة تفعيل plugin معزول إلى `resource_studio.enable_plugin` و`RESOURCE_STUDIO_MCP_ADMIN_TOKEN`. التعطل أو timeout أو خرق عقد JSON يؤدي إلى quarantine محفوظ، ولا يختفي عند إعادة discovery أو إعادة تشغيل الخادم.

## External integration gateway

يقرأ الخادم تكاملات صريحة من `.resource-studio/integrations.json`. لا يقبل gateway عنوان URL من الطلب ولا headers مخصصة؛ كل تكامل يعلن `baseUrl` HTTPS عامًا وعمليات ثابتة بأسماء ومسارات allowlisted. تُحظر عناوين localhost والشبكات الخاصة وredirects غير المعتمدة، وتُقرأ credentials من environment عبر `authEnv` ولا تُعاد في النتائج أو audit.

```json
{
  "integrations": [
    {
      "id": "example.api",
      "name": "Example API",
      "baseUrl": "https://api.example.com",
      "authEnv": "EXAMPLE_API_TOKEN",
      "operations": {
        "health": {"method": "GET", "path": "/health"},
        "submit": {"method": "POST", "path": "/v1/resource-studio/events"}
      }
    }
  ]
}
```

تُستخدم الأدوات `resource_studio.list_integrations` و`resource_studio.plan_integration_request` و`resource_studio.apply_integration_request`. كل نداء شبكة يحتاج خطة، تأكيدًا بشريًا، وadmin authorization. لا تُحفظ خطط التكامل في الحالة الدائمة، ولا يُسمح بإرسال payload خارجيًا دون هذه البوابات.

## MSIX/PRI

تُعامل MSIX وAppX وPRI كوحدة package مستقلة، وليست أنواعًا داخل `.rsrc`. يستخدم `resource_studio.inspect_package` ZIP inspection محدودًا لعرض `AppxManifest.xml` و`AppxBlockMap.xml` و`resources.pri` والـentries والهاشات. هذا لا يدّعي تفسير بنية PRI الداخلية؛ فقراءة MRT Core العميقة تحتاج Windows App SDK أو أدوات Microsoft المناسبة.

تدعم `resource_studio.plan_package_change` و`resource_studio.apply_package_change` عمليات `add` و`replace` و`delete` على member عادي. تُنسخ البيانات إلى workspace، ويُعاد بناء الحزمة عبر `MakeAppx.exe` على Windows فقط، ثم تُفتح وتُفحص من جديد. تُرفض الحزم الموقعة للتعديل العام، ويظل signing خطوة منفصلة تتطلب سياسة وشهادة يختارها المستخدم؛ لا يحتفظ Resource Studio بمفاتيح الإنتاج.

| مرحلة | السلوك |
|---|---|
| inspect | قراءة bounded للـZIP والmanifest/block map/PRI metadata |
| plan | لا يغيّر المصدر؛ يخزن payload في workspace مع SHA-256 |
| apply | MakeAppx على Windows، output جديد، ثم reopen وvalidation |
| signing | منفصل وغير تلقائي؛ الشهادة والمفتاح خارج الحالة الدائمة |
| Store/install validation | ليست بديلًا عن semantic validation في MakeAppx |

## الحالة الدائمة

يحفظ الخادم حالة MCP المحدودة في `.resource-studio/mcp-state.json` بكتابة ذرية. تُبطل confirmation tokens عند إعادة التشغيل. خطط plugin runtime وMSIX المعلقة تصبح `stale_after_restart`، بينما payloadات خطط MSIX تبقى داخل workspace تحت الجذر المصرح وبهاش قابل للتحقق.

## الاختبارات

```bash
PYTHONPATH=. python3 tests/test_mcp_stdio.py
PYTHONPATH=. python3 tests/test_mcp_http.py
PYTHONPATH=. python3 tests/test_mcp_persistence.py
PYTHONPATH=. python3 tests/test_mcp_mutations.py
PYTHONPATH=. python3 tests/test_mcp_plugins.py
PYTHONPATH=. python3 tests/test_mcp_plugin_runtime.py
PYTHONPATH=. python3 tests/test_mcp_package_integrations.py
PYTHONPATH=. python3 tests/core/test_plugin_host.py
PYTHONPATH=. python3 tests/core/test_plugin_quarantine.py
PYTHONPATH=. python3 tests/core/test_external_integrations.py
PYTHONPATH=. python3 tests/core/test_msix.py
```

تثبت الاختبارات التنفيذ خارج العملية، grant enforcement، quarantine، رفض SSRF، allowlisted integrations، package inspection، ومنع تعديل MSIX على Manus دون MakeAppx. أما rebuild الفعلي فيُختبر على Windows عندما تكون أدوات Windows SDK متاحة.

## المراجع

يعتمد الخادم على [Python SDK الرسمي لـ MCP](https://modelcontextprotocol.io/docs/2026-07-28/sdk)، وعلى [مرجع Microsoft PRI](https://learn.microsoft.com/en-us/windows/win32/menurc/pri-indexing-reference)، وعلى [MRT Core](https://learn.microsoft.com/en-us/windows/apps/windows-app-sdk/mrtcore/mrtcore-overview)، وعلى [MakeAppx](https://learn.microsoft.com/en-us/windows/msix/package/create-app-package-with-makeappx-tool)، وعلى [SignTool لتوقيع MSIX](https://learn.microsoft.com/en-us/windows/msix/package/sign-app-package-using-signtool).
