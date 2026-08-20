# عقد MCP المقترح لـ Resource Studio

**الحالة:** عقد أولي قابل للمراجعة  
**Namespace:** `resource_studio`  
**الإصدار الداخلي:** `1.0`

## 1. قواعد عامة

كل أداة تعيد `structuredContent` ثابتًا، ونصًا موجزًا صالحًا للعرض البشري، و`isError` عند الفشل. كل مسار ملف يعاد في صورة `fileId` داخلي بعد التحقق، ولا يُسمح للعميل ببناء مسار نظام اعتباطي داخل النواة.

الاستدعاءات المصنفة **قراءة** لا تعدل شيئًا. الاستدعاءات المصنفة **تخطيط** لا تعدل شيئًا وتنتج خطة. الاستدعاءات المصنفة **تعديل** لا تعمل إلا على مساحة عمل معزولة وبعد تأكيد صريح من المستخدم.

## 2. الموارد Resources

| URI | الوظيفة | قابلية الكتابة |
|---|---|---|
| `resource://workspace/{workspaceId}` | معلومات مساحة العمل ومساراتها المسموحة | للقراءة فقط |
| `resource://file/{fileId}/manifest` | فهرس PE والموارد والتوقيع والهاش | للقراءة فقط |
| `resource://file/{fileId}/resource/{type}/{name}/{language}` | بيانات مورد محدد أو رابط معاينته | للقراءة فقط |
| `resource://plan/{planId}` | خطة تغييرات قابلة للمراجعة | للقراءة فقط |
| `resource://operation/{operationId}/audit` | سجل عملية وتحققها | للقراءة فقط |
| `resource://project/{projectId}` | إعدادات مشروع Resource Studio | للقراءة فقط |

## 3. أدوات القراءة

| الاسم | الغرض | التأثير |
|---|---|---|
| `resource_studio.inspect_file` | فحص نوع الملف، PE headers، الأقسام، التوقيع، والهاش | لا كتابة |
| `resource_studio.index_resources` | تعداد النوع والاسم واللغة والحجم والبصمة | لا كتابة |
| `resource_studio.get_resource` | جلب مورد محدد بصيغة structured أو raw | لا كتابة |
| `resource_studio.preview_resource` | إنتاج معاينة آمنة أو Hex | لا كتابة |
| `resource_studio.diff_files` | مقارنة ملفين أو فهرسين | لا كتابة |
| `resource_studio.verify_signature` | فحص Authenticode عبر طبقة التحقق المحلية | لا كتابة |
| `resource_studio.read_audit` | قراءة سجل العملية | لا كتابة |

### مثال `inspect_file`

```json
{
  "name": "resource_studio.inspect_file",
  "arguments": {
    "fileId": "file_01H...",
    "include": ["pe", "sections", "resources", "signature"],
    "maxBytes": 10485760
  }
}
```

## 4. أدوات التخطيط

| الاسم | الغرض | الناتج |
|---|---|---|
| `resource_studio.create_workspace` | إنشاء نسخة عمل داخل جذر Resource Studio مع بقاء الأصل للقراءة فقط | `workspaceId` وهاش المصدر |
| `resource_studio.plan_resource_change` | بناء خطة إضافة/استبدال/حذف/لغة دون كتابة | `planId` وdiff متوقع |
| `resource_studio.get_plan` | قراءة خطة محفوظة في جلسة الخادم | الخطة نفسها |
| `resource_studio.plan_extract` | تخطيط استخراج موارد إلى مجلد | قائمة ملفات متوقعة |
| `resource_studio.plan_localization` | تخطيط نسخ أو مقارنة اللغات | تقرير فجوات اللغات |
| `resource_studio.plan_package_change` | تخطيط تعديل MSIX/PRI في الوحدة المستقبلية | خطة غير تنفيذية |

## 5. أدوات التعديل

| الاسم | الغرض | التأكيد |
|---|---|---|
| `resource_studio.apply_plan` | تنفيذ خطة على workspace | إلزامي |
| `resource_studio.export_workspace` | تصدير ناتج متحقق إلى مسار يختاره المستخدم | إلزامي |
| `resource_studio.commit_resource` | كتابة مورد محدد إلى نسخة العمل | إلزامي |
| `resource_studio.cancel_plan` | إلغاء خطة قبل التنفيذ | غير مطلوب |
| `resource_studio.rebuild_package` | إعادة بناء حزمة MSIX/PRI مستقبلًا | إلزامي ومقيّد |

لا توجد أداة باسم عام مثل `run_command` أو `write_any_file` في العقد الأساسي؛ منع هذه الأدوات يقلل خطر تنفيذ أوامر غير مقصودة وتجاوز مسار العزل.

## 6. Prompts وموارد مساعدة

| الاسم | الغرض |
|---|---|
| `resource_studio.prompts.review_change` | تلخيص خطة تغييرات بلغة بشرية قبل التأكيد |
| `resource_studio.prompts.localization_report` | إعداد تقرير فجوات الترجمة |
| `resource_studio.prompts.pe_triage` | ترتيب ملاحظات فحص PE للقراءة فقط |
| `resource_studio.prompts.safe_export` | إرشاد المستخدم إلى تحقق ما قبل التصدير |

الـ prompt لا يمنح صلاحية جديدة ولا ينفذ عملية؛ هو قالب عرض أو تحليل يعتمد على موارد وأدوات أخرى.

## 7. نموذج ناتج موحد

```json
{
  "schemaVersion": "resource_studio.result.v1",
  "operationId": "op_01H...",
  "status": "verified",
  "source": {
    "fileId": "file_01H...",
    "sha256": "..."
  },
  "output": {
    "fileId": "file_01H...",
    "sha256": "...",
    "pathPolicy": "workspace-only"
  },
  "changes": [
    {
      "type": "RCDATA",
      "name": "TEST_ADD",
      "language": 1033,
      "action": "added",
      "beforeSha256": null,
      "afterSha256": "..."
    }
  ],
  "warnings": [],
  "verification": {
    "reopened": true,
    "resourceIndexCompared": true,
    "signatureStatus": "not_present"
  },
  "auditUri": "resource://operation/op_01H.../audit"
}
```

## 8. الإشعارات

يعلن الخادم `tools.listChanged` عندما تتغير الأدوات بسبب إضافة plugin، ويعلن تغيّر الموارد عند تحديث workspace أو plan. لا تُستخدم الإشعارات كبديل للتحقق؛ كل عميل يستطيع إعادة قراءة URI عند الحاجة.

## 9. التوافق

الإصدار الأول يحافظ على أسماء الأدوات ونماذجها. الحقول الجديدة تكون اختيارية. التغييرات الكاسرة تنتقل إلى `resource_studio.v2` مع إبقاء v1 خلال فترة هجرة. تُحفظ أمثلة الطلبات والنتائج داخل `tests/fixtures` ويُمنع تغييرها دون تحديث changelog.

## المراجع

[1]: [MCP Tools Specification](https://modelcontextprotocol.io/specification/2026-07-28/server/tools)

[2]: [MCP Versioning](https://modelcontextprotocol.io/docs/2026-07-28/learn/versioning)

[3]: [MCP Security Best Practices](https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices)
