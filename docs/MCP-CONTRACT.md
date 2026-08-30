# Resource Studio MCP Contract

**الحالة:** Phase 1 محلي منفذ عبر `stdio`

**Namespace:** `resource_studio`

**Schema:** `resource_studio.tools.v1` و`resource_studio.result.v1`

## 1. قواعد عامة

يبدأ العميل بتسجيل الملف عبر `resource_studio.register_file`. يعيد الخادم `fileId` محدود الجلسة وSHA-256، وتستخدم الأدوات اللاحقة ذلك المعرّف بدل تمرير مسار جديد في كل استدعاء. يقبل الخادم `path` في أدوات القراءة والتسجيل الأولي للتوافق، لكنه يتحقق دائمًا من الجذر المسموح ولا يقبل مسارًا خارجه.

الاستدعاءات المصنفة قراءة لا تعدل شيئًا. الاستدعاءات المصنفة تخطيط لا تعدل شيئًا وتنتج خطة. التعديل لا يعمل إلا على نسخة workspace معزولة وبعد تأكيد صريح. لا توجد أداة `run_command` أو `write_any_file`.

## 2. Resources

| URI | الوظيفة | قابلية الكتابة |
|---|---|---|
| `resource://workspace/info` | حدود الخادم والجذر وحالة الجلسة | للقراءة فقط |
| `resource://workspace/{workspace_id}` | بيانات مساحة العمل المعزولة | للقراءة فقط |
| `resource://file/{file_id}/manifest` | PE health وفهرس الموارد والتحذيرات | للقراءة فقط |
| `resource://file/{file_id}/resource/{resource_key}` | مورد محدد؛ المفتاح URI-encoded بصيغة `type/name/language` | للقراءة فقط |
| `resource://plan/{plan_id}` | خطة التغيير وحالة التأكيد | للقراءة فقط |
| `resource://operation/{operation_id}/audit` | سجل العملية والتحقق | للقراءة فقط |
| `resource://session/state` | ملخص حالة جلسة MCP الحالية وأعداد الكيانات والخطط المعلقة | للقراءة فقط |
| `resource://session/events` | سجل أحداث محدود للجلسة الحالية | للقراءة فقط |
| `resource://tools/metadata` | آثار الأدوات وشروطها والتأكيد والتدقيق | للقراءة فقط |
| `resource://live-analysis/session/{session_id}` | جلسة تحليل حي مرتبطة ببصمة الهدف | للقراءة فقط |
| `resource://live-analysis/report/{report_id}` | تقرير observations خارجي بعد تطبيعِه وربطه بالهدف | للقراءة فقط |

لا يعلن Phase 1 اشتراكات Resources أو إشعارات `listChanged`؛ القوائم ثابتة خلال جلسة الخادم. موارد observability الجديدة لا تمنح صلاحية تعديل؛ وهي snapshots read-only للحالة والأحداث والعقود.

## 3. Prompts

| الاسم | الغرض |
|---|---|
| `review_change` | إعداد رسالة مراجعة بشرية لخطة قبل التأكيد |
| `pe_triage` | إعداد رسالة فرز قراءة فقط من manifest مسجل |

لا يمنح Prompt صلاحية جديدة ولا ينفذ mutation.

## 4. الأدوات المنفذة

| الفئة | الاسم | التأثير |
|---|---|---|
| Bootstrap | `resource_studio.register_file` | تسجيل read-only وإصدار fileId |
| قراءة | `resource_studio.inspect_file` | PE headers وhealth وhash والموارد |
| قراءة | `resource_studio.index_resources` | فهرسة الموارد وoffset وSHA-256 |
| قراءة | `resource_studio.diff_files` | مقارنة ملفين مسجلين |
| قراءة | `resource_studio.read_audit` | قراءة سجل عملية |
| تخطيط | `resource_studio.create_workspace` | إنشاء نسخة عزل دون تعديل المصدر |
| تخطيط | `resource_studio.plan_resource_change` | خطة replace/add/delete دون كتابة |
| تخطيط | `resource_studio.get_plan` | قراءة الخطة |
| تعديل | `resource_studio.apply_plan` | تطبيق replace موجود عبر `LiefPEWriter` بعد التأكيد |
| تعديل | `resource_studio.export_workspace` | Save As إلى ملف جديد بعد تأكيد مستقل |
| تعديل | `resource_studio.cancel_plan` | إلغاء خطة pending دون كتابة |
| تحليل حي read-only | `resource_studio.live_analysis_contract` | عرض قدرات وحدود adapter دون تنفيذ |
| تحليل حي read-only | `resource_studio.start_live_analysis_session` | إنشاء جلسة مرتبطة بـSHA-256 دون تشغيل أو attach |
| تحليل حي read-only | `resource_studio.import_live_analysis` | استيراد behavioral/memory/API evidence خارجي مطابق للهدف |

تدعم النواة في هذه المرحلة عقد التخطيط الأوسع، لكن backend MCP ينفذ replace فقط. add/delete وتغيير اللغة والمعاينات المتخصصة تضاف فوق نفس المسار بعد تعريف اختباراتها.

## 5. confirmation وlifecycle

كل خطة تحمل `confirmationToken` ووقت إصدار. صلاحية الرمز عشر دقائق. بعد apply يصدر الخادم رمز تصدير مستقل، ولا يسمح `export_workspace` بالكتابة إلى المصدر أو إلى ملف موجود أو إلى مسار خارج `RESOURCE_STUDIO_ROOT`. حالة `fileId` وworkspace وplan وaudit داخل الذاكرة ومحدودة بجلسة stdio.

## 6. عقد observability

يعلن `resource://tools/metadata` metadata منظمة لكل أداة منفذة تحت namespace `resource_studio`. تتضمن metadata نوع الأثر، وكون الأداة لا تعدل المصدر، وشروط التشغيل، ومتطلب التأكيد، ومكان سجل التدقيق المتوقع. هذا المورد مكمل لمخطط الإدخال ولا يستبدله، ولا يفتح أداة غير موجودة في `tools/list`.

يعرض `resource://session/state` أعداد الملفات والمساحات والخطط والتدقيقات والأحداث، والخطط المعلقة، وتسلسل آخر حدث. ويعرض `resource://session/events` آخر 512 حدثًا من دورة الجلسة مثل `file.registered` و`workspace.created` و`plan.created` و`plan.applied` و`workspace.exported` و`plan.cancelled`. الأحداث وصفية وread-only، ولا تُستخدم كرموز تأكيد ولا تغيّر evidence أو verification.

هذه الموارد scoped to the current server session. لا تُعد سجل chain of custody قانونيًا ولا بديلًا عن operation audit أو Evidence Ledger؛ الغرض منها جعل حالة الخادم وآثار الأدوات قابلة للاكتشاف والتدقيق الآلي.

## 7. Live-analysis adapter

يبدأ adapter بصيغة `read-only-external-import`: ينشئ جلسة مرتبطة بـSHA-256 لملف مسجل، ثم يستورد تقريرًا خارجيًا من الأنواع `behavioralTelemetry` أو `memoryAnalysis` أو `apiCallTrace` بشرط تطابق `targetSha256`. لا يبدأ Resource Studio process، ولا يتصل بdebugger، ولا يقرأ live memory، ولا ينفذ debugger commands، ولا يكتب الهدف. يعاد التقرير مع `sessionId` و`sourceSha256` و`evidenceSha256` وprovenance وlimitations.

هذه observations تظل evidence خارجية وليست verdict malware، ولا تُستخدم تلقائيًا لتغيير `resourceTriage` أو `verification`. أي adapter حي فعلي أو تكامل x64dbg أو telemetry capture داخل الجهاز مؤجل إلى قرار أمني مستقل وعزل مخصص.

## 8. نموذج الناتج

```json
{
  "schemaVersion": "resource_studio.result.v1",
  "operationId": "op_01H...",
  "planId": "plan_01H...",
  "status": "verified",
  "source": {
    "workspaceId": "ws_01H...",
    "sha256": "..."
  },
  "output": {
    "file": {
      "fileId": "file_01H...",
      "sha256": "...",
      "size": 1234,
      "role": "verified_output"
    },
    "pathPolicy": "workspace-only"
  },
  "changes": [
    {
      "type": "RCDATA",
      "name": "TEST",
      "language": "1033",
      "action": "modified",
      "beforeSha256": "...",
      "afterSha256": "..."
    }
  ],
  "warnings": [],
  "verification": {
    "reopened": true,
    "resourceHashMatchesPayload": true,
    "writer": {},
    "forensic": {},
    "signatureStatus": "checked_by_writer"
  },
  "auditUri": "resource://operation/op_01H.../audit"
}
```

## 9. حدود النقل

يبقى `stdio` هو المسار المحلي الافتراضي. يدعم المشروع Streamable HTTP المحلي/البعيد الاختياري وplugin discovery وفق وثائق MCP الحالية، لكن موارد observability نفسها لا تحفظ سجلًا دائمًا؛ فهي scoped to the current server session، بينما تبقى state persistence وoperation audit مسارين منفصلين.

## المراجع

[1]: [MCP Tools Specification](https://modelcontextprotocol.io/specification/2026-07-28/server/tools)

[2]: [MCP Versioning](https://modelcontextprotocol.io/docs/2026-07-28/learn/versioning)

[3]: [MCP Security Best Practices](https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices)
