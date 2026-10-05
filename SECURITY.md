# سياسة أمان MCP في Resource Studio

## 1. نموذج التهديد

Resource Studio يتعامل مع ملفات تنفيذية قد تكون حساسة أو غير موثوقة، ويعرض أدوات يمكن أن تقرأ وتعدل هذه الملفات. الخطر ليس في قراءة مورد فقط، بل في أن يطلب نموذج أو عميل تعديل ملف غير مقصود، أو تمرير مسار خارج مساحة العمل، أو تشغيل محتوى غير موثوق، أو تسريب بيانات من ملف إلى جهة خارجية.

## 2. تصنيف الأدوات

| التصنيف | أمثلة | الموافقة |
|---|---|---|
| قراءة | `inspect_file`, `index_resources`, `preview_resource`, `inspect_package`, `list_plugins`, `inspect_plugin`, `list_integrations` | لا تحتاج تأكيدًا، مع احترام المسارات المسموحة |
| تخطيط | `plan_resource_change`, `plan_extract`, `plan_plugin_execution`, `plan_integration_request`, `plan_package_change` | لا تكتب المصدر، وتعرض الأثر والهاش والحدود |
| تعديل/تنفيذ | `apply_plan`, `export_workspace`, `apply_plugin_execution`, `apply_integration_request`, `apply_package_change` | تأكيد بشري صريح؛ plugin/integration الخارجيان يحتاجان admin authorization أيضًا |
| إدارة خادم | `enable_plugin` وتغيير سياسات النقل أو الجذور | admin authorization منفصل، مع سجل تدقيق وquarantine |

## 3. حماية المسارات

يُنشئ الخادم مساحة عمل لكل عملية. الملف الأصلي يوسم `read-only-source` ولا يسمح العقد بأي نداء تعديل عليه. مسارات الإدخال تُطبع وتُتحقق من عدم عبورها إلى مسار خارج الجذور المسموحة. لا تُقبل روابط رمزية أو junctions غير موثقة في مسار الكتابة. يُحفظ الناتج في مجلد جديد، وتُستخدم أسماء ملفات مولدة بدل استقبال اسم تنفيذي عشوائي من النموذج.

## 4. التأكيد البشري

قبل `apply_plan` يعرض Resource Studio: الملف المصدر، هاشه، الناتج، الموارد المتأثرة، العملية، اللغة، الحجم قبل وبعد، حالة التوقيع، والتحذيرات. لا يكفي أن يرسل العميل قيمة `confirmed: true` من دون ربطها بموافقة واجهة المستخدم؛ يجب أن ينشئ الخادم رمز تأكيد قصير العمر مربوطًا بـ `planId` وهاش المصدر.

## 5. منع الأدوات العامة

لا يعرض الخادم أداة تنفيذ أوامر عامة، ولا أداة كتابة مسار عام، ولا أداة تحميل URL ثم تشغيله. تشغيل plugin لا يمرر أمرًا عامًا؛ بل يستخدم `PluginHost` خارج العملية، وstaging مؤقتًا، وentrypoint من manifest مع grant محدد. تشغيل entrypoint عبر MCP معطل افتراضيًا، ويتطلب opt-in صريحًا وadmin authorization وتأكيدًا بشريًا. الإصدار الحالي يدعم `project.read` فقط، ويرفض network/process/filesystem/clipboard حتى تتوفر sandbox adapters متخصصة؛ permission env ليس sandbox OS. التكاملات الخارجية لا تقبل URL أو headers من الطلب، وتستخدم HTTPS allowlist وعمليات ثابتة وبصمة إعدادات تمنع تغيير endpoint بعد التخطيط.

## 6. البيانات والخصوصية

لا تُرسل بيانات الملف خارج الجهاز في النقل المحلي. معاينات الصور والنصوص والموارد الثنائية تبقى محلية افتراضيًا. عند استخدام MCP بعيد، يجب تفعيل المصادقة وتحديد المستخدم والـ workspace، وعدم إرسال المورد الخام إلا عند طلب واضح. تُحذف مساحات العمل المؤقتة وفق سياسة معلنة، مع إبقاء سجل التدقيق المجرد دون محتوى الملف عند الإمكان.

## 7. التوقيعات

تُفحص حالة التوقيع قبل وبعد التعديل. لا يفترض النظام أن التوقيع القديم يبقى صالحًا. إعادة التوقيع ليست ضمن الإصدار الأول، ولا يحتفظ Resource Studio بمفاتيح خاصة. يمكن استدعاء أدوات توقيع محلية لاحقًا بعد اختيار المستخدم للشهادة والسياسة.

## 8. MCP البعيد

يبقى `stdio` هو النقل الافتراضي. عند إضافة Streamable HTTP يجب تنفيذ المصادقة، منع SSRF، التحقق من Origins، ربط الجلسة بالمستخدم، تقليل scopes، عدم تمرير رموز طرف ثالث، ومقاومة confused deputy. لا يسمح الخادم البعيد بتغيير مسارات الجذر أو إضافة plugin أو تشغيل adapter دون صلاحية إدارية منفصلة. لا يُفتح plugin network scope عبر HTTP؛ external integrations تمر عبر gateway allowlist وبموافقة وadmin gate، بينما MSIX/PRI تبقى وحدة package منفصلة عن PE writer.

## 9. MSIX/PRI والتوقيع

تُعامل MSIX/AppX/PRI كحزم data-only مستقلة عن PE. الفحص bounded ويشمل manifest وblock map وPRI metadata، وإعادة البناء تتم عبر MakeAppx.exe في output جديد ثم reopen وvalidation. لا يعدل النظام حزمة موقعة عبر generic writer، ولا يحتفظ بمفتاح خاص؛ signing خطوة مستقلة بشهادة وسياسة يختارها المستخدم.

## 10. سجل التدقيق

كل عملية تسجل:

- هوية العميل والنسخة والبروتوكول.
- اسم الأداة ومعاملاتها المنقحة من الأسرار.
- fileId وworkspaceId وplanId.
- هاش المصدر والناتج.
- الموارد المتأثرة.
- نتيجة التحقق وحالة التوقيع.
- وقت البداية والنهاية والحالة.
- في plugin runtime: pluginId وgrants وسبب quarantine دون تخزين الأسرار.
- في external integration: integrationId وoperation وrequest hash دون payload credentials.

## 11. المراجع

[1]: [MCP Security Best Practices](https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices)

[2]: [MCP Tools Specification](https://modelcontextprotocol.io/specification/2026-07-28/server/tools)

[3]: [MCP Versioning](https://modelcontextprotocol.io/docs/2026-07-28/learn/versioning)

[4]: [Microsoft WinVerifyTrust](https://learn.microsoft.com/en-us/windows/win32/api/wintrust/nf-wintrust-winverifytrust)
