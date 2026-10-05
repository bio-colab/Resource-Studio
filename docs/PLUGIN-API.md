# Plugin API — الإصدار الأول

## الحالة

منفذ ومختبر: manifest registry والصلاحيات، وتشغيل الإضافة خارج العملية عبر `PluginHost` (JSON-lines مع staging ورفض symlinks وحدود timeout/ذاكرة/CPU وتعطيل تلقائي عند الانهيار)، وبوابة dry-run (`dry_run_registered`)، وأدوات MCP إدارية (`inspect_plugin` و`plan_plugin_execution` و`apply_plugin_execution` و`enable_plugin`) بتأكيد وadmin token. سطح `PluginContext` (قراءة/كتابة الموارد وexecute_command/undo_command مع History) منفذ كعقد SDK: مستهلكوه الحاليون الاختبارات، والمستهلكون المصممون الإضافات الخارجية (PLUG-07، EXT-02/03، PROD-12).

## Manifest

```json
{
  "id": "com.example.xliff-importer",
  "name": "XLIFF Importer",
  "version": "1.0.0",
  "api": "resource-editor/v1",
  "entry": "plugin.wasm",
  "kind": "importer",
  "permissions": ["project.read", "files.read"]
}
```

المعرّف lowercase بطول محدود، والإصدار Semantic Version، والـ API الحالي `resource-editor/v1`. الأنواع المعتمدة هي viewer وeditor وimporter وexporter وparser وpanel وautomation.

## الصلاحيات

| الصلاحية | معناها |
|---|---|
| `project.read` | قراءة نموذج المشروع |
| `project.modify` | طلب تعديل عبر Command API |
| `files.read` | قراءة ملفات يوافق عليها المشروع |
| `files.write.project-output` | الكتابة إلى output المشروع فقط |
| `network` | اتصال شبكي صريح، غير ممنوح افتراضيًا |
| `process.execute` | تشغيل عملية خارجية، مؤجل ومقيّد |
| `clipboard.read/write` | التعامل مع الحافظة، غير ممنوح افتراضيًا |

لا تُقبل صلاحية غير معروفة. `PluginContext.require` يرفض كل صلاحية غير موجودة في manifest.

## مسار التنفيذ

plugin host يعمل خارج العملية الأساسية ويتواصل عبر JSON-lines. يرسل host طلبًا يحمل operation وresource snapshot، ولا يمنح plugin handle مباشرًا إلى ملفات النظام. أي تعديل يعود كـ Command أو Patch قابل للمراجعة، ولا يكتب plugin إلى الأصل. صلاحية `project.read` وحدها مدعومة في وقت التشغيل حاليًا؛ بقية الصلاحيات ترفض عند منحها حتى جهوزية sandbox adapters المتخصصة.

## ما تم تأجيله

WASM وNative ABI و.NET وLua/JavaScript لم تُفعّل. لن تضاف لغة تنفيذ جديدة قبل وجود: protocol version، إلغاء، سجل أعمق، وpermission gate أوسع. sandbox adapters لصلاحيات `network` و`process.execute` و`clipboard` و`files.write.project-output` مؤجلة أيضًا؛ entrypoint بلغة Python عبر JSON-lines مدعوم فعليًا مع العزل والحدود الحالية.
