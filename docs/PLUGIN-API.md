# Plugin API — الإصدار الأول

## الحالة

تم تنفيذ manifest registry وصلاحياته فقط. لا يشغل الإصدار الحالي entrypoint ولا يستورد كود plugin داخل العملية الأساسية. هذا الفصل مقصود إلى أن يكتمل العزل خارج العملية والاختبار ضد الانهيار.

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

## مسار التنفيذ المعتمد لاحقًا

يبدأ plugin host خارج العملية الأساسية ويتواصل عبر JSON-lines أو قناة محلية محددة. يرسل host طلبًا يحمل operation وresource snapshot، ولا يمنح plugin handle مباشرًا إلى ملفات النظام. أي تعديل يعود كـ Command أو Patch قابل للمراجعة، ولا يكتب plugin إلى الأصل.

## ما تم تأجيله

WASM وNative ABI و.NET وPython/Lua/JavaScript لم تُفعّل. لن تضاف لغة تنفيذ جديدة قبل وجود: protocol version، timeout، إلغاء، حدود ذاكرة، سجل، permission gate، وتعطيل plugin المتسبب بانهيار.
