# Batch Workspace manifest

يستخدم Batch Workspace صيغة JSON التالية:

```json
{
  "format": "resource_studio.batch.v1",
  "jobs": [
    {
      "input": "input-a.dll",
      "output": "out/input-a.updated.dll",
      "operations": [
        {
          "action": "replace",
          "type": "MANIFEST",
          "name": 1,
          "language": 1033,
          "dataFile": "payload/manifest.xml"
        }
      ]
    },
    {
      "input": "input-b.exe",
      "output": "out/input-b.updated.exe",
      "operations": [
        {
          "action": "change-language",
          "type": "DIALOG",
          "name": 101,
          "sourceLanguage": 1033,
          "targetLanguage": 1049
        }
      ]
    }
  ]
}
```

المسارات النسبية تُفسر بالنسبة إلى مجلد manifest. العمليات المدعومة هي `add` و`replace` و`delete` و`change-language`. تحتاج `add` و`replace` إلى `type` و`name` و`language` و`dataFile`؛ ويحتاج `add` إلى اسم رقمي لأن LIEF يضيف المورد إلى شجرة PE.

## Plan

```powershell
py -3.12 resource_studio_cli.py batch plan batch.json --json
```

يقرأ الأمر كل ملف، ينفذ العمليات في staging مؤقت، يعيد فتح النتائج ويتحقق منها، ويعرض hashes ونتائج العمليات دون إنشاء ملفات المخرجات المطلوبة.

## Apply

```powershell
py -3.12 resource_studio_cli.py batch apply batch.json --report batch-report.json --json
```

لا يسمح المسار بالكتابة in-place. تُجهز كل الوظائف أولًا، ثم تُنقل المخرجات إلى مسارات Save As فقط. إذا كان output موجودًا يُحفظ `*.batch.bak`. وإذا فشل الالتزام بعد بدء النقل، تُستعاد المخرجات التي تم الالتزام بها من نسخها الاحتياطية.

> لا تضع `external executable` أو أي ملف أصلي مهم داخل `output`، ولا تجعل `output` مساويًا لأي `input`. Batch Workspace يرفض ذلك صراحة.
