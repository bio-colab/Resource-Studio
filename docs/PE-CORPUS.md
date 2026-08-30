# PE Corpus

لا تكفي كثرة الاختبارات إذا كانت جميعها تمر على PE واحد. لذلك يحتوي المستودع الآن على corpus صغير لكنه متنوع وقابل لإعادة البناء، مع SHA-256 وtoolchain وarchitecture وprofile وresource coverage لكل PE في [`tests/corpus_manifest.json`](../tests/corpus_manifest.json).

> الـcorpus يختبر parser وinspector وresource graph وwriter على ملفات متعددة، لكنه لا يدّعي تمثيل كل تاريخ PE أو كل packer أو كل compiler.

## التغطية الحالية

| Profile | Architecture | Provenance | الحالة | ما يغطيه |
|---|---|---|---|---|
| Reference resource fixture | x64 | `sample.dll` الموجود سابقًا | متاح | baseline للموارد والـraw/typed paths |
| MinGW minimal | x86 وx64 | مولد من مصدر C محلي بواسطة MinGW-w64 13.2 | متاح | PE32 وPE32+، code/import/export/TLS paths |
| MinGW resource-heavy | x86 وx64 | مولد محلي بواسطة C وRC وMinGW-w64 13.2 | متاح | named/numeric resources، multiple languages، STRINGTABLE، MENU، DIALOGEX، VERSIONINFO، RCDATA |
| Weird alignment | x64 | linker flags `SectionAlignment=0x200` و`FileAlignment=0x200` | متاح | non-page section alignment وbounds/alignment checks |
| Packed benign | x64 | MinGW fixture مضغوط بـUPX 4.2.2 | متاح | static packed-code indicators؛ لا يمثل malware |
| Overlay | x64 | MinGW fixture مع overlay bytes deterministic | متاح | overlay preservation وstatic overlay indicators |
| Test signed | x64 | MinGW fixture موقّع بشهادة اختبار مولدة محليًا عبر osslsigncode 2.8 | متاح | certificate-table/signature state؛ الشهادة ليست هوية ناشر موثوقة |
| Malformed/negative | غير PE أو حالات تلف لاحقة | fixtures نصية وmalformed corpus | متاح جزئيًا | rejection وclassification دون كتابة |

يُعاد بناء generated fixtures بواسطة:

```bash
python3 tools/build_pe_corpus.py
python3 tests/qa/test_corpus_manifest.py
python3 tests/qa/test_pe_corpus_matrix.py
```

لا يُشغّل builder أي PE. فهو يترجم مصادر C/RC، يضغط fixture benign، ويوقع نسخة بشهادة اختبار. أما فحص كل fixture داخل الاختبارات فهو read-only؛ لا توجد حاجة إلى administrator أو إلى لمس `C:\Program Files (x86)\Resource Hacker\`.

## الفجوات الصريحة

| Profile مطلوب | الحالة | الإجراء الصحيح التالي |
|---|---|---|
| ARM64 PE | غير مضاف بعد | إدخال fixture مولد من ARM64 toolchain موثق أو بناء Windows ARM64؛ لا نستخدم ملفًا مجهول المصدر |
| Old MSVC | غير مثبت | إضافة artifact يمكن إثبات toolchain الخاص به وحقوق توزيعه |
| Modern MSVC | غير مثبت | إضافة fixture من Visual Studio/Build Tools مع provenance وترخيص واضح |
| Delphi | غير مثبت | إدخال fixture benign يمكن نسبه إلى Delphi compiler أو مصدر عام يسمح بالتوزيع |
| .NET PE | غير مثبت في corpus الحالي | بناء fixture managed محليًا ثم تسجيل CLR metadata وRID/SDK |
| Authenticode حقيقي موثوق | غير مطلوب للـtest corpus | يبقى test-signed منفصلًا؛ لا تُضمّن شهادة ناشر حقيقية |

هذه الفجوات ليست failures مخفية؛ ستبقى ظاهرة في خطة corpus حتى تُضاف artifacts قابلة للتحقق. لا نستخدم binaries من Windows أو الإنترنت داخل المستودع لمجرد ملء الخانات، لأن provenance وحقوق التوزيع جزء من قيمة corpus.

## ملاحظات الاختبار

يُجري `test_corpus_manifest.py` تحقق SHA-256 وPE parse وmetadata coverage، بينما يُجري `test_pe_corpus_matrix.py` read-only smoke checks على كل PE entry قبل تشغيل mutation chain التاريخية على `sample.dll`. كشف corpus أيضًا اختلافًا حقيقيًا في تمثيل TLS لدى LIEF بين x86/x64؛ عولج بتطبيع range tuple إلى RVA/VA scalar مستقر في `core/pe_inspector.py`.

## مرجع

[1]: https://learn.microsoft.com/en-us/windows/win32/debug/pe-format "Microsoft PE Format"
