# Forensic-goal لـ Resource Studio

## الغاية الاستراتيجية

الهدف هو تحويل Resource Studio من أداة تتحقق من أن الكتابة نجحت إلى منظومة تستطيع **إثبات ما الذي تغير، ولماذا تغير، وأن كل ما عدا التغيير المقصود بقي محفوظًا**. لا يعني ذلك إنشاء Forensics Module منفصل، ولا توسيع المشروع إلى malware scanner أو IOC engine أو YARA أو entropy maps أو hex viewer جديد. المطلوب هو تعميق ما هو موجود أصلًا: Resource Graph وDeep PE invariants وDifferential Verification وWindows Resource Oracle وIntegrity Diagnostics وAuthenticode وRound-trip Contracts وAudit Trail وCorpus.

> **Forensic identity:** Forensic integrity of PE transformation.
>
> السؤال المركزي: «ماذا تغير في هذا الملف، وهل نستطيع إثبات أن التغيير كان مقصودًا وأن كل شيء آخر بقي محفوظًا؟»

## مبدأ الاستقلال عن Writer

لا يكون نجاح Writer دليلًا على نفسه. ينتج Writer candidate أو output، ثم تقوم طبقة تحقق مستقلة بإعادة فتحه وتحليله عبر LIEF وWindows وinvariants وResource Graph وintegrity/signature diagnostics. بعد ذلك فقط يُنشأ الدليل ويُسجل في Audit Trail.

```text
Writer
  ↓
Candidate / Output
  ├── LIEF reopen
  ├── Deep PE invariants
  ├── Resource Graph
  ├── Windows Resource Oracle
  ├── Integrity / Authenticode
  └── Differential verification
          ↓
   Forensic Evidence Report
```

## الطبقات المستهدفة

| المعرّف | الطبقة | معيار الإثبات |
|---|---|---|
| FR-01 | Forensic baseline | لقطة قبل mutation تشمل SHA-256 وmachine وentry point وsections وdirectories وimports وexports وTLS وdebug وsecurity وoverlay وResource Graph، وتحفظ كـJSON artifact ذري عبر Writer أو CLI |
| FR-02 | Canonical Resource Graph | graph مستقر يميز type/name/language وraw/semantic/layout fingerprints ويكشف added/removed/changed/unintended leaves |
| FR-03 | Deep PE preservation | مقارنة مستقلة للهندسة والعناوين والجداول الحساسة: imports وexports وTLS وLoad Config وDebug وOverlay وsections وdirectories |
| FR-04 | Forensic differential | تقرير Targeted/Resource tree/PE/Integrity وbyte-range preservation map بدلاً من `changed=true` فقط؛ أي `UNEXPECTED` byte يفشل evidence |
| FR-05 | Mutation attribution | ربط الفرق بـoperation وresource key وexpected payload وoperation id؛ مثال: `Operation #14 Replace Icon` |
| FR-06 | Independent corroboration | pure loader وraw resource parser يقدمان corroboration مستقلة على كل منصة، ومطابقة LIEF مع Win32 loader قبل/بعد وتسجيل status وpolicy على Windows، دون اعتبار Writer مصدر الحقيقة |
| FR-07 | Evidence report | تقرير machine-readable وhuman-readable يحفظ baseline/result/diff/preservation/integrity/Rich Header/signature/oracle/audit metadata، وchain/env fingerprint، ويفصل passed عن verified ويعلن platform-limited؛ EvidenceLedger اختياري لكشف العبث |
| FR-08 | Forensic UX | Summary → Details → Technical evidence، مع عرض verified/platform-limited وpure-loader status، وتطبيق UX-06/07/08 فقط لعرض الدليل والوصول إليه واختباره |
| FR-09 | Regression hardening | corpus وstructure-aware fuzzing وcrash consistency وdifferential fixtures وraw-parser/preservation/determinism contracts قابلة لإعادة التشغيل |

## شكل الدليل المطلوب

```text
FORENSIC DIFFERENCE

Operation: #14 Replace Icon
Targeted:
  RT_ICON / 1 / 1033
  SHA256: X → Y

Resource tree:
  1 intended node changed
  0 unintended nodes changed
  RT_ICON / 2 / 1033 unchanged
  VERSION unchanged
  MANIFEST unchanged

PE preservation:
  Sections       PRESERVED
  Imports        PRESERVED
  Exports        PRESERVED
  TLS            PRESERVED
  Load Config    PRESERVED
  Debug          PRESERVED
  Overlay        PRESERVED

Integrity:
  Checksum       UPDATED / UNCHANGED / INVALID
  Authenticode   VALID / INVALIDATED / NOT_SIGNED / SKIPPED

Corroboration:
  LIEF           PASSED
  Windows        PASSED / SKIPPED / MISMATCH

Conclusion:
  PASS — targeted transformation corroborated
```

تُشتق هذه القيم من VerificationReport وDeepPEInvariantReport وResourceGraph وPEIntegrityReport وWindows oracle. لا يجوز للواجهة أن تعيد حسابها أو تصنع حكمًا موازيًا؛ دورها presentation وprogressive disclosure فقط. يعرض WPF حاليًا طبقة `Technical evidence` من JSON الناتج، بينما يبقى viewer التفاعلي متعدد التفاصيل لاحقًا.

## Baseline → Mutation → Result

قبل أي mutation يُحفظ baseline immutable في الذاكرة وartifact JSON ذري عند مسار العملية، ويتضمن hash للمدخل ومكونات PE وResource Graph. يوفر CLI الأمر `forensic-baseline` لإنشاء artifact صريح قبل التعديل. بعد serialization وreopen يُبنى result baseline مستقل، ثم ينفذ differential verifier المقارنة. تُحسب byte-range preservation map وتقارن target/resource/header ranges، وأي `UNEXPECTED` byte يجعل forensic difference غير ناجح. يُعاد raw resource parser قراءة النتيجة ويقارنها مع ResourceGraph. بعد commit يُعاد فتح الهدف ويُحسب `verifiedSha256` للbytes المستقرة. لا يُستبدل baseline بملف output ولا يُسمح للـreport أن يعتمد على object writer الداخلي.

| المرحلة | السؤال | النتيجة |
|---|---|---|
| Baseline | كيف كان الملف قبل التعديل؟ | PE baseline hash وstructural/resource snapshot |
| Mutation plan | ما العملية المقصودة وعلى أي target؟ | operation وresource key وexpected semantic/raw payload |
| Result | ماذا خرج بعد serialization وreopen؟ | result snapshot مستقل |
| Differential | ما الذي اختلف؟ | target/resource-tree/PE/integrity diff |
| Attribution | هل الفرق يطابق العملية؟ | expected vs observed مع unintended changes |
| Evidence | هل يمكن إعادة بناء الحكم؟ | report canonical قابل للحفظ وإعادة القراءة |

## حدود Forensic-goal

لا يشمل هذا الهدف timeline عامًّا، ولا تحليل malware، ولا IOC/YARA/PEiD، ولا محرك entropy، ولا إعادة بناء navigation، ولا polish شامل. تُنجز من UX فقط الأجزاء التي تجعل الأدلة مفهومة وقابلة للوصول: UX-06 keyboard/accessibility الأساسية، UX-07 progressive disclosure، وUX-08 reliability workflows.

## Definition of Done

يُعد Forensic-goal محققًا عندما يستطيع Save أن ينتج baseline وresult مستقلين، ويعرض فرقًا موجّهًا إلى target، وينسب الفرق إلى operation وexpected payload، ويثبت preservation للـPE غير المستهدف وbyte budget غير متوقعه صفر، ويقارن LIEF مع raw parser ومع Windows حيث يتوفر oracle، ويعلن platform limitations دون تحويل SKIPPED إلى verified، ويتحقق من bytes بعد commit وdeterminism للعقد المدعومة، ويوثق checksum/Rich Header/signature/commit state، ويحفظ report قابلًا لإعادة التشغيل دون الاعتماد على ادعاء Writer وحده.
