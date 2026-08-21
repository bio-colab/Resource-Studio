# مراجعة توصيات الخبير الجنائي — الجولة الثانية

**التاريخ:** 2026-08-21

## القرار العام

التوصية كشفت فجوات حقيقية داخل Forensic-goal، خصوصًا غياب خريطة byte-range مستقلة وغياب parser خام يقارن مخرجات LIEF. أُخذت هذه الفجوات بجدية، لكن لم تُقبل البنود التي توسع المشروع إلى تحليل سلوكي أو steganography أو تتطلب عزلًا مبالغًا فيه لنداء Win32 لا ينفذ كود PE.

| التوصية | القرار | التنفيذ أو الحد |
|---|---|---|
| سلسلة اشتقاق evidence | مقبول | أضيفت `prevSha256` وenvironment fingerprint وcommand line وsha256 قابل لإعادة البناء إلى `ForensicEvidence`. يبقى ربط كل Project mutation تلقائيًا بledger واحد لاحقًا. |
| byte-range preservation map | مقبول ومطبق | أضيف `PreservationMap` يصنف التغييرات إلى target resource وresource container وheader recalc و`UNEXPECTED`. أي unexpected byte يجعل forensic difference غير ناجح. |
| raw resource parser | مقبول بحدود | أضيف parser مستقل يقرأ PE headers وresource directory وdata entries ويدعم نموذج type/name/language القياسي. يقارن SHA ومفاتيح الموارد مع ResourceGraph، ولا يدعي تغطية كل امتدادات PE غير القياسية. |
| deterministic serialization | مقبول جزئيًا | ثُبت COFF timestamp الأصلي وأضيف اختبار repeated mutation SHA equality. لم تُفرض إعادة كتابة padding أو SOURCE_DATE_EPOCH عالميًا لأن ذلك قد يغير binary أكثر مما يحميه. |
| checksum/AuthentiCode | مطبق جزئيًا مسبقًا | checksum وsignature state مركزيان، وتغيير signed PE محظور في Writer العادي. أضيف Rich Header hash/preservation signal؛ مسار strip/re-sign يبقى explicit ومفصولًا. |
| Job Object وnamed-pipe isolation للـWindows oracle | مرفوض كتعقيد غير مثبت | oracle الحالي يستخدم `LoadLibraryExW` بعلمي `LOAD_LIBRARY_AS_IMAGE_RESOURCE` و`LOAD_LIBRARY_AS_DATAFILE_EXCLUSIVE`، ولا يشغل entrypoint. تبقى مقارنة Win32 مستقلة وWindows-gated، دون إنشاء daemon أو side-effect telemetry غير مطلوب. |
| entropy وssdeep وTLSH وrecursive MZ/steganography | مرفوض خارج النطاق | هذه تنقل المشروع إلى malware/hidden-payload analytics، وهو خارج Forensic-goal المقصود. لا تُضاف مؤشرات risk غير قابلة لتفسير preservation evidence. |

## مبدأ الدليل

> **لا يكفي أن يقول LIEF إن الملف صالح. يجب أن يوضح التقرير ما الذي تغير، وأين تغير، ولماذا يُسمح به، وما الذي corroborated مستقلًا.**

لذلك أصبح التقرير يجمع بين LIEF/invariants وbyte map وraw resource parser وWindows oracle حيث يتوفر. وفي الوقت نفسه لا تُعرض نتيجة parser خام على أنها Windows loader truth؛ كل طبقة تحمل status مستقلًا، وأي اختلاف يظل مرئيًا بدل تسويته إلى `passed`.

## حدود القراءة الخام

الـraw parser يقرأ minimal PE resource model: DOS/PE headers، section table، resource data directory، ثم type/name/language directory nodes و`IMAGE_RESOURCE_DATA_ENTRY`. هذا يكفي لإثبات corroboration للمورد المعتاد في corpus الحالي، لكنه لا يدعي معالجة كل malformed tree أو MUI/LN policy أو resource layouts غير القياسية. هذه الحالات تبقى regression work لا تُخفى خلف نجاح LIEF.

## ما بقي لاحقًا

تبقى provenance Project-wide الذي يمرر `prevSha256` تلقائيًا بين جميع mutations، وتوسيع raw parser coverage، وAtheris corpus طويل التشغيل مع crash minimization، وتقرير forensic متعدد الصيغ. لا تشمل الخطة entropy أو steganography أو recursive payload scanning أو timeline عام.
