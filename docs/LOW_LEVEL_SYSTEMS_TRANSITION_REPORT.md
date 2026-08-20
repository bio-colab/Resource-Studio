# دراسة انتقالية في Low-Level & Systems Programming لـ Resource Studio

## الملخص التنفيذي

الانتقالة النوعية الحقيقية لـ **Resource Studio** لا تأتي من إضافة محررات جديدة أو زيادة عدد أوامر CLI، بل من تغيير طبيعة النواة نفسها: من أداة تعدّل الموارد عبر LIEF إلى **محرك تحويل PE قابل للإثبات والتحقق المستقل**. الفارق جوهري. الأداة التقليدية تقول: «استطعت فتح الملف وكتابته». أما الأداة الناضجة فتقول: «أجريت تغييرًا محددًا، وأثبتُّ أن المورد تغيّر كما طلب المستخدم، وأن كل بنية PE غير مستهدفة بقيت سليمة، وأن Windows نفسه يستطيع تحميل الموارد من الناتج، وأن حالة checksum والتوقيع والالتزام على القرص معروفة بدقة».

مواصفة Microsoft تصف PE/COFF كتنسيق مترابط يضم headers وsections وdata directories وresource table وTLS وdebug وload configuration وcertificate table، وتفرّق صراحة بين file pointers وRVA وVA؛ لذلك لا يكفي اختبار أن LIEF أعاد فتح الملف بعد الكتابة [1]. كما أن Authenticode لا يحسب hash مسطحًا لكل bytes الملف، بل يستثني حقولًا محددة مثل checksum وCertificate Table directory، مما يجعل SHA-256 العادي مؤشرًا للتغير لا حكمًا على صحة التوقيع [2].

> **الخلاصة المركزية:** أقوى ما يمكن فعله الآن هو تقوية الحدود بين المراحل الموجودة أصلًا: parser، writer، invariant checker، Windows loader، signature verifier، filesystem commit، process isolation، وUI process boundary. لا ينبغي إنشاء طبقة PE بديلة كاملة ولا إضافة ميزات مرئية جديدة قبل أن تصبح هذه الحدود عقودًا قابلة للاختبار.

## الحكم على الوضع الحالي

البنية الحالية قوية من ناحية الاتجاه الهندسي. `LiefPEWriter` يرفض الكتابة داخل الملف، يعمل عبر Save As، يكتب إلى temporary file، يعيد فتح الناتج، يتحقق من المورد المستهدف، ويقارن مجموعة من invariants تشمل machine وimagebase وentrypoint وnon-resource sections وdirectories وimports وexports وoverlay وTLS وload configuration وdebug. كما أن دورة الاستقرار الأخيرة أضافت rollback يحافظ على output الموجود عند فشل validation حتى عندما لا يُطلب backup معلن.

لكنها ما تزال أقرب إلى **صحة داخلية يثبتها LIEF** من كونها صحة نظامية يثبتها Windows نفسه. `PEHealth` يتحقق من offsets والأحجام التي يعرضها LIEF، و`ResourceIndex` يقدم فهرسة مناسبة، إلا أنه لا توجد بعد مطابقة مستقلة مع Windows loader. كما أن invariant snapshot لا يصف resource tree نفسه كعقد type/name/language/data، ولا يملك Windows checksum oracle، ولا يميز في تقريره بين flat hash وAuthenticode digest وحالة certificate table.

في طبقة Windows، `WindowsJob` يفرض active-process limit وprocess-memory limit و`KILL_ON_JOB_CLOSE`. هذا أساس جيد، لكنه يحتاج اختبارات descendants فعلية وحدود CPU والزمن والإشعارات، لأن Job Object في Windows مصمم لإدارة مجموعة عمليات وشجرة عمليات وفرض حدود ومحاسبة وإنهاء موحد [6]. وفي WPF، جرى تحسين قراءة stdout وstderr بالتوازي، لكن الأفضل مستقبلًا أن يصبح تشغيل CLI عقدًا stateful واضحًا بدل أن يبقى استدعاء process متزامنًا تتداخل نتيجته مع تحديث الواجهة.

| الطبقة الحالية | ما تثبته الآن | ما ينقصها لتصبح طبقة systems-grade |
|---|---|---|
| LIEF parser/builder | القدرة على parse/write وإعادة فتح الناتج | oracle مستقل لا يعتمد على LIEF وحده |
| Writer | Save As وresource verification وprotected invariants | resource-tree invariants وchecksum/certificate semantics وdurable commit |
| PEHealth | PE validity وفهرس الموارد وoffset bounds | Windows loader walk وsection/resource alignment وnative checksum |
| Round-trip | اختبارات typed وraw وcorpus matrix | عقود byte/semantic/canonical واضحة لكل serializer |
| PE corpus | fixture وcorpus matrix محددان | taxonomy حتمي، ملفات MUI/LN وPE32/PE32+ وموقعة وغير موقعة |
| Isolation | Job Object limits أساسية | descendant stress tests وCPU/time/notification enforcement |
| WPF | UI automation وBMP preview وCLI plumbing | process state model وerror taxonomy وcancellation وaccessibility contract |

## الانتقالات النوعية المقترحة

### 1. Windows Loader Oracle: أعلى عائد بأقل تغيير في المنتج

هذه هي الأولوية الأولى. توثق Microsoft أن `LoadLibraryEx` مع `LOAD_LIBRARY_AS_DATAFILE` أو `LOAD_LIBRARY_AS_IMAGE_RESOURCE` يسمح بتحميل module كبيانات أو image resource دون تحميله كـDLL تنفيذي، وأن `FindResource` و`FindResourceEx` يستطيعان استخدام هذا النوع من mapping [8]. كما أن image-resource mapping يوسع section alignment بحيث يمكن التعامل مع RVA بصورة أقرب إلى طريقة Windows في الوصول إلى الموارد.

التقوية المقترحة ليست زرًا جديدًا للمستخدم. إنها test/validation adapter على Windows، يعمل بعد كل Save As مهم أو في بوابة QA. يحمّل الملف الناتج كـdata/image resource، يعدّد أنواع الموارد وأسماءها ولغاتها، يستدعي `FindResourceEx` و`SizeofResource` و`LoadResource`، ثم يقارن `(type, name, language, size, bytes)` مع فهرس LIEF و`ResourceIndex`.

| معيار النجاح | ما يجب إثباته |
|---|---|
| identity | كل type/name/language في LIEF يطابق Windows، والعكس صحيح |
| size | `SizeofResource` يساوي حجم المورد المفهرس |
| bytes | bytes المحملة من Windows تساوي bytes الناتجة من LIEF |
| safety | module لا يُحمّل ككود ولا تُستدعى DllMain |
| failure | ملفات resource tree المكسورة تُرفض برسالة تشخيصية محددة |

هذا الاختبار سيكشف عيوبًا لا تكشفها إعادة الفتح عبر LIEF، مثل أخطاء في language leaves أو resource directory alignment أو مسارات يفسرها LIEF بتسامح بينما يرفضها Windows.

### 2. PE Invariant Graph بدل قائمة invariants مسطحة

الحماية الحالية جيدة لكنها تمثل أجزاء PE كحقول منفصلة. الانتقال الأفضل هو تحويلها إلى **graph of protected relationships**. لا يكفي أن يكون `directories` متساويًا؛ يجب ربط كل data directory بالقسم الذي يحتويه، وفحص أن RVA وraw offset وvirtual size وraw size والعناوين لا تتناقض.

يُقترح توسيع `PEInvariantSnapshot` إلى مجموعات مستقلة:

| مجموعة الحماية | أمثلة على العلاقات |
|---|---|
| Image identity | machine، imagebase، subsystem، DLL characteristics، entrypoint |
| Section geometry | section alignment، file alignment، RVA/raw mapping، characteristics، non-resource section bytes/shape |
| Directory ownership | كل directory إلى section owner، bounds، alignment، resource exclusion الصريح |
| Resource tree | type/name/language hierarchy، duplicate leaves، data RVA، size، code page |
| Security | checksum، certificate directory، certificate offset/size، signature presence/count |
| Runtime metadata | imports، exports، TLS، load config، debug، relocations |
| Tail data | overlay offset/size/hash، certificate table distinction عن overlay |

العقدة المهمة هنا هي التمييز بين **protected**, **allowed-to-change**, و**recomputed**. مثلًا، checksum قد يتغير بصورة صحيحة، وresource section قد يعاد بناؤه، بينما imports أو TLS لا ينبغي أن تتغير في resource-only operation. هذا يمنع التشدد الخاطئ الذي يرفض كل تغيير مشروع، كما يمنع التساهل الذي يمرر تغييرًا جانبيًا.

### 3. Windows checksum oracle وليس مجرد checksum field

توثق Microsoft أن `CheckSumMappedFile` مخصص للتطبيقات التي تنشئ أو تعدل executable images، وأنه يعيد checksum جديدًا، وأن checksums مطلوبة خصوصًا لـkernel-mode drivers وبعض system DLLs [3]. كما توضح الوثيقة أن على المستدعي وضع checksum الجديد داخل image وتحديث النسخة الموجودة على القرص.

التقوية العملية هي إضافة طبقة Windows QA تستدعي `CheckSumMappedFile` أو `MapFileAndCheckSum` على الناتج، ثم تقارن:

1. checksum stored في Optional Header؛
2. checksum الذي يحسبه LIEF؛
3. checksum الذي تحسبه ImageHlp؛
4. `checksum_valid` في التقرير؛
5. نوع الملف: user-mode PE أم driver/system-like corpus member.

لا ينبغي أن يتولى هذا المسار تعديل checksum تلقائيًا دون قرار موثق؛ الأفضل أولًا أن يكتشف divergence ويصنفه. بعد ذلك يمكن جعل Writer يقرر، حسب policy، هل يعيد حساب checksum أم يعرض أن output يحتاج إلى خطوة Windows-specific post-processing.

### 4. Commit protocol حقيقي: atomic naming مقابل durable persistence

الحالة الحالية تستخدم temporary file ثم `os.replace`. هذا يوفر حماية ممتازة ضد ملف جزئي في كثير من الحالات، لكنه لا يساوي تلقائيًا ضمانًا بأن البيانات وصلت إلى وسيط التخزين عند انقطاع الطاقة. توضح Microsoft أن `ReplaceFile` يستبدل ملفًا بآخر ويمكنه إنشاء backup، وأن backup والملف المستبدل والملف البديل يجب أن تكون على نفس volume [4]. كما تذكر أن `FlushFileBuffers` يفرغ buffers ويجعل البيانات تُكتب إلى الجهاز، مع تحذيرات أداء مرتبطة بكثرة الاستدعاء [5].

الانتقال النوعي هو تقسيم العملية إلى حالات صريحة:

```text
BUILD_TEMP
  -> VALIDATE_TEMP
  -> FLUSH_TEMP
  -> COMMIT_SAME_VOLUME
  -> FLUSH_DIRECTORY_POLICY
  -> REOPEN_AND_VERIFY
  -> PUBLISH_RESULT
```

على Windows، يجب أن يكون adapter قادرًا على استخدام `ReplaceFile` عندما يكون ذلك متاحًا، مع temporary على نفس volume. أما cross-volume Save As فيجب أن يُصنف كـcopy/export وليس atomic replacement. ويجب أن يسجل التقرير مستوى الضمان: `logical-atomic`, `same-volume-replace`, أو `durability-verified` بدل استخدام كلمة atomic بلا تحديد.

### 5. Differential resource oracle: LIEF مقابل Win32 UpdateResource/FindResource

توثق Microsoft أن `UpdateResourceW` يضيف أو يحذف أو يستبدل raw resource data، وأن التغييرات لا تُكتب فعليًا حتى `EndUpdateResource`، وأن البيانات predefined يجب أن تكون valid وproperly aligned، وأن النصوص يجب أن تكون Unicode. كما تفرض Windows قيودًا خاصة على LN وMUI files عند الإضافة والتعديل والحذف وتغيير اللغة [9].

لا أوصي باستبدال LIEF بـ`UpdateResource`. الأفضل استخدامه كـ**differential oracle** في Windows test suite. تُنشأ حالات صغيرة وآمنة مثل replace RCDATA أو add/delete resource، ويُقارن الناتج من المسارين في resource tree والbytes واللغات. أما MUI/LN فيجب تصنيفها صراحة بدل معاملتها كـordinary PE.

هذا سيكشف فرقًا مهمًا بين «المورد الذي يقبله LIEF» و«المورد الذي تتعامل معه Win32 resource APIs كما يتوقع المطورون». وهو تقوية لتغطية الموارد، لا feature جديدة.

### 6. Round-trip contracts: byte، semantic، canonical

توضح دراسة PLClub أن round-trip property في parser/printer تعني serialize ثم parse ومقارنة الناتج مع البنية الأصلية، لكنها تشدد على ضرورة preconditions تفصل المدخلات غير القابلة للتحليل عن failures الحقيقية [11].

في Resource Studio يجب ألا تستخدم كل serializers معيار byte identity نفسه. التوصيف الصحيح هو:

| نوع العقد | الاستخدام المناسب |
|---|---|
| Byte-preserving | raw payload وRCDATA وbytes غير المفسرة |
| Semantic-preserving | Menu وDialog وManifest وVersionInfo وStringTable |
| Canonical-preserving | النماذج التي تعيد ترتيب padding أو alignment أو تمثيل XML |
| PE-transform-preserving | Writer الذي يثبت أن كل ما هو خارج نطاق العملية لم يتغير دلاليًا |

لكل parser/serializer يجب تسجيل normalization rules: padding، ordering، empty strings، XML declaration، UTF-16 terminators، resource language IDs، وicon mask. عندها تصبح failure reports مفيدة بدل رسالة عامة مثل round-trip failed.

### 7. Coverage-guided parser fuzzing بدل bounded random fuzzing فقط

تصف LLVM libFuzzer بأنه in-process coverage-guided evolutionary fuzzer؛ harness يستقبل bytes عشوائية أو malformed ويجب أن يتحمل empty وhuge inputs، وتُبنى mutations اعتمادًا على coverage [10].

المشروع يملك bounded fuzzing وmalformed corpus، وهذا جيد. الانتقال النوعي هو بناء harness لكل parser داخلي، وليس fuzzing PE writer كله في البداية:

| Harness | oracle |
|---|---|
| RES | parse ثم serialize ثم parse normalized records |
| StringTable | 16-slot semantic equality وlength bounds |
| VersionInfo | tree validity وUTF-16 boundaries وblock lengths |
| Manifest | XML parse/validation وعدم crash على namespaces غريبة |
| Menu/Dialog | offset alignment وterminator rules وعدم excessive allocation |
| DIB/ICON/CURSOR | dimensions، bit depth، mask bounds، PNG fallback limits |
| Resource tree | recursion depth، node count، duplicate leaves، data size |

يجب تصنيف outcomes إلى `accepted`, `expected-rejected`, `crash`, `hang`, `timeout`, `excessive-allocation`, و`non-canonical-output`. والأهم أن corpus يُحفظ كأصول صغيرة deterministic، لا كأرقام random لا يمكن إعادة تفسيرها.

### 8. PE corpus علمي لا fixture واحد

الـcorpus الحالي تحسن بإضافة matrix يغطي RCDATA وBITMAP وICON وGROUP_ICON وSTRING وVERSION وتغيير اللغة والحذف. لكن الانتقال النوعي هو تحويل corpus إلى **taxonomy**:

| المحور | العينات التي ينبغي تثبيتها |
|---|---|
| architecture | PE32، PE32+، DLL، EXE، SYS-like عندما يمكن اختباره بأمان |
| resource state | لا resources، resource section صغيرة، section كبيرة، overlay، أسماء نصية ورقمية |
| language | 1033، 1025، neutral، multiple languages، language change |
| signature | unsigned، signed fixture، invalidated signature بعد تعديل، certificate table/padding |
| sections | unusual alignment، resource section ليست آخر section، overlay بعد certificate table |
| Windows localization | LN/MUI samples مع policy explicit |
| malformed | truncation، bad offsets، duplicate leaves، oversized lengths، UTF-16 edge cases |

لكل corpus member يجب وجود metadata: source/provenance، architecture، signature state، expected parser outcome، expected Windows outcome، allowed normalization، وSHA-256. لا ينبغي تنزيل ملفات خارجية تلقائيًا؛ corpus الخارجي يجب أن يكون موثق المصدر ومراجعًا ومثبت hash.

### 9. Job Object كعقد containment قابل للإثبات

وجود `KILL_ON_JOB_CLOSE` وactive-process/memory limits بداية قوية، لكن لا يكفي وجود constants في الكود. يجب إنشاء stress harness يطلق child ثم grandchild ويحاول إبقاءهما بعد إغلاق host، ويقيس:

1. هل تم إنهاء كل descendants؟
2. هل حد active processes يمنع fork storm؟
3. هل memory cap يقتل العملية أو يعيد failure مصنفًا؟
4. هل timeout وCPU limit يعملان؟
5. هل handle cleanup يحدث عند exception وparent crash؟
6. هل يستطيع child فتح output خارج workspace أو الاتصال بالشبكة عندما تكون policy تمنع ذلك؟

هذه تقوية للعزل الموجود. لا يلزم إضافة نظام plugins جديد أو remote MCP.

### 10. UI كـprocess-state machine لا كواجهة أكثر ازدحامًا

التحسين الأعلى في WPF ليس إضافة tab. هو فصل حالات العملية الحالية إلى model واضح:

```text
Idle -> ResolvingCli -> Running -> ReadingOutput -> Validating -> Completed
                                             \-> Failed
                                             \-> Cancelled
```

كل state يجب أن يحدد status text وenabled controls وoutput path وwhether the result is verified. يمنع ذلك الحالات التي يظهر فيها زر Save أو Preview قابلًا للنقر بينما CLI ما زال يعمل أو فشل. ويجب أن ترتبط AutomationProperties بهذه الحالات، لا بالنصوص فقط. اختبار UI الحالي يمكن توسيعه للتحقق من disabled/enabled transitions بدل زيادة السيناريوهات السطحية.

## ترتيب الأولويات

| الأولوية | الانتقال | الأثر | المخاطر | هل هو feature جديد؟ |
|---:|---|---|---|---|
| P0 | Windows Loader Oracle | مرتفع جدًا | منخفض إلى متوسط | لا، validation adapter |
| P0 | Resource-tree invariant graph | مرتفع جدًا | متوسط | لا، تقوية invariant |
| P0 | Windows checksum oracle | مرتفع | منخفض | لا، diagnostic/QA |
| P0 | Durable same-volume commit | مرتفع جدًا | متوسط | لا، تقوية Save As |
| P1 | Differential UpdateResource tests | مرتفع | متوسط | لا، test oracle |
| P1 | Round-trip contract taxonomy | مرتفع | منخفض | لا، test/documentation |
| P1 | Corpus taxonomy وmetadata | مرتفع | منخفض | لا، test corpus |
| P1 | Parser-specific coverage-guided fuzzing | مرتفع | متوسط | لا، QA infrastructure |
| P1 | Job Object descendant stress tests | مرتفع | متوسط | لا، hardening |
| P2 | WPF process-state model | متوسط إلى مرتفع | متوسط | لا، UI reliability |
| P2 | provenance/reproducible validation manifest | متوسط | منخفض | لا، strengthening audit |

## خارطة تنفيذ جراحية مقترحة

### المرحلة A: إثبات ما بعد الكتابة

أضف `SYS-01 WindowsResourceOracle` و`SYS-02 ResourceInvariantGraph` و`SYS-03 ChecksumOracle`. لا تغيّر Writer behavior في البداية؛ اجعلها diagnostics فاشلة بوضوح. الهدف أن نعرف ما الذي يفعله Writer قبل أن نسمح له بتغيير أي policy.

### المرحلة B: تقوية الالتزام

أضف `SYS-04 DurableCommitProtocol`. اجعل commit adapter Windows-specific، واستخدم temporary same-volume وflush وReplaceFile عندما تكون العملية على Windows. احتفظ بمسار `os.replace` للبيئات الأخرى، لكن لا تسوِّ بين atomic naming وdurability في التقرير.

### المرحلة C: جعل الاختبارات عقودًا

أضف `SYS-05 RoundTripContractRegistry`، بحيث يعلن كل serializer هل عقده byte أو semantic أو canonical. أضف `SYS-06 CorpusManifest` مع hashes وexpected outcomes، ثم `SYS-07 ParserFuzzHarnesses` بميزانيات memory/time/depth.

### المرحلة D: إثبات العزل

أضف `SYS-08 JobTreeStress` و`SYS-09 WindowsProcessBoundary`. اختبر descendants وtimeouts وmemory limits وcleanup، ولا تكتفِ باختبار أن process واحدًا بدأ وانتهى.

### المرحلة E: جعل WPF مرآة للعقد

أضف `SYS-10 UiOperationStateContract`. لا تضف tabs. اربط status وbutton states وAutomationProperties بنتيجة CLI وverified flag، واختبر transitions الرئيسية.

## ما لا أوصي بفعله الآن

لا أوصي بكتابة PE writer بديل من الصفر؛ ذلك سيعيد إنتاج أعقد أجزاء alignment وdirectories وcertificate semantics التي يعالجها backend الحالي، ويزيد مساحة الخطأ. لا أوصي أيضًا بتحميل ملفات الهدف كـexecutable DLL للتحقق، فـWindows يوفر data/image resource mappings خصيصًا للوصول إلى الموارد دون تنفيذها [8].

لا أوصي بإضافة مزيد من resource editors قبل اكتمال Windows loader oracle وresource invariant graph. ولا أوصي بجعل Windows UpdateResource هو backend الإنتاجي؛ دوره الأفضل differential oracle، خصوصًا لأن Microsoft تذكر قيود LN/MUI التي تحتاج policy صريحة [9]. كما لا أوصي بفحص fuzzing على `LiefPEWriter` كاملًا قبل بناء parser harnesses أصغر؛ mutation على writer قد ينتج ملفات كبيرة أو جانبية ويصعّب تصنيف failure.

## خلاصة عملية

إذا نُفذت ثلاث تقويات فقط، فلتكن: **Windows loader oracle، invariant graph للـresource tree وPE geometry، وdurable same-volume commit مع checksum/signature diagnostics**. هذه الثلاثة سترفع المشروع من أداة تحرير موثوقة إلى بنية يمكن الوثوق بها عند التعامل مع ملفات PE حقيقية وحساسة.

أما إذا أضيفت ثلاث تقويات أخرى، فلتكن: **corpus taxonomy، parser-specific coverage-guided fuzzing، وJob Object descendant stress testing**. عندها لن يكون المشروع قويًا فقط في الحالة السعيدة، بل سيصبح قادرًا على اكتشاف الأخطاء، تصنيفها، وإثبات حدود سلامته.

> معيار القمة هنا ليس عدد الميزات. معيار القمة هو أن يستطيع المطور أن يجيب بدقة: ماذا تغيّر؟ ماذا لم يتغيّر؟ هل Windows يراه كما يراه Resource Studio؟ هل checksum والتوقيع معروفان؟ ماذا يحدث إذا انهارت العملية أو انقطع التيار؟ وهل يمكن إعادة إنتاج النتيجة من corpus وmanifest وhashes؟

## References

[1]: https://learn.microsoft.com/en-us/windows/win32/debug/pe-format "Microsoft PE Format"

[2]: https://learn.microsoft.com/en-us/windows/win32/secbp/understanding-pe-signatures "Microsoft Understanding Executable File Signing"

[3]: https://learn.microsoft.com/en-us/windows/win32/api/imagehlp/nf-imagehlp-checksummappedfile "Microsoft CheckSumMappedFile"

[4]: https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-replacefilea "Microsoft ReplaceFileA"

[5]: https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-flushfilebuffers "Microsoft FlushFileBuffers"

[6]: https://learn.microsoft.com/en-us/windows/win32/procthread/job-objects "Microsoft Job Objects"

[7]: https://lief.re/doc/latest/formats/pe/modifications/resources.html "LIEF Resources Modification"

[8]: https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-loadlibraryexa "Microsoft LoadLibraryExA"

[9]: https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-updateresourcew "Microsoft UpdateResourceW"

[10]: https://llvm.org/docs/LibFuzzer.html "LLVM libFuzzer"

[11]: https://www.cis.upenn.edu/~plclub/blog/2023-12-07-round-trip-properties/ "Penn PLClub: Exploring Round-trip Properties in Property-based Testing"


## حالة التطبيق بعد main-goal pass

أصبح جزء كبير من الملخص التنفيذي مطبقًا داخل البنية الحالية، دون إنشاء PE backend بديل أو إضافة محررات جديدة. يطابق `SYS-01` Windows Loader Oracle بين LIEF وWin32 loader من حيث type/name/language/size/bytes، ويضيف `SYS-02` resource-tree leaves وbounds/duplicate issues إلى `PEInvariantSnapshot`. يضيف `SYS-03` مقارنة stored/LIEF/ImageHlp checksum وحالة certificate/signature، بينما يضمن `SYS-04` flush وsame-volume commit عبر `ReplaceFileW` أو `MoveFileExW` مع rollback Writer.

كما صار `SYS-05` RoundTrip Contract Registry يميز بين byte وsemantic وcanonical contracts للنماذج الحالية، وصار `SYS-06` يستخدم `UpdateResourceW` على نسخة مؤقتة كـdifferential oracle. يثبت `SYS-07` corpus manifest hashes والتصنيف، ويطبق `SYS-08` bounded parser fuzz harness يصنف accepted وexpected-rejected وcrash وexcessive-allocation وoversize. يثبت `SYS-09` أن Job Object ينهي child وgrandchild، ويضيف `SYS-10` baseline لحالات WPF `Idle/Running/Completed/Failed` مع AutomationId واختبار UIA.

| المعرّف | الحالة الحالية | الفجوة المتبقية |
|---|---|---|
| SYS-01 | مكتمل ومختبر على Windows | توسيع corpus إلى MUI/LN وPE32+/ARM64X |
| SYS-02 | مكتمل ومختبر محليًا وعلى Windows | ربط كل data directory بعلاقات section/RVA/raw geometry بصورة أعمق |
| SYS-03 | مكتمل ومختبر محليًا وعلى Windows | corpus موقع فعليًا وWinVerifyTrust trust-chain matrix |
| SYS-04 | مكتمل ومختبر محليًا وعلى Windows | crash injection وdurability fault matrix على أنظمة ملفات متعددة |
| SYS-05 | مكتمل ومختبر محليًا وعلى Windows | إضافة عقود StringTable/Dialog/RES ذات المعلمات الخاصة |
| SYS-06 | مكتمل ومختبر على Windows | سياسة MUI/LN وتعديلات non-no-op أوسع |
| SYS-07 | مكتمل ومختبر | توسيع corpus الحقيقي المصنف دون تضمين ملفات مرخصة غير لازمة |
| SYS-08 | مكتمل جزئيًا ومختبر | coverage-guided fuzzing مستقل طويل التشغيل |
| SYS-09 | مكتمل ومختبر على Windows | CPU/time/notification limits وstress matrix |
| SYS-10 | مكتمل جزئيًا ومختبر على Windows | async cancellation وenabled-controls/accessibility matrix |

لا ينبغي اعتبار الفجوات المتبقية إخفاقًا في المسار الحالي؛ هي حدود مقصودة حتى لا تتحول طبقة التقوية إلى إضافة ميزات أو ادعاء ضمانات لم تُختبر.


## دورة Verification Engine الجديدة

استجابةً للهدف الاستراتيجي المحدث، انتقلت الدورة التالية من **Feature Engine** إلى **Verification Engine**. لم يعد نجاح Save يُفهم على أنه استدعاء مباشر لـ`LIEF.write()`؛ بل صار Writer ينشئ مرشحًا مؤقتًا، يعيد فتحه، ويمرره عبر graph وinvariants وsemantic diff وpreservation checks قبل السماح بالـdurable commit، ثم يعيد التحقق من الملف بعد commit ويسجل التقرير في `WriteResult` وProject/Batch audit.

| المرحلة | التنفيذ الحالي |
|---|---|
| PLAN | عقود العملية والـtarget payload تُمرر إلى Verification Engine |
| MUTATE | LIEF يغير نسخة الذاكرة فقط |
| SERIALIZE | الكتابة إلى temporary في نفس volume |
| REOPEN | LIEF يعيد فتح المرشح قبل commit |
| STRUCTURAL VALIDATION | PEHealth وDeepPEInvariantReport يفحصان PE headers وsection geometry وalignment وdirectories وresource bounds |
| RESOURCE GRAPH VALIDATION | ResourceGraph canonical leaves مع semantic/layout fingerprints وissues |
| SEMANTIC DIFF | before/after graph diff يحدد added/removed/changed وtargetChanged، مع قبول replace no-op الصحيح دلاليًا |
| PRESERVATION CHECK | imports وexports وTLS وLoad Config وDebug وOverlay وdirectories وnon-resource sections وheader invariants |
| WINDOWS VALIDATION | على Windows تتم مقارنة before/after عبر loader oracle ثم candidate مقابل LIEF؛ خارج Windows الحالة SKIPPED صراحة |
| AUTHENTICODE VERIFICATION | WinVerifyTrust native على Windows، مع `VALID`/`NOT_SIGNED`/`INVALID` وHRESULT |
| COMMIT | durable same-volume commit بعد نجاح المرشح فقط |
| AUDIT | post-commit verification report في WriteResult وProject/Batch audit وCLI JSON |

أضيف أيضًا **structure-aware fuzzing** يغير مواضع PE header وsection وdata-directory ضمن حدود، واختبار crash consistency يحاكي فشل commit وفشل post-commit verification ويثبت بقاء output السابق وعدم ترك rollback artifacts. تبقى التغطية coverage-guided طويلة التشغيل ومصفوفة signed/MUI/LN الواسعة مراحل لاحقة، لا نتائج مفترضة.


## انتقال UI/UX: من بنية يفهمها المطور إلى تجربة يفهمها الإنسان

بعد تثبيت Verification Engine، أصبحت الأولوية التالية هي **قابلية فهم التجربة**. النواة تستطيع الآن إثبات صحة Save، لكن الإثبات لا يكفي إذا لم يفهم المستخدم ما الذي سيفعله البرنامج وما الذي حدث بعد الفعل. لذلك صيغ `docs/UIUX-GOAL.md` كامتداد لـmain-goal، لا كمسار Feature Engine.

الدفعة الأولى أعادت ترتيب سطح WPF إلى Workspace/Editors/Tools، وأظهرت Current PE وسياسة `Save As only` وحالة CLI التفصيلية ومدة العملية. كما أضيفت أسماء وAutomationIds وtooltips لعناصر العمل والتبويبات والجداول والـpreview، مع استخدام system brushes بدل الألوان الثابتة في السطوح التي يجب أن تعمل مع high contrast. وأصبح UI automation يثبت سياق الملف ومناطق العمل والحالة وتفاصيل Preview وImage Wizard، لا مجرد فتح النافذة.

المعيار الجديد هو أن يمر المستخدم بمسار مفهوم: **Open → Explore → Preview → Edit → Save As → Verify**. تبقى raw JSON وVerificationReport متاحة للمطور، لكنها ليست نقطة الدخول الوحيدة للمبتدئ. وتبقى الفجوات المعلنة: async cancellation وStop الكامل لكل النوافذ، checklist Verification summary المرئية الموحدة بعد Save، F6/TabIndex matrix، screen-reader verification الأوسع، واختبارات resize/failure لكل editor.
