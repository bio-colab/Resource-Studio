# ملاحظات بحث أولية: احتياجات مستخدمي أدوات الموارد وPE

## Resource Hacker الرسمي
المصدر: https://www.angusj.com/resourcehacker/

تصف الصفحة الرسمية Resource Hacker بأنه محرر وcompiler/decompiler لموارد تطبيقات Windows ‏32/64-bit، مع دعم EXE وDLL وSCR وRES وMUI. وتذكر أن الأداة توفر واجهة رسومية بالإضافة إلى CLI وسكربتات متعددة الأوامر. الوظائف الرسمية تشمل فتح/عرض/تحرير الموارد، استخراجها واستيرادها، compiler للـRC، إضافة/حذف/تعديل الموارد، تغيير اللغة، وسجل العمليات. كما تذكر أن القوائم والحوارات لديهما WYSIWYG designers، بينما الموارد الثنائية غير المعروفة تُعرض للقراءة فقط ويمكن تصديرها وتعديلها بأداة خارجية ثم استيرادها.

الدلالة للمشروع: Resource Studio لا ينبغي أن ينافس Resource Hacker فقط في العمليات الأساسية؛ قيمته الأكبر هي الأمان، المشاريع، الفهرسة، المقارنة، التحقق، undo/redo، واجهات حديثة، وتحليلات PE لا توفرها أداة واحدة بهذا التركيب.

## Visual Studio Resource Explorer
المصدر: https://devblogs.microsoft.com/visualstudio/introducing-the-revamped-visual-studio-resource-explorer/

تذكر Microsoft أن مشاكل Resource Editor القديمة شملت غياب البحث والفلاتر، صعوبة التعامل مع ملفات كثيرة، قيد فتح ملف واحد، غياب إدارة اللغات جنبًا إلى جنب، وعدم دعم الثيم والتكبير. الميزات الجديدة تشمل Grid موحدًا، تحميل عدة ملفات، عرض اللغات معًا، البحث عبر ملفات متعددة، تعديل عدة ملفات ولغات، Dark mode، التحقق من string.Format placeholders، التحذيرات، العرض الموحّد للنصوص والوسائط، والتكبير. كما تشير الصفحة إلى أهمية التعليقات لكل ترجمة وإتاحة الوصول، وتوضح أن CSV والتكامل مع محركات الترجمة ليست ضمن الإصدار الأساسي.

الدلالة للمشروع: احتياجات UI-02 وUI-03 وUI-04 في TODO ليست تجميلية؛ البحث متعدد الملفات، المقارنة الجانبية للغات، placeholder validation، التعليقات، التكبير، الثيم، وإتاحة الوصول كلها وظائف عملية متوقعة من مستخدم حديث.

## مصادر لاحقة مطلوبة
- Resource Tuner feature list: https://www.heaventools.com/resource-tuner-features.htm
- PE Explorer resource editor: https://www.pe-explorer.com/peexplorer-tour-resource-editor.htm
- CFF Explorer / NTCore: https://ntcore.com/explorer-suite/
- Microsoft Winres documentation: https://learn.microsoft.com/mt-mt/dotnet/framework/tools/winres-exe-windows-forms-resource-editor

## Resource Tuner
المصدر: https://www.heaventools.com/resource-tuner-features.htm

تعرض قائمة الميزات دعم EXE/DLL/MUN وSYS/OCX وغيرها، Unicode، واجهة متعددة اللغات، موارد نصية وصورية وثنائية، PNG/JPEG/AVI/XML وType Library، تغيير اللغة وإنشاء نسخة بلغة أخرى، استخراج جماعي، بحثًا عبر عدة ملفات، Resource Filter، Manifest Wizard، فحصًا وإصلاحًا للموارد، دعم UPX، plugins، Recent Files وFavorites وExplorer integration وbackup وLog pane.

الدلالة: المطورون والهواة يريدون batch extraction، بحثًا عبر عدة ملفات، فلاتر، recent/favorites، سجلًا قابلًا للقراءة، manifest/DPI/UAC helpers، ودعمًا أوسع للموارد غير القياسية. Resource Studio يملك أساس البحث والتقارير والمشاريع، لكنه لا يزال يحتاج batch UX وfavorites وmanifest wizard وmedia/resource preview الأوسع.

## PE Explorer Resource Editor
المصدر: https://www.pe-explorer.com/peexplorer-tour-resource-editor.htm

يركز المصدر على Resource Tree واضح، عرض WYSIWYG للقوائم والحوارات، دعمًا واسعًا للصور وXML وImage Lists وType Library، استخراجًا وتعديلًا وترجمةً واستبدالًا، محررات متخصصة حسب نوع المورد، backup، وإمكانية الرجوع عن التغييرات داخل جلسة التحرير. كما يذكر التعامل مع RCData/DFM لتطبيقات Delphi وعرض الكائنات وخصائصها.

الدلالة: المسار الذي يميز Resource Studio عن محرر خام هو preview/editor حسب نوع المورد، undo حقيقي، ودعم ملفات legacy مثل Delphi RCData/DFM كإضافة اختيارية؛ لا ينبغي اعتبار raw hex وحده تجربة كافية.

## CFF Explorer / Explorer Suite
المصدر: https://ntcore.com/explorer-suite/

يصف المصدر بيئة PE متعددة الملفات تشمل PE32/PE64، تعديل الحقول، دعم .NET الداخلي، PE rebuilder، realigner، hex editor، import adder، integrity checks، extension support، scripting، dependency walker، disassembler، signature manager/updater/collision checker، وتقارير وفحوصات ملفات ومجلدات.

الدلالة: شريحة المطورين المتقدمين لا تريد موارد فقط؛ تريد PE inspection/rebuild/dependency/reporting وسير عمل متعدد الملفات وقابلية scripting. Resource Studio يملك inspection وinvariants وreports وplugin dry-run، لكنه لا يملك بعد PE rebuilder العام أو import editor أو disassembler أو dependency scanner عميقًا، وينبغي إبقاء هذه الأدوات خارج نطاق resource writer الآمن إلى أن تتوفر اختبارات corpus قوية.

## Microsoft Winres.exe
المصدر: https://learn.microsoft.com/en-us/dotnet/framework/tools/winres-exe-windows-forms-resource-editor

يوفر Winres محررًا مرئيًا لموارد Windows Forms، يعيد بناء التصميم من .resx/.resources، يسمح بتعديل Text/Size/Position، إنشاء ثقافة من الملف المحايد، الحفظ باسم ثقافة أخرى، Properties window، error-reporting، وفحص HotKeys. تنبه Microsoft إلى مخاطر فتح ملفات غير موثوقة بسبب binary deserialization.

الدلالة: localization dashboard مفيد، لكن يجب إضافة تحذير ثقة للملفات، وفحص hotkeys، وإدارة culture naming، ومحرر .NET resources منفصل عن Win32 PE resources بدل الخلط بينهما.

## LIEF الرسمي
المصادر:
- https://lief.re/doc/latest/tutorials/07_pe_resource.html
- https://lief.re/doc/latest/formats/pe/modifications/resources.html

توضح وثائق LIEF أن موارد PE شجرة من ثلاثة مستويات TYPE/ID/LANGUAGE، وأن `.rsrc` هو الموضع المعتاد وليس قاعدة مطلقة. يوفر LIEF ResourceDirectory وResourceData والتعديل منخفض المستوى، وResourcesManager لبنى MANIFEST/ICON/VERSION وغيرها، كما يسمح بنقل شجرة الموارد بين ملفين عبر set_resources. وتوضح الوثائق أن إعادة بناء resource tree يجب تفعيلها صراحة في Builder في بعض المسارات.

الدلالة: يجب أن تبقى Resource Studio محافظة على resource-tree invariants، language-aware editing، وround-trip validation؛ أما نقل الموارد بين binaries فهو فرصة قوية لهواة التخصيص لكنه يحتاج مقارنة صارمة للأقسام والتوقيع والـoverlay قبل اعتماده.

## Microsoft PE Format
المصدر: https://learn.microsoft.com/en-us/windows/win32/debug/pe-format

تصف Microsoft PE/COFF كرؤوس وأقسام وdata directories تشمل imports/exports/relocations/resources، وتوضح الفرق بين RVA وfile pointer، PE32 وPE32+، وأهمية NumberOfRvaAndSizes وSizeOfOptionalHeader عند القراءة. كما تذكر أن attribute certificate يرتبط ببيانات قابلة للتحقق، وأن checksum يُفحص خصوصًا لبعض DLLs وبرامج التشغيل والعمليات الحرجة.

الدلالة: ميزة Resource Studio لا ينبغي أن تتحول إلى محرر حقول PE عام قبل امتلاك validators وcorpus لكل architecture؛ الأولوية العملية هي inspector/diagnostics/repair suggestions وشرح الأثر، لا الكتابة الحرة في headers.

## RisohEditor مفتوح المصدر
المصدر: https://github.com/katahiromz/RisohEditor

يقدم RisohEditor مثالًا على توقعات مستخدمي Win32: قراءة وكتابة RC/RES/EXE/DLL، دعم UTF-16، العمل على Windows وReactOS، توثيق متعدد اللغات، ووجود standardization لمعرفات الموارد. صفحة GitHub تعرض 512 نجمة و4606 commits وقت البحث، ما يدل على وجود اهتمام عملي طويل الأمد بأداة Win32 resource مستقلة.

الدلالة: دعم RC/RES/UTF-16 والتعريب والتوثيق متعدد اللغات عناصر جذب حقيقية للهواة، ويمكن لـ Resource Studio أن يميز نفسه بإدارة المشروع، الأمان، diff، وPE diagnostics.
