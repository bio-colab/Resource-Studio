# UI/UX research notes — 2026-08-20

## المصادر المقروءة

| المصدر | الخلاصة القابلة للتطبيق |
|---|---|
| [Windows application development — Best practices](https://learn.microsoft.com/en-us/windows/apps/get-started/best-practices) | الاتساق مع سلوك Windows، اختبار resize وDPI، responsive layout، on-object commanding، copy/paste، scrolling، common controls، dark/light/high contrast، Snap Layout، ودعم الأداء والاستجابة |
| [Keyboard accessibility — Windows apps](https://learn.microsoft.com/en-us/windows/apps/design/accessibility/keyboard-accessibility) | لوحة المفاتيح نموذج تفاعل أساسي؛ يجب اختبار tab order صراحة، إضافة F6 بين المناطق الرئيسية، اختصارات قابلة للاكتشاف، AccessKey/AcceleratorKey، وتوفير focus indicator وعدم جعل pointer-only actions وحيدة |
| [Accessibility design basics — Win32 UX guide](https://github.com/MicrosoftDocs/win32/blob/docs/desktop-src/uxguide/inter-accessibility.md) | كل عنصر تفاعلي يجب أن يكون keyboard accessible ومكشوفًا عبر UI Automation؛ استخدام common controls، عدم الاعتماد على اللون وحده، احترام high contrast/system settings، progressive disclosure، وبدائل للـdrag/double-click |
| [PE Explorer resource editor feature tour](https://www.pe-explorer.com/peexplorer-tour-resource-editor.htm) | أدوات PE الناضجة تجعل resource tree نقطة الدخول، تعرض rendering قريبًا من التطبيق، تبدأ editor مناسبًا حسب النوع، توفر undo/restore وbackup افتراضيًا، وتخدم مطورين ومترجمين وهواة لا المبرمجين فقط |

## ملاحظات أولية من WPF الحالي

الواجهة تبدأ بـWrapPanel طويل من الأزرار العالمية: Open، List، Inspect، Validate، Python GUI، عدة editors، Authenticode، وTheme. هذا يجعل كل شيء متساويًا بصريًا ولا يميز المسار الأساسي Open → Explore → Preview → Edit → Save As → Verify. الواجهة تملك تبويبات Resources/Preview/Search/Batch/Localization/Inspect/Diff، لكنها لا تعرض navigation model أو task hierarchy أو recent/open context.

مسار الحالة الحالي يعرض `StatusText` و`CliStateText`، لكن لا يوجد progress phase أو operation summary أو structured verification checklist مرئي للمستخدم. `RunCliCapture` متزامن داخل UI thread رغم استخدام ReadToEndAsync؛ لذلك يجب اعتبار responsiveness/cancellation عنصر UX لا مجرد accessibility.

الواجهة تملك AutomationId لبعض العناصر فقط: OpenPeButton وPathBox وResourceCountText وSearchQueryBox وSearchButton وImageWizardButton وThemeButton وMainStatusText وCliStateText. معظم الأزرار والتبويبات والجداول والنوافذ لا تملك أسماء automation صريحة أو accelerator metadata. الاختصارات الحالية Ctrl+O/Ctrl+F/Ctrl+I/F5، لكن لا تظهر في tooltips ولا يوجد F6 للتنقل بين المناطق.

الواجهة تعرض raw JSON في TextBox كبير، وDataGrid AutoGenerateColumns، وPreview visual/raw split. هذا مفيد للتشخيص لكنه ليس أفضل نقطة دخول للمبتدئ؛ يلزم progressive disclosure: summary أولًا، details عند الطلب، مع إبقاء raw/JSON advanced view متاحًا للمطور.

## مصادر إضافية

| المصدر | الخلاصة القابلة للتطبيق |
|---|---|
| [UI Automation of a WPF Custom Control](https://learn.microsoft.com/en-us/dotnet/desktop/wpf/controls/ui-automation-of-a-wpf-custom-control) | WPF يبني automation tree موازية للواجهة؛ Button/TextBox لها peers مدمجة بينما Grid/Canvas/Border ليست peers مفيدة عادة؛ يمكن تخصيص AutomationProperties، ويجب رفع property/state events عند تغير الحالة |
| [UX checklist for desktop applications](https://learn.microsoft.com/en-us/windows/win32/uxguide/top-violations) | اختبر resize/DPI، تجنب truncation، استخدم أفعالًا محددة في أزرار commands، راجع disabled controls، استخدم progressive disclosure، determinate progress عند الإمكان، لا تعتمد على اللون وحده، وفرق بين Cancel وClose وStop |
| [Fluent 2 Layout](https://fluent2.microsoft.design/layout) | استخدم proximity والفراغ لبناء hierarchy، نظام spacing أساسه 4px، grid واضح، alignment، responsive reposition/resize/reflow/show-hide/re-architect |
| [Visibility of System Status — Nielsen Norman Group](https://www.nngroup.com/articles/visibility-system-status/) | إبقاء المستخدم مطلعًا على الحالة يقلل عدم اليقين ويبني الثقة؛ feedback فوري وprogress indicator يمنع تكرار الضغط؛ إظهار backstage state مهم عندما يؤثر في قرار المستخدم |

## استنتاجات تصميمية مؤقتة

المشكلة الرئيسية ليست نقص أزرار أو تبويبات؛ بل أن الواجهة الحالية تعرض بنية النظام للمستخدم بدل أن تعرض هدفه. يجب أن يكون السطح الأول task-oriented: Open/Recent ثم Explore resource ثم Preview/Inspect ثم Edit/Save As ثم Verification result. أما Inspect وraw JSON وBatch وLocalization فتظهر كمناطق متقدمة أو ضمن navigation واضحة.

مبادئ الدورة: لا عملية صامتة، لا حالة نجاح عامة بلا معنى، لا warning لوني بلا نص، لا drag-only أو pointer-only، لا زر disabled بلا سبب قابل للفهم، ولا raw JSON كواجهة أولى للمبتدئ. كل عملية طويلة تحتاج phase/status/cancel أو Stop، وكل Save يحتاج output path وverification summary ووسيلة لفتح التفاصيل.

## ملاحظة TabControl وUI automation

| المصدر | الخلاصة |
|---|---|
| [WPF TabControl](https://learn.microsoft.com/en-us/dotnet/desktop/wpf/controls/tabcontrol) | التبويبات تعرض صفحات منفصلة؛ عقد UI automation لعناصر المحتوى يجب اختبارها بعد اختيار TabItem، لا بافتراض أن كل محتوى التبويبات النشطة/غير النشطة ظاهر في الشجرة |
| [UI Automation support for TabItem](https://learn.microsoft.com/en-us/dotnet/framework/ui-automation/ui-automation-support-for-the-tabitem-control-type) | TabItem له selection semantics مستقلة؛ الاختبار الصحيح يختار التبويب ثم ينتظر ظهور/تحديث عناصر الصفحة |

نتيجة عملية: فشل `PreviewDetailsBox` الأول كان مشكلة في توقيت/شجرة UI automation لا في عنصر XAML؛ عُدّل الاختبار ليختار Preview ثم ينتظر العنصر.
