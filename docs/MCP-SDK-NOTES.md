# ملاحظات SDK MCP

المراجع الرسمية:

- https://modelcontextprotocol.io/docs/2026-07-28/sdk
- https://modelcontextprotocol.io/docs/2026-07-28/develop/build-server

تسرد وثائق MCP Python SDK الرسمي ضمن Tier 1، وتذكر أن SDKs الرسمية تدعم إنشاء خوادم تعرض tools/resources/prompts، وبناء العملاء، والنقل المحلي والبعيد، والتوافق النوعي مع البروتوكول.

دليل بناء الخادم يطلب Python 3.10 أو أحدث وPython MCP SDK 2.0.0 أو أحدث. كما يحذر من الكتابة إلى stdout في خادم stdio لأن ذلك يفسد رسائل JSON-RPC؛ يجب أن تذهب السجلات إلى stderr عبر logging.

قرار التنفيذ: استخدام Python وSDK الرسمي بدل تنفيذ JSON-RPC يدويًا. سيبدأ الخادم بأدوات القراءة والفهرسة فقط، ويظل stdout مخصصًا للبروتوكول، مع logging إلى stderr. لا تُضاف تبعية شبكة أو API خارجي في هذه المرحلة.
