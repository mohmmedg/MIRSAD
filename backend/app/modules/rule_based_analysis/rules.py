"""
modules/rule_based_analysis/rules.py

قواعد التصنيف الثابتة (lookup tables) لمحرّك rule-based. مفصولة عن
analyzer.py عمداً — إضافة/تعديل قاعدة هون ما بيحتاج لمس منطق المعالجة،
وهذا بالضبط الفرق الجوهري عن AI Analyzer: هون كل قرار تصنيف قابل للتتبّع
لسطر كود محدد، بدون أي "صندوق أسود".

كل قاعدة فيها حقول نصية عربية + نظائرها الإنجليزية (لاحقة _en)، مصدر واحد
يغذّي التقارير بأي لغة عبر report_formatter.py و analyzer.py:
- title / title_en: عنوان تقني مختصر
- remediation / remediation_en: إجراء تقني محدد (للتقرير التقني)
- business_impact / business_impact_en: صياغة موجّهة لصاحب قرار
- plain_summary / plain_summary_en: شرح بلغة يومية بسيطة جداً
"""

from app.schemas.analysis import Severity

# ---------------------------------------------------------------------------
# Network: منافذ معروفة بمخاطر أمنية "افتراضية" (بغض النظر عن الإصدار)
# ---------------------------------------------------------------------------
RISKY_PORTS: dict[int, dict] = {
    21: {
        "title": "FTP — نقل ملفات بدون تشفير",
        "title_en": "FTP — Unencrypted File Transfer",
        "severity": Severity.MEDIUM,
        "remediation": "استبدل FTP بـ SFTP أو FTPS. إذا كان FTP ضرورياً، قيّد الوصول بجدار ناري لعناوين IP محددة فقط.",
        "remediation_en": "Replace FTP with SFTP or FTPS. If FTP is required, restrict access via firewall to specific IP addresses only.",
        "business_impact": "بيانات الملفات المنقولة (وربما كلمات مرور) تنتقل بدون تشفير، ما يزيد خطر تسريب معلومات حساسة عبر الشبكة.",
        "business_impact_en": "Transferred file data (and possibly credentials) travels unencrypted, increasing the risk of sensitive information leaking over the network.",
        "plain_summary": "الموقع يستخدم طريقة قديمة لنقل الملفات لا تُخفي البيانات أثناء إرسالها، فأي شخص يراقب الشبكة يقدر يشوفها.",
        "plain_summary_en": "The site uses an old file-transfer method that doesn't hide data while sending it, so anyone watching the network can see it.",
    },
    23: {
        "title": "Telnet — بروتوكول غير مشفّر بالكامل",
        "title_en": "Telnet — Fully Unencrypted Protocol",
        "severity": Severity.HIGH,
        "remediation": "أوقف Telnet فوراً واستبدله بـ SSH. Telnet ينقل بيانات الاعتماد كنص صريح (plaintext).",
        "remediation_en": "Disable Telnet immediately and replace it with SSH. Telnet transmits credentials as plaintext.",
        "business_impact": "كلمات المرور وبيانات الدخول تُنقل بدون أي تشفير — أي متطفل على نفس الشبكة يقدر يسرقها مباشرة.",
        "business_impact_en": "Passwords and login data are transmitted with no encryption at all — anyone on the same network can steal them directly.",
        "plain_summary": "في طريقة قديمة جداً للدخول عن بُعد للجهاز، وكلمة السر فيها تنتقل بشكل مكشوف تماماً — أي شخص عالشبكة يقدر يشوفها.",
        "plain_summary_en": "This is a very old way to remotely access the device, and the password travels completely exposed — anyone on the network can see it.",
    },
    25: {
        "title": "SMTP مفتوح — احتمال Open Relay",
        "title_en": "Open SMTP — Possible Open Relay",
        "severity": Severity.MEDIUM,
        "remediation": "تأكد أن السيرفر لا يعمل كـ open mail relay. فعّل SPF/DKIM/DMARC وقيّد من يستطيع الإرسال.",
        "remediation_en": "Verify the server isn't functioning as an open mail relay. Enable SPF/DKIM/DMARC and restrict who can send mail through it.",
        "business_impact": "لو السيرفر مُساء استخدامه لإرسال بريد مزعج، ممكن يوصل نطاق الشركة لقوائم الحظر (blacklists) ويأثر على وصول كل إيميلاتكم.",
        "business_impact_en": "If the server is abused to send spam, your company's domain could land on email blacklists, affecting deliverability of all your emails.",
        "plain_summary": "سيرفر البريد قد يكون مفتوح لأي شخص يستخدمه لإرسال رسائل مزعجة باسمكم دون علمكم.",
        "plain_summary_en": "Your mail server may be open for anyone to use to send spam under your name without your knowledge.",
    },
    135: {
        "title": "MSRPC مكشوف",
        "title_en": "Exposed MSRPC",
        "severity": Severity.MEDIUM,
        "remediation": "قيّد الوصول لمنفذ 135 بجدار ناري؛ نادراً ما يحتاج تعرّضاً مباشراً للإنترنت.",
        "remediation_en": "Restrict access to port 135 via firewall; it rarely needs to be directly exposed to the internet.",
        "business_impact": "خدمة إدارة داخلية بأنظمة Windows مكشوفة للإنترنت، وهذا يوسّع سطح الهجوم بدون داعٍ فعلي.",
        "business_impact_en": "An internal Windows management service is exposed to the internet, needlessly widening the attack surface.",
        "plain_summary": "خدمة داخلية بالجهاز مفتوحة للإنترنت رغم إنها مفروض تبقى داخل الشبكة فقط.",
        "plain_summary_en": "An internal device service is open to the internet even though it should stay inside the network only.",
    },
    139: {
        "title": "NetBIOS مكشوف",
        "title_en": "Exposed NetBIOS",
        "severity": Severity.MEDIUM,
        "remediation": "أوقف NetBIOS over TCP/IP إذا لم يكن مطلوباً، أو قيّده لشبكة داخلية موثوقة فقط.",
        "remediation_en": "Disable NetBIOS over TCP/IP if not needed, or restrict it to a trusted internal network only.",
        "business_impact": "خدمة مشاركة ملفات قديمة مكشوفة، معروفة تاريخياً بثغرات استغلال متعددة.",
        "business_impact_en": "An old file-sharing service is exposed, historically known for multiple exploitable vulnerabilities.",
        "plain_summary": "خدمة قديمة لمشاركة الملفات مفتوحة للإنترنت، وهذا النوع من الخدمات معروف بثغرات كثيرة.",
        "plain_summary_en": "An old file-sharing service is open to the internet, and this type of service is known for many vulnerabilities.",
    },
    445: {
        "title": "SMB مكشوف — سطح هجوم معروف (WannaCry, EternalBlue)",
        "title_en": "Exposed SMB — Known Attack Surface (WannaCry, EternalBlue)",
        "severity": Severity.HIGH,
        "remediation": "لا تعرّض SMB مباشرة للإنترنت أبداً. استخدم VPN للوصول عن بعد، وحدّث لآخر patches أمنية.",
        "remediation_en": "Never expose SMB directly to the internet. Use a VPN for remote access, and keep it fully patched.",
        "business_impact": "هذا بالضبط المنفذ اللي استُغل بهجمات فدية عالمية كبرى (WannaCry). تعرّضه المباشر يشكّل خطراً جدياً على استمرارية العمل.",
        "business_impact_en": "This is the exact port exploited in major global ransomware attacks (WannaCry). Direct exposure poses a serious risk to business continuity.",
        "plain_summary": "في خدمة مشاركة ملفات مفتوحة للإنترنت، ونفس النوع اللي استُخدم بهجمات فدية شهيرة أثّرت على شركات كبيرة حول العالم.",
        "plain_summary_en": "A file-sharing service is open to the internet — the same type used in famous ransomware attacks that hit major companies worldwide.",
    },
    1433: {
        "title": "MSSQL مكشوف",
        "title_en": "Exposed MSSQL",
        "severity": Severity.MEDIUM,
        "remediation": "قيّد الوصول لقاعدة البيانات بجدار ناري، وتأكد من تعطيل حسابات SA الافتراضية الضعيفة.",
        "remediation_en": "Restrict database access via firewall, and ensure weak default SA accounts are disabled.",
        "business_impact": "قاعدة بيانات مكشوفة مباشرة للإنترنت — لو تم اختراقها، كل البيانات المخزّنة (عملاء، مبيعات، إلخ) بخطر.",
        "business_impact_en": "A database is directly exposed to the internet — if breached, all stored data (customers, sales, etc.) is at risk.",
        "plain_summary": "مكان تخزين البيانات (قاعدة البيانات) مفتوح مباشرة للإنترنت، وهذا مو آمن أبداً.",
        "plain_summary_en": "The data storage location (database) is directly open to the internet, which is not safe at all.",
    },
    3306: {
        "title": "MySQL مكشوف",
        "title_en": "Exposed MySQL",
        "severity": Severity.MEDIUM,
        "remediation": "قاعدة البيانات لا يجب أن تكون مكشوفة مباشرة للإنترنت. قيّدها بجدار ناري لعناوين IP محددة.",
        "remediation_en": "The database should never be directly exposed to the internet. Restrict it via firewall to specific IP addresses.",
        "business_impact": "قاعدة بيانات مكشوفة مباشرة للإنترنت — لو تم اختراقها، كل البيانات المخزّنة بخطر مباشر.",
        "business_impact_en": "A database is directly exposed to the internet — if breached, all stored data is at immediate risk.",
        "plain_summary": "مكان تخزين البيانات (قاعدة البيانات) مفتوح مباشرة للإنترنت، وهذا مو آمن أبداً.",
        "plain_summary_en": "The data storage location (database) is directly open to the internet, which is not safe at all.",
    },
    3389: {
        "title": "RDP مكشوف — هدف شائع لهجمات brute-force",
        "title_en": "Exposed RDP — Common Brute-Force Target",
        "severity": Severity.HIGH,
        "remediation": "فعّل Network Level Authentication، استخدم VPN بدل تعريض RDP مباشرة، وفعّل قفل الحساب بعد محاولات فاشلة.",
        "remediation_en": "Enable Network Level Authentication, use a VPN instead of exposing RDP directly, and enable account lockout after failed attempts.",
        "business_impact": "خدمة الدخول عن بُعد للأجهزة مكشوفة مباشرة — من أكثر النقاط استهدافاً بمحاولات تخمين كلمات مرور آلية.",
        "business_impact_en": "Remote desktop access is directly exposed — one of the most commonly targeted points for automated password-guessing attacks.",
        "plain_summary": "في طريقة للدخول عن بُعد للجهاز مفتوحة مباشرة للإنترنت، وهذي من أكثر الأشياء اللي يحاول المخترقون تخمين كلمة سرّها آلياً.",
        "plain_summary_en": "A remote access method for the device is directly open to the internet, and this is one of the things attackers most commonly try to guess the password for automatically.",
    },
    5900: {
        "title": "VNC مكشوف",
        "title_en": "Exposed VNC",
        "severity": Severity.HIGH,
        "remediation": "VNC غالباً بدون تشفير قوي افتراضياً. استخدم VPN أو نفق SSH بدل التعريض المباشر.",
        "remediation_en": "VNC often lacks strong encryption by default. Use a VPN or SSH tunnel instead of direct exposure.",
        "business_impact": "وصول مباشر لشاشة الجهاز عن بُعد مكشوف للإنترنت، غالباً بدون تشفير قوي كافٍ.",
        "business_impact_en": "Direct remote screen access to the device is exposed to the internet, often without adequately strong encryption.",
        "plain_summary": "في طريقة تخلي أي شخص يشوف شاشة الجهاز عن بُعد، وهي مفتوحة للإنترنت بدون حماية كافية.",
        "plain_summary_en": "There's a way for anyone to view the device's screen remotely, and it's open to the internet without adequate protection.",
    },
    6379: {
        "title": "Redis مكشوف بدون مصادقة افتراضياً",
        "title_en": "Exposed Redis — No Authentication by Default",
        "severity": Severity.HIGH,
        "remediation": "فعّل requirepass بإعدادات Redis، ولا تعرّضه مباشرة للإنترنت أبداً.",
        "remediation_en": "Enable requirepass in Redis configuration, and never expose it directly to the internet.",
        "business_impact": "قاعدة بيانات سريعة (Redis) مكشوفة بدون كلمة مرور افتراضياً — وصول مباشر بدون أي حاجز للبيانات المخزّنة فيها.",
        "business_impact_en": "A fast in-memory database (Redis) is exposed with no password by default — direct, unguarded access to the data stored in it.",
        "plain_summary": "مكان تخزين بيانات مؤقتة مفتوح للإنترنت وبدون كلمة سر أساساً — أي شخص يقدر يدخل عليه مباشرة.",
        "plain_summary_en": "A temporary data store is open to the internet with no password at all — anyone can access it directly.",
    },
    27017: {
        "title": "MongoDB مكشوف",
        "title_en": "Exposed MongoDB",
        "severity": Severity.HIGH,
        "remediation": "فعّل المصادقة (authentication) بـ MongoDB، وقيّد الوصول بجدار ناري.",
        "remediation_en": "Enable authentication in MongoDB, and restrict access via firewall.",
        "business_impact": "قاعدة بيانات مكشوفة للإنترنت — عدد كبير من حالات تسريب البيانات العالمية سببها قواعد MongoDB مكشوفة بدون حماية.",
        "business_impact_en": "A database is exposed to the internet — a large number of global data breaches have been caused by unprotected exposed MongoDB instances.",
        "plain_summary": "مكان تخزين البيانات مفتوح للإنترنت، وهذا النوع بالذات كان سبب تسريبات بيانات كبيرة بشركات كثيرة سابقاً.",
        "plain_summary_en": "The data storage location is open to the internet, and this specific type has previously caused major data leaks at many companies.",
    },
}

# ---------------------------------------------------------------------------
# Network: إصدارات برامج معروفة بثغرات موثّقة (CVE) — مطابقة دقيقة
# ---------------------------------------------------------------------------
KNOWN_VULNERABLE_VERSIONS: list[dict] = [
    {
        "product": "vsftpd",
        "version": "2.3.4",
        "title": "vsFTPd 2.3.4 Backdoor Vulnerability (CVE-2011-2523)",
        "title_en": "vsFTPd 2.3.4 Backdoor Vulnerability (CVE-2011-2523)",
        "severity": Severity.CRITICAL,
        "remediation": "قم بترقية vsftpd فوراً لأحدث إصدار مستقر. هذا الإصدار يحوي backdoor موثّق يسمح بتنفيذ أوامر عن بعد.",
        "remediation_en": "Upgrade vsftpd immediately to the latest stable release. This version contains a documented backdoor allowing remote command execution.",
        "business_impact": "هذا الإصدار المحدد فيه باب خلفي معروف عالمياً يسمح لأي مهاجم بالسيطرة الكاملة على السيرفر مباشرة، بدون الحاجة لكلمة مرور.",
        "business_impact_en": "This specific version has a globally known backdoor that lets any attacker take full control of the server directly, without needing a password.",
        "plain_summary": "برنامج نقل الملفات المستخدم فيه فيه باب خلفي معروف — يعني أي شخص يعرف عنه يقدر يدخل ويتحكم بالسيرفر بالكامل بسهولة.",
        "plain_summary_en": "The file-transfer software in use has a known backdoor — meaning anyone aware of it can easily get in and take full control of the server.",
    },
    {
        "product": "OpenSSH",
        "version": "7.2",
        "title": "OpenSSH 7.2 — إصدار قديم فيه ثغرات موثّقة متعددة",
        "title_en": "OpenSSH 7.2 — Outdated Version with Multiple Documented Vulnerabilities",
        "severity": Severity.MEDIUM,
        "remediation": "قم بترقية OpenSSH لأحدث إصدار مستقر (9.x أو أحدث).",
        "remediation_en": "Upgrade OpenSSH to the latest stable release (9.x or newer).",
        "business_impact": "إصدار قديم من برنامج الدخول الآمن، فيه ثغرات معروفة أُصلحت بإصدارات لاحقة — تشغيله يزيد الخطر بدون داعٍ.",
        "business_impact_en": "An outdated secure-login version with known vulnerabilities fixed in later releases — running it needlessly increases risk.",
        "plain_summary": "برنامج الدخول الآمن للجهاز قديم وفيه مشاكل معروفة تم إصلاحها بنسخ أحدث.",
        "plain_summary_en": "The device's secure-login software is outdated and has known issues that were fixed in newer versions.",
    },
]

# ---------------------------------------------------------------------------
# Web: خطورة كل ترويسة أمنية عند غيابها + نص المعالجة
# ---------------------------------------------------------------------------
HEADER_RULES: dict[str, dict] = {
    "Content-Security-Policy": {
        "severity": Severity.MEDIUM,
        "remediation": "أضف ترويسة Content-Security-Policy لتقليل مخاطر XSS وحقن المحتوى الخبيث.",
        "remediation_en": "Add a Content-Security-Policy header to reduce the risk of XSS and malicious content injection.",
        "business_impact": "الموقع أقل حماية أمام محاولات حقن محتوى خبيث بصفحاته، ما يعرّض زوّار الموقع لخطر إضافي.",
        "business_impact_en": "The site has less protection against malicious content injection attempts, exposing visitors to additional risk.",
        "plain_summary": "الموقع ناقصه طبقة حماية تمنع دخول محتوى ضار لصفحاته.",
        "plain_summary_en": "The site is missing a protective layer that prevents harmful content from entering its pages.",
    },
    "Strict-Transport-Security": {
        "severity": Severity.MEDIUM,
        "remediation": "أضف ترويسة Strict-Transport-Security (HSTS) لإجبار المتصفح على استخدام HTTPS دائماً.",
        "remediation_en": "Add a Strict-Transport-Security (HSTS) header to force the browser to always use HTTPS.",
        "business_impact": "المتصفح ما يُجبر دايماً على الاتصال الآمن (HTTPS)، ما يفتح احتمال اعتراض الاتصال بشبكات غير موثوقة.",
        "business_impact_en": "The browser isn't always forced onto a secure (HTTPS) connection, opening the possibility of interception on untrusted networks.",
        "plain_summary": "الموقع ما يضمن دايماً إن الاتصال فيه مشفّر بالكامل، خصوصاً على شبكات واي فاي عامة.",
        "plain_summary_en": "The site doesn't always guarantee the connection is fully encrypted, especially on public Wi-Fi networks.",
    },
    "X-Frame-Options": {
        "severity": Severity.LOW,
        "remediation": "أضف X-Frame-Options: DENY أو SAMEORIGIN لمنع هجمات clickjacking.",
        "remediation_en": "Add X-Frame-Options: DENY or SAMEORIGIN to prevent clickjacking attacks.",
        "business_impact": "موقع خارجي يقدر نظرياً يضمّن صفحتكم داخل صفحته لخداع المستخدمين (clickjacking) — خطر منخفض لكن سهل الإصلاح.",
        "business_impact_en": "An external site could theoretically embed your page within its own to deceive users (clickjacking) — low risk but easy to fix.",
        "plain_summary": "موقع آخر ممكن يخفي صفحتكم جوا صفحته لخداع الزوّار بدون ما يلاحظوا.",
        "plain_summary_en": "Another website could hide your page inside its own to trick visitors without them noticing.",
    },
    "X-Content-Type-Options": {
        "severity": Severity.LOW,
        "remediation": "أضف X-Content-Type-Options: nosniff لمنع المتصفح من تخمين نوع المحتوى بشكل خاطئ.",
        "remediation_en": "Add X-Content-Type-Options: nosniff to prevent the browser from incorrectly guessing content types.",
        "business_impact": "خطر منخفض تقنياً، لكن إصلاحه بسيط ومجاني ويُغلق باباً إضافياً للاستغلال.",
        "business_impact_en": "Technically low risk, but the fix is simple and free, and it closes an additional avenue for exploitation.",
        "plain_summary": "إعداد تقني بسيط ناقص، تأثيره محدود لكن سهل جداً إصلاحه.",
        "plain_summary_en": "A simple technical setting is missing — its impact is limited but it's very easy to fix.",
    },
    "Referrer-Policy": {
        "severity": Severity.INFO,
        "remediation": "أضف Referrer-Policy (مثلاً strict-origin-when-cross-origin) للتحكم بمعلومات الإحالة المُرسلة.",
        "remediation_en": "Add a Referrer-Policy (e.g. strict-origin-when-cross-origin) to control referrer information sent.",
        "business_impact": "معلومة استكشافية بمستوى خطورة منخفض جداً — لا تستدعي أولوية عاجلة.",
        "business_impact_en": "An informational finding with very low severity — doesn't require urgent priority.",
        "plain_summary": "تفصيل تقني بسيط جداً، ما فيه خطر حقيقي حالياً.",
        "plain_summary_en": "A very minor technical detail — no real risk currently.",
    },
    "Permissions-Policy": {
        "severity": Severity.INFO,
        "remediation": "أضف Permissions-Policy لتقييد صلاحيات المتصفح (الكاميرا، الموقع، إلخ) غير المطلوبة.",
        "remediation_en": "Add a Permissions-Policy to restrict unneeded browser capabilities (camera, geolocation, etc.).",
        "business_impact": "معلومة استكشافية بمستوى خطورة منخفض جداً — لا تستدعي أولوية عاجلة.",
        "business_impact_en": "An informational finding with very low severity — doesn't require urgent priority.",
        "plain_summary": "تفصيل تقني بسيط جداً، ما فيه خطر حقيقي حالياً.",
        "plain_summary_en": "A very minor technical detail — no real risk currently.",
    },
}


ADDITIONAL_NETWORK_RULES = {
    21: {"title":"FTP مكشوف", "severity": Severity.HIGH, "remediation":"استخدم SFTP/FTPS وأغلق FTP غير المشفر.", "remediation_en":"Use SFTP/FTPS and disable plaintext FTP.", "business_impact":"قد تتعرض بيانات الاعتماد والبيانات للقراءة أثناء النقل.", "business_impact_en":"Credentials and data may be exposed in transit.", "plain_summary":"FTP غير مشفر ويمكن اعتراض بياناته.", "plain_summary_en":"Plain FTP can expose credentials and data."},
    23: {"title":"Telnet مكشوف", "severity": Severity.HIGH, "remediation":"استبدل Telnet بـ SSH وأغلق المنفذ 23.", "remediation_en":"Replace Telnet with SSH and close port 23.", "business_impact":"الإدارة عن بعد قد تتم بدون تشفير.", "business_impact_en":"Remote administration may occur without encryption.", "plain_summary":"Telnet يرسل الاتصال بدون تشفير قوي.", "plain_summary_en":"Telnet exposes remote sessions without strong encryption."},
    445: {"title":"SMB مكشوف", "severity": Severity.MEDIUM, "remediation":"قيد SMB على الشبكات الموثوقة وعطّل البروتوكولات القديمة وراقب الوصول.", "remediation_en":"Restrict SMB to trusted networks, disable legacy protocols, and monitor access.", "business_impact":"خدمة مشاركة ملفات مكشوفة قد توسّع سطح الهجوم.", "business_impact_en":"An exposed file-sharing service expands attack surface.", "plain_summary":"مشاركة الملفات متاحة على الشبكة وتحتاج تقييداً.", "plain_summary_en":"File sharing is exposed and should be restricted."},
    6379: {"title":"Redis مكشوف", "severity": Severity.HIGH, "remediation":"لا تعرّض Redis للإنترنت؛ قيّد الوصول وفعّل المصادقة والتشفير عند الحاجة.", "remediation_en":"Do not expose Redis publicly; restrict access and require authentication/encryption where appropriate.", "business_impact":"قواعد بيانات/خدمات الذاكرة المكشوفة قد تكشف بيانات حساسة.", "business_impact_en":"Exposed in-memory databases may reveal sensitive data.", "plain_summary":"خدمة Redis ظاهرة على الشبكة وتحتاج تقييداً.", "plain_summary_en":"Redis is exposed and should be restricted."},
    27017: {"title":"MongoDB مكشوف", "severity": Severity.HIGH, "remediation":"قيد MongoDB على الشبكات الموثوقة وفعّل المصادقة والتشفير.", "remediation_en":"Restrict MongoDB to trusted networks and enable authentication and encryption.", "business_impact":"قاعدة البيانات المكشوفة قد تعرّض بيانات التطبيق.", "business_impact_en":"An exposed database may expose application data.", "plain_summary":"قاعدة MongoDB ظاهرة على الشبكة.", "plain_summary_en":"MongoDB is exposed on the network."},
    3389: {"title":"RDP مكشوف", "severity": Severity.MEDIUM, "remediation":"قيّد RDP عبر VPN/ACL وفعّل MFA وسياسات كلمات مرور قوية.", "remediation_en":"Restrict RDP via VPN/ACL, enable MFA, and enforce strong authentication.", "business_impact":"RDP مكشوف يزيد مخاطر محاولات الدخول والاستغلال عن بعد.", "business_impact_en":"Exposed RDP increases remote-access attack risk.", "plain_summary":"سطح الإدارة عن بعد ظاهر ويحتاج تقييداً.", "plain_summary_en":"Remote administration is exposed and should be restricted."},
}

TLS_CERT_EXPIRY_WARNING_DAYS = 30

VULN_CHECK_RULES: dict[str, dict] = {
    "reflected_xss_basic": {
        "title": "Reflected XSS (اختبار أساسي)",
        "title_en": "Reflected XSS (basic test)",
        "severity": Severity.CRITICAL,
        "remediation": "طبّق output encoding على كل مدخلات المستخدم قبل عرضها بالصفحة، وأضف Content-Security-Policy.",
        "remediation_en": "Apply output encoding to all user input before rendering it on the page, and add a Content-Security-Policy.",
        "business_impact": "مهاجم يقدر يشغّل كود خبيث بمتصفح أي زائر للموقع (مثلاً سرقة جلسة تسجيل الدخول) — خطر مباشر على مستخدمي الموقع.",
        "business_impact_en": "An attacker can run malicious code in any visitor's browser (e.g. stealing a login session) — a direct risk to site users.",
        "plain_summary": "لقينا ثغرة تسمح لشخص خبيث يشغّل كود ضار بمتصفح أي زائر للموقع — ممكن يستخدمها يسرق حساب أحد المستخدمين.",
        "plain_summary_en": "We found a flaw that lets a malicious person run harmful code in any visitor's browser — they could use it to steal a user's account.",
    },
    "sqli_error_based": {
        "title": "SQL Injection — error-based (اختبار أساسي)",
        "title_en": "SQL Injection — error-based (basic test)",
        "severity": Severity.CRITICAL,
        "remediation": "استخدم Parameterized Queries / Prepared Statements حصراً، ولا تعرض رسائل خطأ قاعدة البيانات الخام للمستخدم.",
        "remediation_en": "Use Parameterized Queries / Prepared Statements exclusively, and never expose raw database error messages to users.",
        "business_impact": "مهاجم يقدر يتلاعب مباشرة بقاعدة البيانات — قراءة، تعديل، أو حتى حذف بيانات حساسة (عملاء، طلبات، إلخ).",
        "business_impact_en": "An attacker can directly manipulate the database — reading, modifying, or even deleting sensitive data (customers, orders, etc.).",
        "plain_summary": "لقينا ثغرة خطيرة جداً تسمح لشخص خبيث يوصل مباشرة لقاعدة بيانات الموقع، وممكن يشوف أو يغيّر أو يحذف بيانات حساسة.",
        "plain_summary_en": "We found a very serious flaw that lets a malicious person reach the site's database directly, and they could view, change, or delete sensitive data.",
    },
    # NOTE: the entries above were the only two keys here for a long time,
    # but web_scan/scanner.py's actual VulnerabilityCheck.check_name values
    # never matched "reflected_xss_basic" (it emits "reflected_xss_canary"),
    # and several newer checks (open redirect, LFI, form-based canaries,
    # default credentials) had no entry at all. Since this dict is a lookup
    # keyed by check_name with a silent `continue` on a miss, every one of
    # those checks was invisible from this analyzer even when vulnerable was
    # True — the exact same "one engine sees it, the other doesn't" bug
    # class already fixed once for the TLS-certificate check. The entries
    # below close that gap for every check_name scanner.py currently emits.
    "reflected_xss_canary": {
        "title": "Reflected XSS (فحص canary)",
        "title_en": "Reflected XSS (canary probe)",
        "severity": Severity.HIGH,
        "remediation": "طبّق output encoding على كل مدخلات المستخدم قبل عرضها بالصفحة، وأضف Content-Security-Policy.",
        "remediation_en": "Apply output encoding to all user input before rendering it on the page, and add a Content-Security-Policy.",
        "business_impact": "مهاجم يقدر يشغّل كود خبيث بمتصفح أي زائر للموقع.",
        "business_impact_en": "An attacker can run malicious code in any visitor's browser.",
        "plain_summary": "لقينا مؤشر على ثغرة تسمح بتشغيل كود ضار بمتصفح الزوار — يحتاج تأكيد يدوي.",
        "plain_summary_en": "We found an indicator of a flaw that lets malicious code run in visitors' browsers — needs manual confirmation.",
    },
    "open_redirect_canary": {
        "title": "إعادة توجيه مفتوحة (Open Redirect)",
        "title_en": "Open Redirect",
        "severity": Severity.LOW,
        "remediation": "لا تسمح بأي مصادر توجيه موثوقة بدل '*'، خصوصاً بأي نقطة تستخدم باراميتر كوكيز/بيانات اعتماد.",
        "remediation_en": "Whitelist exact redirect destinations instead of trusting a user-supplied URL parameter, especially near any login/credential flow.",
        "business_impact": "يُستخدم عادة بهجمات تصيّد (phishing) لإخفاء رابط خبيث خلف نطاق الموقع الموثوق.",
        "business_impact_en": "Commonly used in phishing attacks to hide a malicious link behind the site's trusted domain.",
        "plain_summary": "الموقع يقدر يعيد توجيه الزوار لأي رابط خارجي بدون تحقق — مفيد لمهاجم يبني رابط تصيّد يبدو موثوق.",
        "plain_summary_en": "The site can redirect visitors to any external link without verification — useful for an attacker building a convincing phishing link.",
    },
    "local_file_inclusion": {
        "title": "تضمين ملفات محلية (Local File Inclusion)",
        "title_en": "Local File Inclusion",
        "severity": Severity.CRITICAL,
        "remediation": "لا تبني مسار ملف من مدخل مستخدم مباشرة؛ استخدم قائمة بيضاء صريحة بأسماء الملفات المسموحة.",
        "remediation_en": "Never build a file path directly from user input; use an explicit whitelist of allowed file names.",
        "business_impact": "مهاجم يقدر يقرأ ملفات حساسة من السيرفر (إعدادات، بيانات اعتماد، وأحياناً ينتقل لتنفيذ كود).",
        "business_impact_en": "An attacker can read sensitive server files (configs, credentials, and sometimes escalate to code execution).",
        "plain_summary": "لقينا ثغرة خطيرة جداً تسمح لشخص خبيث يقرأ ملفات حساسة من داخل السيرفر نفسه.",
        "plain_summary_en": "We found a very serious flaw that lets a malicious person read sensitive files directly off the server.",
    },
    "form_reflected_xss_canary": {
        "title": "Reflected XSS عبر فورم",
        "title_en": "Reflected XSS via form submission",
        "severity": Severity.HIGH,
        "remediation": "طبّق output encoding على كل حقول الفورم قبل عرضها بالصفحة، وأضف Content-Security-Policy.",
        "remediation_en": "Apply output encoding to all form fields before rendering them, and add a Content-Security-Policy.",
        "business_impact": "مهاجم يقدر يشغّل كود خبيث بمتصفح أي زائر عبر فورم عادي (تسجيل دخول، بحث، تواصل).",
        "business_impact_en": "An attacker can run malicious code in any visitor's browser through an ordinary form (login, search, contact).",
        "plain_summary": "فورم بالموقع (زي تسجيل الدخول أو البحث) يسمح بتشغيل كود ضار بمتصفح الزوار.",
        "plain_summary_en": "A form on the site (like login or search) allows malicious code to run in visitors' browsers.",
    },
    "form_sqli_error_based": {
        "title": "SQL Injection عبر فورم — error-based",
        "title_en": "SQL Injection via form submission — error-based",
        "severity": Severity.CRITICAL,
        "remediation": "استخدم Parameterized Queries / Prepared Statements حصراً على كل حقول الفورم، ولا تعرض رسائل خطأ قاعدة البيانات الخام.",
        "remediation_en": "Use Parameterized Queries / Prepared Statements exclusively on all form fields, and never expose raw database error messages.",
        "business_impact": "مهاجم يقدر يتلاعب مباشرة بقاعدة البيانات عبر فورم عادي (زي تسجيل الدخول) بدون أي رابط GET مباشر.",
        "business_impact_en": "An attacker can directly manipulate the database through an ordinary form (like login) with no direct GET link needed.",
        "plain_summary": "فورم بالموقع (زي تسجيل الدخول) يسمح لشخص خبيث يوصل مباشرة لقاعدة بيانات الموقع.",
        "plain_summary_en": "A form on the site (like login) lets a malicious person reach the site's database directly.",
    },
    "default_credentials": {
        "title": "بيانات اعتماد افتراضية محتملة",
        "title_en": "Possible default credentials",
        "severity": Severity.HIGH,
        "remediation": "أجبر تغيير كل بيانات الاعتماد الافتراضية عند أول إعداد، وأزل أي حساب تجريبي/افتراضي قبل الإنتاج.",
        "remediation_en": "Force a change of all default credentials on first setup, and remove any demo/default account before production.",
        "business_impact": "لو صحّت هذي النتيجة، أي شخص يقدر يدخل بحساب لم يُغيَّر أبداً — دخول كامل بدون أي مجهود.",
        "business_impact_en": "If confirmed, anyone can log in with a credential pair that was never changed — full access with essentially no effort.",
        "plain_summary": "استجابة تسجيل الدخول تصرّفت بشكل مختلف مع بيانات اعتماد افتراضية معروفة (زي admin/admin) — يحتاج تأكيد يدوي.",
        "plain_summary_en": "The login response behaved differently with a well-known default credential pair (like admin/admin) — needs manual confirmation.",
    },
    "sqli_boolean_blind": {
        "title": "SQL Injection عمياء محتملة (boolean-based)",
        "title_en": "Possible blind SQL Injection (boolean-based)",
        "severity": Severity.HIGH,
        "remediation": "استخدم Parameterized Queries / Prepared Statements حصراً، حتى لو ما فيه خطأ ظاهر بالاستجابة.",
        "remediation_en": "Use Parameterized Queries / Prepared Statements exclusively, even when no error is visible in the response.",
        "business_impact": "مهاجم يقدر يستخرج بيانات قاعدة البيانات سؤال-سؤال بدون أي رسالة خطأ ظاهرة — أبطأ لكن نفس الخطورة النهائية.",
        "business_impact_en": "An attacker can extract database contents one true/false question at a time with no visible error message — slower, but the same eventual severity.",
        "plain_summary": "لقينا مؤشر سلوكي (مو رسالة خطأ مباشرة) يوحي بثغرة حقن SQL — يحتاج تأكيد يدوي قبل ما نعتبرها مؤكدة.",
        "plain_summary_en": "We found a behavioural indicator (not a direct error message) suggesting a SQL injection flaw — needs manual confirmation before treating it as certain.",
    },
    "sqli_time_blind": {
        "title": "SQL Injection عمياء محتملة (time-based)",
        "title_en": "Possible blind SQL Injection (time-based)",
        "severity": Severity.HIGH,
        "remediation": "استخدم Parameterized Queries / Prepared Statements حصراً، حتى لو ما فيه خطأ أو فرق واضح بالاستجابة.",
        "remediation_en": "Use Parameterized Queries / Prepared Statements exclusively, even when no error or content difference is visible.",
        "business_impact": "مهاجم يقدر يستخرج بيانات قاعدة البيانات عبر قياس زمن الاستجابة فقط — أبطأ تقنية لكن ما تحتاج أي مخرجات مرئية.",
        "business_impact_en": "An attacker can extract database contents purely by measuring response timing — the slowest technique, but needs no visible output at all.",
        "plain_summary": "استجابة السيرفر تأخرت بشكل ملحوظ مع حمولة اختبار توقيت — مؤشر يحتاج تأكيد يدوي، لأن تذبذب الشبكة ممكن يعطي نفس النتيجة.",
        "plain_summary_en": "The server's response was noticeably delayed with a timing test payload — an indicator that needs manual confirmation, since network jitter can produce the same result.",
    },
}
