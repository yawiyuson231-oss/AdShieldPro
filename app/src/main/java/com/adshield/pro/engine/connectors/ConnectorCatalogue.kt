package com.adshield.pro.engine.connectors

import com.adshield.pro.domain.connectors.ConnectorAuth
import com.adshield.pro.domain.connectors.ConnectorFormat
import com.adshield.pro.domain.connectors.ConnectorSpec
import com.adshield.pro.domain.connectors.ConnectorTransport
import com.adshield.pro.domain.connectors.VerificationClass
import com.adshield.pro.domain.intelligence.IntelligenceModule

/**
 * The complete, hand-curated connector catalogue.
 *
 * Rules this file follows (enforced by `ConnectorPlatformTestSuite` and the generated report):
 *  - every id is unique; every HTTP endpoint is https and unique per (method, endpoint);
 *  - every entry names a real provider endpoint or a real Android API;
 *  - credentials are never bundled: providers that require a key are declared but not enabled;
 *  - sources with no public machine interface are listed as NOT IMPLEMENTED / SOURCE UNAVAILABLE
 *    instead of being dressed up as integrations;
 *  - module counts in `docs/CONNECTOR_VERIFICATION.md` are generated from this list, not typed.
 */
object ConnectorCatalogue {

    private const val HOUR = 60L * 60L * 1_000L
    private const val DAY = 24L * HOUR

    private fun feed(
        id: String,
        name: String,
        module: IntelligenceModule,
        provider: String,
        endpoint: String,
        format: ConnectorFormat,
        handlerId: String,
        cacheTtlMs: Long,
        freeUse: String,
        restrictions: String,
        rateLimit: String,
        verification: VerificationClass = VerificationClass.IMPLEMENTED_AND_TESTED,
        auth: ConnectorAuth = ConnectorAuth.NONE,
        defaultEnabled: Boolean = false,
        maxBytes: Int = 4_000_000,
        implemented: Boolean = true
    ) = ConnectorSpec(
        id = id,
        name = name,
        module = module,
        provider = provider,
        endpoint = endpoint,
        format = format,
        transport = ConnectorTransport.HTTP,
        auth = auth,
        freeUse = freeUse,
        restrictions = restrictions,
        rateLimit = rateLimit,
        cacheTtlMs = cacheTtlMs,
        maxBytes = maxBytes,
        defaultEnabled = defaultEnabled,
        implemented = implemented,
        handlerId = handlerId,
        verification = verification,
        docsUrl = endpoint
    )

    private fun native(
        id: String,
        name: String,
        module: IntelligenceModule,
        provider: String,
        api: String,
        probeId: String,
        freeUse: String = "Built into Android; no service, account or cost.",
        restrictions: String = "Read-only Android API; no data leaves the device.",
        auth: ConnectorAuth = ConnectorAuth.NONE,
        verification: VerificationClass = VerificationClass.IMPLEMENTED_NOT_FULLY_VERIFIED,
        defaultEnabled: Boolean = false,
        cacheTtlMs: Long = 10 * 60L * 1_000L
    ) = ConnectorSpec(
        id = id,
        name = name,
        module = module,
        provider = provider,
        endpoint = api,
        method = "CALL",
        format = ConnectorFormat.ANDROID_API,
        transport = ConnectorTransport.NATIVE,
        auth = auth,
        freeUse = freeUse,
        restrictions = restrictions,
        rateLimit = "No remote rate limit; local call is throttled by the scheduler.",
        cacheTtlMs = cacheTtlMs,
        defaultEnabled = defaultEnabled,
        handlerId = probeId,
        verification = verification,
        docsUrl = ""
    )

    // ------------------------------------------------------------------ CYBER DEFENSE

    private fun cyber(): List<ConnectorSpec> = listOf(
        feed(
            id = "cyber.urlhaus.recent", name = "URLhaus recent malicious URLs",
            module = IntelligenceModule.CYBER_DEFENSE, provider = "abuse.ch (URLhaus)",
            endpoint = "https://urlhaus.abuse.ch/downloads/csv_recent/",
            format = ConnectorFormat.CSV, handlerId = "urlhaus-csv", cacheTtlMs = 6 * HOUR,
            freeUse = "Public feed, no account for this download.",
            restrictions = "abuse.ch feeds are for defensive/non-commercial use; the operator may rate-limit or change access.",
            rateLimit = "No published numeric limit; honour Retry-After and cache for hours.",
            verification = VerificationClass.FREE_WITH_RESTRICTIONS, defaultEnabled = true
        ),
        feed(
            id = "cyber.urlhaus.text", name = "URLhaus recent URL list (plain)",
            module = IntelligenceModule.CYBER_DEFENSE, provider = "abuse.ch (URLhaus)",
            endpoint = "https://urlhaus.abuse.ch/downloads/text_recent/",
            format = ConnectorFormat.TEXT, handlerId = "urlhaus-text", cacheTtlMs = 6 * HOUR,
            freeUse = "Public plain-text list.",
            restrictions = "Same abuse.ch terms as the CSV feed; a plain list carries no category metadata.",
            rateLimit = "Cache for hours; conditional requests supported.",
            verification = VerificationClass.FREE_WITH_RESTRICTIONS
        ),
        feed(
            id = "cyber.feodo.c2", name = "Feodo Tracker botnet C2 IPs",
            module = IntelligenceModule.CYBER_DEFENSE, provider = "abuse.ch (Feodo Tracker)",
            endpoint = "https://feodotracker.abuse.ch/downloads/ipblocklist.csv",
            format = ConnectorFormat.CSV, handlerId = "feodo-csv", cacheTtlMs = 6 * HOUR,
            freeUse = "Public botnet C2 blocklist.",
            restrictions = "Defensive use; lists change without notice; IPs can be reassigned, so entries expire.",
            rateLimit = "Cache for hours.",
            verification = VerificationClass.FREE_WITH_RESTRICTIONS, defaultEnabled = true
        ),
        feed(
            id = "cyber.cisa.kev", name = "CISA Known Exploited Vulnerabilities",
            module = IntelligenceModule.CYBER_DEFENSE, provider = "CISA (US government)",
            endpoint = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
            format = ConnectorFormat.JSON, handlerId = "cisa-kev", cacheTtlMs = DAY,
            freeUse = "US Government work, publicly available.",
            restrictions = "Authoritative for the CVEs CISA lists only; it is not a full vulnerability database.",
            rateLimit = "Static file, updated a few times per week.",
            defaultEnabled = true
        ),
        feed(
            id = "cyber.first.epss", name = "FIRST EPSS exploit probability (top 100)",
            module = IntelligenceModule.CYBER_DEFENSE, provider = "FIRST.org",
            endpoint = "https://api.first.org/data/v1/epss?days=1&limit=100&order=!epss",
            format = ConnectorFormat.JSON, handlerId = "epss", cacheTtlMs = DAY,
            freeUse = "Public API, no key.",
            restrictions = "Probability scores are estimates, not proof of exploitation; API is best-effort.",
            rateLimit = "Reasonable use; cache for a day."
        ),
        feed(
            id = "cyber.nvd.recent", name = "NVD latest CVEs",
            module = IntelligenceModule.CYBER_DEFENSE, provider = "NIST NVD",
            endpoint = "https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=100",
            format = ConnectorFormat.JSON, handlerId = "nvd-cves", cacheTtlMs = 12 * HOUR,
            freeUse = "Public API, no key required.",
            restrictions = "Strict anonymous rate limits; descriptions are truncated and CVSS detail is not used here.",
            rateLimit = "5 requests per 30 s without an API key (documented by NIST)."
        ),
        feed(
            id = "cyber.github.advisories", name = "GitHub Security Advisories",
            module = IntelligenceModule.CYBER_DEFENSE, provider = "GitHub",
            endpoint = "https://api.github.com/advisories?per_page=100",
            format = ConnectorFormat.JSON, handlerId = "github-advisories", cacheTtlMs = 12 * HOUR,
            freeUse = "Public REST endpoint without authentication.",
            restrictions = "Unauthenticated quota and API availability are controlled by GitHub.",
            rateLimit = "60 requests per hour per IP unauthenticated."
        ),
        feed(
            id = "cyber.misp.special-use", name = "MISP warninglist: special-use domains",
            module = IntelligenceModule.CYBER_DEFENSE, provider = "MISP project",
            endpoint = "https://raw.githubusercontent.com/MISP/misp-warninglists/main/lists/special-use-domain/list.json",
            format = ConnectorFormat.JSON, handlerId = "misp-list", cacheTtlMs = 7 * DAY,
            freeUse = "Open-source warninglists on GitHub.",
            restrictions = "This list marks reserved/special domains; it is used for suppression, never to accuse a domain.",
            rateLimit = "Static raw.githubusercontent.com file.",
            verification = VerificationClass.FREE_WITH_RESTRICTIONS
        ),
        feed(
            id = "cyber.threatfox", name = "ThreatFox IOC feed",
            module = IntelligenceModule.CYBER_DEFENSE, provider = "abuse.ch (ThreatFox)",
            endpoint = "https://threatfox-api.abuse.ch/api/v1/",
            format = ConnectorFormat.JSON, handlerId = "none", cacheTtlMs = 6 * HOUR,
            freeUse = "Free account required by the provider for API access.",
            restrictions = "Requires an Auth-Key that this build does not ship and does not ask for.",
            rateLimit = "Per-account quota enforced by abuse.ch.",
            verification = VerificationClass.FREE_WITH_RESTRICTIONS,
            auth = ConnectorAuth.REQUIRED_KEY, implemented = false
        ),
        feed(
            id = "cyber.malwarebazaar", name = "MalwareBazaar recent samples",
            module = IntelligenceModule.CYBER_DEFENSE, provider = "abuse.ch (MalwareBazaar)",
            endpoint = "https://bazaar.abuse.ch/export/csv/recent/",
            format = ConnectorFormat.CSV, handlerId = "none", cacheTtlMs = 6 * HOUR,
            freeUse = "Export requires an Auth-Key from abuse.ch.",
            restrictions = "No key is embedded in the APK; the connector stays NOT CONFIGURED.",
            rateLimit = "Governed by abuse.ch account policy.",
            verification = VerificationClass.FREE_WITH_RESTRICTIONS,
            auth = ConnectorAuth.REQUIRED_KEY, implemented = false
        ),
        native(
            id = "cyber.android.signing", name = "APK signature verification",
            module = IntelligenceModule.CYBER_DEFENSE, provider = "Android PackageManager",
            api = "PackageManager#getPackageInfo(GET_SIGNING_CERTIFICATES)",
            probeId = "probe.apk-signing",
            restrictions = "Verifies signing certificates of packages this app can query; it cannot prove an app is benign."
        ),
        native(
            id = "cyber.android.zip", name = "APK/ZIP structure inspection",
            module = IntelligenceModule.CYBER_DEFENSE, provider = "java.util.zip + Android",
            api = "ZipFile over the installed APK",
            probeId = "probe.zip-inspection",
            restrictions = "Inspects the app's own APK; scanning arbitrary archives is bounded by the file picker grant."
        ),
        native(
            id = "cyber.android.sha256", name = "Local SHA-256 hashing",
            module = IntelligenceModule.CYBER_DEFENSE, provider = "Android/JCA",
            api = "java.security.MessageDigest(\"SHA-256\")",
            probeId = "probe.sha256",
            verification = VerificationClass.IMPLEMENTED_AND_TESTED,
            restrictions = "Hashing is exact; it says nothing about whether a file is malicious."
        ),
        native(
            id = "cyber.android.permissions", name = "Suspicious permission detection",
            module = IntelligenceModule.CYBER_DEFENSE, provider = "Android PackageManager",
            api = "PackageManager#getInstalledPackages + requestedPermissions",
            probeId = "probe.permission-audit",
            auth = ConnectorAuth.USER_AUTHORIZATION,
            restrictions = "Visibility is limited to packages Android lets this app query; scoring is heuristic."
        ),
        native(
            id = "cyber.local.hash-index", name = "Local malicious-hash matching",
            module = IntelligenceModule.CYBER_DEFENSE, provider = "On-device Room index",
            api = "threat_indicators (kind=HASH_SHA256)",
            probeId = "probe.hash-index",
            verification = VerificationClass.IMPLEMENTED_AND_TESTED,
            restrictions = "Only matches hashes already cached from public feeds; unknown files are not identified."
        ),
        native(
            id = "cyber.local.ioc-index", name = "Cached IOC matching engine",
            module = IntelligenceModule.CYBER_DEFENSE, provider = "On-device Room index",
            api = "threat_indicators (URL/DOMAIN/IP/CVE)",
            probeId = "probe.ioc-index",
            verification = VerificationClass.IMPLEMENTED_AND_TESTED,
            restrictions = "Offline matching works only for indicators currently cached; stale rows expire."
        )
    )

    // ------------------------------------------------------------------ FINANCIAL DEFENSE

    private fun financial(): List<ConnectorSpec> = listOf(
        feed(
            id = "fin.urlhaus.online", name = "URLhaus online malicious URLs",
            module = IntelligenceModule.FINANCIAL_DEFENSE, provider = "abuse.ch (URLhaus)",
            endpoint = "https://urlhaus.abuse.ch/downloads/csv_online/",
            format = ConnectorFormat.CSV, handlerId = "urlhaus-online-csv", cacheTtlMs = 6 * HOUR,
            freeUse = "Public download.",
            restrictions = "Defensive use; URLs are reported by third parties and can include compromised legitimate sites.",
            rateLimit = "Cache for hours.",
            verification = VerificationClass.FREE_WITH_RESTRICTIONS, defaultEnabled = true
        ),
        feed(
            id = "fin.openphish", name = "OpenPhish community feed",
            module = IntelligenceModule.FINANCIAL_DEFENSE, provider = "OpenPhish",
            endpoint = "https://openphish.com/feed.txt",
            format = ConnectorFormat.TEXT, handlerId = "openphish-text", cacheTtlMs = 2 * HOUR,
            freeUse = "Community feed published by OpenPhish.",
            restrictions = "Community feed is time-limited and the operator restricts redistribution/commercial use; verify current terms before relying on it.",
            rateLimit = "Feed changes frequently; hourly caching is polite.",
            verification = VerificationClass.FREE_WITH_RESTRICTIONS
        ),
        feed(
            id = "fin.phishtank", name = "PhishTank verified phishing URLs",
            module = IntelligenceModule.FINANCIAL_DEFENSE, provider = "OpenDNS / Cisco PhishTank",
            endpoint = "https://data.phishtank.com/data/online-valid.json",
            format = ConnectorFormat.JSON, handlerId = "none", cacheTtlMs = 2 * HOUR,
            freeUse = "Data is free but the download endpoint requires an application key.",
            restrictions = "No application key is embedded; this connector stays NOT CONFIGURED by design.",
            rateLimit = "Key-bound quota controlled by PhishTank.",
            verification = VerificationClass.FREE_WITH_RESTRICTIONS,
            auth = ConnectorAuth.REQUIRED_KEY, implemented = false
        ),
        feed(
            id = "fin.stevenblack.hosts", name = "StevenBlack unified hosts (malware + adware)",
            module = IntelligenceModule.FINANCIAL_DEFENSE, provider = "StevenBlack/hosts (open source)",
            endpoint = "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
            format = ConnectorFormat.TEXT, handlerId = "stevenblack-hosts", cacheTtlMs = 2 * DAY,
            freeUse = "MIT-licensed community hosts list.",
            restrictions = "Mixes adware, trackers and malware; treated as a domain blocklist with lower confidence, not proof of fraud.",
            rateLimit = "Static GitHub file; daily caching is enough.",
            verification = VerificationClass.FREE_WITH_RESTRICTIONS, maxBytes = 12_000_000
        ),
        feed(
            id = "fin.phishing.database", name = "Phishing.Database active domains",
            module = IntelligenceModule.FINANCIAL_DEFENSE, provider = "Mitchell Krog / Phishing.Database",
            endpoint = "https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-domains-ACTIVE.txt",
            format = ConnectorFormat.TEXT, handlerId = "phishing-domains", cacheTtlMs = DAY,
            freeUse = "Open-source community database.",
            restrictions = "Community-curated; false positives happen, so it raises risk instead of blocking silently.",
            rateLimit = "Static GitHub file.",
            verification = VerificationClass.FREE_WITH_RESTRICTIONS, maxBytes = 16_000_000
        ),
        feed(
            id = "fin.misp.url-shortener", name = "MISP warninglist: URL shorteners",
            module = IntelligenceModule.FINANCIAL_DEFENSE, provider = "MISP project",
            endpoint = "https://raw.githubusercontent.com/MISP/misp-warninglists/main/lists/url-shortener/list.json",
            format = ConnectorFormat.JSON, handlerId = "misp-list", cacheTtlMs = 7 * DAY,
            freeUse = "Open-source warninglist.",
            restrictions = "Shorteners are not malicious by themselves; this list is used to warn about hidden destinations.",
            rateLimit = "Static GitHub file.",
            verification = VerificationClass.FREE_WITH_RESTRICTIONS
        ),
        native(
            id = "fin.local.heuristics", name = "Local scam URL heuristics",
            module = IntelligenceModule.FINANCIAL_DEFENSE, provider = "On-device deterministic rules",
            api = "engine/security/UrlThreatScanner + FinancialTargetClassifier",
            probeId = "probe.fin-heuristics",
            verification = VerificationClass.IMPLEMENTED_AND_TESTED,
            restrictions = "Deterministic heuristics; they can miss novel scams and can flag legitimate sites."
        ),
        native(
            id = "fin.local.typosquat", name = "Typosquatting / lookalike detection",
            module = IntelligenceModule.FINANCIAL_DEFENSE, provider = "On-device Levenshtein + brand list",
            api = "engine/intelligence/FinancialTargetClassifier",
            probeId = "probe.typosquat",
            verification = VerificationClass.IMPLEMENTED_AND_TESTED,
            restrictions = "Compares against a small embedded brand list; it does not query registration data."
        ),
        native(
            id = "fin.local.idn", name = "IDN / punycode inspection",
            module = IntelligenceModule.FINANCIAL_DEFENSE, provider = "java.net.IDN",
            api = "java.net.IDN#toUnicode",
            probeId = "probe.idn",
            verification = VerificationClass.IMPLEMENTED_AND_TESTED,
            restrictions = "Detects non-ASCII homographs; it cannot judge intent."
        ),
        native(
            id = "fin.local.brand", name = "Brand impersonation indicators",
            module = IntelligenceModule.FINANCIAL_DEFENSE, provider = "On-device token matching",
            api = "URL host/path token analysis",
            probeId = "probe.brand",
            verification = VerificationClass.IMPLEMENTED_AND_TESTED,
            restrictions = "Token matching only; a brand token in a path is an indicator, not proof."
        ),
        native(
            id = "fin.local.redirect", name = "Malicious redirect inspection",
            module = IntelligenceModule.FINANCIAL_DEFENSE, provider = "On-device URL parser",
            api = "URL parameter/redirect analysis",
            probeId = "probe.redirect",
            verification = VerificationClass.IMPLEMENTED_AND_TESTED,
            restrictions = "Inspects URL structure without opening links; it does not follow redirects."
        ),
        native(
            id = "fin.local.qr", name = "QR payload analysis",
            module = IntelligenceModule.FINANCIAL_DEFENSE, provider = "On-device text analysis",
            api = "Pasted QR payload → URL analysis",
            probeId = "probe.qr",
            verification = VerificationClass.IMPLEMENTED_AND_TESTED,
            restrictions = "Text payloads only — no camera decoding is added, so no new camera permission is requested."
        )
    )

    // ------------------------------------------------------------------ PRIVACY DEFENSE

    private fun privacy(): List<ConnectorSpec> = listOf(
        native(
            "privacy.inventory", "Installed application inventory", IntelligenceModule.PRIVACY_DEFENSE,
            "Android PackageManager", "PackageManager#getInstalledPackages", "probe.app-inventory",
            restrictions = "Android package visibility rules hide apps this app may not query."
        ),
        native(
            "privacy.permissions", "Permission matrix", IntelligenceModule.PRIVACY_DEFENSE,
            "Android PackageManager", "PackageManager#getPackageInfo(requestedPermissions)", "probe.permission-matrix",
            restrictions = "Declared permissions only; runtime grant state is shown where readable."
        ),
        native(
            "privacy.camera", "Camera permission review", IntelligenceModule.PRIVACY_DEFENSE,
            "Android PackageManager", "Manifest.permission.CAMERA", "probe.camera",
            restrictions = "Counts apps that declare camera access; it cannot see actual camera use."
        ),
        native(
            "privacy.microphone", "Microphone permission review", IntelligenceModule.PRIVACY_DEFENSE,
            "Android PackageManager", "Manifest.permission.RECORD_AUDIO", "probe.microphone",
            restrictions = "Declarations only; Android does not expose other apps' live microphone use to normal apps."
        ),
        native(
            "privacy.location", "Location permission review", IntelligenceModule.PRIVACY_DEFENSE,
            "Android PackageManager", "ACCESS_FINE/COARSE_LOCATION", "probe.location",
            restrictions = "Background location grants are not fully visible without special access."
        ),
        native(
            "privacy.contacts-sms", "Contacts and SMS permission review", IntelligenceModule.PRIVACY_DEFENSE,
            "Android PackageManager", "READ_CONTACTS / READ_SMS / RECEIVE_SMS", "probe.contacts-sms",
            restrictions = "SMS permissions are restricted by Play policy; presence is reported, not judged."
        ),
        native(
            "privacy.accessibility", "Accessibility service audit", IntelligenceModule.PRIVACY_DEFENSE,
            "android.accessibilityservice.AccessibilityManager", "AccessibilityManager#getEnabledAccessibilityServiceList",
            "probe.accessibility", restrictions = "Lists enabled services; it cannot inspect what they read."
        ),
        native(
            "privacy.notification-access", "Notification access audit", IntelligenceModule.PRIVACY_DEFENSE,
            "android.service.notification.NotificationListenerService", "NotificationManager#getEnabledListenerPackages",
            "probe.notification-access", restrictions = "Requires the user to grant notification access for this app to be listed itself."
        ),
        native(
            "privacy.usage-access", "Usage access status", IntelligenceModule.PRIVACY_DEFENSE,
            "android.app.usage.UsageStatsManager", "AppOpsManager#checkOpNoThrow(OP_GET_USAGE_STATS)",
            "probe.usage-access", auth = ConnectorAuth.USER_AUTHORIZATION,
            restrictions = "Usage history is only available after the user grants usage access in Settings."
        ),
        native(
            "privacy.appops", "Special app access (AppOps) probe", IntelligenceModule.PRIVACY_DEFENSE,
            "android.app.AppOpsManager", "AppOpsManager#getOpsForPackage", "probe.appops",
            restrictions = "Most AppOps reads are privileged; the probe reports only what is readable."
        ),
        native(
            "privacy.sensor-privacy", "Sensor privacy status", IntelligenceModule.PRIVACY_DEFENSE,
            "android.hardware.SensorPrivacyManager", "SensorPrivacyManager#supportsSensorToggle",
            "probe.sensor-privacy", restrictions = "API 31+; older devices report NOT SUPPORTED."
        ),
        native(
            "privacy.clipboard", "Clipboard privacy diagnostics", IntelligenceModule.PRIVACY_DEFENSE,
            "android.content.ClipboardManager", "ClipboardManager#hasPrimaryClip", "probe.clipboard",
            restrictions = "Android 10+ only exposes clipboard content to the focused app; contents are never stored."
        ),
        native(
            "privacy.biometric", "Biometric availability", IntelligenceModule.PRIVACY_DEFENSE,
            "androidx.biometric.BiometricManager", "BiometricManager#canAuthenticate", "probe.biometric",
            restrictions = "Reports capability only; biometrics are used by the app's own lock, not by this probe."
        ),
        native(
            "privacy.keystore", "Android Keystore status", IntelligenceModule.PRIVACY_DEFENSE,
            "java.security.KeyStore", "KeyStore.getInstance(\"AndroidKeyStore\")", "probe.keystore",
            restrictions = "Confirms keystore availability; hardware backing varies by device."
        ),
        native(
            "privacy.keyguard", "Keyguard / device lock state", IntelligenceModule.PRIVACY_DEFENSE,
            "android.app.KeyguardManager", "KeyguardManager#isDeviceSecure", "probe.keyguard",
            restrictions = "No lock-screen contents are read."
        ),
        native(
            "privacy.signatures", "Installed app signature inspection", IntelligenceModule.PRIVACY_DEFENSE,
            "Android PackageManager", "PackageInfo#signingInfo", "probe.signatures",
            restrictions = "Signature digests only; certificate chains are not validated against a trust store."
        ),
        native(
            "privacy.security-settings", "Android security settings check", IntelligenceModule.PRIVACY_DEFENSE,
            "android.provider.Settings", "Settings.Global ADB / developer options", "probe.security-settings",
            restrictions = "Some global settings are unreadable to normal apps; unreadable values are reported as such."
        ),
        native(
            "privacy.risk-score", "Privacy risk scoring", IntelligenceModule.PRIVACY_DEFENSE,
            "On-device deterministic scoring", "engine/intelligence privacy rules", "probe.privacy-score",
            verification = VerificationClass.IMPLEMENTED_AND_TESTED,
            restrictions = "Explainable score from permission/app counts; not a compliance certification."
        ),
        native(
            "privacy.report", "Privacy report export", IntelligenceModule.PRIVACY_DEFENSE,
            "androidx.core.content.FileProvider", "Report writer", "probe.privacy-report",
            restrictions = "Exports only what this app measured; no account data leaves the device."
        )
    )

    // ------------------------------------------------------------------ NETWORK DEFENSE

    private fun network(): List<ConnectorSpec> = listOf(
        feed(
            "net.ripe.bgp", "RIPEstat BGP state lookup", IntelligenceModule.NETWORK_DEFENSE,
            "RIPE NCC RIPEstat", "https://stat.ripe.net/data/bgp-state/data.json?resource=1.1.1.1",
            ConnectorFormat.JSON, "ripe-bgp-state", 12 * HOUR,
            freeUse = "Public RIPEstat API without registration.",
            restrictions = "Routing visibility only; it does not say whether an address is malicious.",
            rateLimit = "RIPEstat asks clients to keep request rates low; cached here for 12 h.",
            verification = VerificationClass.FREE_WITH_RESTRICTIONS
        ),
        feed(
            "net.rdap.ip", "RDAP IP registration lookup", IntelligenceModule.NETWORK_DEFENSE,
            "rdap.org bootstrap", "https://rdap.org/ip/1.1.1.1",
            ConnectorFormat.JSON, "rdap-lookup", DAY,
            freeUse = "Public RDAP bootstrap redirector.",
            restrictions = "Registration metadata only; availability depends on the responsible registry.",
            rateLimit = "No published limit; daily caching.",
            verification = VerificationClass.FREE_WITH_RESTRICTIONS
        ),
        feed(
            "net.ipify", "Public IP address observation", IntelligenceModule.NETWORK_DEFENSE,
            "ipify", "https://api.ipify.org?format=json",
            ConnectorFormat.JSON, "ipify", 30 * 60L * 1_000L,
            freeUse = "Free public endpoint, no key.",
            restrictions = "Sends a request to a third party, which necessarily learns your public IP. Opt-in only.",
            rateLimit = "No published limit; cached 30 min.",
            verification = VerificationClass.FREE_WITH_RESTRICTIONS
        ),
        feed(
            "net.ipsum", "IPsum aggregated IP blocklist", IntelligenceModule.NETWORK_DEFENSE,
            "stamparm/ipsum (open source)", "https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt",
            ConnectorFormat.TEXT, "ipsum", DAY,
            freeUse = "Open-source aggregation of public blocklists.",
            restrictions = "Aggregated reputation; a listed IP is suspicious, not proven hostile.",
            rateLimit = "Static GitHub file.",
            verification = VerificationClass.FREE_WITH_RESTRICTIONS, maxBytes = 8_000_000
        ),
        native(
            "net.connectivity", "Connectivity monitoring", IntelligenceModule.NETWORK_DEFENSE,
            "android.net.ConnectivityManager", "ConnectivityManager#getActiveNetwork", "probe.connectivity"
        ),
        native(
            "net.capabilities", "Network capabilities", IntelligenceModule.NETWORK_DEFENSE,
            "android.net.NetworkCapabilities", "NetworkCapabilities#hasCapability", "probe.capabilities"
        ),
        native(
            "net.link-properties", "Link properties", IntelligenceModule.NETWORK_DEFENSE,
            "android.net.LinkProperties", "LinkProperties#getLinkAddresses/getDnsServers", "probe.link-properties"
        ),
        native(
            "net.wifi", "Wi-Fi diagnostics", IntelligenceModule.NETWORK_DEFENSE,
            "android.net.wifi.WifiManager", "WifiManager#getConnectionInfo", "probe.wifi",
            auth = ConnectorAuth.USER_AUTHORIZATION,
            restrictions = "SSID/BSSID require location permission on modern Android; otherwise only state is reported."
        ),
        native(
            "net.interfaces", "Network interface inventory", IntelligenceModule.NETWORK_DEFENSE,
            "java.net.NetworkInterface", "NetworkInterface#getNetworkInterfaces", "probe.interfaces"
        ),
        native(
            "net.dns-resolve", "DNS resolution diagnostics", IntelligenceModule.NETWORK_DEFENSE,
            "java.net.InetAddress + app DNS engine", "InetAddress#getAllByName", "probe.dns-resolve"
        ),
        native(
            "net.latency", "Latency measurement", IntelligenceModule.NETWORK_DEFENSE,
            "java.net.Socket", "TCP connect timing to public resolvers", "probe.latency",
            restrictions = "Measures TCP handshake time to fixed public endpoints; it is not a full speed test."
        ),
        native(
            "net.diagnostics-api", "ConnectivityDiagnosticsManager availability", IntelligenceModule.NETWORK_DEFENSE,
            "android.net.ConnectivityDiagnosticsManager", "ConnectivityDiagnosticsManager (API 30+)",
            "probe.diagnostics", restrictions = "API 30+; providers may not publish diagnostics for every network."
        ),
        native(
            "net.stats", "Network usage statistics availability", IntelligenceModule.NETWORK_DEFENSE,
            "android.app.usage.NetworkStatsManager", "NetworkStatsManager#querySummary",
            "probe.net-stats", auth = ConnectorAuth.USER_AUTHORIZATION,
            restrictions = "Historical per-app usage requires usage-access/privileged permissions; unavailable reads are reported."
        ),
        native(
            "net.config-report", "Network configuration report", IntelligenceModule.NETWORK_DEFENSE,
            "On-device report writer", "Report formatter", "probe.net-report",
            verification = VerificationClass.IMPLEMENTED_AND_TESTED
        ),
        native(
            "net.event-history", "Network event history", IntelligenceModule.NETWORK_DEFENSE,
            "On-device Room store", "intelligence_events (NETWORK_DEFENSE)", "probe.net-history",
            verification = VerificationClass.IMPLEMENTED_AND_TESTED
        )
    )

    // ------------------------------------------------------------------ DEVICE INTELLIGENCE

    private fun device(): List<ConnectorSpec> = listOf(
        native("dev.battery", "Battery monitoring", IntelligenceModule.DEVICE_INTELLIGENCE,
            "android.os.BatteryManager", "BatteryManager#BATTERY_PROPERTY_CAPACITY", "probe.battery"),
        native("dev.charging", "Charging status", IntelligenceModule.DEVICE_INTELLIGENCE,
            "android.os.BatteryManager", "BatteryManager#isCharging", "probe.charging"),
        native("dev.temperature", "Battery temperature", IntelligenceModule.DEVICE_INTELLIGENCE,
            "android.os.BatteryManager", "Intent.EXTRA_TEMPERATURE", "probe.temperature",
            restrictions = "Not every device exposes a temperature; unsupported is reported as such."),
        native("dev.health", "Battery health", IntelligenceModule.DEVICE_INTELLIGENCE,
            "android.os.BatteryManager", "Intent.EXTRA_HEALTH", "probe.battery-health"),
        native("dev.storage", "Storage diagnostics", IntelligenceModule.DEVICE_INTELLIGENCE,
            "android.os.StatFs", "StatFs#getAvailableBytes", "probe.storage"),
        native("dev.memory", "Memory diagnostics", IntelligenceModule.DEVICE_INTELLIGENCE,
            "android.app.ActivityManager", "ActivityManager.MemoryInfo", "probe.memory"),
        native("dev.cpu", "CPU information", IntelligenceModule.DEVICE_INTELLIGENCE,
            "java.lang.Runtime + Build", "Runtime#availableProcessors", "probe.cpu"),
        native("dev.thermal", "Thermal status", IntelligenceModule.DEVICE_INTELLIGENCE,
            "android.os.PowerManager", "PowerManager#getCurrentThermalStatus (API 29+)", "probe.thermal"),
        native("dev.sensors", "Sensor inventory", IntelligenceModule.DEVICE_INTELLIGENCE,
            "android.hardware.SensorManager", "SensorManager#getSensorList", "probe.sensors"),
        native("dev.display", "Display diagnostics", IntelligenceModule.DEVICE_INTELLIGENCE,
            "android.view.Display", "Display#getMode/getRefreshRate", "probe.display"),
        native("dev.build", "Device model and Android version", IntelligenceModule.DEVICE_INTELLIGENCE,
            "android.os.Build", "Build.MANUFACTURER/MODEL/VERSION", "probe.build"),
        native("dev.patch", "Security patch level", IntelligenceModule.DEVICE_INTELLIGENCE,
            "android.os.Build.VERSION", "Build.VERSION.SECURITY_PATCH", "probe.patch"),
        native("dev.features", "System feature detection", IntelligenceModule.DEVICE_INTELLIGENCE,
            "android.content.pm.PackageManager", "PackageManager#getSystemAvailableFeatures", "probe.features"),
        native("dev.runtime", "Android runtime information", IntelligenceModule.DEVICE_INTELLIGENCE,
            "java.lang.Runtime", "Runtime#version + Process", "probe.runtime"),
        native("dev.uptime", "Uptime and boot time", IntelligenceModule.DEVICE_INTELLIGENCE,
            "android.os.SystemClock", "SystemClock#elapsedRealtime", "probe.uptime"),
        native("dev.power-save", "Power saver state", IntelligenceModule.DEVICE_INTELLIGENCE,
            "android.os.PowerManager", "PowerManager#isPowerSaveMode", "probe.power-save"),
        native("dev.exit-info", "Application crash history", IntelligenceModule.DEVICE_INTELLIGENCE,
            "android.app.ApplicationExitInfo", "ActivityManager#getHistoricalProcessExitReasons (API 30+)",
            "probe.exit-info", restrictions = "API 30+; only this app's own exit reasons are visible."),
        native("dev.keystore", "Keystore hardware backing", IntelligenceModule.DEVICE_INTELLIGENCE,
            "android.security.keystore.KeyInfo", "KeyInfo#isInsideSecureHardware", "probe.keystore-hardware",
            restrictions = "Hardware backing depends on the device; a software keystore is reported honestly."),
        native("dev.performance", "Device performance history", IntelligenceModule.DEVICE_INTELLIGENCE,
            "On-device Room store", "battery/telemetry history", "probe.performance",
            verification = VerificationClass.IMPLEMENTED_AND_TESTED)
    )

    // ------------------------------------------------------------------ EMERGENCY INTELLIGENCE

    private fun emergency(): List<ConnectorSpec> = listOf(
        feed(
            "emrg.usgs", "USGS earthquakes (past day)", IntelligenceModule.EMERGENCY_INTELLIGENCE,
            "U.S. Geological Survey", "https://earthquake.usgs.gov/earthquakes/feed/v1.0/summary/all_day.geojson",
            ConnectorFormat.JSON, "usgs-quakes", 15 * 60L * 1_000L,
            freeUse = "Public USGS GeoJSON feed.",
            restrictions = "Worldwide earthquakes; magnitude/time are preliminary and may be revised.",
            rateLimit = "Static feed updated every minute; 15 min caching.",
            defaultEnabled = true
        ),
        feed(
            "emrg.gdacs", "GDACS disaster alerts (RSS)", IntelligenceModule.EMERGENCY_INTELLIGENCE,
            "GDACS (EU/UN)", "https://www.gdacs.org/xml/rss.xml",
            ConnectorFormat.RSS, "gdacs-rss", 30 * 60L * 1_000L,
            freeUse = "Public RSS feed.",
            restrictions = "Global coverage; alert levels are GDACS assessments, not local authority orders.",
            rateLimit = "Cache 30 min.",
            defaultEnabled = true
        ),
        feed(
            "emrg.nws", "US National Weather Service alerts", IntelligenceModule.EMERGENCY_INTELLIGENCE,
            "NOAA / NWS", "https://api.weather.gov/alerts/active",
            ConnectorFormat.JSON, "nws-alerts", 15 * 60L * 1_000L,
            freeUse = "Public API, no key; NWS asks for a descriptive User-Agent (sent).",
            restrictions = "United States only. Not a Philippine source.",
            rateLimit = "NWS requests polite usage; 15 min caching.",
            verification = VerificationClass.FREE_WITH_RESTRICTIONS
        ),
        feed(
            "emrg.reliefweb", "ReliefWeb disasters", IntelligenceModule.EMERGENCY_INTELLIGENCE,
            "ReliefWeb (OCHA)", "https://api.reliefweb.int/v1/disasters?appname=omni-shield-x&limit=50&sort[]=date:desc",
            ConnectorFormat.JSON, "reliefweb-disasters", 6 * HOUR,
            freeUse = "Public API; appname parameter is required for identification only.",
            restrictions = "Humanitarian context, not real-time evacuation orders.",
            rateLimit = "ReliefWeb asks for modest rates; 6 h caching.",
            verification = VerificationClass.FREE_WITH_RESTRICTIONS
        ),
        feed(
            "emrg.emsc", "EMSC/SeismicPortal earthquakes", IntelligenceModule.EMERGENCY_INTELLIGENCE,
            "EMSC", "https://www.seismicportal.eu/fdsnws/event/1/query?format=json&limit=50&orderby=time",
            ConnectorFormat.JSON, "seismicportal", 30 * 60L * 1_000L,
            freeUse = "Public FDSN event service.",
            restrictions = "European-Mediterranean catalogue; global coverage is partial.",
            rateLimit = "Cache 30 min.",
            verification = VerificationClass.FREE_WITH_RESTRICTIONS
        ),
        native(
            "emrg.location", "Location relevance permission", IntelligenceModule.EMERGENCY_INTELLIGENCE,
            "android.location.LocationManager", "LocationManager#isProviderEnabled", "probe.location-permission",
            auth = ConnectorAuth.USER_AUTHORIZATION,
            restrictions = "Alerts are still listed without location; relevance sorting needs user permission."
        ),
        native(
            "emrg.history", "Alert history", IntelligenceModule.EMERGENCY_INTELLIGENCE,
            "On-device Room store", "intelligence_events (EMERGENCY_INTELLIGENCE)", "probe.emrg-history",
            verification = VerificationClass.IMPLEMENTED_AND_TESTED
        ),
        feed(
            "emrg.pagasa", "PAGASA official bulletins", IntelligenceModule.EMERGENCY_INTELLIGENCE,
            "PAGASA (DOST, Philippines)", "https://www.pagasa.dost.gov.ph/",
            ConnectorFormat.RSS, "none", 6 * HOUR,
            freeUse = "Official public website.",
            restrictions = "No documented public machine-readable API; this build does not scrape or republish bulletins as if they were an API.",
            rateLimit = "n/a",
            verification = VerificationClass.SOURCE_UNAVAILABLE, implemented = false
        ),
        feed(
            "emrg.ndrrmc", "NDRRMC official announcements", IntelligenceModule.EMERGENCY_INTELLIGENCE,
            "NDRRMC (Philippines)", "https://www.ndrrmc.gov.ph/",
            ConnectorFormat.RSS, "none", 6 * HOUR,
            freeUse = "Official public website.",
            restrictions = "No documented public API; listed as unavailable rather than faked.",
            rateLimit = "n/a",
            verification = VerificationClass.SOURCE_UNAVAILABLE, implemented = false
        ),
        feed(
            "emrg.phivolcs", "PHIVOLCS earthquake bulletins", IntelligenceModule.EMERGENCY_INTELLIGENCE,
            "PHIVOLCS (DOST, Philippines)", "https://earthquake.phivolcs.dost.gov.ph/",
            ConnectorFormat.RSS, "none", 6 * HOUR,
            freeUse = "Official public website.",
            restrictions = "HTML bulletins only; no public machine interface, so not scraped.",
            rateLimit = "n/a",
            verification = VerificationClass.SOURCE_UNAVAILABLE, implemented = false
        ),
        feed(
            "emrg.firms", "NASA FIRMS active fire detections", IntelligenceModule.EMERGENCY_INTELLIGENCE,
            "NASA FIRMS", "https://firms.modaps.eosdis.nasa.gov/api/area/csv",
            ConnectorFormat.CSV, "none", 6 * HOUR,
            freeUse = "Free with a MAP_KEY requested by NASA.",
            restrictions = "Requires a personal MAP_KEY; none is embedded, so the connector stays NOT CONFIGURED.",
            rateLimit = "Key-bound quota.",
            verification = VerificationClass.FREE_WITH_RESTRICTIONS,
            auth = ConnectorAuth.REQUIRED_KEY, implemented = false
        )
    )

    // ------------------------------------------------------------------ AUTOMATION CORE

    private fun automation(): List<ConnectorSpec> = listOf(
        native("auto.workmanager", "WorkManager periodic scheduling", IntelligenceModule.AUTOMATION_CORE,
            "androidx.work.WorkManager", "WorkManager#enqueueUniquePeriodicWork", "probe.workmanager"),
        native("auto.constraints", "Network/battery constraints", IntelligenceModule.AUTOMATION_CORE,
            "androidx.work.Constraints", "Constraints#setRequiredNetworkType", "probe.constraints"),
        native("auto.backoff", "Exponential backoff recovery", IntelligenceModule.AUTOMATION_CORE,
            "androidx.work.BackoffPolicy", "BackoffPolicy.EXPONENTIAL", "probe.backoff",
            verification = VerificationClass.IMPLEMENTED_AND_TESTED),
        native("auto.unique", "Unique work chaining", IntelligenceModule.AUTOMATION_CORE,
            "androidx.work.WorkManager", "enqueueUniqueWork(REPLACE)", "probe.unique-work"),
        native("auto.boot", "Boot rescheduling", IntelligenceModule.AUTOMATION_CORE,
            "android.content.BroadcastReceiver", "ACTION_BOOT_COMPLETED", "probe.boot",
            restrictions = "Only works if the user has launched the app at least once and has not force-stopped it."),
        native("auto.alarm", "AlarmManager timeouts", IntelligenceModule.AUTOMATION_CORE,
            "android.app.AlarmManager", "AlarmManager#setAndAllowWhileIdle", "probe.alarm",
            restrictions = "Exact alarms need a user-granted special permission; inexact alarms are used instead."
        ),
        native("auto.notifications", "Security notifications", IntelligenceModule.AUTOMATION_CORE,
            "android.app.NotificationManager", "NotificationChannel + notify", "probe.notifications",
            restrictions = "Needs POST_NOTIFICATIONS (Android 13+); denial is reported, not hidden."
        ),
        native("auto.pendingintent", "PendingIntent actions", IntelligenceModule.AUTOMATION_CORE,
            "android.app.PendingIntent", "PendingIntent#getActivity", "probe.pending-intent"),
        native("auto.room", "Local event recording", IntelligenceModule.AUTOMATION_CORE,
            "androidx.room.RoomDatabase", "intelligence_events + connector_state", "probe.room",
            verification = VerificationClass.IMPLEMENTED_AND_TESTED),
        native("auto.flow", "Reactive state (Flow)", IntelligenceModule.AUTOMATION_CORE,
            "kotlinx.coroutines.flow", "StateFlow/SharedFlow", "probe.flow",
            verification = VerificationClass.IMPLEMENTED_AND_TESTED),
        native("auto.startup", "AndroidX App Startup initializer", IntelligenceModule.AUTOMATION_CORE,
            "androidx.startup.Initializer", "App Startup", "probe.startup"),
        native("auto.connectivity-callback", "Connectivity callbacks", IntelligenceModule.AUTOMATION_CORE,
            "android.net.ConnectivityManager", "registerDefaultNetworkCallback", "probe.connectivity-callback"),
        native("auto.power-callback", "Power/battery state callbacks", IntelligenceModule.AUTOMATION_CORE,
            "android.content.BroadcastReceiver", "ACTION_BATTERY_CHANGED", "probe.power-callback"),
        native("auto.stale", "Stale-data detection", IntelligenceModule.AUTOMATION_CORE,
            "On-device freshness rules", "ConnectorSnapshot#isStale", "probe.stale",
            verification = VerificationClass.IMPLEMENTED_AND_TESTED),
        native("auto.cache-cleanup", "Cache management", IntelligenceModule.AUTOMATION_CORE,
            "On-device retention", "threat_indicators expiry prune", "probe.cache-cleanup",
            verification = VerificationClass.IMPLEMENTED_AND_TESTED),
        native("auto.report", "Report generation", IntelligenceModule.AUTOMATION_CORE,
            "androidx.core.content.FileProvider", "Threat/privacy report writer", "probe.report",
            restrictions = "Generates a local text report; nothing is uploaded automatically."
        ),
        native("auto.thresholds", "Configurable alert thresholds", IntelligenceModule.AUTOMATION_CORE,
            "DataStore preferences", "UserPreferencesRepository", "probe.thresholds"),
        native("auto.recovery", "Error recovery", IntelligenceModule.AUTOMATION_CORE,
            "Sync engine backoff", "ConnectorSyncEngine#backoffFor", "probe.recovery",
            verification = VerificationClass.IMPLEMENTED_AND_TESTED)
    )

    // ------------------------------------------------------------------ assembly

    val all: List<ConnectorSpec> by lazy {
        (cyber() + financial() + privacy() + network() + device() + emergency() + automation())
            .distinctBy { it.id }
    }

    val byModule: Map<IntelligenceModule, List<ConnectorSpec>> by lazy {
        all.groupBy { it.module }
    }

    fun forModule(module: IntelligenceModule): List<ConnectorSpec> = byModule[module].orEmpty()

    fun find(id: String): ConnectorSpec? = all.firstOrNull { it.id == id }

    /** Feeds only; native probes are executed on demand. */
    val feeds: List<ConnectorSpec> get() = all.filter { it.isFeed }

    val nativeProbes: List<ConnectorSpec> get() = all.filter { !it.isFeed }
}
