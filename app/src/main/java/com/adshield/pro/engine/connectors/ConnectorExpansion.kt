package com.adshield.pro.engine.connectors

import com.adshield.pro.domain.connectors.ConnectorAuth
import com.adshield.pro.domain.connectors.ConnectorFormat
import com.adshield.pro.domain.connectors.ConnectorSpec
import com.adshield.pro.domain.connectors.ConnectorTransport
import com.adshield.pro.domain.connectors.LookupField
import com.adshield.pro.domain.connectors.VerificationClass
import com.adshield.pro.domain.intelligence.IntelligenceModule

/**
 * Second wave of connectors, added after a measured review of the first catalogue.
 *
 * Every HTTP entry here answered a real keyless request from a clean CI runner on 2026-11-06
 * (see `docs/INTEL_LIVE_SOURCES.md`), or is explicitly marked credential-gated / unavailable.
 * Entries that fail that test are declared, never counted as implemented.
 *
 * Rules kept identical to [ConnectorCatalogue]: unique id, unique (method, endpoint) pair, an
 * exact HTTPS endpoint or Android API, and no bundled credentials.
 */
object ConnectorExpansion {

    private const val MINUTE = 60L * 1_000L
    private const val HOUR = 60L * MINUTE
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
        implemented: Boolean = true,
        requestBody: String? = null,
        contentType: String? = null
    ) = ConnectorSpec(
        id = id,
        name = name,
        module = module,
        provider = provider,
        endpoint = endpoint,
        method = if (requestBody != null) "POST" else "GET",
        format = format,
        transport = ConnectorTransport.HTTP,
        auth = auth,
        freeUse = freeUse,
        restrictions = restrictions,
        rateLimit = rateLimit,
        cachePolicy = "Conditional GET where the provider supports ETag/Last-Modified.",
        cacheTtlMs = cacheTtlMs,
        timeoutMs = 15_000,
        maxBytes = maxBytes,
        defaultEnabled = defaultEnabled,
        implemented = implemented,
        handlerId = handlerId,
        verification = verification,
        docsUrl = endpoint,
        requestBody = requestBody,
        contentType = contentType
    )

    private fun lookup(
        id: String,
        name: String,
        module: IntelligenceModule,
        provider: String,
        endpoint: String,
        field: LookupField,
        handlerId: String,
        cacheTtlMs: Long,
        freeUse: String,
        restrictions: String,
        rateLimit: String,
        verification: VerificationClass = VerificationClass.IMPLEMENTED_AND_TESTED,
        auth: ConnectorAuth = ConnectorAuth.NONE,
        implemented: Boolean = true,
        requestBody: String? = null,
        contentType: String? = null
    ) = ConnectorSpec(
        id = id,
        name = name,
        module = module,
        provider = provider,
        endpoint = endpoint,
        method = if (requestBody != null) "POST" else "GET",
        format = ConnectorFormat.JSON,
        transport = ConnectorTransport.HTTP,
        auth = auth,
        freeUse = freeUse,
        restrictions = restrictions,
        rateLimit = rateLimit,
        cachePolicy = "On-demand only; result cached locally for the stated TTL.",
        cacheTtlMs = cacheTtlMs,
        defaultEnabled = false,
        implemented = implemented,
        handlerId = handlerId,
        verification = verification,
        docsUrl = endpoint.substringBefore('?').substringBefore('{'),
        queryField = field,
        requestBody = requestBody,
        contentType = contentType
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
        implemented: Boolean = true,
        cacheTtlMs: Long = 10 * MINUTE
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
        rateLimit = "No remote rate limit; the on-device call is throttled by the scheduler.",
        cachePolicy = "Executed on demand; the last observation is stored with the connector.",
        cacheTtlMs = cacheTtlMs,
        defaultEnabled = false,
        implemented = implemented,
        handlerId = probeId,
        verification = verification,
        docsUrl = "",
        maxRetries = 0
    )

    // ------------------------------------------------------------------ CYBER DEFENSE

    private fun cyber(): List<ConnectorSpec> = listOf(
        feed(
            id = "cyber.sslbl.ja3", name = "SSLBL malicious JA3 fingerprints",
            module = IntelligenceModule.CYBER_DEFENSE, provider = "abuse.ch (SSLBL)",
            endpoint = "https://sslbl.abuse.ch/blacklist/ja3_fingerprints.csv",
            format = ConnectorFormat.CSV, handlerId = "sslbl-ja3", cacheTtlMs = 12 * HOUR,
            freeUse = "Public download, no account.",
            restrictions = "abuse.ch defensive-use terms; JA3 matching needs TLS metadata this app cannot see for other apps.",
            rateLimit = "Downloads updated a few times a day; cache 12 h.",
            verification = VerificationClass.FREE_WITH_RESTRICTIONS
        ),
        feed(
            id = "cyber.sslbl.cert", name = "SSLBL malicious TLS certificates",
            module = IntelligenceModule.CYBER_DEFENSE, provider = "abuse.ch (SSLBL)",
            endpoint = "https://sslbl.abuse.ch/blacklist/sslblacklist.csv",
            format = ConnectorFormat.CSV, handlerId = "sslbl-cert", cacheTtlMs = 12 * HOUR,
            freeUse = "Public download, no account.",
            restrictions = "Certificate SHA-1 fingerprints are indicators, not proof that a connection was malicious.",
            rateLimit = "Cache 12 h.",
            verification = VerificationClass.FREE_WITH_RESTRICTIONS
        ),
        feed(
            id = "cyber.firehol.level1", name = "FireHOL level-1 blocked networks",
            module = IntelligenceModule.CYBER_DEFENSE, provider = "FireHOL",
            endpoint = "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset",
            format = ConnectorFormat.TEXT, handlerId = "ip-list", cacheTtlMs = 12 * HOUR,
            freeUse = "Open data, free to use.",
            restrictions = "A firewall blocklist is aggressive: it includes hosting and scanner ranges, so a match is weak evidence on its own.",
            rateLimit = "Static file on GitHub raw; cache 12 h."
        ),
        feed(
            id = "cyber.et.compromised", name = "Emerging Threats compromised hosts",
            module = IntelligenceModule.CYBER_DEFENSE, provider = "Emerging Threats (Proofpoint)",
            endpoint = "https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
            format = ConnectorFormat.TEXT, handlerId = "ip-list", cacheTtlMs = 6 * HOUR,
            freeUse = "ET Open rules and lists are free.",
            restrictions = "ET asks for attribution; a compromised host yesterday may be clean today.",
            rateLimit = "Cache 6 h.",
            verification = VerificationClass.FREE_WITH_RESTRICTIONS
        ),
        feed(
            id = "cyber.cins.badguys", name = "CINS bad-guys IP list",
            module = IntelligenceModule.CYBER_DEFENSE, provider = "CINSscore",
            endpoint = "https://cinsscore.com/list/ci-badguys.txt",
            format = ConnectorFormat.TEXT, handlerId = "ip-list", cacheTtlMs = 12 * HOUR,
            freeUse = "Free public list.",
            restrictions = "Aggregated reputation list without per-entry evidence; treat as weak corroboration.",
            rateLimit = "Cache 12 h.",
            verification = VerificationClass.FREE_WITH_RESTRICTIONS
        ),
        feed(
            id = "cyber.blocklistde", name = "blocklist.de all attackers",
            module = IntelligenceModule.CYBER_DEFENSE, provider = "blocklist.de",
            endpoint = "https://lists.blocklist.de/lists/all.txt",
            format = ConnectorFormat.TEXT, handlerId = "ip-list", cacheTtlMs = 6 * HOUR,
            freeUse = "Free for non-commercial use.",
            restrictions = "Reports are automated abuse reports and can include false positives after dynamic IP reassignment.",
            rateLimit = "Cache 6 h.",
            verification = VerificationClass.FREE_WITH_RESTRICTIONS
        ),
        feed(
            id = "cyber.tor.exits", name = "Tor exit node list",
            module = IntelligenceModule.CYBER_DEFENSE, provider = "The Tor Project",
            endpoint = "https://check.torproject.org/torbulkexitlist",
            format = ConnectorFormat.TEXT, handlerId = "ip-list", cacheTtlMs = 12 * HOUR,
            freeUse = "Public list published by the Tor Project.",
            restrictions = "An exit node is an anonymising proxy, not malware. The app records it with low confidence and says so.",
            rateLimit = "Cache 12 h."
        ),
        feed(
            id = "cyber.spamhaus.drop", name = "Spamhaus DROP networks",
            module = IntelligenceModule.CYBER_DEFENSE, provider = "Spamhaus",
            endpoint = "https://www.spamhaus.org/drop/drop.txt",
            format = ConnectorFormat.TEXT, handlerId = "ip-list", cacheTtlMs = 12 * HOUR,
            freeUse = "Free for non-commercial, non-redistribution use.",
            restrictions = "Spamhaus terms restrict redistribution; the app only caches it locally for its own matching.",
            rateLimit = "Cache 12 h.",
            verification = VerificationClass.FREE_WITH_RESTRICTIONS
        ),
        feed(
            id = "cyber.sslbl.ip", name = "SSLBL malicious IP blacklist",
            module = IntelligenceModule.CYBER_DEFENSE, provider = "abuse.ch (SSLBL)",
            endpoint = "https://sslbl.abuse.ch/blacklist/sslipblacklist.txt",
            format = ConnectorFormat.TEXT, handlerId = "ip-list", cacheTtlMs = 12 * HOUR,
            freeUse = "Public download, no account.",
            restrictions = "abuse.ch defensive-use terms.",
            rateLimit = "Cache 12 h.",
            verification = VerificationClass.FREE_WITH_RESTRICTIONS
        ),
        feed(
            id = "cyber.exploitdb", name = "Exploit-DB public exploit index",
            module = IntelligenceModule.CYBER_DEFENSE, provider = "Offensive Security (Exploit-DB)",
            endpoint = "https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv",
            format = ConnectorFormat.CSV, handlerId = "exploitdb-csv", cacheTtlMs = DAY,
            freeUse = "Open data (GPLv2 repository).",
            restrictions = "Presence of a public exploit is not proof of exploitation. Only CVE identifiers are stored, never exploit code.",
            rateLimit = "Static CSV; cache 24 h.",
            verification = VerificationClass.FREE_WITH_RESTRICTIONS
        ),
        feed(
            id = "cyber.misp.empty-hashes", name = "MISP warninglist: empty-hash false positives",
            module = IntelligenceModule.CYBER_DEFENSE, provider = "MISP project",
            endpoint = "https://raw.githubusercontent.com/MISP/misp-warninglists/main/lists/empty-hashes/list.json",
            format = ConnectorFormat.JSON, handlerId = "misp-list", cacheTtlMs = DAY,
            freeUse = "Open source warninglists.",
            restrictions = "Suppression-only: entries can remove a false-positive match and never add risk.",
            rateLimit = "Static file; cache 24 h.",
            verification = VerificationClass.FREE_WITH_RESTRICTIONS
        ),

        // --- credential-gated: declared, never bundled, never enabled -----------------
        lookup(
            id = "cyber.urlhaus.api", name = "URLhaus URL lookup (Auth-Key)",
            module = IntelligenceModule.CYBER_DEFENSE, provider = "abuse.ch (URLhaus)",
            endpoint = "https://urlhaus-api.abuse.ch/v1/url/", field = LookupField.URL,
            handlerId = "none", cacheTtlMs = 6 * HOUR,
            freeUse = "abuse.ch API requires a free Auth-Key as of the 2026-11-06 probe (HTTP 401 without one).",
            restrictions = "No key is bundled, so this connector stays NOT CONFIGURED. The public CSV downloads this app used before now return HTTP 410.",
            rateLimit = "Key-bound quota.",
            auth = ConnectorAuth.REQUIRED_KEY, implemented = false,
            requestBody = "url={value}", contentType = "application/x-www-form-urlencoded"
        ),
        lookup(
            id = "cyber.malwarebazaar.api", name = "MalwareBazaar hash lookup (Auth-Key)",
            module = IntelligenceModule.CYBER_DEFENSE, provider = "abuse.ch (MalwareBazaar)",
            endpoint = "https://mb-api.abuse.ch/api/v1/", field = LookupField.HASH_SHA256,
            handlerId = "none", cacheTtlMs = 6 * HOUR,
            freeUse = "Free account key required; the public CSV export returns HTTP 410.",
            restrictions = "No key is bundled; connector stays NOT CONFIGURED and never counts as an integration.",
            rateLimit = "Key-bound quota.",
            auth = ConnectorAuth.REQUIRED_KEY, implemented = false,
            requestBody = "query=get_info&hash={value}",
            contentType = "application/x-www-form-urlencoded"
        ),
        lookup(
            id = "cyber.threatfox.api", name = "ThreatFox IOC search (Auth-Key)",
            module = IntelligenceModule.CYBER_DEFENSE, provider = "abuse.ch (ThreatFox)",
            endpoint = "https://threatfox-api.abuse.ch/api/v1/", field = LookupField.IP,
            handlerId = "none", cacheTtlMs = 6 * HOUR,
            freeUse = "Free account key required (HTTP 401 without one on 2026-11-06).",
            restrictions = "No key is bundled; connector stays NOT CONFIGURED.",
            rateLimit = "Key-bound quota.",
            auth = ConnectorAuth.REQUIRED_KEY, implemented = false,
            requestBody = "{\"query\":\"search_ioc\",\"search_term\":\"{value}\"}",
            contentType = "application/json"
        ),
        lookup(
            id = "cyber.virustotal", name = "VirusTotal file lookup",
            module = IntelligenceModule.CYBER_DEFENSE, provider = "VirusTotal",
            endpoint = "https://www.virustotal.com/api/v3/files/{value}", field = LookupField.HASH_SHA256,
            handlerId = "none", cacheTtlMs = 6 * HOUR,
            freeUse = "Free API key with a small quota; terms restrict commercial use.",
            restrictions = "No key is bundled. The endpoint answers 401 without one.",
            rateLimit = "4 requests/minute on the public free tier.",
            auth = ConnectorAuth.REQUIRED_KEY, implemented = false
        ),
        lookup(
            id = "cyber.abuseipdb", name = "AbuseIPDB IP reputation",
            module = IntelligenceModule.CYBER_DEFENSE, provider = "AbuseIPDB",
            endpoint = "https://api.abuseipdb.com/api/v2/check?ipAddress={value}", field = LookupField.IP,
            handlerId = "none", cacheTtlMs = 6 * HOUR,
            freeUse = "Free account key with a daily quota.",
            restrictions = "No key is bundled; answers 401 without one.",
            rateLimit = "1,000 checks/day on the free tier.",
            auth = ConnectorAuth.REQUIRED_KEY, implemented = false
        ),
        lookup(
            id = "cyber.sonatype.ossindex", name = "Sonatype OSS Index component report",
            module = IntelligenceModule.CYBER_DEFENSE, provider = "Sonatype",
            endpoint = "https://ossindex.sonatype.org/api/v3/component-report", field = LookupField.PACKAGE,
            handlerId = "none", cacheTtlMs = 12 * HOUR,
            freeUse = "Free service; the probe received HTTP 401 anonymously.",
            restrictions = "Not usable without credentials, so it stays NOT CONFIGURED.",
            rateLimit = "Rate limited per caller.",
            auth = ConnectorAuth.REQUIRED_KEY, implemented = false,
            requestBody = "{\"coordinates\":[\"pkg:maven/{name}@{version}\"]}",
            contentType = "application/json"
        ),

        // --- working lookups ----------------------------------------------------------
        lookup(
            id = "cyber.circl.hashlookup", name = "CIRCL hashlookup (known-file census)",
            module = IntelligenceModule.CYBER_DEFENSE, provider = "CIRCL (Luxembourg)",
            endpoint = "https://hashlookup.circl.lu/lookup/sha256/{value}", field = LookupField.HASH_SHA256,
            handlerId = "circl-hashlookup", cacheTtlMs = DAY,
            freeUse = "Free public API, no key.",
            restrictions = "Answers 'is this file publicly known', not 'is it malware'. A hit is often legitimate software.",
            rateLimit = "CIRCL asks for polite use; lookups are on demand and cached."
        ),
        lookup(
            id = "cyber.cveorg", name = "CVE.org CVE record",
            module = IntelligenceModule.CYBER_DEFENSE, provider = "CVE Program (MITRE)",
            endpoint = "https://cveawg.mitre.org/api/cve/{value}", field = LookupField.CVE,
            handlerId = "cveorg", cacheTtlMs = DAY,
            freeUse = "Free public API, no key.",
            restrictions = "A published CVE does not mean this device is affected.",
            rateLimit = "Reasonable-use; on-demand lookups only."
        ),
        lookup(
            id = "cyber.osv.query", name = "OSV.dev package advisory query",
            module = IntelligenceModule.CYBER_DEFENSE, provider = "Google OSV.dev",
            endpoint = "https://api.osv.dev/v1/query", field = LookupField.PACKAGE,
            handlerId = "osv-query", cacheTtlMs = 12 * HOUR,
            freeUse = "Free public API, no key.",
            restrictions = "Only the ecosystems OSV indexes; a clean answer does not prove a package is vulnerability-free.",
            rateLimit = "OSV asks for reasonable use; queries are user-initiated.",
            requestBody = "{\"package\":{\"name\":\"{name}\",\"ecosystem\":\"{ecosystem}\"},\"version\":\"{version}\"}",
            contentType = "application/json"
        ),
        lookup(
            id = "cyber.depsdev", name = "deps.dev version advisories (Maven)",
            module = IntelligenceModule.CYBER_DEFENSE, provider = "Google deps.dev",
            endpoint = "https://api.deps.dev/v3alpha/systems/maven/packages/{name}/versions/{version}",
            field = LookupField.PACKAGE,
            handlerId = "depsdev", cacheTtlMs = 12 * HOUR,
            freeUse = "Free public API, no key.",
            restrictions = "This connector is Maven-only; other ecosystems are served by the OSV connector.",
            rateLimit = "No published numeric limit; user-initiated only."
        )
    )

    // ------------------------------------------------------------------ FINANCIAL DEFENSE

    private fun financial(): List<ConnectorSpec> = listOf(
        feed(
            id = "fin.phishing.army", name = "Phishing Army community blocklist",
            module = IntelligenceModule.FINANCIAL_DEFENSE, provider = "Phishing Army",
            endpoint = "https://phishing.army/download/phishing_army_blocklist_extended.txt",
            format = ConnectorFormat.TEXT, handlerId = "adblock-domain-list", cacheTtlMs = 12 * HOUR,
            freeUse = "Free community blocklist.",
            restrictions = "Aggregated from independent sources; false positives are possible. No per-domain evidence is published.",
            rateLimit = "Cache 12 h.",
            verification = VerificationClass.FREE_WITH_RESTRICTIONS
        ),
        feed(
            id = "fin.ut1.phishing", name = "UT1 phishing domains",
            module = IntelligenceModule.FINANCIAL_DEFENSE, provider = "UT1 (Université Toulouse)",
            endpoint = "https://raw.githubusercontent.com/olbat/ut1-blacklists/master/blacklists/phishing/domains",
            format = ConnectorFormat.TEXT, handlerId = "adblock-domain-list", cacheTtlMs = 12 * HOUR,
            freeUse = "Free open data.",
            restrictions = "Domain-level list without categories; treat a match as a warning, not a verdict.",
            rateLimit = "Static file; cache 12 h."
        ),
        feed(
            id = "fin.blocklistproject.phishing", name = "Blocklist Project phishing list",
            module = IntelligenceModule.FINANCIAL_DEFENSE, provider = "Blocklist Project",
            endpoint = "https://blocklistproject.github.io/Lists/phishing.txt",
            format = ConnectorFormat.TEXT, handlerId = "adblock-domain-list", cacheTtlMs = 12 * HOUR,
            freeUse = "Free public list.",
            restrictions = "Community-maintained; no formal accuracy guarantee.",
            rateLimit = "Static file; cache 12 h."
        ),
        feed(
            id = "fin.malwarefilter.phishing", name = "malware-filter phishing domains",
            module = IntelligenceModule.FINANCIAL_DEFENSE, provider = "malware-filter (open source)",
            endpoint = "https://malware-filter.gitlab.io/malware-filter/phishing-filter.txt",
            format = ConnectorFormat.TEXT, handlerId = "adblock-domain-list", cacheTtlMs = 12 * HOUR,
            freeUse = "Open-source project, free to use.",
            restrictions = "Publishes an update timestamp; the app stores its own fetch time as the freshness source.",
            rateLimit = "Updated every 12 h upstream; cache 12 h."
        ),
        feed(
            id = "fin.scamsniffer.domains", name = "ScamSniffer scam domains",
            module = IntelligenceModule.FINANCIAL_DEFENSE, provider = "ScamSniffer (open source)",
            endpoint = "https://raw.githubusercontent.com/scamsniffer/scam-database/main/blacklist/domains.json",
            format = ConnectorFormat.JSON, handlerId = "json-domain-array", cacheTtlMs = 6 * HOUR,
            freeUse = "MIT-licensed community dataset.",
            restrictions = "Focused on crypto/web3 scam sites; other scam categories are covered by the other lists.",
            rateLimit = "Static JSON; cache 6 h."
        ),
        feed(
            id = "fin.hagezi.tif.mini", name = "HaGeZi threat-intelligence mini list",
            module = IntelligenceModule.FINANCIAL_DEFENSE, provider = "HaGeZi DNS blocklists",
            endpoint = "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/tif.mini.txt",
            format = ConnectorFormat.TEXT, handlerId = "adblock-domain-list", cacheTtlMs = 12 * HOUR,
            freeUse = "GPL-3.0 community list.",
            restrictions = "Wildcard-format threat list; a match can be a compromised legitimate domain.",
            rateLimit = "Cache 12 h.",
            verification = VerificationClass.FREE_WITH_RESTRICTIONS
        ),
        lookup(
            id = "fin.urlscan.domain", name = "urlscan.io public scan search",
            module = IntelligenceModule.FINANCIAL_DEFENSE, provider = "urlscan.io",
            endpoint = "https://urlscan.io/api/v1/search/?q=domain:{host}", field = LookupField.DOMAIN,
            handlerId = "urlscan-search", cacheTtlMs = 6 * HOUR,
            freeUse = "Anonymous search answered on 2026-11-06; most API features need a free key.",
            restrictions = "Search results describe public scans, not maliciousness. urlscan may rate-limit anonymous callers at any time.",
            rateLimit = "Anonymous queries are rate limited; on demand and cached.",
            verification = VerificationClass.FREE_WITH_RESTRICTIONS
        ),
        lookup(
            id = "fin.phishtank.api", name = "PhishTank verified-phishing check",
            module = IntelligenceModule.FINANCIAL_DEFENSE, provider = "PhishTank (Cisco/OpenDNS)",
            endpoint = "https://checkurl.phishtank.com/checkurl/", field = LookupField.URL,
            handlerId = "none", cacheTtlMs = 6 * HOUR,
            freeUse = "Requires a free application key; the public data download returned HTTP 404 anonymously.",
            restrictions = "No key is bundled. Connector stays NOT CONFIGURED.",
            rateLimit = "Key-bound.",
            auth = ConnectorAuth.REQUIRED_KEY, implemented = false,
            requestBody = "url={value}&format=json",
            contentType = "application/x-www-form-urlencoded"
        ),
        lookup(
            id = "fin.safebrowsing", name = "Google Safe Browsing lookup",
            module = IntelligenceModule.FINANCIAL_DEFENSE, provider = "Google",
            endpoint = "https://safebrowsing.googleapis.com/v4/threatMatches:find", field = LookupField.URL,
            handlerId = "none", cacheTtlMs = 6 * HOUR,
            freeUse = "Free API key required; Google terms apply.",
            restrictions = "No key is bundled; connector stays NOT CONFIGURED.",
            rateLimit = "Key-bound quota.",
            auth = ConnectorAuth.REQUIRED_KEY, implemented = false,
            requestBody = "{\"client\":{\"clientId\":\"omnishield-x\",\"clientVersion\":\"1.0\"},\"threatInfo\":{\"threatTypes\":[\"MALWARE\",\"SOCIAL_ENGINEERING\"],\"platformTypes\":[\"ANY_PLATFORM\"],\"threatEntryTypes\":[\"URL\"],\"threatEntries\":[{\"url\":\"{value}\"}]}}",
            contentType = "application/json"
        ),
        native(
            id = "fin.local.qr-image", name = "QR code image decoding",
            module = IntelligenceModule.FINANCIAL_DEFENSE,
            provider = "ZXing (Apache-2.0, on-device)",
            api = "QRCodeReader#decode over a user-selected image", probeId = "probe.qr-image",
            restrictions = "The user must pick the image with the system file picker; no screen capture and no gallery scan.",
            verification = VerificationClass.IMPLEMENTED_AND_TESTED
        )
    )

    // ------------------------------------------------------------------ PRIVACY DEFENSE

    private fun privacy(): List<ConnectorSpec> = listOf(
        native(
            id = "privacy.installer-provenance", name = "Installer provenance",
            module = IntelligenceModule.PRIVACY_DEFENSE, provider = "PackageManager",
            api = "PackageManager#getInstallSourceInfo / getInstallerPackageName",
            probeId = "probe.installer-provenance",
            restrictions = "Sideloaded packages have no installer; that is reported as unknown, not as malicious."
        ),
        native(
            id = "privacy.app-flags", name = "Debuggable / backup flags",
            module = IntelligenceModule.PRIVACY_DEFENSE, provider = "ApplicationInfo",
            api = "ApplicationInfo#FLAG_DEBUGGABLE / FLAG_ALLOW_BACKUP",
            probeId = "probe.app-flags",
            restrictions = "Flags are declarations by the app author; they do not prove data was extracted."
        ),
        native(
            id = "privacy.input-methods", name = "Enabled keyboards / input methods",
            module = IntelligenceModule.PRIVACY_DEFENSE, provider = "InputMethodManager",
            api = "InputMethodManager#getEnabledInputMethodList",
            probeId = "probe.input-methods",
            restrictions = "Only the list of enabled IMEs is read; keystrokes are never observed."
        ),
        native(
            id = "privacy.role-holders", name = "Default role holders",
            module = IntelligenceModule.PRIVACY_DEFENSE, provider = "RoleManager",
            api = "RoleManager#getRoleHolders (SMS, dialer, browser, home)",
            probeId = "probe.role-holders",
            restrictions = "Reading role holders requires no special permission; changing roles is left to Android Settings."
        ),
        native(
            id = "privacy.device-admin", name = "Active device administrators",
            module = IntelligenceModule.PRIVACY_DEFENSE, provider = "DevicePolicyManager",
            api = "DevicePolicyManager#getActiveAdmins",
            probeId = "probe.device-admin",
            restrictions = "Only the count and package names are read; no admin policy is modified."
        ),
        native(
            id = "privacy.work-profile", name = "Work profile / managed user",
            module = IntelligenceModule.PRIVACY_DEFENSE, provider = "UserManager",
            api = "UserManager#isManagedProfile / getUserCount",
            probeId = "probe.work-profile",
            restrictions = "On a managed device the work profile is controlled by the organisation, not by this app."
        ),
        native(
            id = "privacy.vpn-state", name = "Active VPN transport",
            module = IntelligenceModule.PRIVACY_DEFENSE, provider = "ConnectivityManager",
            api = "NetworkCapabilities#TRANSPORT_VPN",
            probeId = "probe.vpn-state",
            restrictions = "Reports whether a VPN transport is active; it cannot identify what another VPN app inspects."
        ),
        native(
            id = "privacy.overlay-access", name = "Display-over-other-apps access",
            module = IntelligenceModule.PRIVACY_DEFENSE, provider = "AppOpsManager / Settings",
            api = "Settings#canDrawOverlays for this app; cross-app AppOps is restricted",
            probeId = "none",
            restrictions = "Android does not let an ordinary app read every other app's overlay grant. Only this app's own grant is readable.",
            verification = VerificationClass.ANDROID_LIMITED, implemented = false
        ),
        native(
            id = "privacy.install-unknown", name = "Install-unknown-apps access",
            module = IntelligenceModule.PRIVACY_DEFENSE, provider = "AppOpsManager",
            api = "AppOpsManager#OP_REQUEST_INSTALL_PACKAGES (own app only)",
            probeId = "none",
            restrictions = "Reading another package's install-packages grant is not permitted for ordinary apps.",
            verification = VerificationClass.ANDROID_LIMITED, implemented = false
        )
    )

    // ------------------------------------------------------------------ NETWORK DEFENSE

    private fun network(): List<ConnectorSpec> = listOf(
        lookup(
            id = "net.ripe.prefix", name = "RIPEstat prefix overview",
            module = IntelligenceModule.NETWORK_DEFENSE, provider = "RIPE NCC",
            endpoint = "https://stat.ripe.net/data/prefix-overview/data.json?resource={value}",
            field = LookupField.IP, handlerId = "ripe-prefix", cacheTtlMs = 6 * HOUR,
            freeUse = "Free public API, no key.",
            restrictions = "Routing data describes ownership, not intent.",
            rateLimit = "RIPE asks for fair use; on-demand only."
        ),
        lookup(
            id = "net.ripe.whois", name = "RIPEstat WHOIS",
            module = IntelligenceModule.NETWORK_DEFENSE, provider = "RIPE NCC",
            endpoint = "https://stat.ripe.net/data/whois/data.json?resource={value}",
            field = LookupField.IP, handlerId = "ripe-prefix", cacheTtlMs = 6 * HOUR,
            freeUse = "Free public API, no key.",
            restrictions = "WHOIS records can be privacy-redacted and can lag reality.",
            rateLimit = "On-demand only."
        ),
        lookup(
            id = "net.rdap.domain", name = "RDAP domain registration",
            module = IntelligenceModule.NETWORK_DEFENSE, provider = "RDAP (IANA bootstrap)",
            endpoint = "https://rdap.org/domain/{value}", field = LookupField.DOMAIN,
            handlerId = "rdap", cacheTtlMs = DAY,
            freeUse = "Free public registry protocol.",
            restrictions = "A recently registered domain is common and is not proof of fraud.",
            rateLimit = "Registry rate limits vary; on demand."
        ),
        lookup(
            id = "net.ipinfo", name = "IPinfo network owner",
            module = IntelligenceModule.NETWORK_DEFENSE, provider = "IPinfo",
            endpoint = "https://ipinfo.io/{value}/json", field = LookupField.IP,
            handlerId = "ipinfo", cacheTtlMs = DAY,
            freeUse = "Tokenless queries are rate limited but free.",
            restrictions = "Approximate geolocation; a token raises the quota but is never required by this app.",
            rateLimit = "Tokenless quota is small; unreachable answers are shown as errors."
        ),
        lookup(
            id = "net.arin.whois", name = "ARIN REST whois",
            module = IntelligenceModule.NETWORK_DEFENSE, provider = "ARIN",
            endpoint = "https://whois.arin.net/rest/ip/{value}.json", field = LookupField.IP,
            handlerId = "arin-whois", cacheTtlMs = DAY,
            freeUse = "Free public REST service.",
            restrictions = "North-American allocations only; other regions use APNIC/RIPE/LACNIC/AFRINIC.",
            rateLimit = "ARIN asks for polite use."
        ),
        lookup(
            id = "net.doh.cloudflare", name = "Cloudflare DNS diagnostic answer",
            module = IntelligenceModule.NETWORK_DEFENSE, provider = "Cloudflare 1.1.1.1",
            endpoint = "https://cloudflare-dns.com/dns-query?name={host}&type=A",
            field = LookupField.DOMAIN, handlerId = "doh-json", cacheTtlMs = MINUTE,
            freeUse = "Free public DNS-over-HTTPS endpoint.",
            restrictions = "Diagnostic only. Filtering stays in the existing DNS engine; this never replaces it.",
            rateLimit = "Respectful diagnostic queries only."
        ),
        lookup(
            id = "net.doh.google", name = "Google Public DNS diagnostic answer",
            module = IntelligenceModule.NETWORK_DEFENSE, provider = "Google Public DNS",
            endpoint = "https://dns.google/resolve?name={host}&type=A",
            field = LookupField.DOMAIN, handlerId = "doh-json", cacheTtlMs = MINUTE,
            freeUse = "Free public DNS-over-HTTPS endpoint.",
            restrictions = "Diagnostic only; the app's own resolver remains authoritative for protection.",
            rateLimit = "Reasonable diagnostic use."
        ),
        native(
            id = "net.private-dns", name = "Private DNS (DoT) configuration",
            module = IntelligenceModule.NETWORK_DEFENSE, provider = "Settings.Global",
            api = "Settings.Global#PRIVATE_DNS_MODE / PRIVATE_DNS_SPECIFIER",
            probeId = "probe.private-dns",
            restrictions = "Some OEM builds restrict these settings reads; a denial is reported verbatim."
        ),
        native(
            id = "net.traffic-stats", name = "Interface traffic counters",
            module = IntelligenceModule.NETWORK_DEFENSE, provider = "TrafficStats",
            api = "TrafficStats#getTotalRxBytes / getTotalTxBytes",
            probeId = "probe.traffic-stats",
            restrictions = "Device-wide totals only; per-app traffic needs user-granted usage access (covered separately)."
        ),
        native(
            id = "net.wifi-security", name = "Wi-Fi link security",
            module = IntelligenceModule.NETWORK_DEFENSE, provider = "WifiManager",
            api = "WifiInfo#getCurrentSecurityType (API 31+) / getSupplicantState",
            probeId = "probe.wifi-security",
            restrictions = "Reading the SSID needs location permission on modern Android; only link security and state are read here."
        ),
    )

    // ------------------------------------------------------------------ DEVICE INTELLIGENCE

    private fun device(): List<ConnectorSpec> = listOf(
        native(
            id = "dev.mediadrm", name = "DRM security level",
            module = IntelligenceModule.DEVICE_INTELLIGENCE, provider = "MediaDrm",
            api = "MediaDrm#getPropertyString(SECURITY_LEVEL)",
            probeId = "probe.mediadrm",
            restrictions = "Only the Widevine security level is read; no media or identifiers are touched."
        ),
        native(
            id = "dev.gles", name = "OpenGL ES capability",
            module = IntelligenceModule.DEVICE_INTELLIGENCE, provider = "ActivityManager",
            api = "ActivityManager#getDeviceConfigurationInfo",
            probeId = "probe.gles",
            restrictions = "Reports the declared GLES version; real GPU performance is not benchmarked."
        ),
        native(
            id = "dev.storage-volumes", name = "Storage volumes",
            module = IntelligenceModule.DEVICE_INTELLIGENCE, provider = "StorageManager",
            api = "StorageManager#getStorageVolumes + getUuid",
            probeId = "probe.storage-volumes",
            restrictions = "Only volume descriptions and free/total space are read; no file contents."
        ),
        native(
            id = "dev.camera-inventory", name = "Camera hardware inventory",
            module = IntelligenceModule.DEVICE_INTELLIGENCE, provider = "CameraManager",
            api = "CameraManager#getCameraIdList + CameraCharacteristics",
            probeId = "probe.camera-inventory",
            restrictions = "Hardware inventory only; no camera is opened and no image is captured."
        ),
        native(
            id = "dev.battery-energy", name = "Battery energy counter",
            module = IntelligenceModule.DEVICE_INTELLIGENCE, provider = "BatteryManager",
            api = "BatteryManager#BATTERY_PROPERTY_ENERGY_COUNTER / CURRENT_NOW",
            probeId = "probe.battery-energy",
            restrictions = "OEMs may return Integer.MIN_VALUE when the fuel gauge does not expose these properties."
        ),
        native(
            id = "dev.timezone-locale", name = "Timezone and locale configuration",
            module = IntelligenceModule.DEVICE_INTELLIGENCE, provider = "Java/Android runtime",
            api = "TimeZone#getDefault + LocaleList",
            probeId = "probe.timezone-locale",
            restrictions = "Read-only configuration snapshot; no personal content."
        )
    )

    // ------------------------------------------------------------------ EMERGENCY INTELLIGENCE

    private fun emergency(): List<ConnectorSpec> = listOf(
        feed(
            id = "emrg.usgs.ph", name = "USGS earthquakes near the Philippines",
            module = IntelligenceModule.EMERGENCY_INTELLIGENCE, provider = "U.S. Geological Survey",
            endpoint = "https://earthquake.usgs.gov/fdsnws/event/1/query?format=geojson&latitude=14.6&longitude=121.0&maxradiuskm=600&minmagnitude=4&limit=50&orderby=time",
            format = ConnectorFormat.JSON, handlerId = "usgs-quakes", cacheTtlMs = 10 * MINUTE,
            freeUse = "Public USGS GeoJSON service.",
            restrictions = "USGS magnitudes and locations are preliminary and can be revised. USGS is not a Philippine authority.",
            rateLimit = "USGS asks for caching; 10 min.",
            defaultEnabled = true
        ),
        feed(
            id = "emrg.usgs.significant", name = "USGS significant earthquakes (7 days)",
            module = IntelligenceModule.EMERGENCY_INTELLIGENCE, provider = "U.S. Geological Survey",
            endpoint = "https://earthquake.usgs.gov/earthquakes/feed/v1.0/summary/significant_week.geojson",
            format = ConnectorFormat.JSON, handlerId = "usgs-quakes", cacheTtlMs = 30 * MINUTE,
            freeUse = "Public USGS GeoJSON feed.",
            restrictions = "\"Significant\" is a USGS editorial threshold, not a local warning level.",
            rateLimit = "Cache 30 min."
        ),
        feed(
            id = "emrg.gdacs.api", name = "GDACS disaster events (JSON)",
            module = IntelligenceModule.EMERGENCY_INTELLIGENCE, provider = "GDACS (EU JRC / UN OCHA)",
            endpoint = "https://www.gdacs.org/gdacsapi/api/events/geteventlist/SEARCH?eventlist=EQ,TC,FL,WF&fromdate=2026-01-01&todate=2026-12-31&limit=50",
            format = ConnectorFormat.JSON, handlerId = "gdacs-api", cacheTtlMs = 30 * MINUTE,
            freeUse = "Public GDACS API.",
            restrictions = "GDACS alert levels are automated assessments, not national authority orders.",
            rateLimit = "Cache 30 min.",
            verification = VerificationClass.FREE_WITH_RESTRICTIONS
        ),
        feed(
            id = "emrg.eonet", name = "NASA EONET natural events",
            module = IntelligenceModule.EMERGENCY_INTELLIGENCE, provider = "NASA EONET",
            endpoint = "https://eonet.gsfc.nasa.gov/api/v3/events?status=open&limit=50",
            format = ConnectorFormat.JSON, handlerId = "eonet", cacheTtlMs = 6 * HOUR,
            freeUse = "Public NASA API, no key.",
            restrictions = "Satellite-derived event catalogue with latency; not an official local warning.",
            rateLimit = "Cache 6 h.",
            verification = VerificationClass.FREE_WITH_RESTRICTIONS
        ),
        feed(
            id = "emrg.open-meteo.flood", name = "River discharge forecast (context)",
            module = IntelligenceModule.EMERGENCY_INTELLIGENCE, provider = "Open-Meteo (GloFAS)",
            endpoint = "https://flood-api.open-meteo.com/v1/flood?latitude=14.6&longitude=121.0&daily=river_discharge&forecast_days=7",
            format = ConnectorFormat.JSON, handlerId = "open-meteo-context", cacheTtlMs = 3 * HOUR,
            freeUse = "Free non-commercial API, no key.",
            restrictions = "A modelled forecast, not a PAGASA flood bulletin. The UI labels it as context and never as an official alert.",
            rateLimit = "Cache 3 h.",
            verification = VerificationClass.FREE_WITH_RESTRICTIONS
        ),
        feed(
            id = "emrg.open-meteo.air", name = "Air quality context (PM2.5)",
            module = IntelligenceModule.EMERGENCY_INTELLIGENCE, provider = "Open-Meteo (CAMS)",
            endpoint = "https://air-quality-api.open-meteo.com/v1/air-quality?latitude=14.6&longitude=121.0&current=pm2_5",
            format = ConnectorFormat.JSON, handlerId = "open-meteo-context", cacheTtlMs = 3 * HOUR,
            freeUse = "Free non-commercial API, no key.",
            restrictions = "Modelled air quality at a coarse grid point, not a sensor measurement or a health advisory.",
            rateLimit = "Cache 3 h.",
            verification = VerificationClass.FREE_WITH_RESTRICTIONS
        ),
        feed(
            id = "emrg.reliefweb.v2", name = "ReliefWeb disasters (v2)",
            module = IntelligenceModule.EMERGENCY_INTELLIGENCE, provider = "ReliefWeb (UN OCHA)",
            endpoint = "https://api.reliefweb.int/v2/disasters?appname=omnishield-x&limit=20",
            format = ConnectorFormat.JSON, handlerId = "none", cacheTtlMs = 6 * HOUR,
            freeUse = "Free API, but the appname must be pre-approved by ReliefWeb (HTTP 403 without approval on 2026-11-06).",
            restrictions = "The v1 API used by the previous build was decommissioned (HTTP 410). Not configured until an approved appname exists.",
            rateLimit = "Registered callers only.",
            verification = VerificationClass.FREE_WITH_RESTRICTIONS,
            auth = ConnectorAuth.REQUIRED_KEY, implemented = false
        )
    )

    // ------------------------------------------------------------------ AUTOMATION CORE

    private fun automation(): List<ConnectorSpec> = listOf(
        native(
            id = "auto.jobscheduler", name = "JobScheduler inspection",
            module = IntelligenceModule.AUTOMATION_CORE, provider = "android.app.job.JobScheduler",
            api = "JobScheduler#getAllPendingJobs (own jobs)",
            probeId = "probe.jobscheduler",
            restrictions = "Only this app's jobs are visible; other apps' jobs are not readable."
        ),
        native(
            id = "auto.content-observer", name = "ContentObserver registration",
            module = IntelligenceModule.AUTOMATION_CORE, provider = "android.database.ContentObserver",
            api = "ContentResolver#registerContentObserver",
            probeId = "probe.content-observer",
            restrictions = "The probe registers and immediately unregisters an observer on a settings URI; it stores no values."
        ),
        native(
            id = "auto.file-observer", name = "FileObserver registration",
            module = IntelligenceModule.AUTOMATION_CORE, provider = "android.os.FileObserver",
            api = "FileObserver on the app cache directory",
            probeId = "probe.file-observer",
            restrictions = "Only the app's own cache directory can be watched on modern Android."
        ),
        native(
            id = "auto.battery-optimization", name = "Battery optimisation exemption",
            module = IntelligenceModule.AUTOMATION_CORE, provider = "PowerManager",
            api = "PowerManager#isIgnoringBatteryOptimizations",
            probeId = "probe.battery-optimization",
            restrictions = "Exemption needs an explicit user action in system settings; this app never asks for it silently."
        ),
        native(
            id = "auto.notification-channel", name = "Notification channel state",
            module = IntelligenceModule.AUTOMATION_CORE, provider = "NotificationManager",
            api = "NotificationManager#getNotificationChannel",
            probeId = "probe.notification-channel",
            restrictions = "Android 13+ notification permission can still block delivery even when the channel exists."
        ),
        native(
            id = "auto.exact-alarms", name = "Exact alarm capability",
            module = IntelligenceModule.AUTOMATION_CORE, provider = "AlarmManager",
            api = "AlarmManager#canScheduleExactAlarms (API 31+)",
            probeId = "probe.exact-alarms",
            restrictions = "The app uses inexact alarms by default; exact alarms need a special user grant."
        ),
        native(
            id = "auto.datastore", name = "DataStore preference read",
            module = IntelligenceModule.AUTOMATION_CORE, provider = "androidx.datastore",
            api = "UserPreferencesRepository snapshot",
            probeId = "probe.datastore",
            restrictions = "Reads only the app's own settings; values are not exported."
        )
    )

    val all: List<ConnectorSpec> by lazy {
        (cyber() + financial() + privacy() + network() + device() + emergency() + automation())
            .filter { spec -> ConnectorCatalogue.baseAll.none { it.id == spec.id } }
            .distinctBy { spec -> spec.id }
    }

    fun forModule(module: IntelligenceModule): List<ConnectorSpec> = all.filter { it.module == module }
}
