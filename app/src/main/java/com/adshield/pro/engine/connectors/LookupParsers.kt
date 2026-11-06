package com.adshield.pro.engine.connectors

import com.adshield.pro.domain.connectors.ConnectorSpec
import com.adshield.pro.domain.connectors.LookupEvidence
import com.adshield.pro.domain.connectors.LookupQuery
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.doubleOrNull
import kotlinx.serialization.json.intOrNull
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import java.util.Locale

/**
 * Pure parsers for on-demand lookup responses.
 *
 * Each parser turns one provider's real payload into a small, labelled evidence set. Nothing here
 * decides that a user is "infected" or that a payment is fraudulent: a provider record is evidence,
 * and the local rules in [LookupRisk] turn it into a bounded, explained score.
 *
 * A 404 is a legitimate answer for a lookup ("this hash is not in the dataset") and is parsed as
 * `found = false`; it is not treated as a connector failure.
 */
object LookupParsers {

    private val json = Json { ignoreUnknownKeys = true; isLenient = true }

    data class Parsed(
        val found: Boolean,
        val riskScore: Int,
        val headline: String,
        val evidence: List<LookupEvidence>,
        val limitation: String? = null
    )

    fun parse(
        handlerId: String,
        spec: ConnectorSpec,
        payload: String?,
        httpCode: Int,
        query: LookupQuery
    ): Parsed {
        val notFound = httpCode == 404 || httpCode == 410
        return when (handlerId) {
            "circl-hashlookup" -> circlHashlookup(payload, notFound)
            "cveorg" -> cveOrg(payload, notFound)
            "osv-query" -> osv(payload)
            "depsdev" -> depsDev(payload)
            "urlscan-search" -> urlscan(payload, notFound)
            "rdap" -> rdap(payload, notFound)
            "ripe-prefix" -> ripePrefix(payload, notFound)
            "ipinfo" -> ipInfo(payload, notFound)
            "arin-whois" -> arin(payload, notFound)
            "doh-json" -> doh(payload, notFound)
            else -> Parsed(
                found = false,
                riskScore = 0,
                headline = "No parser for ${spec.handlerId}",
                evidence = emptyList(),
                limitation = "The connector is declared but its parser is missing; treat this as no data."
            )
        }
    }

    // ------------------------------------------------------------------ CIRCL hashlookup

    /**
     * CIRCL hashlookup answers "is this hash a publicly known file?".
     *
     * That is *not* a malware verdict: the dataset is a file-hash census (NSRL and others), so a
     * hit usually means "known software". It becomes useful when a known hash is also reported by
     * a malicious-feed connector; the score stays low on its own.
     */
    private fun circlHashlookup(payload: String?, notFound: Boolean): Parsed {
        if (notFound) {
            return Parsed(
                false, 0, "Not present in CIRCL hashlookup",
                listOf(LookupEvidence("Result", "No record for this SHA-256 in the CIRCL dataset")),
                "Absence from a public hash census is not evidence that a file is safe."
            )
        }
        val root = objectOrNull(payload) ?: return malformed("CIRCL hashlookup returned a non-JSON body")
        val fileName = root.string("FileName")
        val fileSize = root.string("FileSize")
        val product = root.string("ProductCode")
        val os = root.string("OpSystemCode")
        val trust = root.number("hashlookup:Trust")
        val sha1 = root.string("SHA-1")
        val evidence = buildList {
            fileName?.let { add(LookupEvidence("File name", it.take(120))) }
            fileSize?.let { add(LookupEvidence("File size", "$it bytes")) }
            product?.let { add(LookupEvidence("Product code", it.take(80))) }
            os?.let { add(LookupEvidence("Operating system", it.take(80))) }
            sha1?.let { add(LookupEvidence("SHA-1", it)) }
            trust?.let { add(LookupEvidence("hashlookup trust", "$it / 100")) }
        }
        val found = evidence.isNotEmpty() || root.containsKey("SHA-256")
        return Parsed(
            found = found,
            riskScore = if (found) 25 else 0,
            headline = if (found) {
                "Known file: ${fileName ?: "record present"}"
            } else {
                "Record present without file metadata"
            },
            evidence = evidence,
            limitation = "A known-file hit is not malware; correlate it with a malicious-feed match."
        )
    }

    // ------------------------------------------------------------------ CVE.org

    private fun cveOrg(payload: String?, notFound: Boolean): Parsed {
        if (notFound) {
            return Parsed(false, 0, "No CVE record published", emptyList(), "Not every reserved CVE has a public record yet.")
        }
        val root = objectOrNull(payload) ?: return malformed("CVE Services returned a non-JSON body")
        val metadata = runCatching { root["cveMetadata"]?.jsonObject }.getOrNull()
        val cna = runCatching { root["containers"]?.jsonObject?.get("cna")?.jsonObject }.getOrNull()
        val state = metadata?.string("state").orEmpty()
        val published = metadata?.string("datePublished").orEmpty()
        val title = runCatching {
            cna?.get("descriptions")?.jsonArray?.firstOrNull()?.jsonObject?.string("value")
        }.getOrNull()
        val metrics = runCatching {
            cna?.get("metrics")?.jsonArray?.firstOrNull()?.jsonObject
                ?.get("cvssV3_1")?.jsonObject?.string("baseScore")
        }.getOrNull()
        val evidence = buildList {
            if (state.isNotBlank()) add(LookupEvidence("Record state", state))
            if (published.isNotBlank()) add(LookupEvidence("Published", published))
            if (!title.isNullOrBlank()) add(LookupEvidence("Description", title.take(240)))
            if (!metrics.isNullOrBlank()) add(LookupEvidence("CVSS v3.1 base", metrics))
        }
        return Parsed(
            found = evidence.isNotEmpty(),
            riskScore = if (state.equals("PUBLISHED", true)) 45 else 20,
            headline = if (state.equals("PUBLISHED", true)) "Published CVE record" else "CVE record ($state)",
            evidence = evidence,
            limitation = "A published CVE describes a vulnerability; it does not mean this device is affected."
        )
    }

    // ------------------------------------------------------------------ OSV.dev

    private fun osv(payload: String?): Parsed {
        val root = objectOrNull(payload) ?: return malformed("OSV returned a non-JSON body")
        val vulns = runCatching { root["vulns"]?.jsonArray }.getOrNull()
        if (vulns.isNullOrEmpty()) {
            return Parsed(
                false, 0, "No OSV advisory for this package version", emptyList(),
                "Package queries cover the ecosystems OSV indexes (Maven, npm, PyPI, Go, …)."
            )
        }
        val evidence = vulns.take(8).map { element ->
            val item = runCatching { element.jsonObject }.getOrNull()
            val id = item?.string("id") ?: "advisory"
            val summary = item?.string("summary").orEmpty()
            LookupEvidence(id, summary.take(200))
        }
        return Parsed(
            found = true,
            riskScore = 70,
            headline = "${vulns.size} OSV advisory(ies) affect this version",
            evidence = evidence,
            limitation = "Fix by upgrading to a version the advisory lists as patched."
        )
    }

    // ------------------------------------------------------------------ deps.dev

    private fun depsDev(payload: String?): Parsed {
        val root = objectOrNull(payload) ?: return malformed("deps.dev returned a non-JSON body")
        val advisories = runCatching { root["advisoryKeys"]?.jsonArray }.getOrNull().orEmpty()
        val purl = root.string("purl")
        val evidence = buildList {
            purl?.let { add(LookupEvidence("Package", it.take(160))) }
            advisories.forEach { element ->
                val id = runCatching { element.jsonObject.string("id") }.getOrNull()
                if (!id.isNullOrBlank()) add(LookupEvidence("Advisory", id))
            }
        }
        return Parsed(
            found = advisories.isNotEmpty(),
            riskScore = if (advisories.isNotEmpty()) 65 else 0,
            headline = if (advisories.isEmpty()) {
                "No advisory key for this version in deps.dev"
            } else {
                "${advisories.size} advisory(ies) in deps.dev"
            },
            evidence = evidence,
            limitation = "deps.dev aggregates public advisory sources; absence is not a guarantee."
        )
    }

    // ------------------------------------------------------------------ urlscan.io

    private fun urlscan(payload: String?, notFound: Boolean): Parsed {
        if (notFound) return Parsed(false, 0, "urlscan.io returned no results", emptyList())
        val root = objectOrNull(payload) ?: return malformed("urlscan.io returned a non-JSON body")
        val results = runCatching { root["results"]?.jsonArray }.getOrNull().orEmpty()
        val total = root.number("total")?.toInt() ?: results.size
        val evidence = results.take(5).mapNotNull { element ->
            val page = runCatching {
                element.jsonObject["page"]?.jsonObject
            }.getOrNull() ?: return@mapNotNull null
            val url = page.string("url") ?: return@mapNotNull null
            val server = page.string("server").orEmpty()
            val ip = page.string("ip").orEmpty()
            LookupEvidence("Scanned URL", listOf(url.take(120), server, ip).filter { it.isNotBlank() }.joinToString(" · "))
        }
        return Parsed(
            found = total > 0,
            riskScore = if (total > 0) 35 else 0,
            headline = "$total public scan(s) reference this target",
            evidence = evidence,
            limitation = "Being scanned publicly is not a maliciousness verdict; urlscan may rate-limit anonymous queries."
        )
    }

    // ------------------------------------------------------------------ RDAP

    private fun rdap(payload: String?, notFound: Boolean): Parsed {
        if (notFound) {
            return Parsed(false, 0, "No RDAP registration record", emptyList(), "Not every private or special-use range has an RDAP record.")
        }
        val root = objectOrNull(payload) ?: return malformed("RDAP returned a non-JSON body")
        val name = root.string("ldhName") ?: root.string("name") ?: root.string("handle")
        val country = root.string("country")
        val status = runCatching {
            root["status"]?.jsonArray?.joinToString(", ") { it.toString().trim('"') }
        }.getOrNull()
        val registrar = runCatching {
            root["entities"]?.jsonArray?.firstOrNull()?.jsonObject
                ?.get("vcardArray")?.jsonArray
                ?.getOrNull(1)?.let { runCatching { it.jsonArray }.getOrNull() }
                ?.firstOrNull { it.toString().contains("fn") }
                ?.let { runCatching { it.jsonArray.getOrNull(3) }.getOrNull() }
                ?.toString()?.trim('"')
        }.getOrNull()
        val evidence = buildList {
            name?.let { add(LookupEvidence("Registered name", it)) }
            country?.let { add(LookupEvidence("Country", it)) }
            status?.let { add(LookupEvidence("Status", it)) }
            registrar?.let { add(LookupEvidence("Registrar / holder", it.take(120))) }
        }
        return Parsed(
            found = evidence.isNotEmpty(),
            riskScore = 15,
            headline = "Registration record: ${name ?: "present"}",
            evidence = evidence,
            limitation = "RDAP is registry data; a new or privacy-shielded registration is common and not proof of fraud."
        )
    }

    // ------------------------------------------------------------------ RIPEstat

    private fun ripePrefix(payload: String?, notFound: Boolean): Parsed {
        if (notFound) return Parsed(false, 0, "RIPEstat has no routing data", emptyList())
        val root = objectOrNull(payload) ?: return malformed("RIPEstat returned a non-JSON body")
        val data = runCatching { root["data"]?.jsonObject }.getOrNull()
            ?: return malformed("RIPEstat response has no data object")
        val asns = runCatching { data["asns"]?.jsonArray?.joinToString(", ") { it.toString() } }.getOrNull()
        val prefix = data.string("prefix") ?: data.string("resource")
        val announced = runCatching { data["announced"]?.jsonPrimitive?.contentOrNull }.getOrNull()
        val evidence = buildList {
            prefix?.let { add(LookupEvidence("Prefix", it)) }
            asns?.takeIf { it.isNotBlank() }?.let { add(LookupEvidence("Origin AS", it)) }
            announced?.let { add(LookupEvidence("Announced", it)) }
        }
        return Parsed(
            found = evidence.isNotEmpty(),
            riskScore = 10,
            headline = "Routing record: ${prefix ?: "present"}",
            evidence = evidence,
            limitation = "Routing data describes network ownership, not intent."
        )
    }

    // ------------------------------------------------------------------ IPinfo / ARIN

    private fun ipInfo(payload: String?, notFound: Boolean): Parsed {
        if (notFound) return Parsed(false, 0, "IPinfo returned no record", emptyList())
        val root = objectOrNull(payload) ?: return malformed("IPinfo returned a non-JSON body")
        val ip = root.string("ip")
        val city = root.string("city")
        val region = root.string("region")
        val country = root.string("country")
        val org = root.string("org")
        val evidence = buildList {
            ip?.let { add(LookupEvidence("IP", it)) }
            org?.let { add(LookupEvidence("Organisation / ASN", it.take(140))) }
            if (listOfNotNull(city, region, country).isNotEmpty()) {
                add(LookupEvidence("Location", listOfNotNull(city, region, country).joinToString(", ")))
            }
        }
        return Parsed(
            found = evidence.isNotEmpty(),
            riskScore = 5,
            headline = "Network owner: ${org ?: ip ?: "unknown"}",
            evidence = evidence,
            limitation = "Tokenless IPinfo queries are rate limited and approximate."
        )
    }

    private fun arin(payload: String?, notFound: Boolean): Parsed {
        if (notFound) return Parsed(false, 0, "ARIN returned no record", emptyList())
        val root = objectOrNull(payload) ?: return malformed("ARIN returned a non-JSON body")
        val net = runCatching { root["net"]?.jsonObject }.getOrNull()
            ?: return malformed("ARIN response has no net object")
        val name = net.string("name")
        val handle = net.string("handle")
        val org = runCatching {
            net["orgRef"]?.jsonObject?.string("@name")
        }.getOrNull()
        val evidence = buildList {
            name?.let { add(LookupEvidence("Network name", it.take(120))) }
            handle?.let { add(LookupEvidence("Handle", it)) }
            org?.let { add(LookupEvidence("Organisation", it.take(120))) }
        }
        return Parsed(
            found = evidence.isNotEmpty(),
            riskScore = 5,
            headline = "ARIN registration: ${name ?: handle ?: "present"}",
            evidence = evidence,
            limitation = "ARIN only covers North American allocations; other regions use APNIC/RIPE/LACNIC/AFRINIC."
        )
    }

    // ------------------------------------------------------------------ DoH diagnostics

    /**
     * Diagnostic DoH answer. This does not replace the app's DNS engine and is never used for
     * filtering; it exists to show what an independent public resolver answers for a domain.
     */
    private fun doh(payload: String?, notFound: Boolean): Parsed {
        if (notFound) return Parsed(false, 0, "Resolver returned no answer", emptyList())
        val root = objectOrNull(payload) ?: return malformed("DoH returned a non-JSON body")
        val status = root.number("Status")?.toInt()
        val answers = runCatching { root["Answer"]?.jsonArray }.getOrNull().orEmpty()
        val records = answers.take(8).mapNotNull { element ->
            val item = runCatching { element.jsonObject }.getOrNull() ?: return@mapNotNull null
            val data = item.string("data") ?: return@mapNotNull null
            LookupEvidence("Answer", "$data (TTL ${item.number("TTL")?.toInt() ?: 0}s)")
        }
        val statusText = when (status) {
            0 -> "NOERROR"
            2 -> "SERVFAIL"
            3 -> "NXDOMAIN"
            5 -> "REFUSED"
            else -> "status ${status ?: "?"}"
        }
        return Parsed(
            found = records.isNotEmpty(),
            riskScore = 0,
            headline = "Resolver answered $statusText with ${records.size} record(s)",
            evidence = records,
            limitation = "Diagnostic only. Filtering and blocking stay in the existing DNS engine."
        )
    }

    // ------------------------------------------------------------------ helpers

    private fun malformed(reason: String): Parsed = Parsed(
        found = false,
        riskScore = 0,
        headline = "Unreadable response",
        evidence = listOf(LookupEvidence("Parser error", reason)),
        limitation = "The provider answered with an unexpected shape; nothing was inferred from it."
    )

    private fun objectOrNull(payload: String?): JsonObject? {
        if (payload.isNullOrBlank()) return null
        return runCatching { json.parseToJsonElement(payload).jsonObject }.getOrNull()
    }

    private fun JsonObject.string(key: String): String? =
        (this[key] as? JsonPrimitive)?.contentOrNull?.takeIf { it.isNotBlank() }

    private fun JsonObject.number(key: String): Number? {
        val primitive = this[key] as? JsonPrimitive ?: return null
        return primitive.doubleOrNull ?: primitive.intOrNull
    }
}

/**
 * Deterministic local scoring for lookup evidence. The provider never supplies the number that is
 * shown to the user; this object does, and every input is named in [explain].
 */
object LookupRisk {

    fun combine(findings: List<Pair<String, LookupParsers.Parsed>>): Pair<Int, List<String>> {
        if (findings.isEmpty()) return 0 to listOf("No lookup connector returned a usable answer.")
        var best = 0
        var corroboration = 0
        val reasons = mutableListOf<String>()
        findings.forEach { (name, parsed) ->
            if (parsed.found) {
                corroboration++
                if (parsed.riskScore > best) best = parsed.riskScore
                reasons += "$name reported a record (local weight ${parsed.riskScore}/100)."
            }
        }
        val bonus = ((corroboration - 1) * 5).coerceIn(0, 15)
        if (bonus > 0) reasons += "$bonus point(s) because $corroboration independent providers returned records."
        return (best + bonus).coerceIn(0, 100) to reasons
    }
}
