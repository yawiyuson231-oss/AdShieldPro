package com.adshield.pro.engine.connectors

import com.adshield.pro.domain.connectors.ConnectorSpec
import com.adshield.pro.domain.connectors.LookupEvidence
import com.adshield.pro.domain.connectors.LookupField
import com.adshield.pro.domain.connectors.LookupFinding
import com.adshield.pro.domain.connectors.LookupQuery
import java.net.IDN
import java.net.URLEncoder
import java.util.Locale

/**
 * Executes one on-demand lookup connector.
 *
 * Every value is validated and canonicalised before any request is made, every request is bounded
 * by the connector's timeout/byte/retry policy, and every answer carries the provider name and the
 * HTTP status that produced it. A malformed value never reaches the network.
 */
class IntelLookupEngine(
    private val transport: ConnectorTransport,
    private val now: () -> Long = System::currentTimeMillis
) {

    sealed interface Prepared {
        data class Ready(val target: Target) : Prepared
        data class Invalid(val reason: String) : Prepared
    }

    data class Target(
        val field: LookupField,
        val raw: String,
        val canonical: String,
        val host: String? = null,
        val packageName: String? = null,
        val packageVersion: String? = null,
        val ecosystem: String? = null
    )

    /** Validates and canonicalises a typed value. Returns an explanation when it is unusable. */
    fun prepare(query: LookupQuery): Prepared {
        val trimmed = query.value.trim()
        if (trimmed.isEmpty()) return Prepared.Invalid("empty value")
        if (trimmed.length > 2_000) return Prepared.Invalid("value is longer than 2000 characters")
        return when (query.field) {
            LookupField.HASH_SHA256 -> {
                val value = trimmed.lowercase(Locale.US)
                if (!ConnectorParsers.isSha256(value)) {
                    Prepared.Invalid("a SHA-256 hash must be exactly 64 hexadecimal characters")
                } else {
                    Prepared.Ready(Target(query.field, trimmed, value))
                }
            }

            LookupField.DOMAIN -> {
                val ascii = runCatching {
                    IDN.toASCII(trimmed.trimEnd('.'), IDN.USE_STD3_ASCII_RULES).lowercase(Locale.US)
                }.getOrNull() ?: return Prepared.Invalid("domain is not valid IDNA")
                if (!ConnectorParsers.isDomain(ascii)) {
                    Prepared.Invalid("domain must be a registrable hostname (for example example.com)")
                } else {
                    Prepared.Ready(Target(query.field, trimmed, ascii, host = ascii))
                }
            }

            LookupField.IP -> {
                if (!ConnectorParsers.isIpv4(trimmed)) {
                    Prepared.Invalid("only IPv4 addresses are supported by the current indicator model")
                } else {
                    Prepared.Ready(Target(query.field, trimmed, trimmed))
                }
            }

            LookupField.CVE -> {
                val value = trimmed.uppercase(Locale.US)
                if (!ConnectorParsers.isCve(value)) {
                    Prepared.Invalid("a CVE identifier looks like CVE-2024-12345")
                } else {
                    Prepared.Ready(Target(query.field, trimmed, value))
                }
            }

            LookupField.URL -> {
                val lowered = trimmed.lowercase(Locale.US)
                if (!lowered.startsWith("http://") && !lowered.startsWith("https://")) {
                    return Prepared.Invalid("a URL must start with http:// or https://")
                }
                val host = ConnectorParsers.hostOf(lowered)
                    ?: return Prepared.Invalid("URL has no usable hostname")
                Prepared.Ready(Target(query.field, trimmed, lowered, host = host))
            }

            LookupField.PACKAGE -> {
                // Expected: ecosystem:name@version  (e.g. maven:com.squareup.okhttp3:okhttp@4.12.0)
                val colon = trimmed.indexOf(':')
                val at = trimmed.lastIndexOf('@')
                if (colon <= 0 || at <= colon + 1 || at == trimmed.lastIndex) {
                    return Prepared.Invalid("use ecosystem:name@version, for example maven:com.squareup.okhttp3:okhttp@4.12.0")
                }
                val ecosystem = trimmed.substring(0, colon).lowercase(Locale.US)
                val name = trimmed.substring(colon + 1, at)
                val version = trimmed.substring(at + 1)
                val canonicalEcosystem = when (ecosystem) {
                    "maven", "npm", "pypi", "go", "cargo", "nuget", "rubygems", "packagist", "hex" -> ecosystem
                    else -> return Prepared.Invalid("unsupported ecosystem \"$ecosystem\"")
                }
                Prepared.Ready(
                    Target(
                        field = query.field,
                        raw = trimmed,
                        canonical = "$canonicalEcosystem:$name@$version",
                        packageName = name,
                        packageVersion = version,
                        ecosystem = canonicalEcosystem
                    )
                )
            }
        }
    }

    /** Runs one connector for an already validated target. Never throws. */
    fun execute(spec: ConnectorSpec, query: LookupQuery, prepared: Prepared): LookupFinding {
        if (spec.queryField != query.field) {
            return failure(spec, query, "connector does not accept ${query.field.label}")
        }
        val target = when (prepared) {
            is Prepared.Invalid -> return failure(spec, query, prepared.reason)
            is Prepared.Ready -> prepared.target
        }
        val endpoint = resolve(spec.endpoint, target, forBody = false)
        if (!endpoint.startsWith("https://", ignoreCase = true)) {
            return failure(spec, query, "resolved endpoint is not HTTPS")
        }
        val body = spec.requestBody?.let { resolve(it, target, forBody = true) }
        val resolvedSpec = spec.copy(
            endpoint = endpoint,
            requestBody = body,
            // A redirected endpoint cannot be cached under the connector's original ETag.
            maxRetries = spec.maxRetries.coerceIn(0, 2)
        )
        val result = if (body != null) {
            transport.post(resolvedSpec, body, spec.contentType, null, null)
        } else {
            transport.get(resolvedSpec, null, null)
        }
        val fetchedAt = now()
        return when (result) {
            is TransportResult.Failure -> failure(
                spec, query,
                if (result.offline) "offline — ${result.reason}" else result.reason,
                offline = result.offline
            )

            is TransportResult.Response -> {
                val code = result.code
                when {
                    code == 401 || code == 403 -> failure(
                        spec, query,
                        "provider refused anonymous access (credentials required)",
                        httpCode = code
                    )

                    code == 429 -> failure(spec, query, "provider rate limit", httpCode = code)
                    code in 500..599 -> failure(spec, query, "provider error HTTP $code", httpCode = code)
                    code !in 200..299 && code != 404 && code != 410 -> failure(
                        spec, query, "HTTP $code", httpCode = code
                    )

                    else -> {
                        val parsed = LookupParsers.parse(spec.handlerId, spec, result.body, code, query)
                        LookupFinding(
                            connectorId = spec.id,
                            connectorName = spec.name,
                            provider = spec.provider,
                            module = spec.module,
                            query = query,
                            found = parsed.found,
                            riskScore = parsed.riskScore.coerceIn(0, 100),
                            headline = parsed.headline,
                            evidence = parsed.evidence,
                            attribution = "${spec.provider} · ${spec.endpoint}",
                            fetchedAtEpochMs = fetchedAt,
                            fromCache = false,
                            httpCode = code,
                            limitation = parsed.limitation
                        )
                    }
                }
            }
        }
    }

    private fun failure(
        spec: ConnectorSpec,
        query: LookupQuery,
        reason: String,
        httpCode: Int? = null,
        offline: Boolean = false
    ): LookupFinding = LookupFinding(
        connectorId = spec.id,
        connectorName = spec.name,
        provider = spec.provider,
        module = spec.module,
        query = query,
        found = false,
        riskScore = 0,
        headline = if (offline) "Offline — no answer from ${spec.provider}" else "No usable answer",
        evidence = listOf(LookupEvidence("Error", reason)),
        attribution = spec.provider,
        fetchedAtEpochMs = now(),
        fromCache = false,
        httpCode = httpCode,
        error = reason
    )

    /** Substitutes a validated target into an endpoint/body template. */
    private fun resolve(template: String, target: Target, forBody: Boolean): String {
        val ecosystem = target.ecosystem?.let(::osvEcosystem) ?: ""
        val substitutions = mapOf(
            "{value}" to target.canonical,
            "{host}" to (target.host ?: ""),
            "{name}" to (target.packageName ?: ""),
            "{version}" to (target.packageVersion ?: ""),
            "{ecosystem}" to ecosystem
        )
        var result = template
        substitutions.forEach { (token, rawValue) ->
            val encoded = when {
                forBody -> jsonEscape(rawValue)
                token == "{name}" -> urlEncode(rawValue)
                token == "{version}" -> urlEncode(rawValue)
                token == "{ecosystem}" -> urlEncode(rawValue)
                token == "{host}" -> urlEncode(rawValue)
                else -> urlEncode(rawValue)
            }
            result = result.replace(token, encoded)
        }
        return result
    }

    private fun osvEcosystem(lowercase: String): String = when (lowercase) {
        "maven" -> "Maven"
        "npm" -> "npm"
        "pypi" -> "PyPI"
        "go" -> "Go"
        "cargo" -> "crates.io"
        "nuget" -> "NuGet"
        "rubygems" -> "RubyGems"
        "packagist" -> "Packagist"
        "hex" -> "Hex"
        else -> lowercase
    }

    private fun urlEncode(value: String): String =
        URLEncoder.encode(value, "UTF-8").replace("+", "%20")

    private fun jsonEscape(value: String): String = value
        .replace("\\", "\\\\")
        .replace("\"", "\\\"")
        .replace("\n", "\\n")
        .replace("\r", "\\r")
}
