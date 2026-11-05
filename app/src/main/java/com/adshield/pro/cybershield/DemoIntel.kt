package com.adshield.pro.cybershield

/**
 * Explicit sample indicators for the opt-in map demo overlay. These are
 * documentation examples (RFC 5737 TEST-NET-1 addresses), always rendered with
 * a DEMO badge and never counted in real statistics or intel totals. Pure
 * Kotlin so the separation contract is unit-testable.
 */
object DemoIntel {
    val indicators = listOf(
        demo("192.0.2.10", "US", "Emotet", "online"),
        demo("192.0.2.11", "US", "QakBot", "online"),
        demo("192.0.2.12", "DE", "Dridex", "offline"),
        demo("192.0.2.13", "RU", "TrickBot", "online"),
        demo("192.0.2.14", "BR", "QakBot", "offline"),
        demo("192.0.2.15", "IN", "Emotet", "online"),
        demo("192.0.2.16", "FR", "Dridex", "online"),
        demo("192.0.2.17", "SG", "QakBot", "online"),
        demo("192.0.2.18", "UA", "TrickBot", "offline"),
        demo("192.0.2.19", "PH", "Emotet", "online"),
        demo("192.0.2.20", "JP", "Dridex", "online"),
        demo("192.0.2.21", "GB", "QakBot", "offline")
    )

    private fun demo(ip: String, country: String, family: String, status: String) =
        IntelIndicator(
            ip = ip, port = 443, status = status, countryCode = country,
            asName = "DEMO-NET (sample)", asNumber = 64500, malware = family,
            firstSeenUtc = "2026-01-01 00:00:00", lastOnline = "2026-01-01"
        )
}
