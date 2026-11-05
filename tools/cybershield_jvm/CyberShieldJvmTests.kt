import com.adshield.pro.CyberShieldEngineTestSuite

/**
 * Standalone runner for the CyberShield JVM unit tests. The suite uses org.junit
 * annotations/asserts; minimal JVM stubs are supplied so it runs without the
 * Android Gradle plugin or JUnit jars. The SAME suite also runs under Gradle
 * (testDebugUnitTest) on CI.
 */
fun main() {
    val s = CyberShieldEngineTestSuite()
    val tests: List<Pair<String, () -> Unit>> = listOf(
        "jsonLiteParsesNestedStructuresAndEscapes" to s::jsonLiteParsesNestedStructuresAndEscapes,
        "jsonLiteRejectsMalformedInput" to s::jsonLiteRejectsMalformedInput,
        "feodoParsesRealSchemaWithProvenance" to s::feodoParsesRealSchemaWithProvenance,
        "feodoRejectsEmptyOrWrongShape" to s::feodoRejectsEmptyOrWrongShape,
        "ipv4ValidationIsStrict" to s::ipv4ValidationIsStrict,
        "statuspageMapsAllIndicatorsHonestly" to s::statuspageMapsAllIndicatorsHonestly,
        "statuspageParsesRealResponseShape" to s::statuspageParsesRealResponseShape,
        "statuspageMissingStatusObjectThrows" to s::statuspageMissingStatusObjectThrows,
        "severityClassificationMatchesRealBlockSources" to s::severityClassificationMatchesRealBlockSources,
        "summarizeUsesOnlyRealEventsInWindow" to s::summarizeUsesOnlyRealEventsInWindow,
        "attackVectorSharesAndHourlyBuckets" to s::attackVectorSharesAndHourlyBuckets,
        "protocolDistributionBucketsRealProtocols" to s::protocolDistributionBucketsRealProtocols,
        "correlationGroupsByDomainAndRanksSeverity" to s::correlationGroupsByDomainAndRanksSeverity,
        "sparseInputProducesNoAnomalies" to s::sparseInputProducesNoAnomalies,
        "burstDetectionCarriesMeasuredEvidence" to s::burstDetectionCarriesMeasuredEvidence,
        "beaconingDetectionOnRegularIntervals" to s::beaconingDetectionOnRegularIntervals,
        "subdomainFloodDetection" to s::subdomainFloodDetection,
        "dgaPatternIsFlaggedNeverBlocked" to s::dgaPatternIsFlaggedNeverBlocked,
        "normalTrafficProducesNoFindings" to s::normalTrafficProducesNoFindings,
        "shieldNeverClaimsProtectionWhenInactive" to s::shieldNeverClaimsProtectionWhenInactive,
        "compliancePassesOnSecureDevice" to s::compliancePassesOnSecureDevice,
        "complianceFlagsRealProblems" to s::complianceFlagsRealProblems,
        "complianceMarksUnknownSignalsUnavailable" to s::complianceMarksUnknownSignalsUnavailable,
        "complianceReportJsonRoundTrips" to s::complianceReportJsonRoundTrips,
        "projectionStaysInBounds" to s::projectionStaysInBounds,
        "clusteringGroupsByCountryAndCountsUnlocated" to s::clusteringGroupsByCountryAndCountsUnlocated,
        "clusteringFiltersOnlineAndFamily" to s::clusteringFiltersOnlineAndFamily,
        "bundledWorldAssetsParseAndCoverMajorCountries" to s::bundledWorldAssetsParseAndCoverMajorCountries,
        "demoIndicatorsUseDocumentationIpsOnly" to s::demoIndicatorsUseDocumentationIpsOnly
    )
    var failed = 0
    for ((name, fn) in tests) {
        try {
            fn()
            println("PASS  $name")
        } catch (e: Throwable) {
            failed++
            println("FAIL  $name -> $e")
        }
    }

    // Large-feed parse smoke check (synthetic fixture, explicitly a test input).
    try {
        val sb = StringBuilder("[")
        for (i in 0 until 10_000) {
            if (i > 0) sb.append(',')
            val a = 1 + (i / 250) % 223
            val b = (i % 250) + 1
            sb.append("{\"ip_address\":\"$a.$b.3.4\",\"port\":443,\"status\":\"online\",\"country\":\"US\",\"malware\":\"QakBot\"}")
        }
        sb.append(']')
        val start = System.currentTimeMillis()
        val snap = com.adshield.pro.cybershield.FeodoParser.parse(sb.toString(), start)
        val elapsed = System.currentTimeMillis() - start
        check(snap.indicators.size in 9000..10000) { "unexpected indicator count ${snap.indicators.size}" }
        println("PASS  largeFeedParseSmoke (10k rows in ${elapsed}ms)")
    } catch (e: Throwable) {
        failed++
        println("FAIL  largeFeedParseSmoke -> $e")
    }

    println("CyberShield Kotlin JVM result: ${tests.size + 1} tests, $failed failures")
    if (failed > 0) throw AssertionError("$failed CyberShield JVM tests failed")
}
