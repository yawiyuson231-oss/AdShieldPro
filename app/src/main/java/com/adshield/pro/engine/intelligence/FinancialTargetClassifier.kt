package com.adshield.pro.engine.intelligence

/**
 * Decides whether a scanned link is actually a payment / financial target.
 *
 * This is *classification of real input only*: it never creates a financial event on its own and
 * it never upgrades a clean verdict. The Financial Defense node uses it to attribute a URL scan
 * that the user really performed, and the aggregator uses it to count how many payment links were
 * examined. If the classifier says no, the scan is attributed to Cyber Defense instead.
 */
object FinancialTargetClassifier {

    /** Tokens that unambiguously describe a money movement or payment surface. */
    private val STRONG_TOKENS = listOf(
        "pay", "payment", "payments", "checkout", "billing", "invoice", "remit", "remittance",
        "wallet", "bank", "banking", "transfer", "sendmoney", "send-money", "cashin", "cash-in",
        "cashout", "topup", "top-up", "gcash", "paymaya", "maya", "paypal", "stripe", "venmo",
        "wise", "payoneer", "binance", "coins.ph", "coincph", "usdt", "crypto", "bitcoin",
        "westernunion", "moneygram", "swift", "iban", "card-verify", "cardverify"
    )

    /** Tokens that only indicate a financial surface together with a credential/action word. */
    private val WEAK_TOKENS = listOf(
        "card", "credit", "debit", "account", "secure", "verify", "confirm", "update", "signin",
        "login", "loan", "invest", "trade", "refund", "transaction", "receipt", "biller"
    )

    private val ACTION_TOKENS = listOf(
        "verify", "confirm", "update", "login", "signin", "sign-in", "unlock", "review",
        "validate", "billing", "checkout", "pay", "transfer", "refund", "claim", "wallet"
    )

    data class Classification(val isFinancial: Boolean, val matchedToken: String?, val reason: String)

    fun classify(rawUrl: String, findings: List<String> = emptyList()): Classification {
        val lowered = rawUrl.lowercase()
        val strong = STRONG_TOKENS.firstOrNull { lowered.contains(it) }
        if (strong != null) {
            return Classification(true, strong, "URL contains the financial token \"$strong\"")
        }

        val weak = WEAK_TOKENS.firstOrNull { lowered.contains(it) }
        val action = ACTION_TOKENS.firstOrNull { lowered.contains(it) }
        if (weak != null && action != null && weak != action) {
            return Classification(
                true,
                weak,
                "URL combines a financial surface (\"$weak\") with an action (\"$action\")"
            )
        }

        val finding = findings.firstOrNull { line ->
            val l = line.lowercase()
            STRONG_TOKENS.any { l.contains(it) } || l.contains("payment") || l.contains("credential")
        }
        if (finding != null) {
            return Classification(true, null, "Scan finding references a financial surface")
        }

        return Classification(false, null, "No payment or financial indicator in the scanned URL")
    }

    fun isFinancialTarget(rawUrl: String, findings: List<String> = emptyList()): Boolean =
        classify(rawUrl, findings).isFinancial
}
