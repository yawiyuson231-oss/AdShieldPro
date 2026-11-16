package com.adshield.pro.ui.model

import com.adshield.pro.domain.model.DnsActivityRecord
import com.adshield.pro.domain.model.RuleCategory

/**
 * Turns a DNS log row into the answer to the only question a user has about it: *why*?
 *
 * Every branch here names the component that actually made the decision and what that component
 * checks, so the dialog can never claim more than the engine does. An unknown list name is
 * reported as exactly that — a list name — instead of being dressed up as a product feature.
 */
object BlockReasonExplainer {

    data class Explanation(
        val title: String,
        val body: String,
        val action: String,
        /** False when the row was not a block at all. */
        val isBlock: Boolean
    )

    fun explain(record: DnsActivityRecord): Explanation = explain(
        sourceName = record.sourceList,
        matchedRule = record.matchedRule,
        category = record.category,
        isBlocked = record.isBlocked
    )

    fun explain(
        sourceName: String,
        matchedRule: String?,
        category: RuleCategory?,
        isBlocked: Boolean
    ): Explanation {
        val rule = matchedRule?.takeIf { it.isNotBlank() }

        return when (sourceName) {
            "Video ad infrastructure" -> Explanation(
                title = "Built-in video-ad baseline",
                body = "${rule ?: "This zone"} belongs to video ad serving, verification or measurement. It was " +
                    "refused before any upstream lookup, so this works even with no filter list loaded. Zones that " +
                    "carry playback are never in the baseline.",
                action = if (rule?.contains("probable playback stall") == true) {
                    "This app asked for the same zone repeatedly, which is how a stalled advert step looks. " +
                        "Press \"Allow 15 min\" if the app is stuck right now."
                } else {
                    "Allow it to exempt just this domain, or pause the baseline in Settings."
                },
                isBlock = true
            )
            "CNAME cloaking guard" -> Explanation(
                title = "First-party name resolving to a blocked tracker",
                body = "The queried name is allowed, but its CNAME chain ends at ${rule ?: "a blocked tracker"}. " +
                    "Strict and Custom modes block that chain; balanced modes leave it alone.",
                action = "Allow this domain, or switch to a balanced mode.",
                isBlock = true
            )
            "DNS rebinding guard" -> Explanation(
                title = "Public name answered with a private address",
                body = "The answer pointed at ${rule ?: "a private address"}. That is how a web page reaches your " +
                    "router or an intranet host. The reply was SERVFAIL, because the name itself does exist.",
                action = "If this is an intranet service you rely on, allow it or use a balanced mode.",
                isBlock = true
            )
            "Emergency Allowlist-Only DNS" -> Explanation(
                title = "Emergency allowlist-only mode",
                body = "Emergency mode refuses every name that you or the built-in safety list have not explicitly " +
                    "allowed. ${rule?.let { "Rule: $it." } ?: ""}",
                action = "Turn emergency mode off in Settings to restore normal filtering.",
                isBlock = true
            )
            "Per-App DNS Block" -> Explanation(
                title = "This app is set to block all DNS",
                body = "${rule ?: "The app"} has the per-app policy \"block all\", so none of its lookups resolve.",
                action = "Change the app policy in Settings.",
                isBlock = true
            )
            "Temporary allow" -> Explanation(
                title = "Allowed by a temporary lease",
                body = "You granted this name a bounded pass-through because an app stalled. The lease ends " +
                    "on its own; nothing was added to your rules.${rule?.let { " It overrode: $it." } ?: ""}",
                action = "Nothing to do. Start protection again or wait for the lease to end.",
                isBlock = false
            )
            "System Safety Allowlist" -> Explanation(
                title = "Allowed by the built-in safety list",
                body = "Logins, captchas, single sign-on, payments and connectivity checks are never blocked, " +
                    "even by a rule that matches them.",
                action = "Nothing to do — this is the intended behaviour.",
                isBlock = false
            )
            "User Allowlist", "User Custom Rule" -> Explanation(
                title = if (isBlocked) "Blocked by your own rule" else "Allowed by your own rule",
                body = rule?.let { "Your rule `$it` decided this lookup." }
                    ?: "Your own rule decided this lookup.",
                action = if (isBlocked) "Remove that rule to let it through." else "Nothing to do.",
                isBlock = isBlocked
            )
            "User Blocklist" -> Explanation(
                title = "Blocked by your own blocklist",
                body = rule?.let { "Your rule `$it` blocks this name." } ?: "Your rule blocks this name.",
                action = "Allow it to add an exception that outranks your blocklist.",
                isBlock = true
            )
            "Per-App DNS Filter Bypass" -> Explanation(
                title = "Not filtered for this app",
                body = "${rule ?: "The app"} is set to allow all DNS, so domain filters are skipped for it.",
                action = "Nothing to do unless you want filtering back for that app.",
                isBlock = false
            )
            "Paused (Passthrough)" -> Explanation(
                title = "Protection was paused",
                body = "The lookup happened while protection was paused, so it went straight to the upstream resolver.",
                action = "Nothing to do.",
                isBlock = false
            )
            else -> {
                if (sourceName.startsWith("Network Policy Passthrough")) {
                    Explanation(
                        title = "Not filtered on this network type",
                        body = "This network type is set to passthrough, so the lookup was forwarded without " +
                            "consulting the filter.",
                        action = "Protect the network type in Settings to filter it.",
                        isBlock = false
                    )
                } else {
                    Explanation(
                        title = if (isBlocked) "Blocked by $sourceName" else "Allowed by $sourceName",
                        body = buildString {
                            append(if (isBlocked) "The filter list " else "The list ")
                            append(sourceName)
                            append(" decided this lookup")
                            category?.let { append(" (${it.displayName})") }
                            append(rule?.let { ", matching `$it`." } ?: ".")
                        },
                        action = if (isBlocked) "Allow it to add an exception that outranks this list." else "Nothing to do.",
                        isBlock = isBlocked
                    )
                }
            }
        }
    }
}
