package com.adshield.pro.cybershield

/**
 * Evaluates REAL local security configuration signals into a compliance-style
 * report. Checks are mapped to public best-practice frameworks for orientation
 * only — this is not a formal certification audit. Signals Android does not
 * expose to third-party apps are reported as UNAVAILABLE, never guessed.
 */
object ComplianceEvaluator {

    fun evaluate(
        device: DeviceSecuritySnapshot,
        settings: CsSettingsSnapshot,
        nowEpochMs: Long
    ): ComplianceReport {
        val checks = ArrayList<ComplianceCheck>()

        checks.add(
            check(
                "dns_protection", "On-device DNS protection active", "NIST CSF PR.PT-4",
                when (settings.vpnStatus) {
                    "CONNECTED" -> ComplianceStatus.PASS
                    "PAUSED", "STARTING", "RECONNECTING" -> ComplianceStatus.WARN
                    else -> ComplianceStatus.FAIL
                },
                "Local DNS filter VPN status: ${settings.vpnStatus} " +
                    "(${settings.loadedRuleCount} rules loaded, ${settings.protectionMode} mode).",
                if (settings.vpnStatus != "CONNECTED") "Activate protection from the dashboard shield." else null
            )
        )

        val encrypted = settings.resolverProtocol == "DOH" || settings.resolverProtocol == "DOT"
        checks.add(
            check(
                "encrypted_dns", "Encrypted upstream DNS", "NIST CSF PR.DS-2",
                if (encrypted) ComplianceStatus.PASS else ComplianceStatus.WARN,
                "Upstream protocol: ${settings.resolverProtocol}.",
                if (!encrypted) "Switch to DNS-over-HTTPS or DNS-over-TLS in Settings → DNS resolver." else null
            )
        )

        checks.add(
            check(
                "threat_intel", "Verified threat intelligence blocking", "NIST CSF DE.CM-1",
                when {
                    settings.aetherEnabled && settings.aetherAutoBlock -> ComplianceStatus.PASS
                    settings.aetherEnabled -> ComplianceStatus.WARN
                    else -> ComplianceStatus.WARN
                },
                "AETHER analysis ${if (settings.aetherEnabled) "enabled" else "disabled"}; " +
                    "auto-block of confirmed indicators ${if (settings.aetherAutoBlock) "on" else "off"}.",
                if (!settings.aetherEnabled || !settings.aetherAutoBlock)
                    "Enable AETHER auto-blocking in the Aether AI tab." else null
            )
        )

        checks.add(
            check(
                "filter_updates", "Filter lists update automatically", "CIS Controls v8 §7.3",
                if (settings.autoUpdateFilters) ComplianceStatus.PASS else ComplianceStatus.WARN,
                "Background filter sync is ${if (settings.autoUpdateFilters) "enabled" else "disabled"}.",
                if (!settings.autoUpdateFilters) "Re-enable automatic filter updates in Ad Blocker → Sources." else null
            )
        )

        checks.add(
            boolCheck(
                "screen_lock", "Secure screen lock configured", "CIS Android §2.1",
                device.screenLockSecure,
                "KeyguardManager reports the device ${yesNo(device.screenLockSecure, "is", "is not")} securely locked.",
                "Set a PIN, password or strong biometric screen lock.",
                unavailableReason = "Keyguard state could not be read."
            )
        )

        checks.add(
            boolCheck(
                "storage_encryption", "Storage encryption active", "CIS Android §3.1",
                device.storageEncrypted,
                "DevicePolicyManager reports storage encryption ${yesNo(device.storageEncrypted, "active", "inactive")}.",
                "Encryption is required by modern Android; verify device integrity.",
                unavailableReason = "Encryption state could not be read."
            )
        )

        checks.add(
            inverseBoolCheck(
                "adb_disabled", "USB debugging (ADB) disabled", "CIS Android §2.3",
                device.adbEnabled,
                "ADB debugging is ${if (device.adbEnabled == true) "ENABLED" else "disabled"}.",
                "Disable USB debugging in Developer options when not actively developing.",
                unavailableReason = "ADB setting could not be read."
            )
        )

        checks.add(
            inverseBoolCheck(
                "dev_options", "Developer options disabled", "CIS Android §2.3",
                device.developerOptionsEnabled,
                "Developer options are ${if (device.developerOptionsEnabled == true) "ENABLED" else "off"}.",
                "Turn off Developer options on production devices.",
                unavailableReason = "Developer-options setting could not be read."
            )
        )

        val patchStatus = when {
            device.patchAgeDays == null -> ComplianceStatus.UNAVAILABLE
            device.patchAgeDays <= 90 -> ComplianceStatus.PASS
            device.patchAgeDays <= 180 -> ComplianceStatus.WARN
            else -> ComplianceStatus.FAIL
        }
        checks.add(
            check(
                "security_patch", "Security patch level current", "CIS Controls v8 §7.3",
                patchStatus,
                if (device.securityPatch != null)
                    "Security patch ${device.securityPatch} (${device.patchAgeDays} days old)."
                else "Security patch level not reported by this device.",
                if (patchStatus == ComplianceStatus.WARN || patchStatus == ComplianceStatus.FAIL)
                    "Install the latest available system update." else null
            )
        )

        val sideloadStatus = when {
            device.sideloadedApps == null -> ComplianceStatus.UNAVAILABLE
            device.sideloadedApps == 0 -> ComplianceStatus.PASS
            device.sideloadedApps <= 3 -> ComplianceStatus.WARN
            else -> ComplianceStatus.WARN
        }
        checks.add(
            check(
                "app_sources", "Installed app sources reviewed", "NIST CSF PR.IP-1",
                sideloadStatus,
                if (device.sideloadedApps != null)
                    "${device.sideloadedApps} of ${device.userApps ?: 0} user apps have no recognized installer " +
                        "(possibly sideloaded). Android does not expose other apps' contents for scanning."
                else "App inventory unavailable.",
                if ((device.sideloadedApps ?: 0) > 0)
                    "Review sideloaded apps in the Endpoint card; keep only trusted sources." else null
            )
        )

        checks.add(
            check(
                "network_validated", "Active network validated", "NIST CSF PR.AC-5",
                when (device.networkValidated) {
                    true -> ComplianceStatus.PASS
                    false -> ComplianceStatus.WARN
                    null -> ComplianceStatus.UNAVAILABLE
                },
                "Active network: ${device.networkTransport ?: "unknown"}; " +
                    "internet validation ${device.networkValidated?.toString() ?: "unknown"}.",
                if (device.networkValidated == false)
                    "This network failed validation (captive portal or no internet)." else null
            )
        )

        checks.add(
            check(
                "log_retention", "Activity logging & retention configured", "NIST CSF PR.PT-1",
                if (settings.detailedLogging && settings.logRetentionDays in 1..90)
                    ComplianceStatus.PASS else ComplianceStatus.WARN,
                "Detailed DNS logging ${if (settings.detailedLogging) "on" else "off"}; " +
                    "retention ${settings.logRetentionDays} days. Logs stay on this device.",
                if (!settings.detailedLogging)
                    "Enable detailed logging for audit history, or keep it off for privacy — both are valid choices." else null
            )
        )

        val passed = checks.count { it.status == ComplianceStatus.PASS }
        val warned = checks.count { it.status == ComplianceStatus.WARN }
        val failed = checks.count { it.status == ComplianceStatus.FAIL }
        val unavailable = checks.count { it.status == ComplianceStatus.UNAVAILABLE }
        val scored = passed + warned + failed
        val score = if (scored == 0) 0 else ((passed * 100 + warned * 50) / scored)

        return ComplianceReport(
            generatedAtEpochMs = nowEpochMs,
            deviceModel = device.deviceModel,
            androidVersion = device.androidVersion,
            checks = checks,
            score = score,
            passed = passed,
            warnings = warned,
            failed = failed,
            unavailable = unavailable
        )
    }

    private fun yesNo(v: Boolean?, yes: String, no: String) = if (v == true) yes else no

    private fun check(
        id: String, title: String, framework: String,
        status: ComplianceStatus, detail: String, recommendation: String?
    ) = ComplianceCheck(id, title, framework, status, detail, recommendation)

    private fun boolCheck(
        id: String, title: String, framework: String, value: Boolean?,
        detail: String, recommendation: String, unavailableReason: String
    ) = check(
        id, title, framework,
        when (value) {
            true -> ComplianceStatus.PASS
            false -> ComplianceStatus.FAIL
            null -> ComplianceStatus.UNAVAILABLE
        },
        if (value == null) unavailableReason else detail,
        if (value == false) recommendation else null
    )

    private fun inverseBoolCheck(
        id: String, title: String, framework: String, value: Boolean?,
        detail: String, recommendation: String, unavailableReason: String
    ) = check(
        id, title, framework,
        when (value) {
            false -> ComplianceStatus.PASS
            true -> ComplianceStatus.WARN
            null -> ComplianceStatus.UNAVAILABLE
        },
        if (value == null) unavailableReason else detail,
        if (value == true) recommendation else null
    )
}
