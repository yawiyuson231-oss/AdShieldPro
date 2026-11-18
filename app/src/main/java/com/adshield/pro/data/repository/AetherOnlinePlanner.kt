package com.adshield.pro.data.repository

import com.adshield.pro.engine.aether.AetherOnlineApproval
import com.adshield.pro.engine.aether.AetherOnlineConfig
import com.adshield.pro.engine.aether.AetherOnlineEndpoint
import com.adshield.pro.engine.aether.AetherOnlineHttp
import com.adshield.pro.engine.aether.AetherOnlineResult
import com.adshield.pro.engine.aether.AetherOnlineResult.Problem
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import javax.inject.Inject
import javax.inject.Singleton

/** A user-owned API connection. No bundled credentials and no request on load or save. */
@Singleton
class AetherOnlinePlanner @Inject constructor(private val vault: ProviderCredentialStore) {
    private val http by lazy { AetherOnlineHttp() }

    internal suspend fun configuredEndpoint(): AetherOnlineEndpoint? = withContext(Dispatchers.IO) { readConfig()?.endpoint }

    internal suspend fun save(config: AetherOnlineConfig) = withContext(Dispatchers.IO) {
        // The endpoint and token are one encrypted record so they cannot get out of sync.
        vault.put(CREDENTIAL_SLOT, config.encodeForVault(), durable = true)
    }

    internal suspend fun disconnect() = withContext(Dispatchers.IO) { vault.remove(CREDENTIAL_SLOT, durable = true) }

    internal suspend fun suggest(approved: AetherOnlineApproval.Approved): AetherOnlineResult {
        val config = withContext(Dispatchers.IO) { readConfig() }
        if (!approved.consumeFor(config?.endpoint) || config == null) return AetherOnlineResult.Failed(Problem.NOT_CONFIGURED)
        return http.send(config, approved.prompt)
    }

    private fun readConfig() = vault.get(CREDENTIAL_SLOT)?.let(AetherOnlineConfig::decodeFromVault)

    private companion object {
        const val CREDENTIAL_SLOT = "aether.online.agent.v1"
    }
}
