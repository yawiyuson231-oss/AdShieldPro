package com.adshield.pro.globalvpn.provider

import okhttp3.OkHttpClient
import java.util.concurrent.TimeUnit

/** Shared, conservatively-configured HTTP client for provider discovery (no telemetry). */
internal object ProviderHttp {
    val client: OkHttpClient by lazy {
        OkHttpClient.Builder()
            .connectTimeout(12, TimeUnit.SECONDS)
            .readTimeout(25, TimeUnit.SECONDS)
            .callTimeout(40, TimeUnit.SECONDS)
            .retryOnConnectionFailure(true)
            .build()
    }
}
