package com.adshield.pro.di

import com.adshield.pro.engine.dns.AdaptiveLearningEngine
import com.adshield.pro.engine.dns.CnameIntelligenceEngine
import com.adshield.pro.engine.dns.CompatibilityGuard
import com.adshield.pro.engine.dns.DgaFamilyDetector
import com.adshield.pro.engine.dns.DnsPerformanceOptimizer
import com.adshield.pro.engine.dns.DnsSecurityEngine
import com.adshield.pro.engine.dns.DomainIntelligenceEngine
import com.adshield.pro.engine.dns.InfinityDnsCache
import com.adshield.pro.engine.dns.ThreatIntelligenceManager
import com.adshield.pro.engine.dns.TfliteDomainClassifier
import com.adshield.pro.engine.dns.UpstreamDnsResolver
import com.adshield.pro.engine.dns.VideoAdIntelligence
import com.adshield.pro.engine.filter.FilterRuleEngine
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import javax.inject.Singleton

/**
 * INFINITY DNS — Dependency Injection Module
 *
 * Provides all Infinity DNS intelligence engines as singletons.
 * Each engine is independently testable and can be updated without
 * affecting others (modular, pluggable architecture).
 */
@Module
@InstallIn(SingletonComponent::class)
object InfinityDnsModule {

    @Provides
    @Singleton
    fun provideInfinityDnsCache(): InfinityDnsCache =
        InfinityDnsCache(
            maxEntries = 2048,
            maxMemoryBytes = 4L * 1024 * 1024,
            negativeTtlSeconds = 30,
            staleTtlMs = 5000L
        )

    @Provides
    @Singleton
    fun provideDomainIntelligenceEngine(): DomainIntelligenceEngine =
        DomainIntelligenceEngine()

    @Provides
    @Singleton
    fun provideVideoAdIntelligence(): VideoAdIntelligence =
        VideoAdIntelligence()

    @Provides
    @Singleton
    fun provideThreatIntelligenceManager(): ThreatIntelligenceManager =
        ThreatIntelligenceManager()

    @Provides
    @Singleton
    fun provideDnsSecurityEngine(): DnsSecurityEngine =
        DnsSecurityEngine()

    @Provides
    @Singleton
    fun provideCompatibilityGuard(): CompatibilityGuard =
        CompatibilityGuard()

    @Provides
    @Singleton
    fun provideDnsPerformanceOptimizer(): DnsPerformanceOptimizer =
        DnsPerformanceOptimizer()

    @Provides
    @Singleton
    fun provideCnameIntelligenceEngine(
        filterEngine: FilterRuleEngine,
        videoAdIntelligence: VideoAdIntelligence
    ): CnameIntelligenceEngine =
        CnameIntelligenceEngine(filterEngine, videoAdIntelligence)

    @Provides @Singleton fun provideTfliteDomainClassifier(): TfliteDomainClassifier = TfliteDomainClassifier()
    @Provides @Singleton fun provideAdaptiveLearningEngine(): AdaptiveLearningEngine = AdaptiveLearningEngine()
    @Provides @Singleton fun provideDgaFamilyDetector(): DgaFamilyDetector = DgaFamilyDetector()

    @Provides @Singleton fun provideUpstreamDnsResolver(
        healthMonitor: com.adshield.pro.engine.dns.DnsProviderHealthMonitor,
        infinityCache: InfinityDnsCache,
    ): UpstreamDnsResolver = UpstreamDnsResolver(healthMonitor, infinityCache)
}
