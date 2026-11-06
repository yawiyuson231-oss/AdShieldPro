package com.adshield.pro.di

import android.content.Context
import androidx.room.Room
import com.adshield.pro.data.local.db.AdShieldDao
import com.adshield.pro.data.local.db.AdShieldDatabase
import com.adshield.pro.data.local.db.ConnectorDao
import com.adshield.pro.data.local.db.IntelligenceEventDao
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.android.qualifiers.ApplicationContext
import dagger.hilt.components.SingletonComponent
import javax.inject.Singleton

@Module
@InstallIn(SingletonComponent::class)
object AppModule {

    @Provides
    @Singleton
    fun provideAdShieldDatabase(
        @ApplicationContext context: Context
    ): AdShieldDatabase {
        return Room.databaseBuilder(
            context,
            AdShieldDatabase::class.java,
            AdShieldDatabase.DATABASE_NAME
        )
            .addMigrations(
                AdShieldDatabase.MIGRATION_1_2,
                AdShieldDatabase.MIGRATION_2_3,
                AdShieldDatabase.MIGRATION_3_4,
                AdShieldDatabase.MIGRATION_4_5
            )
            .fallbackToDestructiveMigrationOnDowngrade()
            .build()
    }

    @Provides
    @Singleton
    fun provideAdShieldDao(database: AdShieldDatabase): AdShieldDao {
        return database.adShieldDao()
    }

    @Provides
    @Singleton
    fun provideIntelligenceEventDao(database: AdShieldDatabase): IntelligenceEventDao {
        return database.intelligenceEventDao()
    }

    @Provides
    @Singleton
    fun provideConnectorDao(database: AdShieldDatabase): ConnectorDao {
        return database.connectorDao()
    }

    @Provides
    @Singleton
    fun provideConnectorTransport(): com.adshield.pro.engine.connectors.ConnectorTransport =
        com.adshield.pro.engine.connectors.OkHttpConnectorTransport()

    @Provides
    @Singleton
    fun provideConnectorSyncEngine(
        transport: com.adshield.pro.engine.connectors.ConnectorTransport
    ): com.adshield.pro.engine.connectors.ConnectorSyncEngine =
        com.adshield.pro.engine.connectors.ConnectorSyncEngine(transport)
}
