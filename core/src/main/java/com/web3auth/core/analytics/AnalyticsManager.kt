package com.web3auth.core.analytics

import android.content.Context
import com.segment.analytics.Analytics
import com.segment.analytics.Properties
import com.segment.analytics.Traits

internal object AnalyticsManager {

    private const val SEGMENT_WRITE_KEY = "YOUR_SECRET_WRITE_KEY"
    private var analytics: Analytics? = null
    private var isInitialized = false

    fun initialize(context: Context) {
        if (isInitialized) return

        analytics = Analytics.Builder(context.applicationContext, SEGMENT_WRITE_KEY)
            .trackApplicationLifecycleEvents()
            .recordScreenViews()
            .build()

        Analytics.setSingletonInstance(analytics)
        isInitialized = true
    }

    fun trackEvent(eventName: String, properties: Map<String, Any>? = null) {
        if (!isInitialized) return

        val props = properties?.let {
            Properties().apply {
                it.forEach { (k, v) -> putValue(k, v) }
            }
        }

        analytics?.track(eventName, props)
    }

    fun identifyUser(userId: String, traits: Map<String, Any>? = null) {
        if (!isInitialized) return

        val traitsObj = traits?.let {
            Traits().apply {
                it.forEach { (k, v) -> putValue(k, v) }
            }
        }

        analytics?.identify(userId, traitsObj, null)
    }

    fun reset() {
        analytics?.reset()
        isInitialized = false
    }
}
