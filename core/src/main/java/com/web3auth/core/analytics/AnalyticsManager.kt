package com.web3auth.core.analytics

import android.content.Context
import com.segment.analytics.Analytics
import com.segment.analytics.Properties
import com.segment.analytics.Traits
import com.web3auth.core.BuildConfig

internal object AnalyticsManager {

    private const val SEGMENT_WRITE_KEY =
        SegmentKeys.SEGMENT_WRITE_KEY // Use (SEGMENT_WRITE_KEY) in production builds and (SEGMENT_WRITE_KEY_DEV) in development/testing builds
    private var analytics: Analytics? = null
    private var isInitialized = false

    private val globalProperties: MutableMap<String, Any> = mutableMapOf()

    fun initialize(context: Context) {
        if (isInitialized) return

        analytics = Analytics.Builder(context.applicationContext, SEGMENT_WRITE_KEY)
            .trackApplicationLifecycleEvents()
            .recordScreenViews()
            .build()

        Analytics.setSingletonInstance(analytics)
        isInitialized = true
    }

    fun setGlobalProperties(properties: Map<String, Any>) {
        globalProperties.putAll(properties)
    }

    fun trackEvent(eventName: String, properties: Map<String, Any?>? = null) {
        if (!isInitialized) return
        if (isSkipped()) return

        val combinedProps = Properties().apply {
            globalProperties.forEach { (k, v) -> putValue(k, v) }
            properties?.forEach { (k, v) -> putValue(k, v) }
        }

        analytics?.track(eventName, combinedProps)
    }

    fun identify(userId: String, traits: Map<String, Any>? = null) {
        if (!isInitialized) return
        if (isSkipped()) return

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
        globalProperties.clear()
    }

    private fun isSkipped(): Boolean {
        return BuildConfig.DEBUG
    }
}

