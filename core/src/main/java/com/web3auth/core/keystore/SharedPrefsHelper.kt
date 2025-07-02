package com.web3auth.core.keystore

import android.content.Context
import android.content.SharedPreferences

object SharedPrefsHelper {

    private const val PREF_NAME = "com.web3auth.sdk.prefs"
    private const val MODE = Context.MODE_PRIVATE
    private var prefs: SharedPreferences? = null

    fun init(context: Context) {
        if (prefs == null) {
            prefs = context.applicationContext.getSharedPreferences(PREF_NAME, MODE)
        }
    }

    fun putString(key: String, value: String) {
        prefs?.edit()?.putString(key, value)?.apply()
    }

    fun getString(key: String, defaultValue: String? = null): String? {
        return prefs?.getString(key, defaultValue)
    }

    fun putBoolean(key: String, value: Boolean) {
        prefs?.edit()?.putBoolean(key, value)?.apply()
    }

    fun getBoolean(key: String, defaultValue: Boolean = false): Boolean {
        return prefs?.getBoolean(key, defaultValue) ?: defaultValue
    }

    fun clear() {
        prefs?.edit()?.clear()?.apply()
    }

    fun remove(key: String) {
        prefs?.edit()?.remove(key)?.apply()
    }
}

const val IS_SFA = "isSFA"
