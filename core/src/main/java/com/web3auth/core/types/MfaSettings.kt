package com.web3auth.core.types

import androidx.annotation.Keep

@Keep
data class MfaSettings(
    @Keep private var deviceShareFactor: MfaSetting? = null,
    @Keep private var backUpShareFactor: MfaSetting? = null,
    @Keep private var socialBackupFactor: MfaSetting? = null,
    @Keep private var passwordFactor: MfaSetting? = null,
    @Keep private var passkeysFactor: MfaSetting? = null,
    @Keep private var authenticatorFactor: MfaSetting? = null,
) {
    fun merge(other: MfaSettings?): MfaSettings {
        if (other == null) return this
        return MfaSettings(
            deviceShareFactor = other.deviceShareFactor ?: this.deviceShareFactor,
            backUpShareFactor = other.backUpShareFactor ?: this.backUpShareFactor,
            socialBackupFactor = other.socialBackupFactor ?: this.socialBackupFactor,
            passwordFactor = other.passwordFactor ?: this.passwordFactor,
            passkeysFactor = other.passkeysFactor ?: this.passkeysFactor,
            authenticatorFactor = other.authenticatorFactor ?: this.authenticatorFactor
        )
    }
}
