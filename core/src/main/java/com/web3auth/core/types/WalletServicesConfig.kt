package com.web3auth.core.types

import androidx.annotation.Keep
import com.google.gson.annotations.SerializedName

@Keep
data class WalletServicesConfig(
    @Keep val confirmationStrategy: ConfirmationStrategy? = ConfirmationStrategy.DEFAULT,
    @Keep val whiteLabelData: WhiteLabelData? = null
)

@Keep
enum class ConfirmationStrategy {
    @SerializedName("popup")
    POPUP,

    @SerializedName("modal")
    MODAL,

    @SerializedName("auto-approve")
    AUTO_APPROVE,

    @SerializedName("default")
    DEFAULT
}


