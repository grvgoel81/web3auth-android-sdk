package com.web3auth.core.types

import androidx.annotation.Keep
import com.google.gson.annotations.SerializedName

@Keep
enum class BuildEnv {
    @SerializedName("production")
    PRODUCTION,

    @SerializedName("staging")
    STAGING,

    @SerializedName("testing")
    TESTING
}