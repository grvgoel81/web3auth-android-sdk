package com.web3auth.core.types

import androidx.annotation.Keep
import com.google.gson.annotations.SerializedName

@Keep
data class WhitelistResponse(
    @Keep val urls: List<String>,
    @Keep val signed_urls: Map<String, String>
)

@Keep
data class ProjectConfigResponse(
    @Keep var userDataIncludedInToken: Boolean? = true,
    @Keep val sessionTime: Int? = 30 * 86400,
    @Keep val enableKeyExport: Boolean? = false,
    @Keep val whitelist: WhitelistResponse?,
    @Keep val chains: List<Chains>? = null,
    @Keep val smartAccounts: SmartAccountsConfig? = null,
    @Keep val walletUiConfig: WalletUiConfig? = null,
    @Keep val embeddedWalletAuth: List<AuthConnectionConfig>? = null,
    @Keep val sms_otp_enabled: Boolean,
    @Keep val wallet_connect_enabled: Boolean,
    @Keep val wallet_connect_project_id: String?,
    @Keep val whitelabel: WhiteLabelData? = null,

    )

@Keep
data class SmartAccountsConfig(
    @SerializedName("smartAccountType")
    val smartAccountType: SmartAccountType,

    @SerializedName("walletScope")
    val walletScope: SmartAccountWalletScope,

    @SerializedName("chains")
    val chains: List<ChainConfig>
)

@Keep
data class ChainConfig(
    @SerializedName("chainId")
    val chainId: String,

    @SerializedName("bundlerConfig")
    val bundlerConfig: BundlerConfig,

    @SerializedName("paymasterConfig")
    val paymasterConfig: PaymasterConfig? = null
)

@Keep
data class BundlerConfig(
    @SerializedName("url")
    val url: String
)

@Keep
data class PaymasterConfig(
    @SerializedName("url")
    val url: String
)

@Keep
enum class SmartAccountType {
    @SerializedName("biconomy")
    BICONOMY,

    @SerializedName("kernel")
    KERNEL,

    @SerializedName("safe")
    SAFE,

    @SerializedName("trust")
    TRUST,

    @SerializedName("light")
    LIGHT,

    @SerializedName("simple")
    SIMPLE,

    @SerializedName("nexus")
    NEXUS
}

@Keep
enum class SmartAccountWalletScope {
    @SerializedName("embedded")
    EMBEDDED,

    @SerializedName("all")
    ALL
}


