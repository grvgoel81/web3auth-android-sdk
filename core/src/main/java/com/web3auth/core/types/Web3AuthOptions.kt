package com.web3auth.core.types

import androidx.annotation.Keep
import com.google.gson.annotations.SerializedName
import org.torusresearch.fetchnodedetails.types.Web3AuthNetwork

@Keep
data class Web3AuthOptions(
    @Keep val clientId: String,
    @Keep var redirectUrl: String,
    @Keep var originData: Map<String, String>? = null,
    @SerializedName("buildEnv")
    @Keep var authBuildEnv: BuildEnv = BuildEnv.PRODUCTION,
    @Keep var sdkUrl: String = getSdkUrl(authBuildEnv),
    @Keep var storageServerUrl: String? = null,
    @Keep var sessionSocketUrl: String? = null,
    @Keep val authConnectionConfig: List<AuthConnectionConfig>? = emptyList(),
    @Keep var dashboardUrl: String? = getDashboardUrl(authBuildEnv),
    @Keep var accountAbstractionConfig: String? = null,
    @Keep var walletSdkUrl: String? = getWalletSdkUrl(authBuildEnv),
    @Keep var sessionNamespace: String? = null,
    @Keep var includeUserDataInToken: Boolean? = true,
    @Keep var chains: Chains? = null,
    @Keep var defaultChainId: String? = null,
    @Keep var enableLogging: Boolean = false,
    @Keep val sessionTime: Int = 30 * 86400,
    @SerializedName("network")
    @Keep val web3AuthNetwork: Web3AuthNetwork,
    @Keep val useSFAKey: Boolean? = false,
    @Keep val walletServicesConfig: WalletServicesConfig? = null,
    //@Keep val chainNamespace: ChainNamespace? = ChainNamespace.EIP155,
    @Keep val mfaSettings: MfaSettings? = null,
) {
    init {
        if (dashboardUrl == null) {
            dashboardUrl = getDashboardUrl(authBuildEnv)
        }
    }
}

fun getSdkUrl(buildEnv: BuildEnv?): String {
    val sdkUrl: String = when (buildEnv) {
        BuildEnv.STAGING -> {
            "https://staging-auth.web3auth.io/$authServiceVersion"
        }

        BuildEnv.TESTING -> {
            "https://develop-auth.web3auth.io"
        }

        else -> {
            "https://auth.web3auth.io/$authServiceVersion"
        }
    }
    return sdkUrl
}

fun getWalletSdkUrl(buildEnv: BuildEnv?): String {
    val sdkUrl: String = when (buildEnv) {
        BuildEnv.STAGING -> {
            "https://staging-wallet.web3auth.io/$walletServicesVersion"
        }

        BuildEnv.TESTING -> {
            "https://develop-wallet.web3auth.io"
        }

        else -> {
            "https://wallet.web3auth.io/$walletServicesVersion"
        }
    }
    return sdkUrl
}

fun getDashboardUrl(buildEnv: BuildEnv?): String {
    val sdkUrl: String = when (buildEnv) {
        BuildEnv.STAGING -> {
            "https://staging-account.web3auth.io/$authDashboardVersion/$walletAccountConstant"
        }

        BuildEnv.TESTING -> {
            "https://develop-account.web3auth.io/$walletAccountConstant"
        }

        else -> {
            "https://account.web3auth.io/$authDashboardVersion/$walletAccountConstant"
        }
    }
    return sdkUrl
}

const val authServiceVersion = "v10"
const val walletServicesVersion = "v5"
const val authDashboardVersion = "v9"
const val walletAccountConstant = "wallet/account"
const val WEBVIEW_URL = "walletUrl"
const val REDIRECT_URL = "redirectUrl"
const val CUSTOM_TABS_URL = "customTabsUrl"