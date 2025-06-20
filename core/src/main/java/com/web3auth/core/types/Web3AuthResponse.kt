package com.web3auth.core.types

import androidx.annotation.Keep
import com.google.gson.annotations.SerializedName

@Keep
data class Web3AuthResponse(
    @SerializedName("privKey")
    val privateKey: String? = null,
    val ed25519PrivKey: String? = null,
    val userInfo: UserInfo? = null,
    val error: String? = null,
    val sessionId: String? = null,
    val coreKitKey: String? = null,
    val coreKitEd25519PrivKey: String? = null,
    val factorKey: String? = null,
    val signatures: List<String>? = null,
    val tssShareIndex: Int? = null,
    val tssPubKey: String? = null,
    val tssShare: String? = null,
    val tssTag: String? = null,
    val tssNonce: Int? = null,
    val nodeIndexes: List<Int>? = null,
    val keyMode: String? = null,
    val oAuthPrivateKey: String? = null,
    val tKey: String? = null,
    val walletKey: String? = null,
    val metadataNonce: String? = null,
    val authToken: String? = null,
)