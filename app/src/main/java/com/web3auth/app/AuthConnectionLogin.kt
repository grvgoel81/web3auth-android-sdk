package com.web3auth.app

import com.web3auth.core.types.AuthConnection

data class AuthConnectionLogin(
    val name: String,
    val authConnection: AuthConnection
)