package com.web3auth.core.types

import androidx.annotation.Keep

object Web3AuthError {

    @JvmStatic
    fun getError(errorCode: ErrorCode): String {
        return when (errorCode) {
            ErrorCode.NOUSERFOUND -> {
                "No user found, please login again!"
            }

            ErrorCode.ENCODING_ERROR -> {
                "Encoding Error"
            }

            ErrorCode.DECODING_ERROR -> {
                "Decoding Error"
            }

            ErrorCode.SOMETHING_WENT_WRONG -> {
                "Something went wrong!"
            }

            ErrorCode.RUNTIME_ERROR -> {
                "Runtime Error"
            }

            ErrorCode.APP_CANCELLED -> {
                "App Cancelled"
            }

            ErrorCode.INVALID_LOGIN -> {
                "Invalid Login"
            }

            ErrorCode.MFA_ALREADY_ENABLED -> {
                "MFA already enabled"
            }

            ErrorCode.MFA_NOT_ENABLED -> {
                "MFA is not enabled. Please enable MFA first."
            }

            ErrorCode.USER_CANCELLED -> {
                "User Cancelled"
            }

            ErrorCode.USER_ALREADY_ENABLED_MFA -> {
                "User has already enabled MFA"
            }

            ErrorCode.PROJECT_CONFIG_NOT_FOUND_ERROR -> {
                "Project configuration not found. Please check your project settings."
            }

            ErrorCode.ENABLE_MFA_NOT_ALLOWED -> {
                "Enabling MFA is not allowed for this user."
            }
        }
    }
}

@Keep
enum class ErrorCode {
    NOUSERFOUND,
    ENCODING_ERROR,
    DECODING_ERROR,
    RUNTIME_ERROR,
    APP_CANCELLED,
    SOMETHING_WENT_WRONG,
    INVALID_LOGIN,
    MFA_ALREADY_ENABLED,
    MFA_NOT_ENABLED,
    USER_CANCELLED,
    USER_ALREADY_ENABLED_MFA,
    PROJECT_CONFIG_NOT_FOUND_ERROR,
    ENABLE_MFA_NOT_ALLOWED
}