package com.example.moproapp

import java.io.FileNotFoundException
import java.math.BigInteger

private val BN254_SCALAR_MODULUS = BigInteger(
    "21888242871839275222246405745257275088548364400416034343698204186575808495617"
)

enum class PasswordSaltCacheStatus { Missing, Match, Mismatch }

data class PasswordSaltResolution(
    val salt: String,
    val cacheStatus: PasswordSaltCacheStatus
)

class PasswordLoginLocalException(
    val code: String,
    message: String,
    cause: Throwable? = null
) : Exception(message, cause)

internal fun loadBoundPasswordSalt(
    userId: String,
    loader: (String) -> StoredPasswordSalt
): StoredPasswordSalt {
    val stored = try {
        loader(userId)
    } catch (failure: FileNotFoundException) {
        throw PasswordLoginLocalException(
            "LOCAL_SALT_NOT_FOUND",
            "No local salt record exists for this userId",
            failure
        )
    } catch (failure: Throwable) {
        throw PasswordLoginLocalException(
            "SALT_DECRYPTION_FAILED",
            "This device cannot decrypt the local salt record",
            failure
        )
    }
    if (stored.userId != userId) {
        throw PasswordLoginLocalException(
            "SALT_USER_ID_MISMATCH",
            "Local salt record userId mismatch"
        )
    }
    return stored
}

internal fun computeLoginCommitment(
    password: String,
    salt: String,
    computer: (String, String) -> String
): String {
    val commitment = try {
        computer(password, salt)
    } catch (failure: Throwable) {
        throw PasswordLoginLocalException(
            "COMMITMENT_FAILED",
            "Password format or commitment calculation failed",
            failure
        )
    }
    if (!commitment.matches(Regex("^(0|[1-9][0-9]*)$"))) {
        throw PasswordLoginLocalException(
            "COMMITMENT_FAILED",
            "Commitment calculation returned an invalid field string"
        )
    }
    return commitment
}

internal fun validatePasswordSaltDecimal(salt: String): String {
    if (!isValidPasswordSaltDecimal(salt)) {
        throw PasswordLoginLocalException(
            "INVALID_SERVER_SALT",
            "Server returned an invalid password salt"
        )
    }
    return salt
}

internal fun isValidPasswordSaltDecimal(salt: String): Boolean =
    salt.matches(Regex("^[1-9][0-9]*$")) &&
        runCatching { BigInteger(salt) < BN254_SCALAR_MODULUS }.getOrDefault(false)

internal fun resolveServerPasswordSalt(
    userId: String,
    serverSalt: String,
    localLoader: (String) -> StoredPasswordSalt?
): PasswordSaltResolution {
    val validated = validatePasswordSaltDecimal(serverSalt)
    val local = try {
        localLoader(userId)
    } catch (_failure: Throwable) {
        null
    }
    val status = when {
        local == null -> PasswordSaltCacheStatus.Missing
        local.userId == userId && local.salt == validated -> PasswordSaltCacheStatus.Match
        else -> PasswordSaltCacheStatus.Mismatch
    }
    return PasswordSaltResolution(validated, status)
}

internal fun submitLoginRequest(
    serverUrl: String,
    userId: String,
    commitment: String,
    submitter: (String, String, String) -> PasswordLoginServerResult
): PasswordLoginServerResult = submitter(serverUrl, userId, commitment)

internal fun fetchLoginParameters(
    serverUrl: String,
    userId: String,
    fetcher: (String, String) -> PasswordLoginParameters
): PasswordLoginParameters = fetcher(serverUrl, userId)

internal fun authenticatedPasswordSession(
    serverUrl: String,
    result: PasswordLoginServerResult
): PasswordAuthSession {
    require(result.success && result.token.isNotBlank()) { "Login response has no session token" }
    return PasswordAuthSession(result.userId, serverUrl, result.token, result.expiresAt)
}

internal fun clearedPasswordAfterAttempt(): String = ""
