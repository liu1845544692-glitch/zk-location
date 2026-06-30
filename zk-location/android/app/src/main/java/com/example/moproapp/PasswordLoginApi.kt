package com.example.moproapp

import android.os.SystemClock
import org.json.JSONObject
import java.net.HttpURLConnection
import java.net.URLEncoder
import java.net.URL

data class PasswordLoginParameters(
    val salt: String,
    val circuitVersion: String,
    val networkTimeMs: Long
)

data class PasswordLoginServerResult(
    val httpStatus: Int,
    val success: Boolean,
    val userId: String,
    val networkTimeMs: Long,
    val message: String,
    val token: String = "",
    val expiresAt: Long = 0,
    val expiresInMs: Long = 0
)

class PasswordLoginServerException(
    val httpStatus: Int,
    val serverCode: String,
    message: String
) : Exception(message)

fun fetchPasswordLoginParameters(
    serverUrl: String,
    userId: String
): PasswordLoginParameters {
    require(userId.matches(Regex("^[A-Za-z0-9_.@:-]{3,128}$"))) { "Invalid userId" }
    val started = SystemClock.elapsedRealtimeNanos()
    val connection = (passwordLoginParametersEndpoint(serverUrl, userId)
        .openConnection() as HttpURLConnection).apply {
        requestMethod = "GET"
        connectTimeout = 10_000
        readTimeout = 20_000
        setRequestProperty("Accept", "application/json")
    }
    try {
        val status = connection.responseCode
        val stream = if (status in 200..299) {
            connection.inputStream
        } else {
            connection.errorStream ?: connection.inputStream
        }
        val response = JSONObject(stream.bufferedReader().use { it.readText() })
        if (status !in 200..299) {
            throw PasswordLoginServerException(
                status,
                response.optString("code", "SERVER_ERROR"),
                response.optString("message", "Unable to fetch login parameters")
            )
        }
        check(response.optBoolean("success", false)) { "Invalid login parameters response" }
        val salt = response.getString("salt")
        validatePasswordSaltDecimal(salt)
        return PasswordLoginParameters(
            salt = salt,
            circuitVersion = response.getString("circuitVersion"),
            networkTimeMs = elapsedPasswordLoginMs(started)
        )
    } finally {
        connection.disconnect()
    }
}

fun postPasswordLogin(
    serverUrl: String,
    userId: String,
    passwordCommitment: String
): PasswordLoginServerResult {
    val request = passwordLoginPayload(userId, passwordCommitment)
    val started = SystemClock.elapsedRealtimeNanos()
    val connection = (passwordLoginEndpoint(serverUrl).openConnection() as HttpURLConnection).apply {
        requestMethod = "POST"
        connectTimeout = 10_000
        readTimeout = 20_000
        doOutput = true
        setRequestProperty("Content-Type", "application/json; charset=utf-8")
        setRequestProperty("Accept", "application/json")
    }

    try {
        connection.outputStream.use { output ->
            output.write(request.toString().toByteArray(Charsets.UTF_8))
        }
        val status = connection.responseCode
        val stream = if (status in 200..299) {
            connection.inputStream
        } else {
            connection.errorStream ?: connection.inputStream
        }
        val response = JSONObject(stream.bufferedReader().use { it.readText() })
        if (status !in 200..299) {
            throw PasswordLoginServerException(
                httpStatus = status,
                serverCode = response.optString("code", "SERVER_ERROR"),
                message = response.optString("message", "Password login failed")
            )
        }
        val result = PasswordLoginServerResult(
            httpStatus = status,
            success = response.optBoolean("success", false),
            userId = response.optString("userId"),
            networkTimeMs = elapsedPasswordLoginMs(started),
            message = response.optString("message", "Login succeeded"),
            token = response.getString("token"),
            expiresAt = response.getLong("expiresAt"),
            expiresInMs = response.getLong("expiresInMs")
        )
        check(result.success && result.userId == userId && result.token.isNotBlank()) {
            "Invalid password login response"
        }
        return result
    } finally {
        connection.disconnect()
    }
}

internal fun passwordLoginPayload(userId: String, passwordCommitment: String): JSONObject {
    require(userId.matches(Regex("^[A-Za-z0-9_.@:-]{3,128}$"))) {
        "userId must be 3-128 characters: letters, numbers, _, ., @, :, or -"
    }
    require(passwordCommitment.matches(Regex("^(0|[1-9][0-9]*)$"))) {
        "passwordCommitment must be a canonical decimal string"
    }
    return JSONObject()
        .put("userId", userId)
        .put("passwordCommitment", passwordCommitment)
}

internal fun passwordLoginEndpoint(serverUrl: String): URL {
    val input = URL(serverUrl.trim())
    return URL(input.protocol, input.host, input.port, "/password/login")
}

internal fun passwordLoginParametersEndpoint(serverUrl: String, userId: String): URL {
    val input = URL(serverUrl.trim())
    val encodedUserId = URLEncoder.encode(userId, Charsets.UTF_8.name())
    return URL(
        input.protocol,
        input.host,
        input.port,
        "/password/login-parameters?userId=$encodedUserId"
    )
}

private fun elapsedPasswordLoginMs(startedNs: Long): Long =
    (SystemClock.elapsedRealtimeNanos() - startedNs) / 1_000_000L
