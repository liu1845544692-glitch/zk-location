package com.example.moproapp

import android.os.SystemClock
import org.json.JSONArray
import org.json.JSONObject
import uniffi.mopro.CircomProof
import uniffi.mopro.CircomProofResult
import uniffi.mopro.G1
import uniffi.mopro.G2
import java.net.HttpURLConnection
import java.net.URL

data class PasswordRegistrationServerResult(
    val httpStatus: Int,
    val success: Boolean,
    val proofVerified: Boolean,
    val userId: String,
    val passwordCommitment: String,
    val networkTimeMs: Long,
    val serverVerifyTimeMs: Double,
    val message: String
)

class PasswordRegistrationServerException(
    val httpStatus: Int,
    val serverCode: String,
    message: String
) : Exception(message)

fun postPasswordRegistration(
    serverUrl: String,
    userId: String,
    salt: String,
    passwordCommitment: String,
    proofResult: CircomProofResult
): PasswordRegistrationServerResult {
    val request = passwordRegistrationPayload(
        userId = userId,
        salt = salt,
        passwordCommitment = passwordCommitment,
        proofResult = proofResult
    )
    return postPasswordRegistrationPayload(serverUrl, request)
}

internal fun postPasswordRegistrationPayload(
    serverUrl: String,
    request: JSONObject
): PasswordRegistrationServerResult {
    val started = SystemClock.elapsedRealtimeNanos()
    val connection = (passwordRegistrationEndpoint(serverUrl).openConnection() as HttpURLConnection).apply {
        requestMethod = "POST"
        connectTimeout = 10_000
        readTimeout = 30_000
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
        val responseBody = stream.bufferedReader().use { it.readText() }
        val response = JSONObject(responseBody)
        if (status !in 200..299) {
            throw PasswordRegistrationServerException(
                httpStatus = status,
                serverCode = response.optString("code", "SERVER_ERROR"),
                message = response.optString("error", "Password registration failed")
            )
        }

        val result = PasswordRegistrationServerResult(
            httpStatus = status,
            success = response.optBoolean("success", false),
            proofVerified = response.optBoolean("proofVerified", false),
            userId = response.optString("userId"),
            passwordCommitment = response.optString("passwordCommitment"),
            networkTimeMs = elapsedApiMs(started),
            serverVerifyTimeMs = response.optDouble("serverVerifyTimeMs", Double.NaN),
            message = response.optString("message", "Password registration completed")
        )
        check(result.success) { "Server did not confirm registration success" }
        check(result.proofVerified) { "Server did not verify the password proof" }
        check(result.userId == request.getString("userId")) { "Server userId mismatch" }
        check(result.passwordCommitment == request.getString("passwordCommitment")) {
            "Server commitment mismatch"
        }
        return result
    } finally {
        connection.disconnect()
    }
}

internal fun passwordRegistrationPayload(
    userId: String,
    salt: String,
    passwordCommitment: String,
    proofResult: CircomProofResult
): JSONObject {
    require(userId.matches(Regex("^[A-Za-z0-9_.@:-]{3,128}$"))) {
        "userId must be 3-128 characters: letters, numbers, _, ., @, :, or -"
    }
    require(passwordCommitment.matches(Regex("^(0|[1-9][0-9]*)$"))) {
        "passwordCommitment must be a canonical decimal string"
    }
    require(isValidPasswordSaltDecimal(salt)) {
        "salt must be a canonical non-zero BN254 scalar field element"
    }
    require(proofResult.inputs.size == 1) { "Expected one public signal" }
    require(proofResult.inputs[0] == passwordCommitment) { "Public commitment mismatch" }

    return JSONObject()
        .put("userId", userId)
        .put("salt", salt)
        .put("passwordCommitment", passwordCommitment)
        .put("publicSignals", JSONArray(proofResult.inputs))
        .put("proof", passwordProofToJson(proofResult.proof))
}

internal fun passwordRegistrationEndpoint(serverUrl: String): URL {
    val input = URL(serverUrl.trim())
    val path = input.path.orEmpty().trimEnd('/')
    val endpointPath = if (path.endsWith("/password/register")) {
        path
    } else {
        "/password/register"
    }
    return URL(input.protocol, input.host, input.port, endpointPath)
}

private fun passwordProofToJson(proof: CircomProof): JSONObject =
    JSONObject()
        .put("a", passwordG1ToJson(proof.a))
        .put("b", passwordG2ToJson(proof.b))
        .put("c", passwordG1ToJson(proof.c))
        .put("protocol", proof.protocol.ifBlank { "groth16" })
        .put("curve", proof.curve.ifBlank { "bn128" })

private fun passwordG1ToJson(point: G1): JSONObject =
    JSONObject()
        .put("x", point.x)
        .put("y", point.y)
        .put("z", point.z.ifBlank { "1" })

private fun passwordG2ToJson(point: G2): JSONObject =
    JSONObject()
        .put("x", JSONArray(point.x))
        .put("y", JSONArray(point.y))
        .put("z", JSONArray(point.z.ifEmpty { listOf("1", "0") }))

private fun elapsedApiMs(startedNs: Long): Long =
    (SystemClock.elapsedRealtimeNanos() - startedNs) / 1_000_000L
