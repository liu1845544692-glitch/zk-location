package com.example.moproapp

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.FileNotFoundException
import java.io.IOException

class PasswordLoginLogicTest {
    @Test
    fun fetchesServerSaltWithoutLocalState() {
        val parameters = fetchLoginParameters("http://server", "user-1") { url, userId ->
            assertEquals("http://server", url)
            assertEquals("user-1", userId)
            PasswordLoginParameters("1008", "password-policy-commitment-v1", 9)
        }
        assertEquals("1008", parameters.salt)
    }

    @Test
    fun preservesNetworkFailureWhileFetchingServerSalt() {
        var failed = false
        try {
            fetchLoginParameters("http://server", "user-1") { _, _ ->
                throw IOException("offline")
            }
        } catch (_expected: IOException) {
            failed = true
        }
        assertTrue(failed)
    }

    @Test
    fun serverSaltWorksWhenLocalCacheIsMissing() {
        val resolved = resolveServerPasswordSalt("user-1", "1008") { null }
        assertEquals("1008", resolved.salt)
        assertEquals(PasswordSaltCacheStatus.Missing, resolved.cacheStatus)
    }

    @Test
    fun serverSaltWinsWhenLocalCacheDiffers() {
        val resolved = resolveServerPasswordSalt("user-1", "1008") {
            storedSalt("user-1").copy(salt = "9999")
        }
        assertEquals("1008", resolved.salt)
        assertEquals(PasswordSaltCacheStatus.Mismatch, resolved.cacheStatus)
    }

    @Test
    fun rejectsInvalidServerSalt() {
        for (salt in listOf("", "0", "01", "-1", "1e3",
            "21888242871839275222246405745257275088548364400416034343698204186575808495617")) {
            val error = captureLocalError {
                resolveServerPasswordSalt("user-1", salt) { null }
            }
            assertEquals("INVALID_SERVER_SALT", error.code)
        }
    }

    @Test
    fun loginParametersEndpointEncodesUserId() {
        assertEquals(
            "https://example.test/password/login-parameters?userId=user%40example.test",
            passwordLoginParametersEndpoint("https://example.test/verify-proof", "user@example.test")
                .toString()
        )
    }

    @Test
    fun readsAndDecryptsSaltForMatchingUser() {
        val stored = loadBoundPasswordSalt("user-1") { storedSalt("user-1") }
        assertEquals("1234", stored.salt)
        assertEquals("5678", stored.passwordCommitment)
    }

    @Test
    fun reportsMissingUserSalt() {
        val error = captureLocalError {
            loadBoundPasswordSalt("missing") { throw FileNotFoundException("missing") }
        }
        assertEquals("LOCAL_SALT_NOT_FOUND", error.code)
    }

    @Test
    fun rejectsSaltRecordBoundToAnotherUser() {
        val error = captureLocalError {
            loadBoundPasswordSalt("user-1") { storedSalt("user-2") }
        }
        assertEquals("SALT_USER_ID_MISMATCH", error.code)
    }

    @Test
    fun reportsKeystoreDecryptionFailure() {
        val error = captureLocalError {
            loadBoundPasswordSalt("user-1") { throw IllegalStateException("AEAD tag mismatch") }
        }
        assertEquals("SALT_DECRYPTION_FAILED", error.code)
        assertFalse(error.message.orEmpty().contains("AEAD tag mismatch"))
    }

    @Test
    fun computesCommitmentThroughInjectedRustBoundary() {
        val commitment = computeLoginCommitment("Aa1!bbbb", "1234") { password, salt ->
            assertEquals("Aa1!bbbb", password)
            assertEquals("1234", salt)
            "987654321"
        }
        assertEquals("987654321", commitment)
    }

    @Test
    fun submitsOnlyUserAndCommitmentOnSuccess() {
        val result = submitLoginRequest("http://server", "user-1", "987") { url, user, value ->
            assertEquals("http://server", url)
            assertEquals("user-1", user)
            assertEquals("987", value)
            PasswordLoginServerResult(
                200,
                true,
                user,
                12,
                "Login succeeded",
                token = "session-token",
                expiresAt = 12345,
                expiresInMs = 1000
            )
        }
        assertTrue(result.success)
        val session = authenticatedPasswordSession("http://server", result)
        assertEquals("session-token", session.token)
        assertEquals("user-1", session.userId)
    }

    @Test
    fun preservesInvalidCredentialsError() {
        val error = captureServerError {
            submitLoginRequest("http://server", "user-1", "1") { _, _, _ ->
                throw PasswordLoginServerException(401, "INVALID_CREDENTIALS", "Invalid userId or password")
            }
        }
        assertEquals(401, error.httpStatus)
        assertEquals("INVALID_CREDENTIALS", error.serverCode)
    }

    @Test
    fun preservesNetworkExceptionForRetry() {
        var failed = false
        try {
            submitLoginRequest("http://server", "user-1", "1") { _, _, _ ->
                throw IOException("offline")
            }
        } catch (_expected: IOException) {
            failed = true
        }
        assertTrue(failed)
    }

    @Test
    fun passwordIsClearedAfterAttempt() {
        assertEquals("", clearedPasswordAfterAttempt())
    }

    @Test
    fun loginPayloadContainsNoPasswordSaltOrProof() {
        val payload = passwordLoginPayload("user-1", "987654321")
        assertEquals(setOf("userId", "passwordCommitment"), payload.keys().asSequence().toSet())
        for (field in listOf("password", "salt", "encryptedSalt", "proof", "publicSignals")) {
            assertFalse(payload.has(field))
        }
    }

    private fun storedSalt(userId: String) = StoredPasswordSalt(
        userId = userId,
        salt = "1234",
        passwordCommitment = "5678",
        version = 1
    )

    private fun captureLocalError(block: () -> Unit): PasswordLoginLocalException {
        try {
            block()
        } catch (error: PasswordLoginLocalException) {
            return error
        }
        error("Expected PasswordLoginLocalException")
    }

    private fun captureServerError(block: () -> Unit): PasswordLoginServerException {
        try {
            block()
        } catch (error: PasswordLoginServerException) {
            return error
        }
        error("Expected PasswordLoginServerException")
    }
}
