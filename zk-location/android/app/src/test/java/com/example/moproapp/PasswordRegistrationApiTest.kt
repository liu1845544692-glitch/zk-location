package com.example.moproapp

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import uniffi.mopro.CircomProof
import uniffi.mopro.CircomProofResult
import uniffi.mopro.G1
import uniffi.mopro.G2

class PasswordRegistrationApiTest {
    @Test
    fun payloadContainsOnlyPublicRegistrationData() {
        val payload = passwordRegistrationPayload(
            userId = "test-user-1",
            salt = "1008",
            passwordCommitment = "123456789",
            proofResult = proofResult("123456789")
        )

        assertEquals(
            setOf("userId", "salt", "passwordCommitment", "publicSignals", "proof"),
            payload.keys().asSequence().toSet()
        )
        for (forbidden in listOf(
            "password",
            "confirmPassword",
            "encryptedSalt",
            "witness",
            "paddedPassword",
            "chunk0",
            "chunk1"
        )) {
            assertFalse(payload.has(forbidden))
        }
        assertEquals("1008", payload.getString("salt"))
        assertEquals("123456789", payload.getJSONArray("publicSignals").getString(0))
    }

    @Test
    fun payloadPreservesMoproCoordinatesAsDecimalStrings() {
        val proof = passwordRegistrationPayload(
            "test-user-2",
            "1008",
            "123456789",
            proofResult("123456789")
        ).getJSONObject("proof")

        assertEquals("11", proof.getJSONObject("a").getString("x"))
        assertEquals("22", proof.getJSONObject("a").getString("y"))
        assertEquals("44", proof.getJSONObject("b").getJSONArray("x").getString(0))
        assertEquals("55", proof.getJSONObject("b").getJSONArray("x").getString(1))
        assertEquals("groth16", proof.getString("protocol"))
        assertEquals("bn128", proof.getString("curve"))
    }

    @Test
    fun payloadRejectsCommitmentMismatchAndExtraPublicSignal() {
        assertFails { passwordRegistrationPayload("test-user-3", "1008", "2", proofResult("1")) }
        val extra = proofResult("1").copy(inputs = listOf("1", "2"))
        assertFails { passwordRegistrationPayload("test-user-3", "1008", "1", extra) }
    }

    @Test
    fun payloadRejectsInvalidOrZeroSalt() {
        for (salt in listOf("", "0", "01", "1e3", "-1")) {
            assertFails {
                passwordRegistrationPayload("test-user-3", salt, "1", proofResult("1"))
            }
        }
    }

    @Test
    fun endpointAlwaysTargetsPasswordRegisterOnSameOrigin() {
        assertEquals(
            "http://192.168.2.217:3000/password/register",
            passwordRegistrationEndpoint("http://192.168.2.217:3000/verify-proof").toString()
        )
        assertEquals(
            "https://example.test/password/register",
            passwordRegistrationEndpoint("https://example.test/password/register").toString()
        )
    }

    @Test
    fun encryptedSaltFilesAreBoundToUserId() {
        val first = PasswordSaltStore.fileName("test-user-1")
        val second = PasswordSaltStore.fileName("test-user-2")
        assertNotEquals(first, second)
        assertTrue(first.startsWith("password_registration_salt_v1_"))
        assertTrue(first.endsWith(".json"))
    }

    private fun proofResult(commitment: String): CircomProofResult = CircomProofResult(
        proof = CircomProof(
            a = G1("11", "22", "1"),
            b = G2(listOf("44", "55"), listOf("66", "77"), listOf("1", "0")),
            c = G1("88", "99", "1"),
            protocol = "groth16",
            curve = "bn128"
        ),
        inputs = listOf(commitment)
    )

    private fun assertFails(block: () -> Unit) {
        var failed = false
        try {
            block()
        } catch (_expected: IllegalArgumentException) {
            failed = true
        }
        assertTrue(failed)
    }
}
