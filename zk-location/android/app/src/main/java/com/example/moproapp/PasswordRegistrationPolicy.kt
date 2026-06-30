package com.example.moproapp

import java.math.BigInteger
import java.security.SecureRandom

data class PasswordPolicyValidation(
    val valid: Boolean,
    val error: String? = null
)

fun validateRegistrationPassword(password: String, confirmation: String): PasswordPolicyValidation {
    if (password != confirmation) {
        return PasswordPolicyValidation(false, "Passwords do not match")
    }
    if (password.length !in 8..32) {
        return PasswordPolicyValidation(false, "Password length must be 8 to 32 characters")
    }
    if (!password.all { it.isAsciiLetterOrDigit() || it in "!@#$%^&*" }) {
        return PasswordPolicyValidation(false, "Password contains an unsupported character")
    }
    if (password.none { it in 'a'..'z' }) {
        return PasswordPolicyValidation(false, "Password must contain a lowercase letter")
    }
    if (password.none { it in 'A'..'Z' }) {
        return PasswordPolicyValidation(false, "Password must contain an uppercase letter")
    }
    if (password.none { it in '0'..'9' }) {
        return PasswordPolicyValidation(false, "Password must contain a digit")
    }
    if (password.none { it in "!@#$%^&*" }) {
        return PasswordPolicyValidation(false, "Password must contain an allowed special character")
    }
    return PasswordPolicyValidation(true)
}

fun generateRegistrationSaltDecimal(random: SecureRandom = SecureRandom()): String {
    val bytes = ByteArray(16)
    do {
        random.nextBytes(bytes)
    } while (bytes.all { it == 0.toByte() })
    return BigInteger(1, bytes).toString(10)
}

private fun Char.isAsciiLetterOrDigit(): Boolean =
    this in 'A'..'Z' || this in 'a'..'z' || this in '0'..'9'
