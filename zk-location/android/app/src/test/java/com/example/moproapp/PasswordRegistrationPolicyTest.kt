package com.example.moproapp

import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class PasswordRegistrationPolicyTest {
    @Test fun acceptsLen8() = assertValid("Aa1!bbbb")
    @Test fun acceptsLen16() = assertValid("Aa1!bbbbbbbbbbbb")
    @Test fun acceptsLen32() = assertValid("Aa1!bbbbbbbbbbbbbbbbbbbbbbbbbbbb")

    @Test fun rejectsLength7() = assertInvalid("Aa1!bbb", "Aa1!bbb")
    @Test fun rejectsLength33() = assertInvalid("Aa1!bbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "Aa1!bbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
    @Test fun rejectsMissingLowercase() = assertInvalid("AA1!BBBB", "AA1!BBBB")
    @Test fun rejectsMissingUppercase() = assertInvalid("aa1!bbbb", "aa1!bbbb")
    @Test fun rejectsMissingDigit() = assertInvalid("Aaa!bbbb", "Aaa!bbbb")
    @Test fun rejectsMissingSpecial() = assertInvalid("Aa11bbbb", "Aa11bbbb")
    @Test fun rejectsUnsupportedCharacter() = assertInvalid("Aa1_bbbb", "Aa1_bbbb")
    @Test fun rejectsMismatchedConfirmation() = assertInvalid("Aa1!bbbb", "Aa1!bbbc")

    @Test
    fun secureSaltsAreDistinctAndWithin128Bits() {
        val first = generateRegistrationSaltDecimal()
        val second = generateRegistrationSaltDecimal()
        assertNotEquals(first, second)
        assertTrue(first.toBigInteger().bitLength() <= 128)
        assertTrue(second.toBigInteger().bitLength() <= 128)
    }

    private fun assertValid(password: String) {
        assertTrue(validateRegistrationPassword(password, password).valid)
    }

    private fun assertInvalid(password: String, confirmation: String) {
        assertFalse(validateRegistrationPassword(password, confirmation).valid)
    }
}
