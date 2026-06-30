package com.example.moproapp

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import org.json.JSONObject
import java.nio.charset.StandardCharsets
import java.security.KeyStore
import java.security.MessageDigest
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

data class SaltStorageReceipt(
    val version: Int,
    val fileName: String,
    val encrypted: Boolean
)

data class StoredPasswordSalt(
    val userId: String,
    val salt: String,
    val passwordCommitment: String,
    val version: Int
)

object PasswordSaltStore {
    private const val KEYSTORE = "AndroidKeyStore"
    private const val KEY_ALIAS = "zk_location_password_salt_aes_v1"
    private const val TRANSFORMATION = "AES/GCM/NoPadding"
    private const val VERSION = 1

    fun store(
        context: Context,
        userId: String,
        salt: String,
        commitment: String
    ): SaltStorageReceipt {
        val destination = context.filesDir.resolve(fileName(userId))
        if (destination.exists()) {
            val existing = load(context, userId)
            check(existing.passwordCommitment == commitment && existing.salt == salt) {
                "A different encrypted salt record already exists for this userId"
            }
            return SaltStorageReceipt(VERSION, destination.name, encrypted = true)
        }

        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, getOrCreateKey())
        val ciphertext = cipher.doFinal(salt.toByteArray(StandardCharsets.UTF_8))
        val record = JSONObject()
            .put("version", VERSION)
            .put("algorithm", TRANSFORMATION)
            .put("keyAlias", KEY_ALIAS)
            .put("userId", userId)
            .put("iv", Base64.encodeToString(cipher.iv, Base64.NO_WRAP))
            .put("ciphertext", Base64.encodeToString(ciphertext, Base64.NO_WRAP))
            .put("passwordCommitment", commitment)

        val temporary = context.filesDir.resolve("${destination.name}.tmp")
        temporary.writeText(record.toString(), Charsets.UTF_8)
        check(temporary.renameTo(destination)) { "Unable to install encrypted salt record" }
        return SaltStorageReceipt(VERSION, destination.name, encrypted = true)
    }

    fun load(context: Context, userId: String): StoredPasswordSalt {
        val record = JSONObject(context.filesDir.resolve(fileName(userId)).readText(Charsets.UTF_8))
        check(record.getInt("version") == VERSION) { "Unsupported salt record version" }
        check(record.getString("algorithm") == TRANSFORMATION) { "Unsupported salt encryption" }
        check(record.getString("keyAlias") == KEY_ALIAS) { "Unexpected salt encryption key alias" }
        check(record.getString("userId") == userId) { "Encrypted salt userId mismatch" }
        val cipher = Cipher.getInstance(TRANSFORMATION)
        val iv = Base64.decode(record.getString("iv"), Base64.NO_WRAP)
        cipher.init(Cipher.DECRYPT_MODE, getOrCreateKey(), GCMParameterSpec(128, iv))
        val plaintext = cipher.doFinal(
            Base64.decode(record.getString("ciphertext"), Base64.NO_WRAP)
        )
        return StoredPasswordSalt(
            userId = userId,
            salt = plaintext.toString(StandardCharsets.UTF_8),
            passwordCommitment = record.getString("passwordCommitment"),
            version = VERSION
        )
    }

    fun fileName(userId: String): String =
        "password_registration_salt_v1_${sha256Hex(userId).take(24)}.json"

    private fun getOrCreateKey(): SecretKey {
        val keyStore = KeyStore.getInstance(KEYSTORE).apply { load(null) }
        (keyStore.getKey(KEY_ALIAS, null) as? SecretKey)?.let { return it }

        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, KEYSTORE)
        generator.init(
            KeyGenParameterSpec.Builder(
                KEY_ALIAS,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
            )
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setRandomizedEncryptionRequired(true)
                .setUserAuthenticationRequired(false)
                .build()
        )
        return generator.generateKey()
    }

    private fun sha256Hex(value: String): String =
        MessageDigest.getInstance("SHA-256")
            .digest(value.toByteArray(StandardCharsets.UTF_8))
            .joinToString("") { byte -> "%02x".format(byte.toInt() and 0xff) }
}
