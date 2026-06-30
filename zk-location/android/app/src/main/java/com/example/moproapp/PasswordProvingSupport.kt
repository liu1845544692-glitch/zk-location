package com.example.moproapp

import android.content.Context
import android.os.SystemClock
import org.json.JSONArray
import org.json.JSONObject
import uniffi.mopro.CircomProofResult
import java.io.File
import java.security.MessageDigest
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException
import kotlin.coroutines.suspendCoroutine

internal const val PASSWORD_ZKEY_NAME = "password_policy_commitment_final.zkey"
internal const val PASSWORD_ZKEY_SIZE = 140_303_535L
internal const val PASSWORD_ZKEY_SHA256 =
    "8bee38b7a43668f9df5b67a5d17e8f27e6419cdee98dfa912d17d4b1e8ee9156"

internal data class ZkeyPrepareResult(
    val path: String,
    val assetSize: Long,
    val fileSize: Long,
    val assetSha256: String,
    val fileSha256: String,
    val copyMs: Long,
    val reuseMs: Long,
    val copied: Boolean
) {
    fun toReport(label: String): String = listOf(
        "label=$label",
        "asset=$PASSWORD_ZKEY_NAME",
        "path=$path",
        "asset_size=$assetSize",
        "file_size=$fileSize",
        "asset_sha256=$assetSha256",
        "file_sha256=$fileSha256",
        "expected_sha256=$PASSWORD_ZKEY_SHA256",
        "copy_ms=$copyMs",
        "reuse_ms=$reuseMs",
        "copied=$copied",
        "storage_note=APK contains one zkey copy and filesDir contains one copied zkey after prepare"
    ).joinToString("\n") + "\n"
}

internal fun preparePasswordZkey(context: Context): ZkeyPrepareResult {
    val destination = File(context.filesDir, PASSWORD_ZKEY_NAME)
    val started = elapsedRealtimeNs()
    if (destination.exists() && destination.length() == PASSWORD_ZKEY_SIZE) {
        val assetSha = sha256Asset(context, PASSWORD_ZKEY_NAME)
        val fileSha = sha256File(destination)
        if (assetSha == PASSWORD_ZKEY_SHA256 && fileSha == PASSWORD_ZKEY_SHA256) {
            return ZkeyPrepareResult(
                destination.absolutePath,
                PASSWORD_ZKEY_SIZE,
                destination.length(),
                assetSha,
                fileSha,
                0,
                elapsedMs(started),
                false
            )
        }
    }

    val temp = File(context.filesDir, "$PASSWORD_ZKEY_NAME.tmp")
    val digest = MessageDigest.getInstance("SHA-256")
    val copyStarted = elapsedRealtimeNs()
    context.assets.open(PASSWORD_ZKEY_NAME).use { input ->
        temp.outputStream().use { output ->
            val buffer = ByteArray(1024 * 1024)
            while (true) {
                val read = input.read(buffer)
                if (read < 0) break
                digest.update(buffer, 0, read)
                output.write(buffer, 0, read)
            }
        }
    }
    val assetSha = digest.digest().toHex()
    require(temp.length() == PASSWORD_ZKEY_SIZE) { "copied zkey size mismatch: ${temp.length()}" }
    require(assetSha == PASSWORD_ZKEY_SHA256) { "asset zkey sha mismatch" }
    if (destination.exists()) destination.delete()
    require(temp.renameTo(destination)) { "failed to install copied zkey" }
    val fileSha = sha256File(destination)
    require(fileSha == PASSWORD_ZKEY_SHA256) { "file zkey sha mismatch" }
    return ZkeyPrepareResult(
        destination.absolutePath,
        PASSWORD_ZKEY_SIZE,
        destination.length(),
        assetSha,
        fileSha,
        elapsedMs(copyStarted),
        0,
        true
    )
}

internal suspend fun <T> runLargeStack(name: String, block: () -> T): T =
    suspendCoroutine { continuation ->
        Thread(
            null,
            {
                try {
                    continuation.resume(block())
                } catch (error: Throwable) {
                    continuation.resumeWithException(error)
                }
            },
            name,
            64L * 1024L * 1024L
        ).start()
    }

internal fun proofResultJson(result: CircomProofResult): String {
    val proof = result.proof
    return JSONObject()
        .put(
            "proof",
            JSONObject()
                .put("a", JSONObject().put("x", proof.a.x).put("y", proof.a.y).put("z", proof.a.z))
                .put(
                    "b",
                    JSONObject()
                        .put("x", JSONArray(proof.b.x))
                        .put("y", JSONArray(proof.b.y))
                        .put("z", JSONArray(proof.b.z))
                )
                .put("c", JSONObject().put("x", proof.c.x).put("y", proof.c.y).put("z", proof.c.z))
                .put("protocol", proof.protocol)
                .put("curve", proof.curve)
        )
        .put("inputs", JSONArray(result.inputs))
        .toString()
}

private fun sha256Asset(context: Context, name: String): String {
    val digest = MessageDigest.getInstance("SHA-256")
    context.assets.open(name).use { input ->
        val buffer = ByteArray(1024 * 1024)
        while (true) {
            val read = input.read(buffer)
            if (read < 0) break
            digest.update(buffer, 0, read)
        }
    }
    return digest.digest().toHex()
}

private fun sha256File(file: File): String {
    val digest = MessageDigest.getInstance("SHA-256")
    file.inputStream().use { input ->
        val buffer = ByteArray(1024 * 1024)
        while (true) {
            val read = input.read(buffer)
            if (read < 0) break
            digest.update(buffer, 0, read)
        }
    }
    return digest.digest().toHex()
}

private fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it) }

private fun elapsedRealtimeNs(): Long = SystemClock.elapsedRealtimeNanos()

private fun elapsedMs(startNs: Long): Long =
    (SystemClock.elapsedRealtimeNanos() - startNs) / 1_000_000L
