package com.example.moproapp

import android.content.Context
import android.content.pm.ApplicationInfo
import android.os.SystemClock
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.json.JSONArray
import org.json.JSONObject
import uniffi.mopro.CircomProofResult
import uniffi.mopro.ProofLib
import uniffi.mopro.generatePasswordCircomProofDiagnostic
import uniffi.mopro.generatePasswordRegistrationInput
import uniffi.mopro.hashCircomProofResult
import uniffi.mopro.verifyCircomProof
import java.io.File
import java.util.concurrent.atomic.AtomicBoolean

enum class PasswordRegistrationState {
    Idle,
    Validating,
    GeneratingSalt,
    ConstructingInput,
    PreparingZkey,
    GeneratingProof,
    Verifying,
    Submitting,
    ServerVerifying,
    StoringSalt,
    Success,
    ServerError,
    Error
}

data class PasswordRegistrationResult(
    val userId: String,
    val passwordCommitment: String,
    val proof: CircomProofResult?,
    val publicSignals: List<String>,
    val proofTimeMs: Long,
    val verifyTimeMs: Long,
    val networkTimeMs: Long,
    val serverVerifyTimeMs: Double,
    val totalTimeMs: Long,
    val proofSizeBytes: Int,
    val nativeVerify: Boolean,
    val kotlinVerify: Boolean,
    val ffiProofHashMatch: Boolean,
    val httpStatus: Int?,
    val serverProofVerified: Boolean,
    val saltStorageVersion: Int?,
    val saltStorageFile: String?,
    val negativeHttpStatus: Int?,
    val negativeRejected: Boolean?,
    val success: Boolean,
    val error: String?
)

private data class PendingPasswordRegistration(
    val userId: String,
    val serverUrl: String,
    val salt: String,
    val localResult: PasswordRegistrationResult,
    val totalStartedNs: Long,
    val serverResult: PasswordRegistrationServerResult? = null
)

private object PasswordRegistrationProofGuard {
    val active = AtomicBoolean(false)
}

@Composable
fun PasswordRegisterScreen(
    autoTest: Boolean,
    initialUserId: String = "",
    initialServerUrl: String = "",
    runNegativeTest: Boolean = false,
    recoveryCheck: Boolean = false,
    onBackToLogin: (String, String) -> Unit = { _, _ -> },
    modifier: Modifier = Modifier
) {
    val context = LocalContext.current
    val debugBuild = context.applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE != 0
    val scope = rememberCoroutineScope()
    var userId by remember { mutableStateOf(initialUserId) }
    var serverUrl by remember {
        mutableStateOf(initialServerUrl.ifBlank { "http://192.168.2.217:3000" })
    }
    var password by remember { mutableStateOf("") }
    var confirmation by remember { mutableStateOf("") }
    var state by remember { mutableStateOf(PasswordRegistrationState.Idle) }
    var result by remember { mutableStateOf<PasswordRegistrationResult?>(null) }
    var pending by remember { mutableStateOf<PendingPasswordRegistration?>(null) }
    var error by remember { mutableStateOf<String?>(null) }
    var recoveryStatus by remember { mutableStateOf<String?>(null) }
    var autoStarted by remember { mutableStateOf(false) }
    val busy = state in setOf(
        PasswordRegistrationState.Validating,
        PasswordRegistrationState.GeneratingSalt,
        PasswordRegistrationState.ConstructingInput,
        PasswordRegistrationState.PreparingZkey,
        PasswordRegistrationState.GeneratingProof,
        PasswordRegistrationState.Verifying,
        PasswordRegistrationState.Submitting,
        PasswordRegistrationState.ServerVerifying,
        PasswordRegistrationState.StoringSalt
    )

    suspend fun submitAndStore(candidate: PendingPasswordRegistration) {
        var active = candidate
        var currentStage = PasswordRegistrationState.Submitting
        try {
            error = null
            var server = active.serverResult
            if (server == null) {
                state = PasswordRegistrationState.Submitting
                server = withContext(Dispatchers.IO) {
                    postPasswordRegistration(
                        serverUrl = active.serverUrl,
                        userId = active.userId,
                        salt = active.salt,
                        passwordCommitment = active.localResult.passwordCommitment,
                        proofResult = checkNotNull(active.localResult.proof)
                    )
                }
                active = active.copy(serverResult = server)
                pending = active
            }

            currentStage = PasswordRegistrationState.ServerVerifying
            state = currentStage
            check(server.success && server.proofVerified) { "Server proof verification failed" }
            check(server.userId == active.userId) { "Server userId mismatch" }
            check(server.passwordCommitment == active.localResult.passwordCommitment) {
                "Server commitment mismatch"
            }

            currentStage = PasswordRegistrationState.StoringSalt
            state = currentStage
            val storage = withContext(Dispatchers.IO) {
                runCatching {
                    val receipt = PasswordSaltStore.store(
                        context = context,
                        userId = active.userId,
                        salt = active.salt,
                        commitment = active.localResult.passwordCommitment
                    )
                    val recovered = PasswordSaltStore.load(context, active.userId)
                    check(
                        recovered.salt == active.salt &&
                            recovered.passwordCommitment == active.localResult.passwordCommitment
                    ) { "Encrypted salt recovery check failed" }
                    receipt
                }.getOrNull()
            }

            var negativeStatus: Int? = null
            var negativeRejected: Boolean? = null
            if (debugBuild && autoTest && runNegativeTest) {
                val tampered = passwordRegistrationPayload(
                    userId = active.userId,
                    salt = active.salt,
                    passwordCommitment = active.localResult.passwordCommitment,
                    proofResult = checkNotNull(active.localResult.proof)
                ).put(
                    "passwordCommitment",
                    (active.localResult.passwordCommitment.toBigInteger() + 1.toBigInteger()).toString()
                )
                try {
                    withContext(Dispatchers.IO) {
                        postPasswordRegistrationPayload(active.serverUrl, tampered)
                    }
                    negativeRejected = false
                } catch (failure: PasswordRegistrationServerException) {
                    negativeStatus = failure.httpStatus
                    negativeRejected = failure.serverCode == "COMMITMENT_MISMATCH"
                }
                check(negativeRejected == true) { "Commitment plus one request was not rejected" }
            }

            val completed = active.localResult.copy(
                networkTimeMs = server.networkTimeMs,
                serverVerifyTimeMs = server.serverVerifyTimeMs,
                totalTimeMs = elapsedRegistrationMs(active.totalStartedNs),
                httpStatus = server.httpStatus,
                serverProofVerified = true,
                saltStorageVersion = storage?.version,
                saltStorageFile = storage?.fileName,
                negativeHttpStatus = negativeStatus,
                negativeRejected = negativeRejected,
                success = true,
                error = null
            )
            result = completed
            pending = null
            state = PasswordRegistrationState.Success
            if (debugBuild && autoTest) {
                writeRegistrationTestResult(context, completed)
            }
        } catch (failure: Throwable) {
            pending = active
            val serverFailure =
                currentStage in setOf(
                    PasswordRegistrationState.Submitting,
                    PasswordRegistrationState.ServerVerifying
                ) && active.serverResult == null
            val safeError = if (serverFailure) {
                passwordServerError(failure)
            } else {
                registrationError(currentStage, failure)
            }
            result = active.localResult.copy(
                httpStatus = (failure as? PasswordRegistrationServerException)?.httpStatus,
                totalTimeMs = elapsedRegistrationMs(active.totalStartedNs),
                error = safeError
            )
            state = if (serverFailure) {
                PasswordRegistrationState.ServerError
            } else {
                PasswordRegistrationState.Error
            }
            error = safeError
            if (debugBuild && autoTest) {
                writeRegistrationTestResult(context, checkNotNull(result))
            }
        }
    }

    suspend fun performRegistration(
        userIdValue: String,
        serverUrlValue: String,
        passwordValue: String,
        confirmationValue: String
    ) {
        if (!PasswordRegistrationProofGuard.active.compareAndSet(false, true)) {
            state = PasswordRegistrationState.Error
            error = "A password registration is already running"
            return
        }

        val totalStarted = SystemClock.elapsedRealtimeNanos()
        var currentStage = PasswordRegistrationState.Validating
        try {
            state = currentStage
            error = null
            result = null
            pending = null
            check(userIdValue.matches(Regex("^[A-Za-z0-9_.@:-]{3,128}$"))) {
                "userId must be 3-128 characters: letters, numbers, _, ., @, :, or -"
            }
            passwordRegistrationEndpoint(serverUrlValue)
            val validation = validateRegistrationPassword(passwordValue, confirmationValue)
            check(validation.valid) { validation.error ?: "Password validation failed" }

            currentStage = PasswordRegistrationState.GeneratingSalt
            state = currentStage
            val salt = withContext(Dispatchers.Default) { generateRegistrationSaltDecimal() }

            currentStage = PasswordRegistrationState.ConstructingInput
            state = currentStage
            val input = withContext(Dispatchers.Default) {
                generatePasswordRegistrationInput(passwordValue, salt)
            }
            val inputJson = JSONObject(input)
            val commitment = scalarString(inputJson, "passwordCommitment")
            check(scalarString(inputJson, "salt") == salt) { "Salt was altered across FFI" }

            currentStage = PasswordRegistrationState.PreparingZkey
            state = currentStage
            val zkey = withContext(Dispatchers.IO) { preparePasswordZkey(context) }

            currentStage = PasswordRegistrationState.GeneratingProof
            state = currentStage
            val proofStarted = SystemClock.elapsedRealtimeNanos()
            val diagnostic = runLargeStack("password-registration-proof") {
                generatePasswordCircomProofDiagnostic(zkey.path, input)
            }
            val proofTimeMs = elapsedRegistrationMs(proofStarted)
            val proof = diagnostic.proofResult

            currentStage = PasswordRegistrationState.Verifying
            state = currentStage
            val ffiHash = hashCircomProofResult(proof)
            val proofSize = proofResultJson(proof).toByteArray(Charsets.UTF_8).size
            check(proof.inputs.size == 1) { "Expected one public signal" }
            check(proof.inputs[0] == commitment) { "Public commitment mismatch" }
            check(diagnostic.nativeVerify) { "Native Arkworks verification failed" }
            check(ffiHash == diagnostic.proofSha256) { "Proof changed across UniFFI" }
            check(diagnostic.zkeySha256 == PASSWORD_ZKEY_SHA256) { "Proving key integrity failed" }

            val verifyStarted = SystemClock.elapsedRealtimeNanos()
            val kotlinVerified = runLargeStack("password-registration-verify") {
                verifyCircomProof(zkey.path, proof, ProofLib.ARKWORKS)
            }
            val verifyTimeMs = elapsedRegistrationMs(verifyStarted)
            check(kotlinVerified) { "Kotlin Arkworks verification failed" }

            val local = PasswordRegistrationResult(
                userId = userIdValue,
                passwordCommitment = commitment,
                proof = proof,
                publicSignals = proof.inputs,
                proofTimeMs = proofTimeMs,
                verifyTimeMs = verifyTimeMs,
                networkTimeMs = 0,
                serverVerifyTimeMs = Double.NaN,
                totalTimeMs = elapsedRegistrationMs(totalStarted),
                proofSizeBytes = proofSize,
                nativeVerify = diagnostic.nativeVerify,
                kotlinVerify = kotlinVerified,
                ffiProofHashMatch = ffiHash == diagnostic.proofSha256,
                httpStatus = null,
                serverProofVerified = false,
                saltStorageVersion = null,
                saltStorageFile = null,
                negativeHttpStatus = null,
                negativeRejected = null,
                success = false,
                error = null
            )
            val candidate = PendingPasswordRegistration(
                userId = userIdValue,
                serverUrl = serverUrlValue,
                salt = salt,
                localResult = local,
                totalStartedNs = totalStarted
            )
            pending = candidate
            result = local
            password = ""
            confirmation = ""
            submitAndStore(candidate)
        } catch (failure: Throwable) {
            val safeError = registrationError(currentStage, failure)
            result = emptyRegistrationResult(userIdValue, totalStarted, safeError)
            state = PasswordRegistrationState.Error
            error = safeError
            if (debugBuild && autoTest) {
                writeRegistrationTestResult(context, checkNotNull(result))
            }
        } finally {
            PasswordRegistrationProofGuard.active.set(false)
        }
    }

    suspend fun retryPending(candidate: PendingPasswordRegistration) {
        if (!PasswordRegistrationProofGuard.active.compareAndSet(false, true)) return
        try {
            submitAndStore(candidate)
        } finally {
            PasswordRegistrationProofGuard.active.set(false)
        }
    }

    LaunchedEffect(autoTest, recoveryCheck) {
        if (!debugBuild || autoStarted) return@LaunchedEffect
        if (recoveryCheck) {
            autoStarted = true
            val recovered = runCatching {
                withContext(Dispatchers.IO) { PasswordSaltStore.load(context, initialUserId) }
            }
            recoveryStatus = if (recovered.isSuccess) "Encrypted salt recovery: PASS" else
                "Encrypted salt recovery: FAIL"
            writeRegistrationRecoveryResult(
                context = context,
                userId = initialUserId,
                success = recovered.isSuccess,
                commitment = recovered.getOrNull()?.passwordCommitment.orEmpty()
            )
        } else if (autoTest) {
            autoStarted = true
            performRegistration(
                userIdValue = initialUserId,
                serverUrlValue = serverUrl,
                passwordValue = "Aa1!bbbb",
                confirmationValue = "Aa1!bbbb"
            )
        }
    }

    Column(
        modifier = modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        Text("Password Register", style = MaterialTheme.typography.headlineSmall)
        OutlinedButton(
            onClick = { onBackToLogin(userId, serverUrl) },
            enabled = !busy,
            modifier = Modifier.fillMaxWidth()
        ) {
            Text(if (result?.success == true) "Continue to Login" else "Back to Login")
        }
        OutlinedTextField(
            value = userId,
            onValueChange = { userId = it },
            label = { Text("User ID") },
            modifier = Modifier.fillMaxWidth(),
            singleLine = true,
            enabled = !busy && pending == null
        )
        OutlinedTextField(
            value = serverUrl,
            onValueChange = { serverUrl = it },
            label = { Text("Server URL") },
            modifier = Modifier.fillMaxWidth(),
            singleLine = true,
            enabled = !busy && pending == null
        )
        OutlinedTextField(
            value = password,
            onValueChange = { password = it },
            label = { Text("Password") },
            modifier = Modifier.fillMaxWidth(),
            singleLine = true,
            enabled = !busy && pending == null,
            visualTransformation = PasswordVisualTransformation(),
            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password)
        )
        OutlinedTextField(
            value = confirmation,
            onValueChange = { confirmation = it },
            label = { Text("Confirm Password") },
            modifier = Modifier.fillMaxWidth(),
            singleLine = true,
            enabled = !busy && pending == null,
            visualTransformation = PasswordVisualTransformation(),
            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password)
        )
        Text(
            "8–32 characters · uppercase · lowercase · digit · ! @ # $ % ^ & *",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            Button(
                onClick = {
                    val retry = pending
                    scope.launch {
                        if (retry != null) {
                            retryPending(retry)
                        } else {
                            performRegistration(userId, serverUrl, password, confirmation)
                        }
                    }
                },
                enabled = !busy && !recoveryCheck,
                modifier = Modifier.weight(1f)
            ) {
                Text(
                    when {
                        pending?.serverResult != null -> "Complete local storage"
                        pending != null -> "Retry submission"
                        else -> "Generate proof / Register"
                    }
                )
            }
            OutlinedButton(
                onClick = {
                    pending = null
                    result = null
                    error = null
                    state = PasswordRegistrationState.Idle
                },
                enabled = !busy && pending?.serverResult == null,
                modifier = Modifier.weight(0.45f)
            ) {
                Text("Clear")
            }
        }
        if (busy) LinearProgressIndicator(modifier = Modifier.fillMaxWidth())
        Text("Status: ${state.name}", style = MaterialTheme.typography.bodyMedium)
        recoveryStatus?.let { Text(it) }
        result?.let { registration ->
            if (registration.passwordCommitment.isNotEmpty()) {
                Text("Commitment", style = MaterialTheme.typography.titleSmall)
                Text(registration.passwordCommitment, style = MaterialTheme.typography.bodySmall)
            }
            Text("Proof: ${registration.proofSizeBytes} bytes")
            Text("Proof time: ${registration.proofTimeMs} ms")
            Text("Local verify time: ${registration.verifyTimeMs} ms")
            if (registration.httpStatus != null) {
                Text("Server HTTP: ${registration.httpStatus}")
                Text("Server proof verify: ${registration.serverProofVerified}")
                Text("Network time: ${registration.networkTimeMs} ms")
                Text("Server verify time: ${registration.serverVerifyTimeMs} ms")
            }
            Text("Native verify: ${registration.nativeVerify}")
            Text("Local verify: ${registration.kotlinVerify}")
            if (registration.success) Text("Registration succeeded")
        }
        error?.let { Text(it, color = MaterialTheme.colorScheme.error) }
    }
}

private fun scalarString(json: JSONObject, name: String): String {
    val value = json.get(name)
    return if (value is JSONArray) {
        check(value.length() == 1) { "$name is not scalar" }
        value.getString(0)
    } else {
        value.toString()
    }
}

private fun emptyRegistrationResult(
    userId: String,
    startedNs: Long,
    error: String
): PasswordRegistrationResult = PasswordRegistrationResult(
    userId = userId,
    passwordCommitment = "",
    proof = null,
    publicSignals = emptyList(),
    proofTimeMs = 0,
    verifyTimeMs = 0,
    networkTimeMs = 0,
    serverVerifyTimeMs = Double.NaN,
    totalTimeMs = elapsedRegistrationMs(startedNs),
    proofSizeBytes = 0,
    nativeVerify = false,
    kotlinVerify = false,
    ffiProofHashMatch = false,
    httpStatus = null,
    serverProofVerified = false,
    saltStorageVersion = null,
    saltStorageFile = null,
    negativeHttpStatus = null,
    negativeRejected = null,
    success = false,
    error = error
)

private fun registrationError(stage: PasswordRegistrationState, failure: Throwable): String {
    if (stage == PasswordRegistrationState.Validating && failure.message != null) {
        return failure.message!!
    }
    return when (stage) {
        PasswordRegistrationState.GeneratingSalt -> "Secure salt generation failed"
        PasswordRegistrationState.ConstructingInput -> "Password circuit input construction failed"
        PasswordRegistrationState.PreparingZkey -> "Proving key preparation failed"
        PasswordRegistrationState.GeneratingProof -> "Witness or proof generation failed"
        PasswordRegistrationState.Verifying -> failure.message?.takeIf {
            it == "Native Arkworks verification failed" ||
                it == "Kotlin Arkworks verification failed" ||
                it == "Public commitment mismatch" ||
                it == "Proof changed across UniFFI"
        } ?: "Local proof verification failed"
        PasswordRegistrationState.StoringSalt -> "Encrypted salt storage failed"
        else -> "Password registration failed"
    }
}

private fun passwordServerError(failure: Throwable): String =
    if (failure is PasswordRegistrationServerException) {
        "Server rejected registration (${failure.httpStatus}/${failure.serverCode}): ${failure.message}"
    } else {
        "Network or server error: ${failure.message ?: failure.javaClass.simpleName}"
    }

private fun writeRegistrationTestResult(context: Context, result: PasswordRegistrationResult) {
    val directory = File(context.filesDir, "password_register_test").also { it.mkdirs() }
    File(directory, "server-result.txt").writeText(
        listOf(
            "success=${result.success}",
            "user_id=${result.userId}",
            "password_commitment=${result.passwordCommitment}",
            "public_signal_count=${result.publicSignals.size}",
            "public_signal_0=${result.publicSignals.firstOrNull().orEmpty()}",
            "public_signal_match=${result.publicSignals.firstOrNull() == result.passwordCommitment}",
            "native_verify=${result.nativeVerify}",
            "kotlin_verify=${result.kotlinVerify}",
            "ffi_proof_hash_match=${result.ffiProofHashMatch}",
            "http_status=${result.httpStatus ?: 0}",
            "server_proof_verified=${result.serverProofVerified}",
            "proof_time_ms=${result.proofTimeMs}",
            "local_verify_time_ms=${result.verifyTimeMs}",
            "network_time_ms=${result.networkTimeMs}",
            "server_verify_time_ms=${result.serverVerifyTimeMs}",
            "total_time_ms=${result.totalTimeMs}",
            "proof_size_bytes=${result.proofSizeBytes}",
            "salt_storage_version=${result.saltStorageVersion ?: 0}",
            "salt_storage_file=${result.saltStorageFile.orEmpty()}",
            "negative_http_status=${result.negativeHttpStatus ?: 0}",
            "negative_rejected=${result.negativeRejected ?: false}",
            "error=${result.error.orEmpty()}"
        ).joinToString("\n") + "\n",
        Charsets.UTF_8
    )
}

private fun writeRegistrationRecoveryResult(
    context: Context,
    userId: String,
    success: Boolean,
    commitment: String
) {
    val directory = File(context.filesDir, "password_register_test").also { it.mkdirs() }
    File(directory, "recovery-result.txt").writeText(
        listOf(
            "success=$success",
            "user_id=$userId",
            "password_commitment=$commitment"
        ).joinToString("\n") + "\n",
        Charsets.UTF_8
    )
}

private fun elapsedRegistrationMs(startedNs: Long): Long =
    (SystemClock.elapsedRealtimeNanos() - startedNs) / 1_000_000L
