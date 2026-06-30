package com.example.moproapp

import android.content.Context
import android.content.pm.ApplicationInfo
import android.os.SystemClock
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
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
import uniffi.mopro.computePasswordCommitment
import java.io.File
import java.util.concurrent.atomic.AtomicBoolean

enum class PasswordLoginState {
    Idle,
    Validating,
    FetchingSalt,
    ComputingCommitment,
    Submitting,
    Success,
    Error
}

data class PasswordLoginResult(
    val userId: String,
    val passwordCommitment: String,
    val commitmentTimeMs: Long,
    val networkTimeMs: Long,
    val totalTimeMs: Long,
    val httpStatus: Int?,
    val success: Boolean,
    val errorCode: String?,
    val error: String?,
    val saltCacheStatus: PasswordSaltCacheStatus? = null
)

data class PasswordAuthSession(
    val userId: String,
    val serverUrl: String,
    val token: String,
    val expiresAt: Long
)

private data class PendingPasswordLogin(
    val serverUrl: String,
    val result: PasswordLoginResult,
    val totalStartedNs: Long
)

private object PasswordLoginGuard {
    val active = AtomicBoolean(false)
}

@Composable
fun PasswordLoginScreen(
    autoTest: Boolean,
    initialUserId: String = "",
    initialServerUrl: String = "",
    onLoginSuccess: (PasswordAuthSession) -> Unit = {},
    onRegisterRequested: (String, String) -> Unit = { _, _ -> },
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
    var state by remember { mutableStateOf(PasswordLoginState.Idle) }
    var result by remember { mutableStateOf<PasswordLoginResult?>(null) }
    var pending by remember { mutableStateOf<PendingPasswordLogin?>(null) }
    var error by remember { mutableStateOf<String?>(null) }
    var autoStarted by remember { mutableStateOf(false) }
    val busy = state in setOf(
        PasswordLoginState.Validating,
        PasswordLoginState.FetchingSalt,
        PasswordLoginState.ComputingCommitment,
        PasswordLoginState.Submitting
    )

    suspend fun submit(candidate: PendingPasswordLogin) {
        try {
            state = PasswordLoginState.Submitting
            error = null
            val response = withContext(Dispatchers.IO) {
                submitLoginRequest(
                    candidate.serverUrl,
                    candidate.result.userId,
                    candidate.result.passwordCommitment,
                    ::postPasswordLogin
                )
            }
            val completed = candidate.result.copy(
                networkTimeMs = candidate.result.networkTimeMs + response.networkTimeMs,
                totalTimeMs = elapsedLoginMs(candidate.totalStartedNs),
                httpStatus = response.httpStatus,
                success = true,
                errorCode = null,
                error = null
            )
            pending = null
            result = completed
            state = PasswordLoginState.Success
            if (!autoTest) {
                onLoginSuccess(authenticatedPasswordSession(candidate.serverUrl, response))
            }
        } catch (failure: PasswordLoginServerException) {
            val canRetry = failure.httpStatus >= 500
            pending = if (canRetry) candidate else null
            val message = if (failure.serverCode == "INVALID_CREDENTIALS") {
                "Invalid userId or password"
            } else {
                "Server error (${failure.httpStatus}/${failure.serverCode})"
            }
            result = candidate.result.copy(
                totalTimeMs = elapsedLoginMs(candidate.totalStartedNs),
                httpStatus = failure.httpStatus,
                success = false,
                errorCode = failure.serverCode,
                error = message
            )
            state = PasswordLoginState.Error
            error = message
        } catch (failure: Throwable) {
            pending = candidate
            val message = "Network error: ${failure.message ?: failure.javaClass.simpleName}"
            result = candidate.result.copy(
                totalTimeMs = elapsedLoginMs(candidate.totalStartedNs),
                success = false,
                errorCode = "NETWORK_ERROR",
                error = message
            )
            state = PasswordLoginState.Error
            error = message
        }
    }

    suspend fun login(userIdValue: String, serverUrlValue: String, passwordValue: String) {
        if (!PasswordLoginGuard.active.compareAndSet(false, true)) return
        val totalStarted = SystemClock.elapsedRealtimeNanos()
        try {
            state = PasswordLoginState.Validating
            error = null
            result = null
            pending = null
            check(userIdValue.isNotBlank()) { "userId is required" }
            check(userIdValue.matches(Regex("^[A-Za-z0-9_.@:-]{3,128}$"))) {
                "userId format is invalid"
            }
            check(passwordValue.isNotEmpty()) { "Password is required" }
            passwordLoginEndpoint(serverUrlValue)

            state = PasswordLoginState.FetchingSalt
            val parameters = withContext(Dispatchers.IO) {
                fetchLoginParameters(
                    serverUrlValue,
                    userIdValue,
                    ::fetchPasswordLoginParameters
                )
            }
            val saltResolution = withContext(Dispatchers.IO) {
                resolveServerPasswordSalt(userIdValue, parameters.salt) { requestedUserId ->
                    runCatching { PasswordSaltStore.load(context, requestedUserId) }.getOrNull()
                }
            }

            state = PasswordLoginState.ComputingCommitment
            val commitmentStarted = SystemClock.elapsedRealtimeNanos()
            val commitment = withContext(Dispatchers.Default) {
                computeLoginCommitment(passwordValue, saltResolution.salt, ::computePasswordCommitment)
            }
            val commitmentTimeMs = elapsedLoginMs(commitmentStarted)
            password = clearedPasswordAfterAttempt()

            val local = PasswordLoginResult(
                userId = userIdValue,
                passwordCommitment = commitment,
                commitmentTimeMs = commitmentTimeMs,
                networkTimeMs = parameters.networkTimeMs,
                totalTimeMs = elapsedLoginMs(totalStarted),
                httpStatus = null,
                success = false,
                errorCode = null,
                error = null,
                saltCacheStatus = saltResolution.cacheStatus
            )
            val candidate = PendingPasswordLogin(serverUrlValue, local, totalStarted)
            result = local
            pending = candidate
            submit(candidate)
        } catch (failure: Throwable) {
            password = clearedPasswordAfterAttempt()
            val message = when (failure) {
                is PasswordLoginServerException -> if (failure.serverCode == "INVALID_CREDENTIALS") {
                    "Invalid userId or password"
                } else {
                    "Server error (${failure.httpStatus}/${failure.serverCode})"
                }
                else -> passwordLoginLocalError(state, failure)
            }
            result = PasswordLoginResult(
                userId = userIdValue,
                passwordCommitment = "",
                commitmentTimeMs = 0,
                networkTimeMs = 0,
                totalTimeMs = elapsedLoginMs(totalStarted),
                httpStatus = null,
                success = false,
                errorCode = if (failure is PasswordLoginServerException) {
                    failure.serverCode
                } else {
                    localLoginErrorCode(state, failure)
                },
                error = message
            )
            state = PasswordLoginState.Error
            error = message
        } finally {
            PasswordLoginGuard.active.set(false)
        }
    }

    suspend fun retry(candidate: PendingPasswordLogin) {
        if (!PasswordLoginGuard.active.compareAndSet(false, true)) return
        try {
            submit(candidate)
        } finally {
            PasswordLoginGuard.active.set(false)
        }
    }

    LaunchedEffect(autoTest) {
        if (debugBuild && autoTest && !autoStarted) {
            autoStarted = true
            val testResult = runPasswordLoginDeviceTest(
                userId = initialUserId,
                serverUrl = serverUrl,
                correctPassword = "Aa1!bbbb",
                wrongPassword = "Aa1!bbbc"
            )
            writePasswordLoginTestResult(context, testResult)
            result = testResult.correct
            state = if (testResult.passed) PasswordLoginState.Success else PasswordLoginState.Error
            error = testResult.error
            password = clearedPasswordAfterAttempt()
            testResult.session?.let(onLoginSuccess)
        }
    }

    Column(
        modifier = modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        Text("Password Login", style = MaterialTheme.typography.headlineSmall)
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
        Button(
            onClick = {
                val retryCandidate = pending
                scope.launch {
                    if (retryCandidate == null) {
                        login(userId, serverUrl, password)
                    } else {
                        retry(retryCandidate)
                    }
                }
            },
            enabled = !busy && !autoTest,
            modifier = Modifier.fillMaxWidth()
        ) {
            Text(if (pending == null) "Login" else "Retry request")
        }
        OutlinedButton(
            onClick = {
                password = clearedPasswordAfterAttempt()
                onRegisterRequested(userId, serverUrl)
            },
            enabled = !busy && pending == null && !autoTest,
            modifier = Modifier.fillMaxWidth()
        ) {
            Text("Register")
        }
        OutlinedButton(
            onClick = {
                password = clearedPasswordAfterAttempt()
                pending = null
                result = null
                error = null
                state = PasswordLoginState.Idle
            },
            enabled = !busy,
            modifier = Modifier.fillMaxWidth()
        ) {
            Text("Clear")
        }
        if (busy) LinearProgressIndicator(modifier = Modifier.fillMaxWidth())
        Text("Status: ${state.name}")
        result?.let { loginResult ->
            if (loginResult.passwordCommitment.isNotEmpty()) {
                Text("Commitment", style = MaterialTheme.typography.titleSmall)
                Text(loginResult.passwordCommitment, style = MaterialTheme.typography.bodySmall)
            }
            Text("Commitment time: ${loginResult.commitmentTimeMs} ms")
            Text("Network time: ${loginResult.networkTimeMs} ms")
            loginResult.saltCacheStatus?.let {
                Text("Salt source: Server (local cache: ${it.name})")
            }
            Text("Total time: ${loginResult.totalTimeMs} ms")
            loginResult.httpStatus?.let { Text("HTTP status: $it") }
            if (loginResult.success) Text("Login succeeded")
        }
        error?.let { Text(it, color = MaterialTheme.colorScheme.error) }
    }
}

private data class PasswordLoginDeviceTestResult(
    val correct: PasswordLoginResult,
    val wrongHttpStatus: Int,
    val wrongCode: String,
    val wrongCommitmentDifferent: Boolean,
    val missingHttpStatus: Int,
    val missingCode: String,
    val session: PasswordAuthSession?,
    val passed: Boolean,
    val error: String?
)

private suspend fun runPasswordLoginDeviceTest(
    userId: String,
    serverUrl: String,
    correctPassword: String,
    wrongPassword: String
): PasswordLoginDeviceTestResult = withContext(Dispatchers.IO) {
    val totalStarted = SystemClock.elapsedRealtimeNanos()
    try {
        val parameters = fetchPasswordLoginParameters(serverUrl, userId)
        val serverSalt = validatePasswordSaltDecimal(parameters.salt)

        val correctStarted = SystemClock.elapsedRealtimeNanos()
        val correctCommitment = computePasswordCommitment(correctPassword, serverSalt)
        val commitmentTimeMs = elapsedLoginMs(correctStarted)
        val correctResponse = postPasswordLogin(serverUrl, userId, correctCommitment)
        val correctResult = PasswordLoginResult(
            userId = userId,
            passwordCommitment = correctCommitment,
            commitmentTimeMs = commitmentTimeMs,
            networkTimeMs = parameters.networkTimeMs + correctResponse.networkTimeMs,
            totalTimeMs = elapsedLoginMs(totalStarted),
            httpStatus = correctResponse.httpStatus,
            success = true,
            errorCode = null,
            error = null
        )

        val wrongCommitment = computePasswordCommitment(wrongPassword, serverSalt)
        var wrongStatus = 0
        var wrongCode = ""
        try {
            postPasswordLogin(serverUrl, userId, wrongCommitment)
        } catch (failure: PasswordLoginServerException) {
            wrongStatus = failure.httpStatus
            wrongCode = failure.serverCode
        }

        var missingStatus = 0
        var missingCode = ""
        try {
            fetchPasswordLoginParameters(serverUrl, "missing-$userId")
        } catch (failure: PasswordLoginServerException) {
            missingStatus = failure.httpStatus
            missingCode = failure.serverCode
        }

        val passed =
            correctResult.success &&
                wrongCommitment != correctCommitment &&
                wrongStatus == 401 &&
                wrongCode == "INVALID_CREDENTIALS" &&
                missingStatus == 401 &&
                missingCode == "INVALID_CREDENTIALS"
        PasswordLoginDeviceTestResult(
            correct = correctResult,
            wrongHttpStatus = wrongStatus,
            wrongCode = wrongCode,
            wrongCommitmentDifferent = wrongCommitment != correctCommitment,
            missingHttpStatus = missingStatus,
            missingCode = missingCode,
            session = authenticatedPasswordSession(serverUrl, correctResponse),
            passed = passed,
            error = if (passed) null else "Password login device test failed"
        )
    } catch (failure: Throwable) {
        PasswordLoginDeviceTestResult(
            correct = PasswordLoginResult(
                userId = userId,
                passwordCommitment = "",
                commitmentTimeMs = 0,
                networkTimeMs = 0,
                totalTimeMs = elapsedLoginMs(totalStarted),
                httpStatus = null,
                success = false,
                errorCode = "DEVICE_TEST_FAILED",
                error = failure.message
            ),
            wrongHttpStatus = 0,
            wrongCode = "",
            wrongCommitmentDifferent = false,
            missingHttpStatus = 0,
            missingCode = "",
            session = null,
            passed = false,
            error = failure.message ?: failure.javaClass.simpleName
        )
    }
}

private fun writePasswordLoginTestResult(context: Context, result: PasswordLoginDeviceTestResult) {
    val directory = File(context.filesDir, "password_login_test").also { it.mkdirs() }
    File(directory, "result.txt").writeText(
        listOf(
            "passed=${result.passed}",
            "user_id=${result.correct.userId}",
            "correct_success=${result.correct.success}",
            "correct_http_status=${result.correct.httpStatus ?: 0}",
            "correct_commitment=${result.correct.passwordCommitment}",
            "commitment_time_ms=${result.correct.commitmentTimeMs}",
            "network_time_ms=${result.correct.networkTimeMs}",
            "total_time_ms=${result.correct.totalTimeMs}",
            "wrong_commitment_different=${result.wrongCommitmentDifferent}",
            "wrong_http_status=${result.wrongHttpStatus}",
            "wrong_code=${result.wrongCode}",
            "missing_http_status=${result.missingHttpStatus}",
            "missing_code=${result.missingCode}",
            "proof_generated=false",
            "error=${result.error.orEmpty()}"
        ).joinToString("\n") + "\n",
        Charsets.UTF_8
    )
}

private fun passwordLoginLocalError(state: PasswordLoginState, failure: Throwable): String =
    when (state) {
        PasswordLoginState.Validating -> failure.message ?: "Login input is invalid"
        PasswordLoginState.FetchingSalt -> failure.message ?: "Unable to fetch password salt"
        PasswordLoginState.ComputingCommitment -> "Password format or commitment calculation failed"
        else -> failure.message ?: "Password login failed"
    }

private fun localLoginErrorCode(state: PasswordLoginState, failure: Throwable): String =
    when (state) {
        PasswordLoginState.Validating -> when {
            failure.message == "userId is required" -> "USER_ID_REQUIRED"
            failure.message == "Password is required" -> "PASSWORD_REQUIRED"
            else -> "INVALID_INPUT"
        }
        PasswordLoginState.FetchingSalt -> "SALT_FETCH_FAILED"
        PasswordLoginState.ComputingCommitment -> "COMMITMENT_FAILED"
        else -> "LOGIN_FAILED"
    }

private fun elapsedLoginMs(startedNs: Long): Long =
    (SystemClock.elapsedRealtimeNanos() - startedNs) / 1_000_000L
