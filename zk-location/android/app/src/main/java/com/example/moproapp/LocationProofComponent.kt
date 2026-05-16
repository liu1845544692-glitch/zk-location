/*
 * 文件功能：
 * - Android 主业务界面，串联注册/登录、key 绑定、GNSS、H3/Circom proof、Keystore 签名和服务端验证。
 * - UI 只展示本次登录后产生的 active key 和 proof 状态，不复用历史 attestation 展示。
 *
 * 执行流程：
 * 1. 未登录时显示 AuthEntry，调用 /auth/register 或 /auth/login。
 * 2. 登录后显示地图、状态条、Actions 和 Results。
 * 3. Generate new key and bind 重新生成 Keystore key，并提交 certificateChain 给服务端验证。
 * 4. GNSS 获取经纬度，Rust/mopro 生成 H3 半平面输入和 ZK proof。
 * 5. Keystore 对 public_commitment + server_nonce 签名。
 * 6. Send proof to server 提交 proof、public inputs 和签名，由服务端统一验证。
 */
package com.example.moproapp

import android.Manifest
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import uniffi.mopro.CircomProof
import uniffi.mopro.CircomProofResult
import uniffi.mopro.G1
import uniffi.mopro.G2
import uniffi.mopro.ProofLib
import uniffi.mopro.generateCircomProof
import uniffi.mopro.generateLocationCircuitInput
import uniffi.mopro.verifyCircomProof
import java.net.HttpURLConnection
import java.net.URI
import java.net.URL
import org.json.JSONArray
import org.json.JSONObject

@Composable
fun LocationProofComponent(modifier: Modifier = Modifier) {
    // context：当前 Android Context，用于权限、GNSS 和 assets 访问。
    val context = LocalContext.current
    // latitude/longitude：本次 GNSS 读取到的 WGS84 坐标，作为 proof 私有输入来源。
    var latitude by remember { mutableStateOf<Double?>(null) }
    var longitude by remember { mutableStateOf<Double?>(null) }
    // locationSummary：GNSS 输出摘要，用于 Results 页面展示。
    var locationSummary by remember { mutableStateOf<String?>(null) }
    // selectedResolution：当前 H3 resolution，改变后旧 proof/signature 会失效。
    var selectedResolution by remember { mutableIntStateOf(9) }
    // resolutionMenuExpanded：H3 resolution 下拉菜单展开状态。
    var resolutionMenuExpanded by remember { mutableStateOf(false) }
    // provingTime/verifyingTime/valid/publicInputs：本地 proof 生成和验证结果展示状态。
    var provingTime by remember { mutableStateOf<String?>(null) }
    var verifyingTime by remember { mutableStateOf<String?>(null) }
    var valid by remember { mutableStateOf<String?>(null) }
    var publicInputs by remember { mutableStateOf<String?>(null) }
    // serverUrl：服务端 /verify-proof URL，其他接口会从它推导同 host 下路径。
    var serverUrl by remember { mutableStateOf("http://10.0.2.2:3000/verify-proof") }
    // serverResponse/reportSummary/performanceSummary：服务端验证、报告和性能统计显示内容。
    var serverResponse by remember { mutableStateOf<String?>(null) }
    var reportSummary by remember { mutableStateOf<String?>(null) }
    var performanceSummary by remember { mutableStateOf<String?>(null) }
    // keyRegistration：客户端本地最近一次 Keystore key 生成结果。
    var keyRegistration by remember { mutableStateOf<LocationKeyRegistration?>(null) }
    // signatureResult：当前 proof commitment 的 Keystore 签名结果，发送成功后清空防止复用。
    var signatureResult by remember { mutableStateOf<LocationCommitmentSignature?>(null) }
    // authUsername/authPassword/authToken/authSummary：账号输入和当前登录 session 状态。
    var authUsername by remember { mutableStateOf("alice") }
    var authPassword by remember { mutableStateOf("correct-password") }
    var authToken by remember { mutableStateOf<String?>(null) }
    var authSummary by remember { mutableStateOf<String?>(null) }
    // keyBindingSummary：服务端返回的 active key attestation 摘要，仅来自本次登录后的绑定/查询。
    var keyBindingSummary by remember { mutableStateOf<String?>(null) }
    // error：最近一次失败原因，供 Results/Error 展示。
    var error by remember { mutableStateOf<String?>(null) }
    // isActionSetOpen/isViewSetOpen/selectedOutput/operationStatus：弹窗和结果页 UI 状态。
    var isActionSetOpen by remember { mutableStateOf(false) }
    var isViewSetOpen by remember { mutableStateOf(false) }
    var selectedOutput by remember { mutableStateOf<OutputSection?>(null) }
    var operationStatus by remember { mutableStateOf<OperationStatus?>(null) }
    // isGenerating...isReporting：各异步操作的忙碌状态，用于禁用按钮和显示加载状态。
    var isGenerating by remember { mutableStateOf(false) }
    var isVerifying by remember { mutableStateOf(false) }
    var isAuthenticating by remember { mutableStateOf(false) }
    var isBindingKey by remember { mutableStateOf(false) }
    var isSigning by remember { mutableStateOf(false) }
    var isSendingProof by remember { mutableStateOf(false) }
    var isLocating by remember { mutableStateOf(false) }
    var isReporting by remember { mutableStateOf(false) }
    // proofGenerationMs：最近一次客户端 proof 生成耗时，会随 proof 提交给服务端日志。
    var proofGenerationMs by remember { mutableStateOf<Long?>(null) }
    // clientProofTimes/serverVerifyTimes：本次 App 会话内的本地性能样本。
    var clientProofTimes by remember { mutableStateOf<List<Long>>(emptyList()) }
    var serverVerifyTimes by remember { mutableStateOf<List<Long>>(emptyList()) }
    // result：当前 Circom proof 结果，空 proof 表示还未生成。
    var result by remember {
        mutableStateOf(emptyProofResult())
    }

    // zkeyPath：从 assets 复制出的 areajudge proving key 文件路径。
    val zkeyPath = getFilePathFromAssets("areajudge_final.zkey")
    // isBusy：任意异步操作进行中时禁用主操作，避免状态交叉。
    val isBusy = isGenerating || isVerifying || isAuthenticating ||
        isBindingKey || isSigning || isSendingProof || isLocating || isReporting
    // clearProofState：位置、resolution 或 key 改变后清除旧 proof/signature/server response。
    val clearProofState = {
        provingTime = null
        verifyingTime = null
        valid = null
        publicInputs = null
        signatureResult = null
        serverResponse = null
        proofGenerationMs = null
        result = emptyProofResult()
        selectedOutput = null
    }
    // resetAfterLocation：GNSS 更新后统一清理旧 proof 状态并提示用户。
    val resetAfterLocation = {
        clearProofState()
        operationStatus = OperationStatus("GNSS", true, locationSummary ?: "Location updated")
    }
    // locationPermissionLauncher：请求精确定位权限后的回调入口。
    val locationPermissionLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.RequestPermission()
    ) { granted ->
        if (granted) {
            isLocating = true
            error = null
            GnssLocationReader.requestSingleFix(
                context = context,
                onLocation = { location ->
                    latitude = location.latitude
                    longitude = location.longitude
                    locationSummary = "GNSS: ${formatCoordinate(location.latitude)}, ${formatCoordinate(location.longitude)}"
                    resetAfterLocation()
                    isLocating = false
                },
                onError = {
                    error = it
                    operationStatus = OperationStatus("GNSS", false, it)
                    isLocating = false
                }
            )
        } else {
            error = "Fine location permission denied"
            operationStatus = OperationStatus("GNSS", false, error ?: "Permission denied")
        }
    }

    // registerAction：调用服务端注册接口，成功后进入登录态但不自动生成 key。
    val registerAction = {
        isAuthenticating = true
        error = null
        Thread {
            try {
                // auth：服务端返回的 token 和展示摘要。
                val auth = postAuth(serverUrl, "/auth/register", authUsername, authPassword)
                authToken = auth.token
                authSummary = auth.summary
                keyBindingSummary = null
                keyRegistration = null
                clearProofState()
                operationStatus = OperationStatus("Register", true, auth.summary)
            } catch (e: Exception) {
                val message = e.message ?: e.toString()
                error = message
                operationStatus = OperationStatus("Register", false, message)
            } finally {
                isAuthenticating = false
            }
        }.start()
    }

    // loginAction：调用服务端登录接口；服务端会清空旧 active key，要求重新绑定。
    val loginAction = {
        isAuthenticating = true
        error = null
        Thread {
            try {
                // auth：服务端返回的本次登录 session token。
                val auth = postAuth(serverUrl, "/auth/login", authUsername, authPassword)
                authToken = auth.token
                authSummary = auth.summary
                keyBindingSummary = null
                keyRegistration = null
                clearProofState()
                operationStatus = OperationStatus("Login", true, auth.summary)
            } catch (e: Exception) {
                val message = e.message ?: e.toString()
                error = message
                operationStatus = OperationStatus("Login", false, message)
            } finally {
                isAuthenticating = false
            }
        }.start()
    }

    Column(
        modifier = modifier
            .fillMaxSize()
            .background(MaterialTheme.colorScheme.background)
            .padding(12.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.spacedBy(10.dp)
    ) {
        if (authToken == null) {
            AuthEntry(
                serverUrl = serverUrl,
                username = authUsername,
                password = authPassword,
                isBusy = isBusy,
                authSummary = authSummary,
                onServerUrlChange = { serverUrl = it },
                onUsernameChange = { authUsername = it },
                onPasswordChange = { authPassword = it },
                onRegister = registerAction,
                onLogin = loginAction,
                modifier = Modifier
                    .fillMaxWidth()
                    .weight(1f)
            )
        } else {
            AppHeader(
                username = authUsername,
                serverUrl = serverUrl,
                isBusy = isBusy
            )

            Surface(
                modifier = Modifier
                    .fillMaxWidth()
                    .weight(1f),
                shape = RoundedCornerShape(8.dp),
                color = MaterialTheme.colorScheme.surface,
                border = BorderStroke(1.dp, MaterialTheme.colorScheme.outline)
            ) {
                Box(modifier = Modifier.fillMaxSize()) {
                    CampusOfflineMap(
                        latitude = latitude,
                        longitude = longitude,
                        selectedResolution = selectedResolution,
                        modifier = Modifier.fillMaxSize(),
                        fillAvailableHeight = true,
                        showDetails = false
                    )
                }
            }

            StatusStrip(
                hasKey = keyBindingSummary != null,
                hasLocation = latitude != null && longitude != null,
                hasProof = result.proof.a.x.isNotEmpty(),
                hasSignature = signatureResult != null,
                serverAccepted = serverResponse?.contains("Valid: true") == true
            )

            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(8.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                Button(
                    onClick = { isActionSetOpen = true },
                    modifier = Modifier
                        .weight(1f)
                        .heightIn(min = 44.dp),
                    enabled = !isBusy,
                    shape = RoundedCornerShape(8.dp),
                    contentPadding = PaddingValues(horizontal = 12.dp, vertical = 8.dp)
                ) {
                    Text(if (isBusy) "Processing" else "Actions", fontSize = 13.sp, fontWeight = FontWeight.SemiBold)
                }

                OutlinedButton(
                    onClick = { isViewSetOpen = true },
                    modifier = Modifier
                        .weight(1f)
                        .heightIn(min = 44.dp),
                    enabled = !isBusy,
                    shape = RoundedCornerShape(8.dp),
                    contentPadding = PaddingValues(horizontal = 12.dp, vertical = 8.dp)
                ) {
                    Text("Results", fontSize = 13.sp, fontWeight = FontWeight.SemiBold)
                }
            }
        }
    }

    if (authToken != null && isActionSetOpen) {
        ActionSetDialog(
            serverUrl = serverUrl,
            selectedResolution = selectedResolution,
            resolutionMenuExpanded = resolutionMenuExpanded,
            isBusy = isBusy,
            hasLocation = latitude != null && longitude != null,
            hasProof = result.proof.a.x.isNotEmpty(),
            hasCommitment = result.inputs.isNotEmpty(),
            isLoggedIn = authToken != null,
            onDismiss = { isActionSetOpen = false },
            onServerUrlChange = { serverUrl = it },
            onLogout = {
                val token = authToken
                if (token == null) {
                    operationStatus = OperationStatus("Logout", false, "Already logged out")
                } else {
                    isAuthenticating = true
                    Thread {
                        try {
                            val summary = postLogout(serverUrl, token)
                            authToken = null
                            authSummary = null
                            keyBindingSummary = null
                            keyRegistration = null
                            clearProofState()
                            operationStatus = OperationStatus("Logout", true, summary)
                        } catch (e: Exception) {
                            val message = e.message ?: e.toString()
                            error = message
                            operationStatus = OperationStatus("Logout", false, message)
                        } finally {
                            isAuthenticating = false
                        }
                    }.start()
                }
            },
            onVerifyKey = {
                val token = authToken
                if (token == null) {
                    operationStatus = OperationStatus("Verify key", false, "Login before verifying key")
                } else {
                    isReporting = true
                    error = null
                    Thread {
                        try {
                            val summary = fetchActiveKeySummary(serverUrl, token)
                            keyBindingSummary = summary
                            operationStatus = OperationStatus("Verify key", true, summary)
                        } catch (e: Exception) {
                            val message = e.message ?: e.toString()
                            error = message
                            operationStatus = OperationStatus("Verify key", false, message)
                        } finally {
                            isReporting = false
                        }
                    }.start()
                }
            },
            onFetchStats = {
                isReporting = true
                Thread {
                    try {
                        val serverStats = fetchServerStats(serverUrl)
                        performanceSummary = buildPerformanceSummary(
                            clientProofTimes = clientProofTimes,
                            serverVerifyTimes = serverVerifyTimes,
                            serverStats = serverStats
                        )
                        operationStatus = OperationStatus("Stats", true, performanceSummary ?: "No stats")
                    } catch (e: Exception) {
                        val message = e.message ?: e.toString()
                        error = message
                        operationStatus = OperationStatus("Stats", false, message)
                    } finally {
                        isReporting = false
                    }
                }.start()
            },
            onExportReport = {
                isReporting = true
                Thread {
                    try {
                        reportSummary = fetchExperimentReport(serverUrl)
                        operationStatus = OperationStatus("Report", true, reportSummary ?: "No report")
                    } catch (e: Exception) {
                        val message = e.message ?: e.toString()
                        error = message
                        operationStatus = OperationStatus("Report", false, message)
                    } finally {
                        isReporting = false
                    }
                }.start()
            },
            onBindKey = {
                val token = authToken
                if (token == null) {
                    val message = "Login before binding Keystore key"
                    error = message
                    operationStatus = OperationStatus("Bind key", false, message)
                } else {
                    isBindingKey = true
                    signatureResult = null
                    error = null
                    Thread {
                        try {
                            val (registration, summary) = generateNewKeyAndBind(serverUrl, token)
                            keyRegistration = registration
                            keyBindingSummary = summary
                            clearProofState()
                            operationStatus = OperationStatus("Generate new key and bind", true, summary)
                        } catch (e: Exception) {
                            val message = e.message ?: e.toString()
                            error = message
                            operationStatus = OperationStatus("Generate new key and bind", false, message)
                        } finally {
                            isBindingKey = false
                        }
                    }.start()
                }
            },
            onGetGnss = {
                if (GnssLocationReader.hasFineLocationPermission(context)) {
                    isLocating = true
                    error = null
                    GnssLocationReader.requestSingleFix(
                        context = context,
                        onLocation = { location ->
                            latitude = location.latitude
                            longitude = location.longitude
                            locationSummary = "GNSS: ${formatCoordinate(location.latitude)}, ${formatCoordinate(location.longitude)}"
                            resetAfterLocation()
                            isLocating = false
                        },
                        onError = {
                            error = it
                            operationStatus = OperationStatus("GNSS", false, it)
                            isLocating = false
                        }
                    )
                } else {
                    locationPermissionLauncher.launch(Manifest.permission.ACCESS_FINE_LOCATION)
                }
            },
            onResolutionMenuChange = { resolutionMenuExpanded = it },
            onSelectResolution = { resolution ->
                selectedResolution = resolution
                resolutionMenuExpanded = false
                clearProofState()
                operationStatus = OperationStatus(
                    title = "Resolution",
                    success = true,
                    message = "H3 resolution set to $resolution"
                )
            },
            onGenerateProof = {
                val currentLat = latitude
                val currentLon = longitude
                if (currentLat == null || currentLon == null) {
                    val message = "Get GNSS location before generating proof"
                    error = message
                    operationStatus = OperationStatus("Proof", false, message)
                } else {
                    isGenerating = true
                    provingTime = null
                    verifyingTime = null
                    valid = null
                    publicInputs = null
                    signatureResult = null
                    error = null
                    Thread {
                        try {
                            val input = generateLocationCircuitInput(
                                currentLat,
                                currentLon,
                                selectedResolution.toUByte()
                            )
                            val startTime = System.currentTimeMillis()
                            result = generateCircomProof(zkeyPath, input, ProofLib.ARKWORKS)
                            val elapsed = System.currentTimeMillis() - startTime
                            proofGenerationMs = elapsed
                            clientProofTimes = clientProofTimes + elapsed
                            provingTime = "$elapsed ms"
                            publicInputs = formatProofSummary(result)
                            serverResponse = null
                            operationStatus = OperationStatus(
                                "Proof",
                                true,
                                "Proof generated in ${provingTime ?: "-"}"
                            )
                        } catch (e: Exception) {
                            val message = e.message ?: e.toString()
                            error = message
                            operationStatus = OperationStatus("Proof", false, message)
                        } finally {
                            isGenerating = false
                        }
                    }.start()
                }
            },
            onVerifyProof = {
                isVerifying = true
                verifyingTime = null
                error = null
                Thread {
                    try {
                        val startTime = System.currentTimeMillis()
                        val verified = verifyCircomProof(zkeyPath, result, ProofLib.ARKWORKS)
                        verifyingTime = "${System.currentTimeMillis() - startTime} ms"
                        valid = verified.toString()
                        operationStatus = OperationStatus(
                            "Verification",
                            verified,
                            "Valid: $verified, time: ${verifyingTime ?: "-"}"
                        )
                    } catch (e: Exception) {
                        val message = e.message ?: e.toString()
                        error = message
                        operationStatus = OperationStatus("Verification", false, message)
                    } finally {
                        isVerifying = false
                    }
                }.start()
            },
            onSignCommitment = {
                if (authToken == null || keyBindingSummary == null) {
                    val message = "Login and bind key before signing"
                    error = message
                    operationStatus = OperationStatus("Signature", false, message)
                } else {
                    isSigning = true
                    signatureResult = null
                    error = null
                    Thread {
                        try {
                            val commitment = result.inputs.firstOrNull()
                                ?: error("Missing public commitment. Generate proof first.")
                            val serverNonce = requestServerNonce(serverUrl).nonce
                            signatureResult = KeystoreLocationSigner.signCommitment(
                                publicCommitment = commitment,
                                serverNonce = serverNonce
                            )
                            keyRegistration = KeystoreLocationSigner.ensureKey(
                                serverNonce.toByteArray()
                            )
                            operationStatus = OperationStatus(
                                "Signature",
                                true,
                                "Commitment signed with server nonce ${shortValue(serverNonce)}"
                            )
                        } catch (e: Exception) {
                            val message = e.message ?: e.toString()
                            error = message
                            operationStatus = OperationStatus("Signature", false, message)
                        } finally {
                            isSigning = false
                        }
                    }.start()
                }
            },
            onSendProofToServer = {
                if (result.proof.a.x.isEmpty()) {
                    val message = "Generate proof before sending to server"
                    error = message
                    operationStatus = OperationStatus("Server verify", false, message)
                } else if (signatureResult == null) {
                    val message = "Sign commitment before sending to server"
                    error = message
                    operationStatus = OperationStatus("Server verify", false, message)
                } else if (authToken == null || keyBindingSummary == null) {
                    val message = "Login and bind key before sending proof to server"
                    error = message
                    operationStatus = OperationStatus("Server verify", false, message)
                } else {
                    isSendingProof = true
                    serverResponse = null
                    error = null
                    Thread {
                        try {
                            val signature = signatureResult
                                ?: error("Sign commitment before sending to server")
                            val token = authToken
                                ?: error("Login before sending proof to server")
                            val response = postProofToServer(
                                serverUrl = serverUrl,
                                proofResult = result,
                                signatureResult = signature,
                                bearerToken = token,
                                h3Resolution = selectedResolution,
                                provingTimeMs = proofGenerationMs
                            )
                            serverVerifyTimes = serverVerifyTimes + response.elapsedMs
                            serverResponse = response.summary
                            if (response.valid) {
                                signatureResult = null
                            }
                            operationStatus = OperationStatus(
                                title = "Server verify",
                                success = response.valid,
                                message = serverResponse ?: "No response"
                            )
                        } catch (e: Exception) {
                            val message = e.message ?: e.toString()
                            error = message
                            serverResponse = message
                            operationStatus = OperationStatus("Server verify", false, message)
                        } finally {
                            isSendingProof = false
                        }
                    }.start()
                }
            }
        )
    }

    if (isViewSetOpen) {
        ViewSetDialog(
            selectedOutput = selectedOutput,
            authSummary = authSummary,
            keyBindingSummary = keyBindingSummary,
            locationSummary = locationSummary,
            keyRegistration = keyRegistration,
            provingTime = provingTime,
            publicInputs = publicInputs,
            serverResponse = serverResponse,
            reportSummary = reportSummary,
            performanceSummary = performanceSummary,
            verifyingTime = verifyingTime,
            valid = valid,
            signatureResult = signatureResult,
            error = error,
            onDismiss = { isViewSetOpen = false },
            onSelectOutput = { selectedOutput = it }
        )
    }

    selectedOutput?.let { section ->
        OutputSectionDialog(
            section = section,
            authSummary = authSummary,
            keyBindingSummary = keyBindingSummary,
            selectedResolution = selectedResolution,
            locationSummary = locationSummary,
            keyRegistration = keyRegistration,
            provingTime = provingTime,
            publicInputs = publicInputs,
            serverResponse = serverResponse,
            reportSummary = reportSummary,
            performanceSummary = performanceSummary,
            verifyingTime = verifyingTime,
            valid = valid,
            signatureResult = signatureResult,
            error = error,
            onDismiss = { selectedOutput = null }
        )
    }

    operationStatus?.let { status ->
        OperationStatusDialog(
            status = status,
            onDismiss = { operationStatus = null }
        )
    }
}

@Composable
/** 顶部栏，展示当前用户、服务端 host 和全局忙碌状态。 */
private fun AppHeader(
    // username：当前登录用户名。
    username: String,
    // serverUrl：用户输入的服务端 verify URL。
    serverUrl: String,
    // isBusy：是否存在正在执行的异步操作。
    isBusy: Boolean
) {
    Surface(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(8.dp),
        color = MaterialTheme.colorScheme.surface,
        border = BorderStroke(1.dp, MaterialTheme.colorScheme.outline)
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 12.dp, vertical = 10.dp),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = "ZK Location",
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.SemiBold
                )
                Text(
                    text = "$username · ${serverUrl.hostLabel()}",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
            StatusBadge(
                text = if (isBusy) "Working" else "Ready",
                active = !isBusy
            )
        }
    }
}

@Composable
/** Proof pipeline 状态条，按 key -> GNSS -> proof -> sign -> server 展示进度。 */
private fun StatusStrip(
    // hasKey：服务端是否已有本次登录后的 active key。
    hasKey: Boolean,
    // hasLocation：是否已经获取 GNSS 坐标。
    hasLocation: Boolean,
    // hasProof：是否已生成本地 proof。
    hasProof: Boolean,
    // hasSignature：是否已用 Keystore 对 commitment 签名。
    hasSignature: Boolean,
    // serverAccepted：服务端是否返回最终 valid=true。
    serverAccepted: Boolean
) {
    Surface(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(8.dp),
        color = MaterialTheme.colorScheme.surface,
        border = BorderStroke(1.dp, MaterialTheme.colorScheme.outline)
    ) {
        Column(
            modifier = Modifier.padding(10.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            Text(
                text = "Proof pipeline",
                style = MaterialTheme.typography.labelMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(6.dp)
            ) {
                StatusPill("Key", hasKey, Modifier.weight(1f))
                StatusPill("GNSS", hasLocation, Modifier.weight(1f))
                StatusPill("Proof", hasProof, Modifier.weight(1f))
                StatusPill("Sign", hasSignature, Modifier.weight(1f))
                StatusPill("Server", serverAccepted, Modifier.weight(1f))
            }
        }
    }
}

@Composable
/** 单个 pipeline 状态胶囊。 */
private fun StatusPill(
    // label：状态名称，例如 Key/GNSS/Proof。
    label: String,
    // active：该阶段是否已经完成。
    active: Boolean,
    // modifier：外部布局传入的尺寸约束。
    modifier: Modifier = Modifier
) {
    Surface(
        modifier = modifier.heightIn(min = 30.dp),
        shape = RoundedCornerShape(8.dp),
        color = if (active) Color(0xFFE7F6F2) else MaterialTheme.colorScheme.surfaceVariant,
        border = BorderStroke(
            1.dp,
            if (active) Color(0xFF99D6C9) else MaterialTheme.colorScheme.outline
        )
    ) {
        Box(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 4.dp, vertical = 6.dp),
            contentAlignment = Alignment.Center
        ) {
            Text(
                text = label,
                fontSize = 11.sp,
                fontWeight = if (active) FontWeight.SemiBold else FontWeight.Normal,
                color = if (active) Color(0xFF0F766E) else MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
    }
}

@Composable
/** 顶部 Ready/Working 状态标签。 */
private fun StatusBadge(text: String, active: Boolean) {
    Surface(
        shape = RoundedCornerShape(8.dp),
        color = if (active) Color(0xFFE7F6F2) else Color(0xFFFFF4E5),
        border = BorderStroke(1.dp, if (active) Color(0xFF99D6C9) else Color(0xFFF3C98B))
    ) {
        Text(
            text = text,
            modifier = Modifier.padding(horizontal = 10.dp, vertical = 5.dp),
            fontSize = 12.sp,
            fontWeight = FontWeight.SemiBold,
            color = if (active) Color(0xFF0F766E) else Color(0xFF92400E)
        )
    }
}

/** 从完整 URL 中提取 host，失败时回退显示原字符串。 */
private fun String.hostLabel(): String {
    return try {
        URI(trim()).host ?: trim()
    } catch (_: Exception) {
        trim()
    }
}

@Composable
/** 未登录页面，负责账号、密码和服务端地址输入。 */
private fun AuthEntry(
    // serverUrl：服务端 verify URL 输入框值。
    serverUrl: String,
    // username/password：注册或登录使用的账号密码。
    username: String,
    password: String,
    // isBusy：认证请求执行中时禁用输入。
    isBusy: Boolean,
    // authSummary：最近一次注册/登录结果摘要。
    authSummary: String?,
    // on...Change：把输入框变化回写到父组件状态。
    onServerUrlChange: (String) -> Unit,
    onUsernameChange: (String) -> Unit,
    onPasswordChange: (String) -> Unit,
    // onRegister/onLogin：注册和登录按钮回调。
    onRegister: () -> Unit,
    onLogin: () -> Unit,
    // modifier：登录卡片外部布局约束。
    modifier: Modifier = Modifier
) {
    Box(
        modifier = modifier
            .fillMaxWidth(),
        contentAlignment = Alignment.Center
    ) {
        Card(
            modifier = Modifier
                .fillMaxWidth()
                .verticalScroll(rememberScrollState()),
            shape = RoundedCornerShape(8.dp),
            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
            border = BorderStroke(1.dp, MaterialTheme.colorScheme.outline)
        ) {
            Column(
                modifier = Modifier.padding(16.dp),
                verticalArrangement = Arrangement.spacedBy(10.dp),
                horizontalAlignment = Alignment.CenterHorizontally
            ) {
                Text(
                    "ZK Location",
                    style = MaterialTheme.typography.headlineSmall,
                    fontWeight = FontWeight.SemiBold
                )
                Text(
                    "Private location proof client",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                Spacer(modifier = Modifier.height(2.dp))
                OutlinedTextField(
                    value = serverUrl,
                    onValueChange = onServerUrlChange,
                    modifier = Modifier.fillMaxWidth(),
                    enabled = !isBusy,
                    singleLine = true,
                    shape = RoundedCornerShape(8.dp),
                    label = { Text("Server URL", fontSize = 12.sp) },
                    textStyle = MaterialTheme.typography.bodySmall
                )
                OutlinedTextField(
                    value = username,
                    onValueChange = onUsernameChange,
                    modifier = Modifier.fillMaxWidth(),
                    enabled = !isBusy,
                    singleLine = true,
                    shape = RoundedCornerShape(8.dp),
                    label = { Text("Username", fontSize = 12.sp) },
                    textStyle = MaterialTheme.typography.bodySmall
                )
                OutlinedTextField(
                    value = password,
                    onValueChange = onPasswordChange,
                    modifier = Modifier.fillMaxWidth(),
                    enabled = !isBusy,
                    singleLine = true,
                    shape = RoundedCornerShape(8.dp),
                    visualTransformation = PasswordVisualTransformation(),
                    label = { Text("Password", fontSize = 12.sp) },
                    textStyle = MaterialTheme.typography.bodySmall
                )
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    CompactActionButton(
                        "Register",
                        enabled = !isBusy,
                        modifier = Modifier.weight(1f),
                        onClick = onRegister
                    )
                    CompactActionButton(
                        "Login",
                        enabled = !isBusy,
                        modifier = Modifier.weight(1f),
                        onClick = onLogin
                    )
                }
                if (isBusy) {
                    CircularProgressIndicator(modifier = Modifier.padding(top = 4.dp))
                }
                if (authSummary != null) {
                    Surface(
                        modifier = Modifier.fillMaxWidth(),
                        shape = RoundedCornerShape(8.dp),
                        color = MaterialTheme.colorScheme.surfaceVariant
                    ) {
                        Text(
                            authSummary,
                            modifier = Modifier.padding(10.dp),
                            style = MaterialTheme.typography.bodySmall
                        )
                    }
                }
            }
        }
    }
}

@Composable
/** Actions 弹窗，集中放置账号、key、GNSS、proof、签名和实验导出操作。 */
private fun ActionSetDialog(
    // serverUrl：当前服务端地址。
    serverUrl: String,
    // selectedResolution：当前 H3 resolution。
    selectedResolution: Int,
    // resolutionMenuExpanded：resolution 下拉菜单是否展开。
    resolutionMenuExpanded: Boolean,
    // isBusy：是否禁用所有动作按钮。
    isBusy: Boolean,
    // hasLocation/hasProof/hasCommitment/isLoggedIn：按钮启用条件。
    hasLocation: Boolean,
    hasProof: Boolean,
    hasCommitment: Boolean,
    isLoggedIn: Boolean,
    // onDismiss：关闭弹窗。
    onDismiss: () -> Unit,
    // onServerUrlChange：更新服务端地址。
    onServerUrlChange: (String) -> Unit,
    // onLogout...onSendProofToServer：各业务动作回调，由父组件持有真实状态。
    onLogout: () -> Unit,
    onVerifyKey: () -> Unit,
    onFetchStats: () -> Unit,
    onExportReport: () -> Unit,
    onBindKey: () -> Unit,
    onGetGnss: () -> Unit,
    onResolutionMenuChange: (Boolean) -> Unit,
    onSelectResolution: (Int) -> Unit,
    onGenerateProof: () -> Unit,
    onVerifyProof: () -> Unit,
    onSignCommitment: () -> Unit,
    onSendProofToServer: () -> Unit
) {
    AlertDialog(
        onDismissRequest = onDismiss,
        shape = RoundedCornerShape(8.dp),
        title = {
            Text(
                "Actions",
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.SemiBold
            )
        },
        text = {
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .verticalScroll(rememberScrollState()),
                verticalArrangement = Arrangement.spacedBy(8.dp),
                horizontalAlignment = Alignment.CenterHorizontally
            ) {
                if (isBusy) {
                    CircularProgressIndicator(modifier = Modifier.padding(4.dp))
                }
                OutlinedTextField(
                    value = serverUrl,
                    onValueChange = onServerUrlChange,
                    modifier = Modifier.fillMaxWidth(),
                    enabled = !isBusy,
                    singleLine = true,
                    shape = RoundedCornerShape(8.dp),
                    label = { Text("Server URL", fontSize = 12.sp) },
                    textStyle = MaterialTheme.typography.bodySmall
                )
                Text(
                    "Account",
                    modifier = Modifier.fillMaxWidth(),
                    style = MaterialTheme.typography.labelMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                CompactActionButton("Logout", enabled = !isBusy && isLoggedIn, outlined = true, onClick = onLogout)
                CompactActionButton("Verify key", enabled = !isBusy && isLoggedIn, outlined = true, onClick = onVerifyKey)
                CompactActionButton("Generate new key and bind", enabled = !isBusy && isLoggedIn, onClick = onBindKey)
                Text(
                    "Proof workflow",
                    modifier = Modifier.fillMaxWidth(),
                    style = MaterialTheme.typography.labelMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                CompactActionButton("GNSS", enabled = !isBusy, onClick = onGetGnss)
                Column {
                    CompactActionButton(
                        label = "Resolution: $selectedResolution",
                        enabled = !isBusy,
                        outlined = true,
                        onClick = { onResolutionMenuChange(true) }
                    )
                    DropdownMenu(
                        expanded = resolutionMenuExpanded,
                        onDismissRequest = { onResolutionMenuChange(false) }
                    ) {
                        (6..15).forEach { resolution ->
                            DropdownMenuItem(
                                text = { Text(resolution.toString(), fontSize = 12.sp) },
                                onClick = { onSelectResolution(resolution) }
                            )
                        }
                    }
                }
                CompactActionButton("Generate proof", enabled = !isBusy && hasLocation, onClick = onGenerateProof)
                CompactActionButton("Verify proof", enabled = !isBusy && hasProof, onClick = onVerifyProof)
                CompactActionButton("Sign commitment", enabled = !isBusy && hasCommitment && isLoggedIn, onClick = onSignCommitment)
                CompactActionButton("Send proof to server", enabled = !isBusy && hasProof, onClick = onSendProofToServer)
                Text(
                    "Experiment",
                    modifier = Modifier.fillMaxWidth(),
                    style = MaterialTheme.typography.labelMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                CompactActionButton("Server stats", enabled = !isBusy, outlined = true, onClick = onFetchStats)
                CompactActionButton("Export report", enabled = !isBusy, outlined = true, onClick = onExportReport)
            }
        },
        confirmButton = {
            CompactActionButton("Close", enabled = !isBusy, outlined = true, onClick = onDismiss)
        }
    )
}

@Composable
/** Results 弹窗，显示可查看的结果分类。 */
private fun ViewSetDialog(
    // selectedOutput：当前打开的结果分类。
    selectedOutput: OutputSection?,
    // authSummary/keyBindingSummary/locationSummary：账号、key、GNSS 状态文本。
    authSummary: String?,
    keyBindingSummary: String?,
    locationSummary: String?,
    // keyRegistration/signatureResult：本地 Keystore 生成和签名结果。
    keyRegistration: LocationKeyRegistration?,
    provingTime: String?,
    publicInputs: String?,
    serverResponse: String?,
    reportSummary: String?,
    performanceSummary: String?,
    verifyingTime: String?,
    valid: String?,
    signatureResult: LocationCommitmentSignature?,
    error: String?,
    // onDismiss/onSelectOutput：关闭结果页或选择结果分类。
    onDismiss: () -> Unit,
    onSelectOutput: (OutputSection) -> Unit
) {
    AlertDialog(
        onDismissRequest = onDismiss,
        shape = RoundedCornerShape(8.dp),
        title = {
            Text(
                "Results",
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.SemiBold
            )
        },
        text = {
            Column(
                modifier = Modifier.fillMaxWidth(),
                verticalArrangement = Arrangement.spacedBy(6.dp)
            ) {
                OutputSectionButton(
                    label = "Auth",
                    enabled = authSummary != null || keyBindingSummary != null,
                    selected = selectedOutput == OutputSection.AUTH,
                    onClick = { onSelectOutput(OutputSection.AUTH) }
                )
                OutputSectionButton(
                    label = "GNSS",
                    enabled = locationSummary != null,
                    selected = selectedOutput == OutputSection.GNSS,
                    onClick = { onSelectOutput(OutputSection.GNSS) }
                )
                OutputSectionButton(
                    label = "Keystore",
                    enabled = keyRegistration != null,
                    selected = selectedOutput == OutputSection.KEYSTORE,
                    onClick = { onSelectOutput(OutputSection.KEYSTORE) }
                )
                OutputSectionButton(
                    label = "Proof",
                    enabled = provingTime != null || publicInputs != null,
                    selected = selectedOutput == OutputSection.PROOF,
                    onClick = { onSelectOutput(OutputSection.PROOF) }
                )
                OutputSectionButton(
                    label = "Server",
                    enabled = serverResponse != null,
                    selected = selectedOutput == OutputSection.SERVER,
                    onClick = { onSelectOutput(OutputSection.SERVER) }
                )
                OutputSectionButton(
                    label = "Stats",
                    enabled = performanceSummary != null,
                    selected = selectedOutput == OutputSection.PERFORMANCE,
                    onClick = { onSelectOutput(OutputSection.PERFORMANCE) }
                )
                OutputSectionButton(
                    label = "Report",
                    enabled = reportSummary != null,
                    selected = selectedOutput == OutputSection.REPORT,
                    onClick = { onSelectOutput(OutputSection.REPORT) }
                )
                OutputSectionButton(
                    label = "Verification",
                    enabled = verifyingTime != null || valid != null,
                    selected = selectedOutput == OutputSection.VERIFICATION,
                    onClick = { onSelectOutput(OutputSection.VERIFICATION) }
                )
                OutputSectionButton(
                    label = "Signature",
                    enabled = signatureResult != null,
                    selected = selectedOutput == OutputSection.SIGNATURE,
                    onClick = { onSelectOutput(OutputSection.SIGNATURE) }
                )
                OutputSectionButton(
                    label = "Error",
                    enabled = error != null,
                    selected = selectedOutput == OutputSection.ERROR,
                    onClick = { onSelectOutput(OutputSection.ERROR) }
                )
            }
        },
        confirmButton = {
            CompactActionButton("Close", outlined = true, onClick = onDismiss)
        }
    )
}

@Composable
/** 单次操作完成后的状态弹窗。 */
private fun OperationStatusDialog(
    // status：操作标题、成功状态和具体消息。
    status: OperationStatus,
    // onDismiss：关闭状态弹窗。
    onDismiss: () -> Unit
) {
    AlertDialog(
        onDismissRequest = onDismiss,
        shape = RoundedCornerShape(8.dp),
        title = {
            Text(
                text = if (status.success) "${status.title} succeeded" else "${status.title} failed",
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.SemiBold
            )
        },
        text = {
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .heightIn(max = 420.dp)
                    .verticalScroll(rememberScrollState())
            ) {
                Text(
                    text = status.message,
                    style = MaterialTheme.typography.bodySmall
                )
            }
        },
        confirmButton = {
            CompactActionButton("OK", onClick = onDismiss)
        }
    )
}

@Composable
/** 统一样式的小尺寸按钮，支持实心和描边两种模式。 */
private fun CompactActionButton(
    // label：按钮文字。
    label: String,
    // enabled：按钮是否可点击。
    enabled: Boolean = true,
    // outlined：true 使用 OutlinedButton，false 使用 Button。
    outlined: Boolean = false,
    // modifier：外部传入布局约束。
    modifier: Modifier = Modifier.fillMaxWidth(),
    // onClick：点击回调。
    onClick: () -> Unit
) {
    // buttonModifier/contentPadding/shape：统一按钮尺寸、内边距和 8dp 圆角。
    val buttonModifier = modifier
        .heightIn(min = 38.dp)
    val contentPadding = PaddingValues(horizontal = 12.dp, vertical = 7.dp)
    val shape = RoundedCornerShape(8.dp)

    if (outlined) {
        OutlinedButton(
            onClick = onClick,
            modifier = buttonModifier,
            enabled = enabled,
            shape = shape,
            contentPadding = contentPadding,
            border = BorderStroke(1.dp, MaterialTheme.colorScheme.outline)
        ) {
            Text(label, fontSize = 12.sp, fontWeight = FontWeight.Medium)
        }
    } else {
        Button(
            onClick = onClick,
            modifier = buttonModifier,
            enabled = enabled,
            shape = shape,
            colors = ButtonDefaults.buttonColors(
                containerColor = MaterialTheme.colorScheme.primary,
                contentColor = MaterialTheme.colorScheme.onPrimary
            ),
            contentPadding = contentPadding
        ) {
            Text(label, fontSize = 12.sp, fontWeight = FontWeight.SemiBold)
        }
    }
}

@Composable
/** 具体结果内容弹窗，根据 OutputSection 显示对应业务摘要。 */
private fun OutputSectionDialog(
    // section：当前展示的结果类型。
    section: OutputSection,
    // 下面这些参数都是父组件已生成的业务结果，只读展示，不在此处修改。
    authSummary: String?,
    keyBindingSummary: String?,
    selectedResolution: Int,
    locationSummary: String?,
    keyRegistration: LocationKeyRegistration?,
    provingTime: String?,
    publicInputs: String?,
    serverResponse: String?,
    reportSummary: String?,
    performanceSummary: String?,
    verifyingTime: String?,
    valid: String?,
    signatureResult: LocationCommitmentSignature?,
    error: String?,
    onDismiss: () -> Unit
) {
    AlertDialog(
        onDismissRequest = onDismiss,
        shape = RoundedCornerShape(8.dp),
        title = {
            Text(
                section.title,
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.SemiBold
            )
        },
        text = {
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .verticalScroll(rememberScrollState()),
                verticalArrangement = Arrangement.spacedBy(6.dp)
            ) {
                when (section) {
                    OutputSection.AUTH -> {
                        Text(authSummary ?: "No auth output", style = MaterialTheme.typography.bodyMedium)
                        Text(keyBindingSummary ?: "No key binding output", style = MaterialTheme.typography.bodyMedium)
                    }

                    OutputSection.GNSS -> {
                        Text(locationSummary ?: "No GNSS output", style = MaterialTheme.typography.bodyMedium)
                        Text("H3 resolution: $selectedResolution", style = MaterialTheme.typography.bodyMedium)
                    }

                    OutputSection.KEYSTORE -> {
                        val key = keyRegistration
                        if (key == null) {
                            Text("No Keystore output", style = MaterialTheme.typography.bodyMedium)
                        } else {
                            Text(explainedValue("Hardware backed", key.hardwareBacked.toString(), "true 表示私钥由可信硬件保护，普通应用无法导出"), style = MaterialTheme.typography.bodyMedium)
                            Text(explainedValue("Attested", key.generationMode.contains("attested").toString(), "true 表示这把 key 带 Key Attestation 证明材料"), style = MaterialTheme.typography.bodyMedium)
                        }
                    }

                    OutputSection.PROOF -> {
                        Text("Proving: ${provingTime ?: "-"}", style = MaterialTheme.typography.bodyMedium)
                        Text(publicInputs ?: "No proof summary", style = MaterialTheme.typography.bodyMedium)
                    }

                    OutputSection.SERVER -> {
                        Text(serverResponse ?: "No server response", style = MaterialTheme.typography.bodyMedium)
                    }

                    OutputSection.PERFORMANCE -> {
                        Text(performanceSummary ?: "No performance stats", style = MaterialTheme.typography.bodyMedium)
                    }

                    OutputSection.REPORT -> {
                        Text(reportSummary ?: "No experiment report", style = MaterialTheme.typography.bodyMedium)
                    }

                    OutputSection.VERIFICATION -> {
                        Text("Verifying: ${verifyingTime ?: "-"}", style = MaterialTheme.typography.bodyMedium)
                        Text("Valid: ${valid ?: "-"}", style = MaterialTheme.typography.bodyMedium)
                    }

                    OutputSection.SIGNATURE -> {
                        val signature = signatureResult
                        if (signature == null) {
                            Text("No signature output", style = MaterialTheme.typography.bodyMedium)
                        } else {
                            Text(explainedValue("Signed", "true", "已使用 Android Keystore 私钥签名当前 commitment 和 nonce"), style = MaterialTheme.typography.bodyMedium)
                            Text(explainedValue("Commitment", shortValue(payloadField(signature.payload, "public_commitment")), "TEE payload 中绑定的公开承诺"), style = MaterialTheme.typography.bodyMedium)
                            Text(explainedValue("Nonce", shortValue(payloadField(signature.payload, "server_nonce")), "服务端下发的一次性防重放随机数"), style = MaterialTheme.typography.bodyMedium)
                            Text(explainedValue("Local signature check", signature.verifiedLocally.toString(), "客户端本地用公钥自检签名是否正确"), style = MaterialTheme.typography.bodyMedium)
                        }
                    }

                    OutputSection.ERROR -> {
                        Text(error ?: "No error", color = MaterialTheme.colorScheme.error)
                    }
                }
            }
        },
        confirmButton = {
            CompactActionButton("Close", outlined = true, onClick = onDismiss)
        }
    )
}

@Composable
/** Results 弹窗中的单个分类按钮。 */
private fun OutputSectionButton(
    // label：分类名称。
    label: String,
    // enabled：该分类是否有内容可看。
    enabled: Boolean,
    // selected：该分类是否已经被选中。
    selected: Boolean,
    // onClick：选择该分类。
    onClick: () -> Unit
) {
    CompactActionButton(
        label = label,
        enabled = enabled,
        outlined = !selected,
        onClick = onClick
    )
}

/** 缩短长字符串，只保留前后片段，避免 UI 被 proof/signature 挤爆。 */
private fun shortValue(value: String): String {
    return if (value.length <= 48) value else "${value.take(24)}...${value.takeLast(16)}"
}

/** 统一输出格式：字段名、字段值和中文解释。 */
private fun explainedValue(label: String, value: String, meaning: String): String {
    // renderedValue：空字符串统一显示为 "-"。
    val renderedValue = value.ifBlank { "-" }
    return "$label: $renderedValue（$meaning）"
}

/** 将 Circom proof 公开输入转换为 UI 摘要。 */
private fun formatProofSummary(proofResult: CircomProofResult): String {
    return listOf(
        explainedValue("Public commitment", shortValue(proofResult.inputs.firstOrNull().orEmpty()), "ZK proof 绑定的公开承诺"),
        explainedValue("Public inputs", proofResult.inputs.size.toString(), "提交给服务端验证的公开输入数量")
    ).joinToString("\n")
}

/** 从规范化 Keystore payload 中提取指定字段。 */
private fun payloadField(payload: String, key: String): String {
    return payload
        .lineSequence()
        .mapNotNull { line ->
            val separator = line.indexOf("=")
            if (separator <= 0) null else line.take(separator) to line.drop(separator + 1)
        }
        .firstOrNull { it.first == key }
        ?.second
        .orEmpty()
}

/** Results 中可查看的输出分类。 */
private enum class OutputSection(val title: String) {
    AUTH("Auth"),
    GNSS("GNSS"),
    KEYSTORE("Keystore"),
    PROOF("Proof"),
    SERVER("Server"),
    PERFORMANCE("Stats"),
    REPORT("Report"),
    VERIFICATION("Verification"),
    SIGNATURE("Signature"),
    ERROR("Error")
}

/** 单次操作状态，用于 OperationStatusDialog。 */
private data class OperationStatus(
    // title：操作名称。
    val title: String,
    // success：操作是否成功。
    val success: Boolean,
    // message：详细展示文本。
    val message: String
)

/** 服务端 /verify-proof 响应摘要。 */
private data class ServerProofResponse(
    // statusCode：HTTP 状态码。
    val statusCode: Int,
    // body：原始响应 body。
    val body: String,
    // valid：客户端解析出的最终验证结果。
    val valid: Boolean,
    // summary：面向 UI 的中文解释。
    val summary: String,
    // elapsedMs：客户端观察到的请求响应耗时。
    val elapsedMs: Long
)

/** 注册/登录响应摘要。 */
private data class ServerAuthResponse(
    // token：服务端 bearer session token。
    val token: String,
    // summary：面向 UI 的登录结果说明。
    val summary: String
)

/** 服务端 nonce 响应摘要。 */
private data class ServerNonceResponse(
    // nonce：一次性随机数，用于 key registration challenge 或签名防重放。
    val nonce: String,
    // expiresAt：服务端 nonce 过期时间戳。
    val expiresAt: Long,
    // expiresInMs：服务端返回的剩余有效时间。
    val expiresInMs: Long
)

private fun formatCoordinate(value: Double): String {
    return "%.7f".format(value)
}

private fun postAuth(
    serverUrl: String,
    path: String,
    username: String,
    password: String
): ServerAuthResponse {
    // response：/auth/register 或 /auth/login 的 HTTP JSON 响应。
    val response = postJson(
        url = endpointUrlFor(serverUrl, path),
        body = JSONObject()
            .put("username", username)
            .put("password", password)
    )
    // json：解析后的认证响应对象。
    val json = JSONObject(response.body)
    // token：服务端 session token，后续接口放入 Authorization header。
    val token = json.optString("token")
    if (token.isBlank()) {
        error("Auth response missing token: ${response.body}")
    }

    // user/normalizedUsername：服务端返回的用户对象和展示用用户名。
    val user = json.optJSONObject("user")
    val normalizedUsername = user?.optString("username").orEmpty()
    return ServerAuthResponse(
        token = token,
        summary = listOf(
            explainedValue("User", normalizedUsername, "当前登录用户"),
            explainedValue("Login", "true", "服务端已返回 session token，客户端后续会自动携带")
        ).joinToString("\n")
    )
}

private fun requestKeyRegistrationNonce(serverUrl: String, token: String): ServerNonceResponse {
    // response：服务端为本次 key attestation challenge 下发的 nonce。
    val response = postJson(
        url = endpointUrlFor(serverUrl, "/keys/register-nonce"),
        body = JSONObject(),
        bearerToken = token
    )
    return parseNonceResponse(response.body)
}

private fun generateNewKeyAndBind(
    serverUrl: String,
    token: String
): Pair<LocationKeyRegistration, String> {
    // nonce：服务端生成的 key registration challenge。
    val nonce = requestKeyRegistrationNonce(serverUrl, token).nonce
    // registration：Android Keystore 新生成 key 后导出的公钥和 attestation 证书链。
    val registration = KeystoreLocationSigner.createOrReplaceKey(
        nonce.toByteArray(Charsets.UTF_8)
    )
    // summary：服务端验证 attestation 并绑定 active key 后返回的摘要。
    val summary = postKeyRegistration(serverUrl, token, nonce, registration)
    return registration to listOf(
        explainedValue("New key generated", "true", "已重新生成 Android Keystore key，并通过服务端 attestation 验证后绑定到当前用户"),
        summary
    ).joinToString("\n")
}

private fun postKeyRegistration(
    serverUrl: String,
    token: String,
    nonce: String,
    registration: LocationKeyRegistration
): String {
    // response：/keys/register 响应，包含服务端验证后的 key/attestation 摘要。
    val response = postJson(
        url = endpointUrlFor(serverUrl, "/keys/register"),
        body = JSONObject()
            .put("nonce", nonce)
            .put("publicKey", registration.publicKeyBase64)
            .put("certificateChain", JSONArray(registration.certificateChainBase64)),
        bearerToken = token
    )
    // json/key：解析服务端返回的 active key 对象。
    val json = JSONObject(response.body)
    val key = json.optJSONObject("key")
    return formatKeySummary(key)
}

private fun formatKeySummary(key: JSONObject?): String {
    // attestation：服务端验证 Android Key Attestation 后返回的可信性摘要。
    val attestation = key?.optJSONObject("attestation")
    // authorization：attestation 授权列表摘要，包含 purpose/digest/curve 等字段。
    val authorization = attestation?.optJSONObject("authorization")
    return listOf(
        explainedValue("Key bound", (key != null).toString(), "当前用户是否已有服务端绑定的 active key"),
        explainedValue("KeyMint security", attestation?.optString("keyMintSecurityLevel").orEmpty(), "生成并保护签名私钥的安全级别"),
        explainedValue("Root trusted", (attestation?.optBoolean("rootTrusted", false) ?: false).toString(), "证书链根证书是否在服务端 trust store 中"),
        explainedValue("Purpose SIGN", (attestation?.optBoolean("purposeSign", false) ?: authorization?.optBoolean("purposeSign", false) ?: false).toString(), "attestation 授权列表是否允许该 key 用于签名"),
        explainedValue("Digest SHA-256", (attestation?.optBoolean("digestSha256", false) ?: authorization?.optBoolean("digestSha256", false) ?: false).toString(), "attestation 授权列表是否允许 SHA-256 摘要"),
        explainedValue("Curve P-256", (attestation?.optBoolean("ecCurveP256", false) ?: authorization?.optBoolean("ecCurveP256", false) ?: false).toString(), "attestation 授权列表是否声明 P-256 曲线"),
        explainedValue("Verified boot", attestation?.optString("verifiedBootState", authorization?.optString("verifiedBootState").orEmpty()).orEmpty(), "设备支持时显示 verified boot 状态")
    ).joinToString("\n")
}

private fun requestServerNonce(serverUrl: String): ServerNonceResponse {
    // response：服务端签名防重放 nonce。
    val response = getJson(endpointUrlFor(serverUrl, "/nonce"))
    return parseNonceResponse(response.body)
}

private fun postLogout(serverUrl: String, token: String): String {
    // response：服务端撤销当前 session 的结果。
    val response = postJson(
        url = endpointUrlFor(serverUrl, "/auth/logout"),
        body = JSONObject(),
        bearerToken = token
    )
    // json：解析后的 logout 结果。
    val json = JSONObject(response.body)
    return explainedValue("Logout", json.optBoolean("revoked", false).toString(), "服务端是否已撤销当前 session token")
}

private fun fetchActiveKeySummary(serverUrl: String, token: String): String {
    // response：查询当前用户本次登录后的 active key。
    val response = getJson(endpointUrlFor(serverUrl, "/keys/active"), token)
    // json/key：active key 为空表示还没有重新 Generate new key and bind。
    val json = JSONObject(response.body)
    val key = json.optJSONObject("key")
    return if (key == null) {
        "Key generated: false（当前用户还未生成并绑定 key）"
    } else {
        formatKeySummary(key)
    }
}

/** 获取服务端性能统计 JSON。 */
private fun fetchServerStats(serverUrl: String): JSONObject {
    return JSONObject(getJson(endpointUrlFor(serverUrl, "/stats/performance")).body)
}

/** 获取服务端最新实验报告，并压缩为 UI 摘要。 */
private fun fetchExperimentReport(serverUrl: String): String {
    // json：服务端实验报告 JSON。
    val json = JSONObject(getJson(endpointUrlFor(serverUrl, "/reports/latest")).body)
    // stats/latestKey/latestProof：报告中的统计摘要和最近关键事件。
    val stats = json.optJSONObject("stats")
    val latestKey = json.optJSONObject("latestKeyRegister")
    val latestProof = json.optJSONObject("latestProofVerify")
    return listOf(
        explainedValue("Generated at", json.optString("generatedAt"), "服务端生成报告的时间"),
        explainedValue("Entries", json.optInt("sourceEntryCount", 0).toString(), "参与统计的交互日志条数"),
        explainedValue("Proof verify count", stats?.optJSONObject("counts")?.optInt("proofVerify", 0).toString(), "服务端 proof verify 记录数量"),
        explainedValue("Valid proof verifies", stats?.optInt("validProofVerifyCount", 0).toString(), "服务端最终 valid=true 的次数"),
        explainedValue("Signature valid count", stats?.optInt("signatureValidCount", 0).toString(), "服务端验签成功次数"),
        explainedValue("Nonce consumed count", stats?.optInt("nonceConsumedCount", 0).toString(), "服务端 nonce 成功消费次数"),
        explainedValue("Latest key", latestKey?.optString("publicKeyFingerprint", "-").orEmpty(), "最近一次绑定 key 的公钥指纹"),
        explainedValue("Latest proof valid", latestProof?.optBoolean("valid", false).toString(), "最近一次 proof 提交的最终结果"),
        explainedValue("Latest verify ms", latestProof?.optLong("durationMs", 0L).toString(), "最近一次服务端 verify 耗时")
    ).joinToString("\n")
}

/** 合并客户端本地耗时和服务端日志耗时，生成性能摘要。 */
private fun buildPerformanceSummary(
    clientProofTimes: List<Long>,
    serverVerifyTimes: List<Long>,
    serverStats: JSONObject
): String {
    // serverProofStats/serverKeyStats：服务端日志聚合出来的 proof/key register 耗时统计。
    val serverProofStats = serverStats.optJSONObject("proofVerifyDurationMs")
    val serverKeyStats = serverStats.optJSONObject("keyRegisterDurationMs")
    return listOf(
        explainedValue("Client proof samples", clientProofTimes.size.toString(), "本次 App 会话内 proof 生成样本数"),
        explainedValue("Client proof time", summarizeLongs(clientProofTimes), "本次 App 会话内 proof 生成耗时统计"),
        explainedValue("Client send/verify samples", serverVerifyTimes.size.toString(), "本次 App 会话内发送 proof 并接收响应样本数"),
        explainedValue("Client send/verify time", summarizeLongs(serverVerifyTimes), "客户端观察到的网络往返和服务端处理总耗时"),
        explainedValue("Server proof verify", formatJsonStats(serverProofStats), "服务端日志中的 proof verify 耗时统计"),
        explainedValue("Server key register", formatJsonStats(serverKeyStats), "服务端日志中的 key register 耗时统计"),
        explainedValue("Server valid proofs", serverStats.optInt("validProofVerifyCount", 0).toString(), "服务端最终 valid=true 的 proof verify 次数"),
        explainedValue("Server signatures", serverStats.optInt("signatureValidCount", 0).toString(), "服务端 ECDSA 验签成功次数"),
        explainedValue("Server nonces", serverStats.optInt("nonceConsumedCount", 0).toString(), "服务端 nonce 成功消费次数")
    ).joinToString("\n")
}

/** 对 Long 毫秒样本做 count/avg/min/max 摘要。 */
private fun summarizeLongs(values: List<Long>): String {
    if (values.isEmpty()) return "n/a"
    // min/max/avg：本地采样的最小、最大、平均耗时。
    val min = values.minOrNull() ?: 0L
    val max = values.maxOrNull() ?: 0L
    val avg = values.average()
    return "count=${values.size}, avg=${"%.2f".format(avg)} ms, min=$min ms, max=$max ms"
}

/** 格式化服务端返回的统计对象。 */
private fun formatJsonStats(stats: JSONObject?): String {
    if (stats == null || stats.optInt("count", 0) == 0) return "n/a"
    return "count=${stats.optInt("count")}, avg=${stats.optDouble("avg")} ms, min=${stats.optLong("min")} ms, max=${stats.optLong("max")} ms"
}

/** 发送 GET JSON 请求。 */
private fun getJson(url: URL, bearerToken: String? = null): HttpJsonResponse {
    // connection：GET 请求连接，按需加入 bearer token。
    val connection = (url.openConnection() as HttpURLConnection).apply {
        requestMethod = "GET"
        connectTimeout = 10_000
        readTimeout = 10_000
        setRequestProperty("Accept", "application/json")
        if (bearerToken != null) {
            setRequestProperty("Authorization", "Bearer $bearerToken")
        }
    }

    return try {
        readHttpJson(connection)
    } finally {
        connection.disconnect()
    }
}

/** 发送 POST JSON 请求。 */
private fun postJson(
    url: URL,
    body: JSONObject,
    bearerToken: String? = null
): HttpJsonResponse {
    // connection：POST 请求连接，统一发送 JSON body。
    val connection = (url.openConnection() as HttpURLConnection).apply {
        requestMethod = "POST"
        connectTimeout = 10_000
        readTimeout = 20_000
        doOutput = true
        setRequestProperty("Content-Type", "application/json; charset=utf-8")
        setRequestProperty("Accept", "application/json")
        if (bearerToken != null) {
            setRequestProperty("Authorization", "Bearer $bearerToken")
        }
    }

    return try {
        connection.outputStream.use { output ->
            output.write(body.toString().toByteArray(Charsets.UTF_8))
        }
        readHttpJson(connection)
    } finally {
        connection.disconnect()
    }
}

/** 简化 HTTP JSON 响应结构。 */
private data class HttpJsonResponse(
    // statusCode：HTTP 状态码。
    val statusCode: Int,
    // body：响应体文本。
    val body: String
)

/** 读取 HttpURLConnection 的 JSON 响应，非 2xx 直接抛出包含 body 的错误。 */
private fun readHttpJson(connection: HttpURLConnection): HttpJsonResponse {
    // statusCode：服务端 HTTP 响应码。
    val statusCode = connection.responseCode
    // stream：成功读 inputStream，失败优先读 errorStream。
    val stream = if (statusCode in 200..299) {
        connection.inputStream
    } else {
        connection.errorStream ?: connection.inputStream
    }
    // body：完整响应文本。
    val body = stream.bufferedReader().use { it.readText() }
    if (statusCode !in 200..299) {
        error("HTTP $statusCode\n$body")
    }
    return HttpJsonResponse(statusCode = statusCode, body = body)
}

/** 解析服务端 nonce JSON，并确保 nonce 字段存在。 */
private fun parseNonceResponse(body: String): ServerNonceResponse {
    // json：nonce 响应对象。
    val json = JSONObject(body)
    // nonce：服务端下发的一次性字符串。
    val nonce = json.optString("nonce")
    if (nonce.isBlank()) {
        error("Nonce response missing nonce: $body")
    }
    return ServerNonceResponse(
        nonce = nonce,
        expiresAt = json.optLong("expiresAt", 0L),
        expiresInMs = json.optLong("expiresInMs", 0L)
    )
}

/** 从用户输入的 verify URL 推导同 host 下的服务端接口 URL。 */
private fun endpointUrlFor(serverUrl: String, path: String): URL {
    // uri：解析后的服务端 URL。
    val uri = URI(serverUrl.trim())
    if (uri.scheme.isNullOrBlank() || uri.host.isNullOrBlank()) {
        error("Invalid server URL: $serverUrl")
    }

    return URI(
        uri.scheme,
        uri.userInfo,
        uri.host,
        uri.port,
        path,
        null,
        null
    ).toURL()
}

private fun postProofToServer(
    serverUrl: String,
    proofResult: CircomProofResult,
    signatureResult: LocationCommitmentSignature?,
    bearerToken: String,
    h3Resolution: Int,
    provingTimeMs: Long?
): ServerProofResponse {
    // payload：最终提交给 /verify-proof 的 JSON 字符串。
    val payload = proofResultToServerPayload(proofResult, signatureResult, h3Resolution, provingTimeMs)
    // connection：verify-proof POST 请求连接。
    val connection = (URL(serverUrl).openConnection() as HttpURLConnection).apply {
        requestMethod = "POST"
        connectTimeout = 10_000
        readTimeout = 20_000
        doOutput = true
        setRequestProperty("Content-Type", "application/json; charset=utf-8")
        setRequestProperty("Accept", "application/json")
        setRequestProperty("Prefer", "return=minimal")
        setRequestProperty("Authorization", "Bearer $bearerToken")
    }

    return try {
        connection.outputStream.use { output ->
            output.write(payload.toByteArray(Charsets.UTF_8))
        }

        // startTime：从服务端开始处理响应前记录时间，用于客户端观察耗时。
        val startTime = System.currentTimeMillis()
        // statusCode：verify-proof HTTP 状态码。
        val statusCode = connection.responseCode
        // stream：成功和失败分别读取对应响应流。
        val stream = if (statusCode in 200..299) {
            connection.inputStream
        } else {
            connection.errorStream ?: connection.inputStream
        }
        // body：服务端 verify 响应文本。
        val body = stream.bufferedReader().use { it.readText() }
        // valid：尽量解析服务端 valid 字段，解析失败按 false。
        val valid = try {
            JSONObject(body).optBoolean("valid", false)
        } catch (_: Exception) {
            false
        }

        ServerProofResponse(
            statusCode = statusCode,
            body = body,
            valid = statusCode in 200..299 && valid,
            summary = formatServerProofResponse(statusCode, body),
            elapsedMs = System.currentTimeMillis() - startTime
        )
    } finally {
        connection.disconnect()
    }
}

/** 将服务端 verify 响应格式化为中文解释文本。 */
private fun formatServerProofResponse(statusCode: Int, body: String): String {
    return try {
        // json：服务端返回的验证结果 JSON。
        val json = JSONObject(body)
        if (statusCode !in 200..299) {
            return "HTTP $statusCode（HTTP 状态码，非 2xx 表示请求失败）\n" +
                explainedValue("Error", json.optString("error", body), "服务端返回的失败原因")
        }

        // lines：逐行积累 UI 展示文本。
        val lines = mutableListOf<String>()
        // signature/nonce：兼容完整响应中嵌套的 signature 和 nonce 对象。
        val signature = json.optJSONObject("signature")
        val nonce = json.optJSONObject("nonce")
        // signatureValid/commitmentBound/nonceConsumed：兼容精简响应和完整响应两种字段形态。
        val signatureValid = if (json.has("signatureValid")) {
            json.optBoolean("signatureValid", false)
        } else {
            signature?.optBoolean("signatureValid", false) ?: false
        }
        val commitmentBound = if (json.has("commitmentBound")) {
            json.optBoolean("commitmentBound", false)
        } else {
            signature?.optBoolean("commitmentBound", false) ?: false
        }
        val nonceConsumed = if (json.has("nonceConsumed")) {
            json.optBoolean("nonceConsumed", false)
        } else {
            nonce?.optBoolean("consumed", false) ?: false
        }
        lines += "HTTP $statusCode（HTTP 状态码，200 表示服务端已处理请求）"
        lines += explainedValue("Valid", json.optBoolean("valid", false).toString(), "最终结果，proof、签名、commitment 绑定和 nonce 全部通过才为 true")
        lines += explainedValue("Proof", json.optBoolean("proofValid", false).toString(), "ZK proof 是否验证通过")
        lines += explainedValue("Signature", signatureValid.toString(), "服务端是否用用户绑定公钥验证 ECDSA 签名通过")
        lines += explainedValue("Commitment bound", commitmentBound.toString(), "TEE 签名 payload 中的 commitment 是否等于 proof 的公开输入")
        lines += explainedValue("Nonce consumed", nonceConsumed.toString(), "服务端 nonce 是否已成功消费，用于防重放")
        // reason：服务端给出的可选失败原因。
        val reason = json.optString(
            "reason",
            signature?.optString("reason", nonce?.optString("reason", "") ?: "") ?: ""
        )
        if (reason.isNotBlank() && reason != "null") {
            lines += explainedValue("Reason", reason, "服务端给出的失败或补充说明")
        }
        lines.joinToString("\n")
    } catch (_: Exception) {
        "HTTP $statusCode\n$body"
    }
}

/** 将 mopro CircomProofResult 和 Keystore 签名组装成服务端 verify-proof 请求。 */
private fun proofResultToServerPayload(
    proofResult: CircomProofResult,
    signatureResult: LocationCommitmentSignature?,
    h3Resolution: Int,
    provingTimeMs: Long?
): String {
    // proof：Groth16 proof 主体。
    val proof = proofResult.proof
    // proofJson：服务端 snarkjs verifier 可解析的 proof JSON。
    val proofJson = JSONObject()
        .put("a", g1ToJson(proof.a))
        .put("b", g2ToJson(proof.b))
        .put("c", g1ToJson(proof.c))
        .put("protocol", proof.protocol)
        .put("curve", proof.curve)

    // requestJson：verify-proof 请求体，包含 proof、公开输入和实验指标。
    val requestJson = JSONObject()
        .put("proof", proofJson)
        .put("inputs", JSONArray(proofResult.inputs))
        .put(
            "metrics",
            JSONObject()
                .put("h3Resolution", h3Resolution)
                .put("clientProvingTimeMs", provingTimeMs ?: JSONObject.NULL)
        )

    if (signatureResult != null) {
        requestJson.put(
            "tee",
            JSONObject()
                .put("payload", signatureResult.payload)
                .put("signature", signatureResult.signatureBase64)
        )
    }

    return requestJson
        .toString()
}

/** 将 G1 点转换为服务端可解析的 JSON。 */
private fun g1ToJson(value: G1): JSONObject {
    return JSONObject()
        .put("x", value.x)
        .put("y", value.y)
        .put("z", value.z)
}

/** 将 G2 点转换为服务端可解析的 JSON。 */
private fun g2ToJson(value: G2): JSONObject {
    return JSONObject()
        .put("x", JSONArray(value.x))
        .put("y", JSONArray(value.y))
        .put("z", JSONArray(value.z))
}

/** 构造空 proof 状态，用于 UI 初始化和清理旧 proof。 */
private fun emptyProofResult(): CircomProofResult {
    return CircomProofResult(
        proof = CircomProof(
            a = G1(x = "", y = "", z = ""),
            b = G2(x = listOf(), y = listOf(), z = listOf()),
            c = G1(x = "", y = "", z = ""),
            protocol = "",
            curve = ""
        ),
        inputs = listOf()
    )
}
