/*
 * 文件功能：
 * - Android 主业务界面，串联注册/登录、key 绑定、GNSS、位置 proof、Source/Destination IP、时间戳、端口、协议 proof 和结果查看。
 * - UI 只展示本次登录后产生的 active key 和 proof 状态，不复用历史 attestation 展示。
 *
 * 执行流程：
 * 1. 未登录时显示 AuthEntry，调用 /auth/register 或 /auth/login。
 * 2. 登录后显示地图、顶部栏、Location、Regex 和 Results。
 * 3. Generate new key and bind 重新生成 Keystore key，并提交 certificateChain 给服务端验证。
 * 4. GNSS 获取经纬度并展示地图，Location 面板可用当前 H3 resolution 本地生成位置 proof。
 * 5. Location 面板可用已绑定 Keystore key 签名当前 proof commitment，并把 proof + signature 发送到服务端验证。
 * 6. Regex 面板支持 JSON 文本/文件导入，并分别使用 regex_ip、regex_timestamp、port_trans、unit 和 protocol_regex 电路分步本地生成和验证 proof。
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
import androidx.compose.foundation.layout.widthIn
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.HorizontalDivider
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
import java.io.File
import java.net.HttpURLConnection
import java.net.URI
import java.net.URL
import java.security.MessageDigest
import org.json.JSONArray
import org.json.JSONObject

@Composable
fun LocationProofComponent(
    initialAuthToken: String? = null,
    initialAuthUsername: String = "",
    initialServerUrl: String = "",
    onSessionEnded: () -> Unit = {},
    modifier: Modifier = Modifier
) {
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
    // sourceIpInput/sourceIpVerificationSummary：Source IP 正则 proof 本地验证输入和结果摘要。
    var sourceIpInput by remember { mutableStateOf("192.168.1.12") }
    var sourceIpVerificationSummary by remember { mutableStateOf<String?>(null) }
    // destinationIpInput/destinationIpVerificationSummary：Destination IP 正则 proof 本地验证输入和结果摘要。
    var destinationIpInput by remember { mutableStateOf("192.168.1.1") }
    var destinationIpVerificationSummary by remember { mutableStateOf<String?>(null) }
    // regexImportText/regexImportSummary：Regex JSON 导入文本和最近一次导入摘要。
    var regexImportText by remember { mutableStateOf(defaultRegexImportJson()) }
    var regexImportSummary by remember { mutableStateOf<String?>(null) }
    // timestampInput/timestampVerificationSummary：时间戳正则 proof 本地验证输入和结果摘要。
    var timestampInput by remember { mutableStateOf("2024-02-29 23:59:59.999999") }
    var timestampVerificationSummary by remember { mutableStateOf<String?>(null) }
    // portInput/portVerificationSummary：端口正则 proof 本地验证输入和结果摘要。
    var portInput by remember { mutableStateOf("502") }
    var portVerificationSummary by remember { mutableStateOf<String?>(null) }
    // transInput/transVerificationSummary：事务 ID proof 本地验证输入和结果摘要，复用 port_trans 电路的 0..65535 约束。
    var transInput by remember { mutableStateOf("19164") }
    var transVerificationSummary by remember { mutableStateOf<String?>(null) }
    // unitInput/unitVerificationSummary：Unit proof 本地验证输入和结果摘要，复用公共数字字段模板的 0..255 约束。
    var unitInput by remember { mutableStateOf("0") }
    var unitVerificationSummary by remember { mutableStateOf<String?>(null) }
    // protocolInput/protocolVerificationSummary：协议成员 proof 本地验证输入和结果摘要。
    var protocolInput by remember { mutableStateOf("Modbus/TCP") }
    var protocolVerificationSummary by remember { mutableStateOf<String?>(null) }
    // regexRecordVerificationSummary：联合日志记录 proof 的生成/验证摘要，独立于七个单字段 proof。
    var regexRecordVerificationSummary by remember { mutableStateOf<String?>(null) }
    // serverUrl：服务端 /verify-proof URL，其他接口会从它推导同 host 下路径。
    var serverUrl by remember(initialServerUrl) {
        mutableStateOf(
            initialServerUrl
                .ifBlank { "http://192.168.2.217:3000" }
                .trimEnd('/') + "/verify-proof"
        )
    }
    // keyRegistration：客户端本地最近一次 Keystore key 生成结果。
    var keyRegistration by remember { mutableStateOf<LocationKeyRegistration?>(null) }
    // signatureResult：当前 proof commitment 的 Keystore 签名结果，发送成功后清空防止复用。
    var signatureResult by remember { mutableStateOf<LocationCommitmentSignature?>(null) }
    // authUsername/authPassword/authToken/authSummary：账号输入和当前登录 session 状态。
    var authUsername by remember(initialAuthUsername) {
        mutableStateOf(initialAuthUsername.ifBlank { "alice" })
    }
    var authPassword by remember { mutableStateOf("") }
    var authToken by remember(initialAuthToken) { mutableStateOf(initialAuthToken) }
    var authSummary by remember { mutableStateOf<String?>(null) }
    // keyBindingSummary：服务端返回的 active key attestation 摘要，仅来自本次登录后的绑定/查询。
    var keyBindingSummary by remember { mutableStateOf<String?>(null) }
    // error：最近一次失败原因，供 Results/Error 展示。
    var error by remember { mutableStateOf<String?>(null) }
    // isActionSetOpen/isRegexSetOpen/isViewSetOpen/selectedOutput/operationStatus：弹窗和结果页 UI 状态。
    var isActionSetOpen by remember { mutableStateOf(false) }
    var isRegexSetOpen by remember { mutableStateOf(false) }
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
    var isVerifyingSourceIp by remember { mutableStateOf(false) }
    var isVerifyingDestinationIp by remember { mutableStateOf(false) }
    var isGeneratingRegexRecord by remember { mutableStateOf(false) }
    var isVerifyingRegexRecord by remember { mutableStateOf(false) }
    var isSendingRegexRecord by remember { mutableStateOf(false) }
    var isVerifyingTimestamp by remember { mutableStateOf(false) }
    var isVerifyingPort by remember { mutableStateOf(false) }
    var isVerifyingTrans by remember { mutableStateOf(false) }
    var isVerifyingUnit by remember { mutableStateOf(false) }
    var isVerifyingProtocol by remember { mutableStateOf(false) }
    // sourceIpProofResult/sourceIpNormalizedInput：Source IP 正则 proof 的本地生成结果和规范化输入。
    var sourceIpProofResult by remember { mutableStateOf(emptyProofResult()) }
    var sourceIpNormalizedInput by remember { mutableStateOf<String?>(null) }
    // destinationIpProofResult/destinationIpNormalizedInput：Destination IP 正则 proof 的本地生成结果和规范化输入。
    var destinationIpProofResult by remember { mutableStateOf(emptyProofResult()) }
    var destinationIpNormalizedInput by remember { mutableStateOf<String?>(null) }
    // timestampProofResult/timestampNormalizedInput：时间戳正则 proof 的本地生成结果和规范化输入。
    var timestampProofResult by remember { mutableStateOf(emptyProofResult()) }
    var timestampNormalizedInput by remember { mutableStateOf<String?>(null) }
    // portProofResult/portNormalizedInput：端口正则 proof 的本地生成结果和规范化输入。
    var portProofResult by remember { mutableStateOf(emptyProofResult()) }
    var portNormalizedInput by remember { mutableStateOf<String?>(null) }
    // transProofResult/transNormalizedInput：事务 ID proof 的本地生成结果和规范化输入。
    var transProofResult by remember { mutableStateOf(emptyProofResult()) }
    var transNormalizedInput by remember { mutableStateOf<String?>(null) }
    // unitProofResult/unitNormalizedInput：Unit proof 的本地生成结果和规范化输入。
    var unitProofResult by remember { mutableStateOf(emptyProofResult()) }
    var unitNormalizedInput by remember { mutableStateOf<String?>(null) }
    // protocolProofResult/protocolNormalizedInput：协议成员 proof 的本地生成结果和规范化输入。
    var protocolProofResult by remember { mutableStateOf(emptyProofResult()) }
    var protocolNormalizedInput by remember { mutableStateOf<String?>(null) }
    // regexRecordProofResult：联合日志记录 proof 结果。
    var regexRecordProofResult by remember { mutableStateOf(emptyProofResult()) }
    // result：当前 Circom proof 结果，空 proof 表示还未生成。
    var result by remember {
        mutableStateOf(emptyProofResult())
    }

    // areajudgeZkeyPath：从 assets 复制出的位置 proving key 文件路径。
    val areajudgeZkeyPath = getFilePathFromAssets("areajudge_final.zkey")
    // regexIpZkeyPath：从 assets 复制出的 IPv4 正则 proving key 文件路径。
    val regexIpZkeyPath = getFilePathFromAssets("regex_ip_final.zkey")
    // regexTimestampZkeyPath：从 assets 复制出的时间戳正则 proving key 文件路径。
    val regexTimestampZkeyPath = getFilePathFromAssets("regex_timestamp_final.zkey")
    // portTransZkeyPath：从 assets 复制出的 Port/Trans 共用 proving key 文件路径。
    val portTransZkeyPath = getFilePathFromAssets("port_trans_final.zkey")
    // unitZkeyPath：从 assets 复制出的 Unit proving key 文件路径。
    val unitZkeyPath = getFilePathFromAssets("unit_final.zkey")
    // protocolRegexZkeyPath：从 assets 复制出的协议 proving key 文件路径。
    val protocolRegexZkeyPath = getFilePathFromAssets("protocol_regex_final.zkey")
    // regexRecordZkeyPath：从 assets 复制出的联合日志记录 proving key 文件路径。
    val regexRecordZkeyPath = getFilePathFromAssets("regex_record_final.zkey")
    // isBusy：任意异步操作进行中时禁用主操作，避免状态交叉。
    val isBusy = isGenerating || isVerifying || isAuthenticating ||
        isBindingKey || isSigning || isSendingProof || isLocating || isReporting ||
        isVerifyingSourceIp || isVerifyingDestinationIp || isVerifyingTimestamp || isVerifyingPort || isVerifyingTrans ||
        isVerifyingUnit || isVerifyingProtocol ||
        isGeneratingRegexRecord || isVerifyingRegexRecord || isSendingRegexRecord
    // clearProofState：位置、resolution 或 key 改变后清除旧 proof/signature/server response。
    val clearProofState = {
        provingTime = null
        verifyingTime = null
        valid = null
        publicInputs = null
        signatureResult = null
        result = emptyProofResult()
        selectedOutput = null
    }
    // resetAfterLocation：GNSS 更新后统一清理旧 proof 状态并提示用户。
    val resetAfterLocation = {
        clearProofState()
        operationStatus = OperationStatus("GNSS", true, locationSummary ?: "Location updated")
    }
    // clear...：导入或手动修改 Regex 输入后清空对应旧 proof，避免新输入复用旧 proof。
    val clearSourceIpProof = {
        sourceIpProofResult = emptyProofResult()
        sourceIpNormalizedInput = null
        sourceIpVerificationSummary = null
    }
    val clearDestinationIpProof = {
        destinationIpProofResult = emptyProofResult()
        destinationIpNormalizedInput = null
        destinationIpVerificationSummary = null
    }
    val clearTimestampProof = {
        timestampProofResult = emptyProofResult()
        timestampNormalizedInput = null
        timestampVerificationSummary = null
    }
    val clearPortProof = {
        portProofResult = emptyProofResult()
        portNormalizedInput = null
        portVerificationSummary = null
    }
    val clearTransProof = {
        transProofResult = emptyProofResult()
        transNormalizedInput = null
        transVerificationSummary = null
    }
    val clearUnitProof = {
        unitProofResult = emptyProofResult()
        unitNormalizedInput = null
        unitVerificationSummary = null
    }
    val clearProtocolProof = {
        protocolProofResult = emptyProofResult()
        protocolNormalizedInput = null
        protocolVerificationSummary = null
    }
    val clearRegexRecordProof = {
        regexRecordProofResult = emptyProofResult()
        regexRecordVerificationSummary = null
    }
    // applyRegexImport：解析 JSON 文本或文件内容，并把识别出的字段填入 Regex 面板。
    val applyRegexImport = { jsonText: String ->
        try {
            val imported = parseRegexImportValues(jsonText)
            val appliedFields = mutableListOf<String>()
            imported.sourceIp?.let {
                sourceIpInput = it
                clearSourceIpProof()
                clearRegexRecordProof()
                appliedFields += "Source IP=$it"
            }
            imported.destinationIp?.let {
                destinationIpInput = it
                clearDestinationIpProof()
                clearRegexRecordProof()
                appliedFields += "Destination IP=$it"
            }
            imported.timestamp?.let {
                timestampInput = it
                clearTimestampProof()
                clearRegexRecordProof()
                appliedFields += "Timestamp=$it"
            }
            imported.port?.let {
                portInput = it
                clearPortProof()
                clearRegexRecordProof()
                appliedFields += "Port=$it"
            }
            imported.trans?.let {
                transInput = it
                clearTransProof()
                clearRegexRecordProof()
                appliedFields += "Trans=$it"
            }
            imported.unit?.let {
                unitInput = it
                clearUnitProof()
                clearRegexRecordProof()
                appliedFields += "Unit=$it"
            }
            imported.protocol?.let {
                protocolInput = it
                clearProtocolProof()
                clearRegexRecordProof()
                appliedFields += "Protocol=$it"
            }

            regexImportSummary = null
        } catch (e: Exception) {
            val message = e.message ?: e.toString()
            regexImportSummary = explainedValue("Import failed", message, "JSON 文本或文件内容无法解析为支持的字段")
            operationStatus = OperationStatus("Regex JSON import", false, regexImportSummary ?: message)
        }
    }
    // regexJsonFileLauncher：从手机选择 JSON/text 文件，读取内容后复用同一套导入逻辑。
    val regexJsonFileLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.GetContent()
    ) { uri ->
        if (uri != null) {
            try {
                val importedText = context.contentResolver
                    .openInputStream(uri)
                    ?.bufferedReader()
                    ?.use { it.readText() }
                    ?: error("Unable to read selected file")
                regexImportText = importedText
                applyRegexImport(importedText)
            } catch (e: Exception) {
                val message = e.message ?: e.toString()
                regexImportSummary = explainedValue("Import failed", message, "读取手机文件失败")
                operationStatus = OperationStatus("Regex JSON file", false, regexImportSummary ?: message)
            }
        }
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

    // logoutAction：从主页面顶部退出当前 session，并清理本地 key/proof 状态。
    val logoutAction = {
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
                    onSessionEnded()
                } catch (e: Exception) {
                    val message = e.message ?: e.toString()
                    error = message
                    operationStatus = OperationStatus("Logout", false, message)
                } finally {
                    isAuthenticating = false
                }
            }.start()
        }
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
                onLogout = logoutAction
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
                    Text(if (isBusy) "Processing" else "Location", fontSize = 13.sp, fontWeight = FontWeight.SemiBold)
                }

                OutlinedButton(
                    onClick = { isRegexSetOpen = true },
                    modifier = Modifier
                        .weight(1f)
                        .heightIn(min = 44.dp),
                    enabled = !isBusy,
                    shape = RoundedCornerShape(8.dp),
                    contentPadding = PaddingValues(horizontal = 12.dp, vertical = 8.dp)
                ) {
                    Text("Regex", fontSize = 13.sp, fontWeight = FontWeight.SemiBold)
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
            isLoggedIn = authToken != null,
            hasKey = keyRegistration != null,
            hasLocation = latitude != null && longitude != null,
            hasProof = result.inputs.isNotEmpty(),
            hasSignature = signatureResult != null,
            onDismiss = { isActionSetOpen = false },
            onServerUrlChange = { serverUrl = it },
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
            onGenerateProof = {
                val lat = latitude
                val lon = longitude
                if (lat == null || lon == null) {
                    val message = "Run GNSS before generating location proof"
                    error = message
                    operationStatus = OperationStatus("Generate proof", false, message)
                } else {
                    isGenerating = true
                    error = null
                    signatureResult = null
                    startProofWorker("location-proof-generate") {
                        try {
                            val startedAt = System.currentTimeMillis()
                            val circuitInput = generateLocationCircuitInput(
                                lat,
                                lon,
                                selectedResolution.toUByte()
                            )
                            val proof = generateCircomProof(
                                areajudgeZkeyPath,
                                circuitInput,
                                ProofLib.ARKWORKS
                            )
                            val elapsedMs = System.currentTimeMillis() - startedAt
                            result = proof
                            provingTime = "$elapsedMs ms"
                            verifyingTime = null
                            valid = null
                            publicInputs = listOf(
                                compactValue("Generated", "true"),
                                compactValue("Time", "$elapsedMs ms"),
                                compactValue("Area", "H3 r$selectedResolution"),
                                compactValue("Location", "${formatCoordinate(lat)}, ${formatCoordinate(lon)}"),
                                formatProofSummary(proof)
                            ).joinToString("\n")
                            operationStatus = OperationStatus(
                                "Generate proof",
                                true,
                                publicInputs ?: "Location proof generated"
                            )
                        } catch (e: Exception) {
                            val message = e.message ?: e.toString()
                            result = emptyProofResult()
                            provingTime = null
                            publicInputs = null
                            error = message
                            operationStatus = OperationStatus("Generate proof", false, message)
                        } finally {
                            isGenerating = false
                        }
                    }
                }
            },
            onVerifyProof = {
                if (result.inputs.isEmpty()) {
                    val message = "Generate proof before verifying location proof"
                    error = message
                    operationStatus = OperationStatus("Verify proof", false, message)
                } else {
                    isVerifying = true
                    error = null
                    startProofWorker("location-proof-verify") {
                        try {
                            val startedAt = System.currentTimeMillis()
                            val verified = verifyCircomProof(
                                areajudgeZkeyPath,
                                result,
                                ProofLib.ARKWORKS
                            )
                            val elapsedMs = System.currentTimeMillis() - startedAt
                            verifyingTime = "$elapsedMs ms"
                            valid = verified.toString()
                            operationStatus = OperationStatus(
                                "Verify proof",
                                verified,
                                listOf(
                                    compactValue("Verified", verified.toString()),
                                    compactValue("Time", "$elapsedMs ms")
                                ).joinToString("\n")
                            )
                        } catch (e: Exception) {
                            val message = e.message ?: e.toString()
                            verifyingTime = null
                            valid = "false"
                            error = message
                            operationStatus = OperationStatus("Verify proof", false, message)
                        } finally {
                            isVerifying = false
                        }
                    }
                }
            },
            onSignCommitment = {
                val token = authToken
                val commitment = result.inputs.firstOrNull().orEmpty()
                when {
                    token == null -> {
                        val message = "Login before signing commitment"
                        error = message
                        operationStatus = OperationStatus("Sign commitment", false, message)
                    }

                    keyRegistration == null -> {
                        val message = "Generate new key and bind before signing commitment"
                        error = message
                        operationStatus = OperationStatus("Sign commitment", false, message)
                    }

                    commitment.isBlank() -> {
                        val message = "Generate proof before signing commitment"
                        error = message
                        operationStatus = OperationStatus("Sign commitment", false, message)
                    }

                    else -> {
                        isSigning = true
                        error = null
                        Thread {
                            try {
                                val nonce = requestServerNonce(serverUrl)
                                val signature = KeystoreLocationSigner.signCommitment(commitment, nonce.nonce)
                                signatureResult = signature
                                operationStatus = OperationStatus(
                                    "Sign commitment",
                                    signature.verifiedLocally,
                                    listOf(
                                        explainedValue("Signed", "true", "已使用 Android Keystore 私钥签名当前 proof commitment"),
                                        explainedValue("Commitment", shortValue(commitment), "签名 payload 中绑定的 ZK proof 公开承诺"),
                                        explainedValue("Nonce", shortValue(nonce.nonce), "服务端 /nonce 下发的一次性防重放随机数"),
                                        explainedValue("Local signature check", signature.verifiedLocally.toString(), "客户端本地用 leaf public key 自检签名")
                                    ).joinToString("\n")
                                )
                            } catch (e: Exception) {
                                val message = e.message ?: e.toString()
                                signatureResult = null
                                error = message
                                operationStatus = OperationStatus("Sign commitment", false, message)
                            } finally {
                                isSigning = false
                            }
                        }.start()
                    }
                }
            },
            onSendProof = {
                val token = authToken
                val signature = signatureResult
                when {
                    token == null -> {
                        val message = "Login before sending proof"
                        error = message
                        operationStatus = OperationStatus("Send proof to server", false, message)
                    }

                    keyRegistration == null -> {
                        val message = "Generate new key and bind before sending proof"
                        error = message
                        operationStatus = OperationStatus("Send proof to server", false, message)
                    }

                    result.inputs.isEmpty() -> {
                        val message = "Generate proof before sending proof"
                        error = message
                        operationStatus = OperationStatus("Send proof to server", false, message)
                    }

                    signature == null -> {
                        val message = "Sign commitment before sending proof"
                        error = message
                        operationStatus = OperationStatus("Send proof to server", false, message)
                    }

                    else -> {
                        isSendingProof = true
                        error = null
                        Thread {
                            try {
                                val summary = postProofToServer(serverUrl, token, result, signature)
                                operationStatus = OperationStatus("Send proof to server", true, summary)
                                signatureResult = null
                            } catch (e: Exception) {
                                val message = e.message ?: e.toString()
                                error = message
                                operationStatus = OperationStatus("Send proof to server", false, message)
                            } finally {
                                isSendingProof = false
                            }
                        }.start()
                    }
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
            }
        )
    }

    val generateRegexRecordProof = {
        isGeneratingRegexRecord = true
        error = null
        startProofWorker("regex-record-proof-generate") {
            try {
                val recordInput = buildRegexRecordCircuitInput(regexImportText)
                val startedAt = System.currentTimeMillis()
                val proof = generateCircomProof(
                    regexRecordZkeyPath,
                    recordInput.circuitInput,
                    ProofLib.ARKWORKS
                )
                val elapsedMs = System.currentTimeMillis() - startedAt
                require(proof.inputs.firstOrNull() == recordInput.recordCommitment) {
                    "Generated proof public input mismatch: expected recordCommitment ${shortValue(recordInput.recordCommitment)}, got ${shortValue(proof.inputs.firstOrNull().orEmpty())}"
                }
                regexRecordProofResult = proof
                regexRecordVerificationSummary = formatRegexRecordVerificationSummary(
                    recordInput = recordInput,
                    proofGenerated = true,
                    proofVerified = null,
                    accepted = null,
                    proofInputs = proof.inputs,
                    provingMs = elapsedMs,
                    verifyingMs = null,
                    errorMessage = null
                )
                operationStatus = OperationStatus(
                    "Record proof generation",
                    true,
                    regexRecordVerificationSummary ?: "Record proof generated"
                )
            } catch (e: Exception) {
                val message = e.message ?: e.toString()
                regexRecordProofResult = emptyProofResult()
                regexRecordVerificationSummary = formatRegexRecordVerificationSummary(
                    recordInput = null,
                    proofGenerated = false,
                    proofVerified = null,
                    accepted = false,
                    proofInputs = emptyList(),
                    provingMs = null,
                    verifyingMs = null,
                    errorMessage = message
                )
                error = message
                operationStatus = OperationStatus(
                    "Record proof generation",
                    false,
                    regexRecordVerificationSummary ?: message
                )
            } finally {
                isGeneratingRegexRecord = false
            }
        }
    }

    val verifyRegexRecordProof = {
        if (regexRecordProofResult.proof.a.x.isEmpty()) {
            val message = "Generate record proof before local verification"
            regexRecordVerificationSummary = formatRegexRecordVerificationSummary(
                recordInput = null,
                proofGenerated = false,
                proofVerified = false,
                accepted = false,
                proofInputs = emptyList(),
                provingMs = null,
                verifyingMs = null,
                errorMessage = message
            )
            operationStatus = OperationStatus("Record proof verification", false, regexRecordVerificationSummary ?: message)
        } else {
            isVerifyingRegexRecord = true
            error = null
            startProofWorker("regex-record-proof-verify") {
                try {
                    val startedAt = System.currentTimeMillis()
                    val verification = verifyRegexRecordProofWithFallback(regexRecordZkeyPath, regexRecordProofResult)
                    val elapsedMs = System.currentTimeMillis() - startedAt
                    regexRecordVerificationSummary = listOf(
                        regexRecordVerificationSummary ?: "",
                        compactValue("Verified", verification.verified.toString()),
                        compactValue("Backend", verification.backend),
                        verification.detail?.let { compactValue("Detail", it) }.orEmpty(),
                        compactValue("Verifying", "$elapsedMs ms")
                    ).filter { it.isNotBlank() }.joinToString("\n")
                    operationStatus = OperationStatus(
                        "Record proof verification",
                        verification.verified,
                        regexRecordVerificationSummary ?: "Record proof verified"
                    )
                } catch (e: Exception) {
                    val message = e.message ?: e.toString()
                    regexRecordVerificationSummary = listOf(
                        regexRecordVerificationSummary ?: "",
                        compactValue("Verified", "false"),
                        compactValue("Error", message)
                    ).filter { it.isNotBlank() }.joinToString("\n")
                    error = message
                    operationStatus = OperationStatus(
                        "Record proof verification",
                        false,
                        regexRecordVerificationSummary ?: message
                    )
                } finally {
                    isVerifyingRegexRecord = false
                }
            }
        }
    }

    val sendRegexRecordProofToServer = {
        val token = authToken
        when {
            token == null -> {
                val message = "Login before sending record proof"
                error = message
                operationStatus = OperationStatus("Send record proof", false, message)
            }

            regexRecordProofResult.proof.a.x.isEmpty() -> {
                val message = "Generate record proof before sending it"
                error = message
                operationStatus = OperationStatus("Send record proof", false, message)
            }

            else -> {
                isSendingRegexRecord = true
                error = null
                Thread {
                    try {
                        val summary = postRegexRecordProofToServer(
                            serverUrl,
                            token,
                            regexRecordProofResult,
                            regexRecordZkeyPath
                        )
                        regexRecordVerificationSummary = listOf(
                            regexRecordVerificationSummary ?: "",
                            summary
                        ).filter { it.isNotBlank() }.joinToString("\n")
                        operationStatus = OperationStatus("Send record proof", true, summary)
                    } catch (e: Exception) {
                        val message = e.message ?: e.toString()
                        error = message
                        operationStatus = OperationStatus("Send record proof", false, message)
                    } finally {
                        isSendingRegexRecord = false
                    }
                }.start()
            }
        }
    }

    if (authToken != null && isRegexSetOpen) {
        RegexSetDialog(
            regexImportText = regexImportText,
            sourceIpInput = sourceIpInput,
            destinationIpInput = destinationIpInput,
            timestampInput = timestampInput,
            portInput = portInput,
            transInput = transInput,
            unitInput = unitInput,
            protocolInput = protocolInput,
            isBusy = isBusy,
            sourceIpVerificationSummary = sourceIpVerificationSummary,
            destinationIpVerificationSummary = destinationIpVerificationSummary,
            timestampVerificationSummary = timestampVerificationSummary,
            portVerificationSummary = portVerificationSummary,
            transVerificationSummary = transVerificationSummary,
            unitVerificationSummary = unitVerificationSummary,
            protocolVerificationSummary = protocolVerificationSummary,
            regexRecordVerificationSummary = regexRecordVerificationSummary,
            hasSourceIpProof = sourceIpProofResult.proof.a.x.isNotEmpty(),
            hasDestinationIpProof = destinationIpProofResult.proof.a.x.isNotEmpty(),
            hasTimestampProof = timestampProofResult.proof.a.x.isNotEmpty(),
            hasPortProof = portProofResult.proof.a.x.isNotEmpty(),
            hasTransProof = transProofResult.proof.a.x.isNotEmpty(),
            hasUnitProof = unitProofResult.proof.a.x.isNotEmpty(),
            hasProtocolProof = protocolProofResult.proof.a.x.isNotEmpty(),
            hasRegexRecordProof = regexRecordProofResult.proof.a.x.isNotEmpty(),
            onDismiss = { isRegexSetOpen = false },
            onRegexImportTextChange = {
                regexImportText = it
                clearRegexRecordProof()
            },
            onParseRegexImportText = { applyRegexImport(regexImportText) },
            onPickRegexJsonFile = { regexJsonFileLauncher.launch("*/*") },
            onGenerateAllProofs = {},
            onVerifyAllProofs = {},
            onGenerateRecordProof = generateRegexRecordProof,
            onViewRecordProof = {
                operationStatus = OperationStatus(
                    "Record proof",
                    regexRecordProofResult.proof.a.x.isNotEmpty(),
                    regexRecordVerificationSummary ?: "No record proof output yet"
                )
            },
            onVerifyRecordProof = verifyRegexRecordProof,
            onSendRecordProofToServer = sendRegexRecordProofToServer,
            onSourceIpInputChange = {
                sourceIpInput = it
                clearSourceIpProof()
                clearRegexRecordProof()
            },
            onGenerateSourceIpProof = {
                isVerifyingSourceIp = true
                error = null
                startProofWorker("source-ip-regex-proof-generate") {
                    try {
                        val (circuitInput, normalizedIp) = buildIpv4RegexCircuitInput(sourceIpInput)
                        val startTime = System.currentTimeMillis()
                        sourceIpProofResult = generateCircomProof(regexIpZkeyPath, circuitInput, ProofLib.ARKWORKS)
                        val generatedMs = System.currentTimeMillis() - startTime
                        sourceIpNormalizedInput = normalizedIp
                        sourceIpVerificationSummary = formatIpv4VerificationSummary(
                            rawInput = sourceIpInput,
                            normalizedInput = normalizedIp,
                            proofGenerated = true,
                            proofVerified = null,
                            accepted = null,
                            proofInputs = sourceIpProofResult.inputs,
                            provingMs = generatedMs,
                            verifyingMs = null,
                            errorMessage = null
                        )
                        operationStatus = OperationStatus(
                            "Source IP proof generation",
                            true,
                            sourceIpVerificationSummary ?: "No Source IP verification output"
                        )
                    } catch (e: Exception) {
                        val message = e.message ?: e.toString()
                        sourceIpProofResult = emptyProofResult()
                        sourceIpNormalizedInput = null
                        sourceIpVerificationSummary = formatIpv4VerificationSummary(
                            rawInput = sourceIpInput,
                            normalizedInput = null,
                            proofGenerated = false,
                            proofVerified = null,
                            accepted = false,
                            proofInputs = emptyList(),
                            provingMs = null,
                            verifyingMs = null,
                            errorMessage = message
                        )
                        operationStatus = OperationStatus(
                            "Source IP proof generation",
                            false,
                            sourceIpVerificationSummary ?: message
                        )
                    } finally {
                        isVerifyingSourceIp = false
                    }
                }
            },
            onVerifySourceIpProof = {
                if (sourceIpProofResult.proof.a.x.isEmpty()) {
                    val message = "Generate Source IP proof before local verification"
                    sourceIpVerificationSummary = formatIpv4VerificationSummary(
                        rawInput = sourceIpInput,
                        normalizedInput = sourceIpNormalizedInput,
                        proofGenerated = false,
                        proofVerified = false,
                        accepted = false,
                        proofInputs = emptyList(),
                        provingMs = null,
                        verifyingMs = null,
                        errorMessage = message
                    )
                    operationStatus = OperationStatus("Source IP proof verification", false, sourceIpVerificationSummary ?: message)
                } else {
                    isVerifyingSourceIp = true
                    error = null
                    startProofWorker("source-ip-regex-proof-verify") {
                        try {
                            val verifyStart = System.currentTimeMillis()
                            val verified = verifyCircomProof(regexIpZkeyPath, sourceIpProofResult, ProofLib.ARKWORKS)
                            val verifiedMs = System.currentTimeMillis() - verifyStart
                            val accepted = verified && sourceIpProofResult.inputs.firstOrNull() == "1"
                            sourceIpVerificationSummary = formatIpv4VerificationSummary(
                                rawInput = sourceIpInput,
                                normalizedInput = sourceIpNormalizedInput,
                                proofGenerated = true,
                                proofVerified = verified,
                                accepted = accepted,
                                proofInputs = sourceIpProofResult.inputs,
                                provingMs = null,
                                verifyingMs = verifiedMs,
                                errorMessage = null
                            )
                            operationStatus = OperationStatus(
                                "Source IP proof verification",
                                accepted,
                                sourceIpVerificationSummary ?: "No Source IP verification output"
                            )
                        } catch (e: Exception) {
                            val message = e.message ?: e.toString()
                            sourceIpVerificationSummary = formatIpv4VerificationSummary(
                                rawInput = sourceIpInput,
                                normalizedInput = sourceIpNormalizedInput,
                                proofGenerated = true,
                                proofVerified = false,
                                accepted = false,
                                proofInputs = sourceIpProofResult.inputs,
                                provingMs = null,
                                verifyingMs = null,
                                errorMessage = message
                            )
                            operationStatus = OperationStatus(
                                "Source IP proof verification",
                                false,
                                sourceIpVerificationSummary ?: message
                            )
                        } finally {
                            isVerifyingSourceIp = false
                        }
                    }
                }
            },
            onDestinationIpInputChange = {
                destinationIpInput = it
                clearDestinationIpProof()
                clearRegexRecordProof()
            },
            onGenerateDestinationIpProof = {
                isVerifyingDestinationIp = true
                error = null
                startProofWorker("destination-ip-regex-proof-generate") {
                    try {
                        val (circuitInput, normalizedIp) = buildIpv4RegexCircuitInput(destinationIpInput)
                        val startTime = System.currentTimeMillis()
                        destinationIpProofResult = generateCircomProof(regexIpZkeyPath, circuitInput, ProofLib.ARKWORKS)
                        val generatedMs = System.currentTimeMillis() - startTime
                        destinationIpNormalizedInput = normalizedIp
                        destinationIpVerificationSummary = formatIpv4VerificationSummary(
                            rawInput = destinationIpInput,
                            normalizedInput = normalizedIp,
                            proofGenerated = true,
                            proofVerified = null,
                            accepted = null,
                            proofInputs = destinationIpProofResult.inputs,
                            provingMs = generatedMs,
                            verifyingMs = null,
                            errorMessage = null
                        )
                        operationStatus = OperationStatus(
                            "Destination IP proof generation",
                            true,
                            destinationIpVerificationSummary ?: "No Destination IP verification output"
                        )
                    } catch (e: Exception) {
                        val message = e.message ?: e.toString()
                        destinationIpProofResult = emptyProofResult()
                        destinationIpNormalizedInput = null
                        destinationIpVerificationSummary = formatIpv4VerificationSummary(
                            rawInput = destinationIpInput,
                            normalizedInput = null,
                            proofGenerated = false,
                            proofVerified = null,
                            accepted = false,
                            proofInputs = emptyList(),
                            provingMs = null,
                            verifyingMs = null,
                            errorMessage = message
                        )
                        operationStatus = OperationStatus(
                            "Destination IP proof generation",
                            false,
                            destinationIpVerificationSummary ?: message
                        )
                    } finally {
                        isVerifyingDestinationIp = false
                    }
                }
            },
            onVerifyDestinationIpProof = {
                if (destinationIpProofResult.proof.a.x.isEmpty()) {
                    val message = "Generate Destination IP proof before local verification"
                    destinationIpVerificationSummary = formatIpv4VerificationSummary(
                        rawInput = destinationIpInput,
                        normalizedInput = destinationIpNormalizedInput,
                        proofGenerated = false,
                        proofVerified = false,
                        accepted = false,
                        proofInputs = emptyList(),
                        provingMs = null,
                        verifyingMs = null,
                        errorMessage = message
                    )
                    operationStatus = OperationStatus(
                        "Destination IP proof verification",
                        false,
                        destinationIpVerificationSummary ?: message
                    )
                } else {
                    isVerifyingDestinationIp = true
                    error = null
                    startProofWorker("destination-ip-regex-proof-verify") {
                        try {
                            val verifyStart = System.currentTimeMillis()
                            val verified = verifyCircomProof(regexIpZkeyPath, destinationIpProofResult, ProofLib.ARKWORKS)
                            val verifiedMs = System.currentTimeMillis() - verifyStart
                            val accepted = verified && destinationIpProofResult.inputs.firstOrNull() == "1"
                            destinationIpVerificationSummary = formatIpv4VerificationSummary(
                                rawInput = destinationIpInput,
                                normalizedInput = destinationIpNormalizedInput,
                                proofGenerated = true,
                                proofVerified = verified,
                                accepted = accepted,
                                proofInputs = destinationIpProofResult.inputs,
                                provingMs = null,
                                verifyingMs = verifiedMs,
                                errorMessage = null
                            )
                            operationStatus = OperationStatus(
                                "Destination IP proof verification",
                                accepted,
                                destinationIpVerificationSummary ?: "No Destination IP verification output"
                            )
                        } catch (e: Exception) {
                            val message = e.message ?: e.toString()
                            destinationIpVerificationSummary = formatIpv4VerificationSummary(
                                rawInput = destinationIpInput,
                                normalizedInput = destinationIpNormalizedInput,
                                proofGenerated = true,
                                proofVerified = false,
                                accepted = false,
                                proofInputs = destinationIpProofResult.inputs,
                                provingMs = null,
                                verifyingMs = null,
                                errorMessage = message
                            )
                            operationStatus = OperationStatus(
                                "Destination IP proof verification",
                                false,
                                destinationIpVerificationSummary ?: message
                            )
                        } finally {
                            isVerifyingDestinationIp = false
                        }
                    }
                }
            },
            onTimestampInputChange = {
                timestampInput = it
                clearTimestampProof()
                clearRegexRecordProof()
            },
            onGenerateTimestampProof = {
                isVerifyingTimestamp = true
                error = null
                startProofWorker("timestamp-regex-proof-generate") {
                    try {
                        val (circuitInput, normalizedTimestamp) = buildTimestampRegexCircuitInput(timestampInput)
                        val startTime = System.currentTimeMillis()
                        timestampProofResult = generateCircomProof(
                            regexTimestampZkeyPath,
                            circuitInput,
                            ProofLib.ARKWORKS
                        )
                        val generatedMs = System.currentTimeMillis() - startTime
                        timestampNormalizedInput = normalizedTimestamp
                        timestampVerificationSummary = formatTimestampVerificationSummary(
                            rawInput = timestampInput,
                            normalizedInput = normalizedTimestamp,
                            proofGenerated = true,
                            proofVerified = null,
                            accepted = null,
                            proofInputs = timestampProofResult.inputs,
                            provingMs = generatedMs,
                            verifyingMs = null,
                            errorMessage = null
                        )
                        operationStatus = OperationStatus(
                            "Timestamp proof generation",
                            true,
                            timestampVerificationSummary ?: "No timestamp verification output"
                        )
                    } catch (e: Exception) {
                        val message = e.message ?: e.toString()
                        timestampProofResult = emptyProofResult()
                        timestampNormalizedInput = null
                        timestampVerificationSummary = formatTimestampVerificationSummary(
                            rawInput = timestampInput,
                            normalizedInput = null,
                            proofGenerated = false,
                            proofVerified = null,
                            accepted = false,
                            proofInputs = emptyList(),
                            provingMs = null,
                            verifyingMs = null,
                            errorMessage = message
                        )
                        operationStatus = OperationStatus(
                            "Timestamp proof generation",
                            false,
                            timestampVerificationSummary ?: message
                        )
                    } finally {
                        isVerifyingTimestamp = false
                    }
                }
            },
            onVerifyTimestampProof = {
                if (timestampProofResult.proof.a.x.isEmpty()) {
                    val message = "Generate timestamp proof before local verification"
                    timestampVerificationSummary = formatTimestampVerificationSummary(
                        rawInput = timestampInput,
                        normalizedInput = timestampNormalizedInput,
                        proofGenerated = false,
                        proofVerified = false,
                        accepted = false,
                        proofInputs = emptyList(),
                        provingMs = null,
                        verifyingMs = null,
                        errorMessage = message
                    )
                    operationStatus = OperationStatus(
                        "Timestamp proof verification",
                        false,
                        timestampVerificationSummary ?: message
                    )
                } else {
                    isVerifyingTimestamp = true
                    error = null
                    startProofWorker("timestamp-regex-proof-verify") {
                        try {
                            val verifyStart = System.currentTimeMillis()
                            val verified = verifyCircomProof(
                                regexTimestampZkeyPath,
                                timestampProofResult,
                                ProofLib.ARKWORKS
                            )
                            val verifiedMs = System.currentTimeMillis() - verifyStart
                            val accepted = verified && timestampProofResult.inputs.firstOrNull() == "1"
                            timestampVerificationSummary = formatTimestampVerificationSummary(
                                rawInput = timestampInput,
                                normalizedInput = timestampNormalizedInput,
                                proofGenerated = true,
                                proofVerified = verified,
                                accepted = accepted,
                                proofInputs = timestampProofResult.inputs,
                                provingMs = null,
                                verifyingMs = verifiedMs,
                                errorMessage = null
                            )
                            operationStatus = OperationStatus(
                                "Timestamp proof verification",
                                accepted,
                                timestampVerificationSummary ?: "No timestamp verification output"
                            )
                        } catch (e: Exception) {
                            val message = e.message ?: e.toString()
                            timestampVerificationSummary = formatTimestampVerificationSummary(
                                rawInput = timestampInput,
                                normalizedInput = timestampNormalizedInput,
                                proofGenerated = true,
                                proofVerified = false,
                                accepted = false,
                                proofInputs = timestampProofResult.inputs,
                                provingMs = null,
                                verifyingMs = null,
                                errorMessage = message
                            )
                            operationStatus = OperationStatus(
                                "Timestamp proof verification",
                                false,
                                timestampVerificationSummary ?: message
                            )
                        } finally {
                            isVerifyingTimestamp = false
                        }
                    }
                }
            },
            onPortInputChange = {
                portInput = it
                portProofResult = emptyProofResult()
                portNormalizedInput = null
                portVerificationSummary = null
                clearRegexRecordProof()
            },
            onGeneratePortProof = {
                isVerifyingPort = true
                error = null
                startProofWorker("port-regex-proof-generate") {
                    try {
                        val (circuitInput, normalizedPort) = buildPortRegexCircuitInput(portInput)
                        val startTime = System.currentTimeMillis()
                        portProofResult = generateCircomProof(
                            portTransZkeyPath,
                            circuitInput,
                            ProofLib.ARKWORKS
                        )
                        val generatedMs = System.currentTimeMillis() - startTime
                        portNormalizedInput = normalizedPort
                        portVerificationSummary = formatPortVerificationSummary(
                            rawInput = portInput,
                            normalizedInput = normalizedPort,
                            proofGenerated = true,
                            proofVerified = null,
                            accepted = null,
                            proofInputs = portProofResult.inputs,
                            provingMs = generatedMs,
                            verifyingMs = null,
                            errorMessage = null
                        )
                        operationStatus = OperationStatus(
                            "Port proof generation",
                            true,
                            portVerificationSummary ?: "No port verification output"
                        )
                    } catch (e: Exception) {
                        val message = e.message ?: e.toString()
                        portProofResult = emptyProofResult()
                        portNormalizedInput = null
                        portVerificationSummary = formatPortVerificationSummary(
                            rawInput = portInput,
                            normalizedInput = null,
                            proofGenerated = false,
                            proofVerified = null,
                            accepted = false,
                            proofInputs = emptyList(),
                            provingMs = null,
                            verifyingMs = null,
                            errorMessage = message
                        )
                        operationStatus = OperationStatus(
                            "Port proof generation",
                            false,
                            portVerificationSummary ?: message
                        )
                    } finally {
                        isVerifyingPort = false
                    }
                }
            },
            onVerifyPortProof = {
                if (portProofResult.proof.a.x.isEmpty()) {
                    val message = "Generate port proof before local verification"
                    portVerificationSummary = formatPortVerificationSummary(
                        rawInput = portInput,
                        normalizedInput = portNormalizedInput,
                        proofGenerated = false,
                        proofVerified = false,
                        accepted = false,
                        proofInputs = emptyList(),
                        provingMs = null,
                        verifyingMs = null,
                        errorMessage = message
                    )
                    operationStatus = OperationStatus(
                        "Port proof verification",
                        false,
                        portVerificationSummary ?: message
                    )
                } else {
                    isVerifyingPort = true
                    error = null
                    startProofWorker("port-regex-proof-verify") {
                        try {
                            val verifyStart = System.currentTimeMillis()
                            val verified = verifyCircomProof(
                                portTransZkeyPath,
                                portProofResult,
                                ProofLib.ARKWORKS
                            )
                            val verifiedMs = System.currentTimeMillis() - verifyStart
                            val accepted = verified && portProofResult.inputs.firstOrNull() == "1"
                            portVerificationSummary = formatPortVerificationSummary(
                                rawInput = portInput,
                                normalizedInput = portNormalizedInput,
                                proofGenerated = true,
                                proofVerified = verified,
                                accepted = accepted,
                                proofInputs = portProofResult.inputs,
                                provingMs = null,
                                verifyingMs = verifiedMs,
                                errorMessage = null
                            )
                            operationStatus = OperationStatus(
                                "Port proof verification",
                                accepted,
                                portVerificationSummary ?: "No port verification output"
                            )
                        } catch (e: Exception) {
                            val message = e.message ?: e.toString()
                            portVerificationSummary = formatPortVerificationSummary(
                                rawInput = portInput,
                                normalizedInput = portNormalizedInput,
                                proofGenerated = true,
                                proofVerified = false,
                                accepted = false,
                                proofInputs = portProofResult.inputs,
                                provingMs = null,
                                verifyingMs = null,
                                errorMessage = message
                            )
                            operationStatus = OperationStatus(
                                "Port proof verification",
                                false,
                                portVerificationSummary ?: message
                            )
                        } finally {
                            isVerifyingPort = false
                        }
                    }
                }
            },
            onTransInputChange = {
                transInput = it
                transProofResult = emptyProofResult()
                transNormalizedInput = null
                transVerificationSummary = null
                clearRegexRecordProof()
            },
            onGenerateTransProof = {
                isVerifyingTrans = true
                error = null
                startProofWorker("trans-regex-proof-generate") {
                    try {
                        val (circuitInput, normalizedTrans) = buildPortRegexCircuitInput(transInput, "Trans")
                        val startTime = System.currentTimeMillis()
                        transProofResult = generateCircomProof(
                            portTransZkeyPath,
                            circuitInput,
                            ProofLib.ARKWORKS
                        )
                        val generatedMs = System.currentTimeMillis() - startTime
                        transNormalizedInput = normalizedTrans
                        transVerificationSummary = formatUint16VerificationSummary(
                            label = "Trans",
                            rawInput = transInput,
                            normalizedInput = normalizedTrans,
                            proofGenerated = true,
                            proofVerified = null,
                            accepted = null,
                            proofInputs = transProofResult.inputs,
                            provingMs = generatedMs,
                            verifyingMs = null,
                            errorMessage = null
                        )
                        operationStatus = OperationStatus(
                            "Trans proof generation",
                            true,
                            transVerificationSummary ?: "No Trans verification output"
                        )
                    } catch (e: Exception) {
                        val message = e.message ?: e.toString()
                        transProofResult = emptyProofResult()
                        transNormalizedInput = null
                        transVerificationSummary = formatUint16VerificationSummary(
                            label = "Trans",
                            rawInput = transInput,
                            normalizedInput = null,
                            proofGenerated = false,
                            proofVerified = null,
                            accepted = false,
                            proofInputs = emptyList(),
                            provingMs = null,
                            verifyingMs = null,
                            errorMessage = message
                        )
                        operationStatus = OperationStatus(
                            "Trans proof generation",
                            false,
                            transVerificationSummary ?: message
                        )
                    } finally {
                        isVerifyingTrans = false
                    }
                }
            },
            onVerifyTransProof = {
                if (transProofResult.proof.a.x.isEmpty()) {
                    val message = "Generate Trans proof before local verification"
                    transVerificationSummary = formatUint16VerificationSummary(
                        label = "Trans",
                        rawInput = transInput,
                        normalizedInput = transNormalizedInput,
                        proofGenerated = false,
                        proofVerified = false,
                        accepted = false,
                        proofInputs = emptyList(),
                        provingMs = null,
                        verifyingMs = null,
                        errorMessage = message
                    )
                    operationStatus = OperationStatus(
                        "Trans proof verification",
                        false,
                        transVerificationSummary ?: message
                    )
                } else {
                    isVerifyingTrans = true
                    error = null
                    startProofWorker("trans-regex-proof-verify") {
                        try {
                            val verifyStart = System.currentTimeMillis()
                            val verified = verifyCircomProof(
                                portTransZkeyPath,
                                transProofResult,
                                ProofLib.ARKWORKS
                            )
                            val verifiedMs = System.currentTimeMillis() - verifyStart
                            val accepted = verified && transProofResult.inputs.firstOrNull() == "1"
                            transVerificationSummary = formatUint16VerificationSummary(
                                label = "Trans",
                                rawInput = transInput,
                                normalizedInput = transNormalizedInput,
                                proofGenerated = true,
                                proofVerified = verified,
                                accepted = accepted,
                                proofInputs = transProofResult.inputs,
                                provingMs = null,
                                verifyingMs = verifiedMs,
                                errorMessage = null
                            )
                            operationStatus = OperationStatus(
                                "Trans proof verification",
                                accepted,
                                transVerificationSummary ?: "No Trans verification output"
                            )
                        } catch (e: Exception) {
                            val message = e.message ?: e.toString()
                            transVerificationSummary = formatUint16VerificationSummary(
                                label = "Trans",
                                rawInput = transInput,
                                normalizedInput = transNormalizedInput,
                                proofGenerated = true,
                                proofVerified = false,
                                accepted = false,
                                proofInputs = transProofResult.inputs,
                                provingMs = null,
                                verifyingMs = null,
                                errorMessage = message
                            )
                            operationStatus = OperationStatus(
                                "Trans proof verification",
                                false,
                                transVerificationSummary ?: message
                            )
                        } finally {
                            isVerifyingTrans = false
                        }
                    }
                }
            },
            onUnitInputChange = {
                unitInput = it
                unitProofResult = emptyProofResult()
                unitNormalizedInput = null
                unitVerificationSummary = null
                clearRegexRecordProof()
            },
            onGenerateUnitProof = {
                isVerifyingUnit = true
                error = null
                startProofWorker("unit-regex-proof-generate") {
                    try {
                        val (circuitInput, normalizedUnit) = buildUintDecimalCircuitInput(
                            rawInput = unitInput,
                            fieldLabel = "Unit",
                            digits = 3,
                            maxValue = 255
                        )
                        val startTime = System.currentTimeMillis()
                        unitProofResult = generateCircomProof(
                            unitZkeyPath,
                            circuitInput,
                            ProofLib.ARKWORKS
                        )
                        val generatedMs = System.currentTimeMillis() - startTime
                        unitNormalizedInput = normalizedUnit
                        unitVerificationSummary = formatUintFieldVerificationSummary(
                            label = "Unit",
                            rawInput = unitInput,
                            normalizedInput = normalizedUnit,
                            maxValue = 255,
                            proofGenerated = true,
                            proofVerified = null,
                            accepted = null,
                            proofInputs = unitProofResult.inputs,
                            provingMs = generatedMs,
                            verifyingMs = null,
                            errorMessage = null
                        )
                        operationStatus = OperationStatus(
                            "Unit proof generation",
                            true,
                            unitVerificationSummary ?: "No Unit verification output"
                        )
                    } catch (e: Exception) {
                        val message = e.message ?: e.toString()
                        unitProofResult = emptyProofResult()
                        unitNormalizedInput = null
                        unitVerificationSummary = formatUintFieldVerificationSummary(
                            label = "Unit",
                            rawInput = unitInput,
                            normalizedInput = null,
                            maxValue = 255,
                            proofGenerated = false,
                            proofVerified = null,
                            accepted = false,
                            proofInputs = emptyList(),
                            provingMs = null,
                            verifyingMs = null,
                            errorMessage = message
                        )
                        operationStatus = OperationStatus(
                            "Unit proof generation",
                            false,
                            unitVerificationSummary ?: message
                        )
                    } finally {
                        isVerifyingUnit = false
                    }
                }
            },
            onVerifyUnitProof = {
                if (unitProofResult.proof.a.x.isEmpty()) {
                    val message = "Generate Unit proof before local verification"
                    unitVerificationSummary = formatUintFieldVerificationSummary(
                        label = "Unit",
                        rawInput = unitInput,
                        normalizedInput = unitNormalizedInput,
                        maxValue = 255,
                        proofGenerated = false,
                        proofVerified = false,
                        accepted = false,
                        proofInputs = emptyList(),
                        provingMs = null,
                        verifyingMs = null,
                        errorMessage = message
                    )
                    operationStatus = OperationStatus(
                        "Unit proof verification",
                        false,
                        unitVerificationSummary ?: message
                    )
                } else {
                    isVerifyingUnit = true
                    error = null
                    startProofWorker("unit-regex-proof-verify") {
                        try {
                            val verifyStart = System.currentTimeMillis()
                            val verified = verifyCircomProof(
                                unitZkeyPath,
                                unitProofResult,
                                ProofLib.ARKWORKS
                            )
                            val verifiedMs = System.currentTimeMillis() - verifyStart
                            val accepted = verified && unitProofResult.inputs.firstOrNull() == "1"
                            unitVerificationSummary = formatUintFieldVerificationSummary(
                                label = "Unit",
                                rawInput = unitInput,
                                normalizedInput = unitNormalizedInput,
                                maxValue = 255,
                                proofGenerated = true,
                                proofVerified = verified,
                                accepted = accepted,
                                proofInputs = unitProofResult.inputs,
                                provingMs = null,
                                verifyingMs = verifiedMs,
                                errorMessage = null
                            )
                            operationStatus = OperationStatus(
                                "Unit proof verification",
                                accepted,
                                unitVerificationSummary ?: "No Unit verification output"
                            )
                        } catch (e: Exception) {
                            val message = e.message ?: e.toString()
                            unitVerificationSummary = formatUintFieldVerificationSummary(
                                label = "Unit",
                                rawInput = unitInput,
                                normalizedInput = unitNormalizedInput,
                                maxValue = 255,
                                proofGenerated = true,
                                proofVerified = false,
                                accepted = false,
                                proofInputs = unitProofResult.inputs,
                                provingMs = null,
                                verifyingMs = null,
                                errorMessage = message
                            )
                            operationStatus = OperationStatus(
                                "Unit proof verification",
                                false,
                                unitVerificationSummary ?: message
                            )
                        } finally {
                            isVerifyingUnit = false
                        }
                    }
                }
            },
            onProtocolInputChange = {
                protocolInput = it
                protocolProofResult = emptyProofResult()
                protocolNormalizedInput = null
                protocolVerificationSummary = null
                clearRegexRecordProof()
            },
            onGenerateProtocolProof = {
                isVerifyingProtocol = true
                error = null
                startProofWorker("protocol-regex-proof-generate") {
                    try {
                        val (circuitInput, normalizedProtocol) = buildProtocolRegexCircuitInput(protocolInput)
                        val startTime = System.currentTimeMillis()
                        protocolProofResult = generateCircomProof(
                            protocolRegexZkeyPath,
                            circuitInput,
                            ProofLib.ARKWORKS
                        )
                        val generatedMs = System.currentTimeMillis() - startTime
                        protocolNormalizedInput = normalizedProtocol
                        protocolVerificationSummary = formatProtocolVerificationSummary(
                            rawInput = protocolInput,
                            normalizedInput = normalizedProtocol,
                            proofGenerated = true,
                            proofVerified = null,
                            accepted = null,
                            proofInputs = protocolProofResult.inputs,
                            provingMs = generatedMs,
                            verifyingMs = null,
                            errorMessage = null
                        )
                        operationStatus = OperationStatus(
                            "Protocol proof generation",
                            true,
                            protocolVerificationSummary ?: "No protocol verification output"
                        )
                    } catch (e: Exception) {
                        val message = e.message ?: e.toString()
                        protocolProofResult = emptyProofResult()
                        protocolNormalizedInput = null
                        protocolVerificationSummary = formatProtocolVerificationSummary(
                            rawInput = protocolInput,
                            normalizedInput = null,
                            proofGenerated = false,
                            proofVerified = null,
                            accepted = false,
                            proofInputs = emptyList(),
                            provingMs = null,
                            verifyingMs = null,
                            errorMessage = message
                        )
                        operationStatus = OperationStatus(
                            "Protocol proof generation",
                            false,
                            protocolVerificationSummary ?: message
                        )
                    } finally {
                        isVerifyingProtocol = false
                    }
                }
            },
            onVerifyProtocolProof = {
                if (protocolProofResult.proof.a.x.isEmpty()) {
                    val message = "Generate protocol proof before local verification"
                    protocolVerificationSummary = formatProtocolVerificationSummary(
                        rawInput = protocolInput,
                        normalizedInput = protocolNormalizedInput,
                        proofGenerated = false,
                        proofVerified = false,
                        accepted = false,
                        proofInputs = emptyList(),
                        provingMs = null,
                        verifyingMs = null,
                        errorMessage = message
                    )
                    operationStatus = OperationStatus(
                        "Protocol proof verification",
                        false,
                        protocolVerificationSummary ?: message
                    )
                } else {
                    isVerifyingProtocol = true
                    error = null
                    startProofWorker("protocol-regex-proof-verify") {
                        try {
                            val verifyStart = System.currentTimeMillis()
                            val verified = verifyCircomProof(
                                protocolRegexZkeyPath,
                                protocolProofResult,
                                ProofLib.ARKWORKS
                            )
                            val verifiedMs = System.currentTimeMillis() - verifyStart
                            val accepted = verified && protocolProofResult.inputs.firstOrNull() == "1"
                            protocolVerificationSummary = formatProtocolVerificationSummary(
                                rawInput = protocolInput,
                                normalizedInput = protocolNormalizedInput,
                                proofGenerated = true,
                                proofVerified = verified,
                                accepted = accepted,
                                proofInputs = protocolProofResult.inputs,
                                provingMs = null,
                                verifyingMs = verifiedMs,
                                errorMessage = null
                            )
                            operationStatus = OperationStatus(
                                "Protocol proof verification",
                                accepted,
                                protocolVerificationSummary ?: "No protocol verification output"
                            )
                        } catch (e: Exception) {
                            val message = e.message ?: e.toString()
                            protocolVerificationSummary = formatProtocolVerificationSummary(
                                rawInput = protocolInput,
                                normalizedInput = protocolNormalizedInput,
                                proofGenerated = true,
                                proofVerified = false,
                                accepted = false,
                                proofInputs = protocolProofResult.inputs,
                                provingMs = null,
                                verifyingMs = null,
                                errorMessage = message
                            )
                            operationStatus = OperationStatus(
                                "Protocol proof verification",
                                false,
                                protocolVerificationSummary ?: message
                            )
                        } finally {
                            isVerifyingProtocol = false
                        }
                    }
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
            sourceIpVerificationSummary = sourceIpVerificationSummary,
            destinationIpVerificationSummary = destinationIpVerificationSummary,
            timestampVerificationSummary = timestampVerificationSummary,
            portVerificationSummary = portVerificationSummary,
            transVerificationSummary = transVerificationSummary,
            unitVerificationSummary = unitVerificationSummary,
            protocolVerificationSummary = protocolVerificationSummary,
            regexRecordVerificationSummary = regexRecordVerificationSummary,
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
            sourceIpVerificationSummary = sourceIpVerificationSummary,
            destinationIpVerificationSummary = destinationIpVerificationSummary,
            timestampVerificationSummary = timestampVerificationSummary,
            portVerificationSummary = portVerificationSummary,
            transVerificationSummary = transVerificationSummary,
            unitVerificationSummary = unitVerificationSummary,
            protocolVerificationSummary = protocolVerificationSummary,
            regexRecordVerificationSummary = regexRecordVerificationSummary,
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
/** 顶部栏，展示当前用户、服务端 host 和退出入口。 */
private fun AppHeader(
    // username：当前登录用户名。
    username: String,
    // serverUrl：用户输入的服务端 verify URL。
    serverUrl: String,
    // onLogout：退出当前服务端 session。
    onLogout: () -> Unit
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
            CompactActionButton(
                "Logout",
                enabled = true,
                outlined = true,
                modifier = Modifier.widthIn(min = 92.dp),
                onClick = onLogout
            )
        }
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
/** Location 弹窗，集中放置账号、key、GNSS、resolution 和实验导出操作。 */
private fun ActionSetDialog(
    // serverUrl：当前服务端地址。
    serverUrl: String,
    // selectedResolution：当前 H3 resolution。
    selectedResolution: Int,
    // resolutionMenuExpanded：resolution 下拉菜单是否展开。
    resolutionMenuExpanded: Boolean,
    // isBusy：是否禁用所有动作按钮。
    isBusy: Boolean,
    // isLoggedIn：按钮启用条件。
    isLoggedIn: Boolean,
    // hasKey：是否已在本次登录后生成并绑定 Keystore key。
    hasKey: Boolean,
    // hasLocation：是否已有 GNSS 坐标，可用于生成位置 proof。
    hasLocation: Boolean,
    // hasProof：是否已有可本地验证的位置 proof。
    hasProof: Boolean,
    // hasSignature：是否已有当前 proof commitment 的 Keystore 签名。
    hasSignature: Boolean,
    // onDismiss：关闭弹窗。
    onDismiss: () -> Unit,
    // onServerUrlChange：更新服务端地址。
    onServerUrlChange: (String) -> Unit,
    // onVerifyKey...onSelectResolution：各业务动作回调，由父组件持有真实状态。
    onVerifyKey: () -> Unit,
    onBindKey: () -> Unit,
    onGetGnss: () -> Unit,
    onGenerateProof: () -> Unit,
    onVerifyProof: () -> Unit,
    onSignCommitment: () -> Unit,
    onSendProof: () -> Unit,
    onResolutionMenuChange: (Boolean) -> Unit,
    onSelectResolution: (Int) -> Unit
) {
    AlertDialog(
        onDismissRequest = onDismiss,
        shape = RoundedCornerShape(8.dp),
        title = {
            Text(
                "Location",
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
                CompactActionButton("Verify key", enabled = !isBusy && isLoggedIn, outlined = true, onClick = onVerifyKey)
                CompactActionButton("Generate new key and bind", enabled = !isBusy && isLoggedIn, onClick = onBindKey)
                Text(
                    "Location",
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
                CompactActionButton("Verify proof", enabled = !isBusy && hasProof, outlined = true, onClick = onVerifyProof)
                CompactActionButton("Sign commitment", enabled = !isBusy && isLoggedIn && hasKey && hasProof, outlined = true, onClick = onSignCommitment)
                CompactActionButton("Send proof to server", enabled = !isBusy && isLoggedIn && hasKey && hasProof && hasSignature, onClick = onSendProof)
            }
        },
        confirmButton = {
            CompactActionButton("Close", enabled = !isBusy, outlined = true, onClick = onDismiss)
        }
    )
}

@Suppress("UNUSED_PARAMETER")
@Composable
/** Regex 弹窗，集中放置 IPv4、时间戳、Port/Trans/Unit 数字字段和协议 proof 的本地生成和本地验证。 */
private fun RegexSetDialog(
    // regexImportText：JSON 导入文本。
    regexImportText: String,
    // sourceIpInput：Source IP 正则 proof 的原始用户输入。
    sourceIpInput: String,
    // destinationIpInput：Destination IP 正则 proof 的原始用户输入。
    destinationIpInput: String,
    // timestampInput：时间戳正则 proof 的原始用户输入。
    timestampInput: String,
    // portInput：端口正则 proof 的原始用户输入。
    portInput: String,
    // transInput：事务 ID proof 的原始用户输入。
    transInput: String,
    // unitInput：Unit proof 的原始用户输入。
    unitInput: String,
    // protocolInput：协议成员 proof 的原始用户输入。
    protocolInput: String,
    // isBusy：是否禁用所有动作按钮。
    isBusy: Boolean,
    sourceIpVerificationSummary: String?,
    destinationIpVerificationSummary: String?,
    timestampVerificationSummary: String?,
    portVerificationSummary: String?,
    transVerificationSummary: String?,
    unitVerificationSummary: String?,
    protocolVerificationSummary: String?,
    regexRecordVerificationSummary: String?,
    // hasSourceIpProof...hasProtocolProof：对应输入是否已经生成过本地 proof。
    hasSourceIpProof: Boolean,
    hasDestinationIpProof: Boolean,
    hasTimestampProof: Boolean,
    hasPortProof: Boolean,
    hasTransProof: Boolean,
    hasUnitProof: Boolean,
    hasProtocolProof: Boolean,
    hasRegexRecordProof: Boolean,
    // onDismiss：关闭弹窗。
    onDismiss: () -> Unit,
    // onRegexImport...：更新、解析 JSON 文本或从文件选择 JSON 内容。
    onRegexImportTextChange: (String) -> Unit,
    onParseRegexImportText: () -> Unit,
    onPickRegexJsonFile: () -> Unit,
    // onGenerateAllProofs/onVerifyAllProofs：批量生成和批量验证当前全部 Regex proof。
    onGenerateAllProofs: () -> Unit,
    onVerifyAllProofs: () -> Unit,
    onGenerateRecordProof: () -> Unit,
    onViewRecordProof: () -> Unit,
    onVerifyRecordProof: () -> Unit,
    onSendRecordProofToServer: () -> Unit,
    // onSourceIpInputChange：更新 Source IP 验证输入。
    onSourceIpInputChange: (String) -> Unit,
    // onGenerateSourceIpProof/onVerifySourceIpProof：生成 proof 与验证 proof 的两步操作。
    onGenerateSourceIpProof: () -> Unit,
    onVerifySourceIpProof: () -> Unit,
    // onDestinationIpInputChange：更新 Destination IP 验证输入。
    onDestinationIpInputChange: (String) -> Unit,
    // onGenerateDestinationIpProof/onVerifyDestinationIpProof：生成 proof 与验证 proof 的两步操作。
    onGenerateDestinationIpProof: () -> Unit,
    onVerifyDestinationIpProof: () -> Unit,
    // onTimestampInputChange：更新时间戳验证输入。
    onTimestampInputChange: (String) -> Unit,
    // onGenerateTimestampProof/onVerifyTimestampProof：时间戳 proof 的生成和验证操作。
    onGenerateTimestampProof: () -> Unit,
    onVerifyTimestampProof: () -> Unit,
    // onPortInputChange：更新端口验证输入。
    onPortInputChange: (String) -> Unit,
    // onGeneratePortProof/onVerifyPortProof：端口 proof 的生成和验证操作。
    onGeneratePortProof: () -> Unit,
    onVerifyPortProof: () -> Unit,
    // onTransInputChange：更新事务 ID 验证输入。
    onTransInputChange: (String) -> Unit,
    // onGenerateTransProof/onVerifyTransProof：事务 ID proof 的生成和验证操作。
    onGenerateTransProof: () -> Unit,
    onVerifyTransProof: () -> Unit,
    // onUnitInputChange：更新 Unit 验证输入。
    onUnitInputChange: (String) -> Unit,
    // onGenerateUnitProof/onVerifyUnitProof：Unit proof 的生成和验证操作。
    onGenerateUnitProof: () -> Unit,
    onVerifyUnitProof: () -> Unit,
    // onProtocolInputChange：更新协议验证输入。
    onProtocolInputChange: (String) -> Unit,
    // onGenerateProtocolProof/onVerifyProtocolProof：协议 proof 的生成和验证操作。
    onGenerateProtocolProof: () -> Unit,
    onVerifyProtocolProof: () -> Unit
) {
    AlertDialog(
        onDismissRequest = onDismiss,
        shape = RoundedCornerShape(8.dp),
        title = {
            Text(
                "Regex",
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
                    value = regexImportText,
                    onValueChange = onRegexImportTextChange,
                    modifier = Modifier.fillMaxWidth(),
                    enabled = !isBusy,
                    minLines = 3,
                    maxLines = 6,
                    shape = RoundedCornerShape(8.dp),
                    label = { Text("JSON text or file content", fontSize = 12.sp) },
                    textStyle = MaterialTheme.typography.bodySmall
                )
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    CompactActionButton(
                        "Apply JSON",
                        enabled = !isBusy,
                        modifier = Modifier.weight(1f),
                        onClick = onParseRegexImportText
                    )
                    CompactActionButton(
                        "Pick file",
                        enabled = !isBusy,
                        outlined = true,
                        modifier = Modifier.weight(1f),
                        onClick = onPickRegexJsonFile
                    )
                }
                Text(
                    "Record proof",
                    modifier = Modifier.fillMaxWidth(),
                    style = MaterialTheme.typography.labelMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                CompactActionButton("Generate record proof", enabled = !isBusy, onClick = onGenerateRecordProof)
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    CompactActionButton(
                        "View record proof",
                        enabled = !isBusy && regexRecordVerificationSummary != null,
                        outlined = true,
                        modifier = Modifier.weight(1f),
                        onClick = onViewRecordProof
                    )
                    CompactActionButton(
                        "Verify record proof",
                        enabled = !isBusy && hasRegexRecordProof,
                        outlined = true,
                        modifier = Modifier.weight(1f),
                        onClick = onVerifyRecordProof
                    )
                }
                CompactActionButton(
                    "Send record proof to server",
                    enabled = !isBusy && hasRegexRecordProof,
                    onClick = onSendRecordProofToServer
                )
                HorizontalDivider()
                OutlinedTextField(
                    value = sourceIpInput,
                    onValueChange = onSourceIpInputChange,
                    modifier = Modifier.fillMaxWidth(),
                    enabled = !isBusy,
                    singleLine = true,
                    shape = RoundedCornerShape(8.dp),
                    label = { Text("Source IP", fontSize = 12.sp) },
                    textStyle = MaterialTheme.typography.bodySmall
                )
                HorizontalDivider()
                OutlinedTextField(
                    value = destinationIpInput,
                    onValueChange = onDestinationIpInputChange,
                    modifier = Modifier.fillMaxWidth(),
                    enabled = !isBusy,
                    singleLine = true,
                    shape = RoundedCornerShape(8.dp),
                    label = { Text("Destination IP", fontSize = 12.sp) },
                    textStyle = MaterialTheme.typography.bodySmall
                )
                HorizontalDivider()
                OutlinedTextField(
                    value = timestampInput,
                    onValueChange = onTimestampInputChange,
                    modifier = Modifier.fillMaxWidth(),
                    enabled = !isBusy,
                    singleLine = true,
                    shape = RoundedCornerShape(8.dp),
                    label = { Text("Timestamp", fontSize = 12.sp) },
                    textStyle = MaterialTheme.typography.bodySmall
                )
                HorizontalDivider()
                OutlinedTextField(
                    value = portInput,
                    onValueChange = onPortInputChange,
                    modifier = Modifier.fillMaxWidth(),
                    enabled = !isBusy,
                    singleLine = true,
                    shape = RoundedCornerShape(8.dp),
                    label = { Text("Port", fontSize = 12.sp) },
                    textStyle = MaterialTheme.typography.bodySmall
                )
                HorizontalDivider()
                OutlinedTextField(
                    value = transInput,
                    onValueChange = onTransInputChange,
                    modifier = Modifier.fillMaxWidth(),
                    enabled = !isBusy,
                    singleLine = true,
                    shape = RoundedCornerShape(8.dp),
                    label = { Text("Trans", fontSize = 12.sp) },
                    textStyle = MaterialTheme.typography.bodySmall
                )
                HorizontalDivider()
                OutlinedTextField(
                    value = unitInput,
                    onValueChange = onUnitInputChange,
                    modifier = Modifier.fillMaxWidth(),
                    enabled = !isBusy,
                    singleLine = true,
                    shape = RoundedCornerShape(8.dp),
                    label = { Text("Unit", fontSize = 12.sp) },
                    textStyle = MaterialTheme.typography.bodySmall
                )
                HorizontalDivider()
                OutlinedTextField(
                    value = protocolInput,
                    onValueChange = onProtocolInputChange,
                    modifier = Modifier.fillMaxWidth(),
                    enabled = !isBusy,
                    singleLine = true,
                    shape = RoundedCornerShape(8.dp),
                    label = { Text("Protocol", fontSize = 12.sp) },
                    textStyle = MaterialTheme.typography.bodySmall
                )
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
    sourceIpVerificationSummary: String?,
    destinationIpVerificationSummary: String?,
    timestampVerificationSummary: String?,
    portVerificationSummary: String?,
    transVerificationSummary: String?,
    unitVerificationSummary: String?,
    protocolVerificationSummary: String?,
    regexRecordVerificationSummary: String?,
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
                    label = "Source IP",
                    enabled = sourceIpVerificationSummary != null,
                    selected = selectedOutput == OutputSection.SOURCE_IP,
                    onClick = { onSelectOutput(OutputSection.SOURCE_IP) }
                )
                OutputSectionButton(
                    label = "Destination IP",
                    enabled = destinationIpVerificationSummary != null,
                    selected = selectedOutput == OutputSection.DESTINATION_IP,
                    onClick = { onSelectOutput(OutputSection.DESTINATION_IP) }
                )
                OutputSectionButton(
                    label = "Timestamp",
                    enabled = timestampVerificationSummary != null,
                    selected = selectedOutput == OutputSection.TIMESTAMP,
                    onClick = { onSelectOutput(OutputSection.TIMESTAMP) }
                )
                OutputSectionButton(
                    label = "Port",
                    enabled = portVerificationSummary != null,
                    selected = selectedOutput == OutputSection.PORT,
                    onClick = { onSelectOutput(OutputSection.PORT) }
                )
                OutputSectionButton(
                    label = "Trans",
                    enabled = transVerificationSummary != null,
                    selected = selectedOutput == OutputSection.TRANS,
                    onClick = { onSelectOutput(OutputSection.TRANS) }
                )
                OutputSectionButton(
                    label = "Unit",
                    enabled = unitVerificationSummary != null,
                    selected = selectedOutput == OutputSection.UNIT,
                    onClick = { onSelectOutput(OutputSection.UNIT) }
                )
                OutputSectionButton(
                    label = "Protocol",
                    enabled = protocolVerificationSummary != null,
                    selected = selectedOutput == OutputSection.PROTOCOL,
                    onClick = { onSelectOutput(OutputSection.PROTOCOL) }
                )
                OutputSectionButton(
                    label = "Record",
                    enabled = regexRecordVerificationSummary != null,
                    selected = selectedOutput == OutputSection.RECORD,
                    onClick = { onSelectOutput(OutputSection.RECORD) }
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
    sourceIpVerificationSummary: String?,
    destinationIpVerificationSummary: String?,
    timestampVerificationSummary: String?,
    portVerificationSummary: String?,
    transVerificationSummary: String?,
    unitVerificationSummary: String?,
    protocolVerificationSummary: String?,
    regexRecordVerificationSummary: String?,
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

                    OutputSection.SOURCE_IP -> {
                        Text(sourceIpVerificationSummary ?: "No Source IP verification output", style = MaterialTheme.typography.bodyMedium)
                    }

                    OutputSection.DESTINATION_IP -> {
                        Text(destinationIpVerificationSummary ?: "No Destination IP verification output", style = MaterialTheme.typography.bodyMedium)
                    }

                    OutputSection.TIMESTAMP -> {
                        Text(timestampVerificationSummary ?: "No timestamp verification output", style = MaterialTheme.typography.bodyMedium)
                    }

                    OutputSection.PORT -> {
                        Text(portVerificationSummary ?: "No port verification output", style = MaterialTheme.typography.bodyMedium)
                    }

                    OutputSection.TRANS -> {
                        Text(transVerificationSummary ?: "No Trans verification output", style = MaterialTheme.typography.bodyMedium)
                    }

                    OutputSection.UNIT -> {
                        Text(unitVerificationSummary ?: "No Unit verification output", style = MaterialTheme.typography.bodyMedium)
                    }

                    OutputSection.PROTOCOL -> {
                        Text(protocolVerificationSummary ?: "No protocol verification output", style = MaterialTheme.typography.bodyMedium)
                    }

                    OutputSection.RECORD -> {
                        Text(regexRecordVerificationSummary ?: "No record proof output", style = MaterialTheme.typography.bodyMedium)
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

/** 简洁输出格式，用于操作弹窗，避免长解释堆叠。 */
private fun compactValue(label: String, value: String): String {
    return "$label: ${value.ifBlank { "-" }}"
}

/** 将 Circom proof 公开输入转换为 UI 摘要。 */
private fun formatProofSummary(proofResult: CircomProofResult): String {
    return listOf(
        compactValue("Commitment", shortValue(proofResult.inputs.firstOrNull().orEmpty())),
        compactValue("Public inputs", proofResult.inputs.size.toString())
    ).joinToString("\n")
}

/** 用较大的线程栈运行 mopro native prover，避免 witness/prover 在默认 Java Thread 栈上崩溃。 */
private fun startProofWorker(name: String, block: () -> Unit) {
    // stackSizeBytes：native witness/prover 有较深调用栈，64 MiB 给 Android 真机留足余量。
    val stackSizeBytes = 64L * 1024L * 1024L
    Thread(null, Runnable { block() }, name, stackSizeBytes).start()
}

/** 将用户 IPv4 输入转换为 regex_ip 电路输入 JSON。 */
private fun buildIpv4RegexCircuitInput(rawInput: String): Pair<String, String> {
    // trimmedInput：去掉首尾空白后的用户输入。
    val trimmedInput = rawInput.trim()
    // parts：按点号拆分出的四个 IPv4 段。
    val parts = trimmedInput.split('.')
    require(parts.size == 4) {
        "IPv4 must contain exactly four segments separated by three dots"
    }

    // normalizedParts：每段左补零为 3 位，便于电路固定读取 ddd.ddd.ddd.ddd。
    val normalizedParts = parts.mapIndexed { index, part ->
        require(part.isNotEmpty()) {
            "IPv4 segment ${index + 1} is empty"
        }
        require(part.length <= 3) {
            "IPv4 segment ${index + 1} is longer than 3 characters"
        }
        require(part.all { it in '0'..'9' }) {
            "IPv4 segment ${index + 1} must contain only digits"
        }
        require(part.toInt() <= 255) {
            "IPv4 segment ${index + 1} must be in 0..255"
        }
        part.padStart(3, '0')
    }
    // normalizedIp：电路实际验证的 15 字节字符串。
    val normalizedIp = normalizedParts.joinToString(".")
    // asciiValues：normalizedIp 的 ASCII/Unicode code point，电路会约束它们必须是数字或点号。
    val asciiValues = normalizedIp.map { char -> char.code.toString() }
    // circuitInput：mopro generateCircomProof 接收的 JSON 输入。
    val circuitInput = JSONObject()
        .put("msg", JSONArray(asciiValues))
        .toString()

    return circuitInput to normalizedIp
}

/** 生成 IPv4 本地 ZK 正则验证摘要。 */
private fun formatIpv4VerificationSummary(
    rawInput: String,
    normalizedInput: String?,
    proofGenerated: Boolean,
    proofVerified: Boolean?,
    accepted: Boolean?,
    proofInputs: List<String>,
    provingMs: Long?,
    verifyingMs: Long?,
    errorMessage: String?
): String {
    return listOfNotNull(
        compactValue("Input", rawInput),
        normalizedInput?.let { compactValue("Circuit input", it) },
        compactValue("Generated", proofGenerated.toString()),
        proofVerified?.let { compactValue("Verified", it.toString()) },
        accepted?.let { compactValue("Valid", it.toString()) },
        proofInputs.firstOrNull()?.let { compactValue("Public output", it) },
        provingMs?.let { compactValue("Proving", "$it ms") },
        verifyingMs?.let { compactValue("Verifying", "$it ms") },
        errorMessage?.let { compactValue("Error", it) }
    ).joinToString("\n")
}

/** 将用户端口或事务 ID 输入转换为 port_trans 电路输入 JSON。 */
private fun buildPortRegexCircuitInput(rawInput: String, fieldLabel: String = "Port"): Pair<String, String> {
    return buildUintDecimalCircuitInput(
        rawInput = rawInput,
        fieldLabel = fieldLabel,
        digits = 5,
        maxValue = 65535
    )
}

/** 将通用十进制数字字段输入转换为 UintDecimalField 电路输入 JSON。 */
private fun buildUintDecimalCircuitInput(
    rawInput: String,
    fieldLabel: String,
    digits: Int,
    maxValue: Int
): Pair<String, String> {
    // trimmedInput：去掉首尾空白后的用户数字字段输入。
    val trimmedInput = rawInput.trim()
    require(trimmedInput.isNotEmpty()) {
        "$fieldLabel must not be empty"
    }
    require(trimmedInput.length <= digits) {
        "$fieldLabel must be at most $digits digits"
    }
    require(trimmedInput.all { it in '0'..'9' }) {
        "$fieldLabel must contain only digits"
    }

    // fieldValue：解析后的十进制整数，范围必须和入口电路的 MAX_VALUE 参数一致。
    val fieldValue = trimmedInput.toInt()
    require(fieldValue in 0..maxValue) {
        "$fieldLabel must be in 0..$maxValue"
    }

    // normalizedField：电路实际验证的固定 digits 字节数字字符串。
    val normalizedField = trimmedInput.padStart(digits, '0')
    // asciiValues：normalizedField 的 ASCII code point，电路会再次验证数字格式和范围。
    val asciiValues = normalizedField.map { char -> char.code.toString() }
    val circuitInput = JSONObject()
        .put("msg", JSONArray(asciiValues))
        .toString()

    return circuitInput to normalizedField
}

/** 生成端口本地 ZK 正则验证摘要。 */
private fun formatPortVerificationSummary(
    rawInput: String,
    normalizedInput: String?,
    proofGenerated: Boolean,
    proofVerified: Boolean?,
    accepted: Boolean?,
    proofInputs: List<String>,
    provingMs: Long?,
    verifyingMs: Long?,
    errorMessage: String?
): String {
    return formatUint16VerificationSummary(
        label = "Port",
        rawInput = rawInput,
        normalizedInput = normalizedInput,
        proofGenerated = proofGenerated,
        proofVerified = proofVerified,
        accepted = accepted,
        proofInputs = proofInputs,
        provingMs = provingMs,
        verifyingMs = verifyingMs,
        errorMessage = errorMessage
    )
}

/** 生成复用 port_trans 电路的 16-bit 数字字段本地 ZK 验证摘要。 */
private fun formatUint16VerificationSummary(
    label: String,
    rawInput: String,
    normalizedInput: String?,
    proofGenerated: Boolean,
    proofVerified: Boolean?,
    accepted: Boolean?,
    proofInputs: List<String>,
    provingMs: Long?,
    verifyingMs: Long?,
    errorMessage: String?
): String {
    return formatUintFieldVerificationSummary(
        label = label,
        rawInput = rawInput,
        normalizedInput = normalizedInput,
        maxValue = 65535,
        proofGenerated = proofGenerated,
        proofVerified = proofVerified,
        accepted = accepted,
        proofInputs = proofInputs,
        provingMs = provingMs,
        verifyingMs = verifyingMs,
        errorMessage = errorMessage
    )
}

/** 生成通用数字字段本地 ZK 验证摘要。 */
private fun formatUintFieldVerificationSummary(
    label: String,
    rawInput: String,
    normalizedInput: String?,
    maxValue: Int,
    proofGenerated: Boolean,
    proofVerified: Boolean?,
    accepted: Boolean?,
    proofInputs: List<String>,
    provingMs: Long?,
    verifyingMs: Long?,
    errorMessage: String?
): String {
    val circuitName = if (maxValue == 65535) "port_trans" else "unit"
    return listOfNotNull(
        compactValue("Field", label),
        compactValue("Input", rawInput),
        normalizedInput?.let { compactValue("Circuit input", it) },
        compactValue("Circuit", circuitName),
        compactValue("Generated", proofGenerated.toString()),
        proofVerified?.let { compactValue("Verified", it.toString()) },
        accepted?.let { compactValue("Valid", it.toString()) },
        proofInputs.firstOrNull()?.let { compactValue("Public output", it) },
        provingMs?.let { compactValue("Proving", "$it ms") },
        verifyingMs?.let { compactValue("Verifying", "$it ms") },
        errorMessage?.let { compactValue("Error", it) }
    ).joinToString("\n")
}

/** 将用户协议输入转换为 protocol_regex 电路输入 JSON。 */
private fun buildProtocolRegexCircuitInput(rawInput: String): Pair<String, String> {
    // protocol：去掉首尾空白后的协议字段，当前大小写敏感。
    val protocol = rawInput.trim()
    // allowedProtocols：当前 PLC 报文实验接受的协议名称集合。
    val allowedProtocols = setOf("Modbus/TCP", "ARP", "DHCP", "TCP")
    require(protocol in allowedProtocols) {
        "Protocol must be one of Modbus/TCP, ARP, DHCP, TCP"
    }

    // asciiBytes：固定 10 字节电路输入；短协议右侧用 0 补齐。
    val asciiBytes = MutableList(10) { "0" }
    protocol.forEachIndexed { index, char ->
        asciiBytes[index] = char.code.toString()
    }
    val circuitInput = JSONObject()
        .put("msg", JSONArray(asciiBytes))
        .toString()

    return circuitInput to asciiBytes.joinToString(prefix = "[", postfix = "]")
}

/** 生成协议成员本地 ZK 验证摘要。 */
private fun formatProtocolVerificationSummary(
    rawInput: String,
    normalizedInput: String?,
    proofGenerated: Boolean,
    proofVerified: Boolean?,
    accepted: Boolean?,
    proofInputs: List<String>,
    provingMs: Long?,
    verifyingMs: Long?,
    errorMessage: String?
): String {
    return listOfNotNull(
        compactValue("Input", rawInput),
        normalizedInput?.let { compactValue("Circuit bytes", it) },
        compactValue("Generated", proofGenerated.toString()),
        proofVerified?.let { compactValue("Verified", it.toString()) },
        accepted?.let { compactValue("Valid", it.toString()) },
        proofInputs.firstOrNull()?.let { compactValue("Public output", it) },
        provingMs?.let { compactValue("Proving", "$it ms") },
        verifyingMs?.let { compactValue("Verifying", "$it ms") },
        errorMessage?.let { compactValue("Error", it) }
    ).joinToString("\n")
}

/** 生成联合日志记录 proof 的本地 ZK 验证摘要。 */
private fun formatRegexRecordVerificationSummary(
    recordInput: RegexRecordCircuitInput?,
    proofGenerated: Boolean,
    proofVerified: Boolean?,
    accepted: Boolean?,
    proofInputs: List<String>,
    provingMs: Long?,
    verifyingMs: Long?,
    errorMessage: String?
): String {
    return listOfNotNull(
        compactValue("Generated", proofGenerated.toString()),
        proofVerified?.let { compactValue("Verified", it.toString()) },
        accepted?.let { compactValue("Valid", it.toString()) },
        provingMs?.let { compactValue("Proving", "$it ms") },
        verifyingMs?.let { compactValue("Verifying", "$it ms") },
        recordInput?.recordCommitment?.let { compactValue("Commitment", shortValue(it)) },
        recordInput?.normalizedSourceIp?.let { compactValue("Source IP", it) },
        recordInput?.normalizedDestinationIp?.let { compactValue("Destination IP", it) },
        recordInput?.normalizedTimestamp?.let { compactValue("Timestamp", it) },
        recordInput?.normalizedProtocolBytes?.let { compactValue("Protocol bytes", it) },
        proofInputs.firstOrNull()?.let { compactValue("Public input", shortValue(it)) },
        errorMessage?.let { compactValue("Error", it) }
    ).joinToString("\n")
}

private data class RegexRecordProofVerification(
    val verified: Boolean,
    val backend: String,
    val detail: String?
)

/** 联合日志记录 proof 的本地验证：Android 当前 native 构建使用 Arkworks。 */
private fun verifyRegexRecordProofWithFallback(
    zkeyPath: String,
    proofResult: CircomProofResult
): RegexRecordProofVerification {
    val arkworks = runCatching {
        verifyCircomProof(zkeyPath, proofResult, ProofLib.ARKWORKS)
    }
    if (arkworks.getOrNull() == true) {
        return RegexRecordProofVerification(
            verified = true,
            backend = "Arkworks",
            detail = null
        )
    }

    val rapidsnark = runCatching {
        verifyCircomProof(zkeyPath, proofResult, ProofLib.RAPIDSNARK)
    }
    if (rapidsnark.getOrNull() == true) {
        return RegexRecordProofVerification(
            verified = true,
            backend = "Rapidsnark fallback",
            detail = arkworks.exceptionOrNull()?.message ?: "Arkworks returned false"
        )
    }

    val detail = listOfNotNull(
        arkworks.exceptionOrNull()?.message ?: "Arkworks returned false",
        rapidsnark.exceptionOrNull()?.message ?: "Rapidsnark returned false"
    ).joinToString("; ")
    return RegexRecordProofVerification(
        verified = false,
        backend = "Arkworks + Rapidsnark fallback",
        detail = detail
    )
}

/** 将用户时间戳输入转换为 regex_timestamp 电路输入 JSON，并在进入 native prover 前执行同等语义校验。 */
private fun buildTimestampRegexCircuitInput(rawInput: String): Pair<String, String> {
    // normalizedTimestamp：时间戳不做补零，用户必须直接输入固定 26 字节格式。
    val normalizedTimestamp = rawInput.trim()
    val timestampPattern = Regex("""^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{6}$""")
    require(timestampPattern.matches(normalizedTimestamp)) {
        "Timestamp must use YYYY-MM-DD HH:mm:ss.ffffff"
    }

    // year...microsecond：固定位置解析出的时间字段，与电路读取位置保持一致。
    val year = normalizedTimestamp.substring(0, 4).toInt()
    val month = normalizedTimestamp.substring(5, 7).toInt()
    val day = normalizedTimestamp.substring(8, 10).toInt()
    val hour = normalizedTimestamp.substring(11, 13).toInt()
    val minute = normalizedTimestamp.substring(14, 16).toInt()
    val second = normalizedTimestamp.substring(17, 19).toInt()
    val microsecond = normalizedTimestamp.substring(20, 26).toInt()

    require(month in 1..12) { "Timestamp month must be in 1..12" }
    val maxDays = when (month) {
        2 -> if (isGregorianLeapYear(year)) 29 else 28
        4, 6, 9, 11 -> 30
        else -> 31
    }
    require(day in 1..maxDays) {
        "Timestamp day must be in 1..$maxDays for the selected year and month"
    }
    require(hour in 0..23) { "Timestamp hour must be in 0..23" }
    require(minute in 0..59) { "Timestamp minute must be in 0..59" }
    require(second in 0..59) { "Timestamp second must be in 0..59" }
    require(microsecond in 0..999999) { "Timestamp microsecond must be in 0..999999" }

    // asciiValues：固定时间戳的 ASCII code point，电路会再次验证格式、范围和闰年规则。
    val asciiValues = normalizedTimestamp.map { char -> char.code.toString() }
    val circuitInput = JSONObject()
        .put("msg", JSONArray(asciiValues))
        .toString()

    return circuitInput to normalizedTimestamp
}

/** 按公历规则判断年份是否为闰年，与 regex_timestamp 电路中的 IsLeapYear 保持一致。 */
private fun isGregorianLeapYear(year: Int): Boolean {
    return year % 400 == 0 || (year % 4 == 0 && year % 100 != 0)
}

/** 生成时间戳本地 ZK 正则验证摘要。 */
private fun formatTimestampVerificationSummary(
    rawInput: String,
    normalizedInput: String?,
    proofGenerated: Boolean,
    proofVerified: Boolean?,
    accepted: Boolean?,
    proofInputs: List<String>,
    provingMs: Long?,
    verifyingMs: Long?,
    errorMessage: String?
): String {
    return listOfNotNull(
        compactValue("Input", rawInput),
        normalizedInput?.let { compactValue("Circuit input", it) },
        compactValue("Generated", proofGenerated.toString()),
        proofVerified?.let { compactValue("Verified", it.toString()) },
        accepted?.let { compactValue("Valid", it.toString()) },
        proofInputs.firstOrNull()?.let { compactValue("Public output", it) },
        provingMs?.let { compactValue("Proving", "$it ms") },
        verifyingMs?.let { compactValue("Verifying", "$it ms") },
        errorMessage?.let { compactValue("Error", it) }
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
    SOURCE_IP("Source IP"),
    DESTINATION_IP("Destination IP"),
    TIMESTAMP("Timestamp"),
    PORT("Port"),
    TRANS("Trans"),
    UNIT("Unit"),
    PROTOCOL("Protocol"),
    RECORD("Record"),
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

/** 服务端 proof 验证结果摘要。 */
private data class ServerProofVerificationResponse(
    // valid：服务端对 proof + signature + nonce 的整体判定。
    val valid: Boolean,
    // summary：面向 UI 展示的验证摘要。
    val summary: String
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

private fun postProofToServer(
    serverUrl: String,
    token: String,
    proofResult: CircomProofResult,
    signature: LocationCommitmentSignature
): String {
    // response：服务端 /verify-proof 对 proof、签名、nonce 的整体验证结果。
    val response = postJson(
        url = endpointUrlFor(serverUrl, "/verify-proof"),
        body = proofResultToServerPayload(proofResult, signature),
        bearerToken = token
    )
    val parsed = formatServerProofResponse(response.body)
    if (!parsed.valid) {
        error(parsed.summary)
    }
    return parsed.summary
}

private fun postRegexRecordProofToServer(
    serverUrl: String,
    token: String,
    proofResult: CircomProofResult,
    zkeyPath: String
): String {
    val response = postJson(
        url = endpointUrlFor(serverUrl, "/verify-regex-proof"),
        body = proofOnlyPayload(proofResult, zkeyPath),
        bearerToken = token
    )
    val parsed = formatRegexServerProofResponse(response.body)
    if (!parsed.valid) {
        error(parsed.summary)
    }
    return parsed.summary
}

private fun proofResultToServerPayload(
    proofResult: CircomProofResult,
    signature: LocationCommitmentSignature
): JSONObject {
    return JSONObject()
        .put("proof", proofToJson(proofResult.proof))
        .put("inputs", JSONArray(proofResult.inputs))
        .put("publicSignals", JSONArray(proofResult.inputs))
        .put(
            "tee",
            JSONObject()
                .put("payload", signature.payload)
                .put("signature", signature.signatureBase64)
        )
}

private fun proofOnlyPayload(proofResult: CircomProofResult, zkeyPath: String): JSONObject {
    return JSONObject()
        .put("proof", proofToJson(proofResult.proof))
        .put("inputs", JSONArray(proofResult.inputs))
        .put("publicSignals", JSONArray(proofResult.inputs))
        .put(
            "clientArtifacts",
            JSONObject()
                .put("regexRecordZkeySha256", sha256Hex(File(zkeyPath)))
        )
}

private fun proofToJson(proof: CircomProof): JSONObject {
    return JSONObject()
        .put("a", g1ToJson(proof.a))
        .put("b", g2ToJson(proof.b))
        .put("c", g1ToJson(proof.c))
        .put("protocol", proof.protocol.ifBlank { "groth16" })
        .put("curve", proof.curve.ifBlank { "bn128" })
}

private fun g1ToJson(point: G1): JSONObject {
    return JSONObject()
        .put("x", point.x)
        .put("y", point.y)
        .put("z", point.z.ifBlank { "1" })
}

private fun g2ToJson(point: G2): JSONObject {
    return JSONObject()
        .put("x", JSONArray(point.x))
        .put("y", JSONArray(point.y))
        .put("z", JSONArray(point.z.ifEmpty { listOf("1", "0") }))
}

private fun formatServerProofResponse(body: String): ServerProofVerificationResponse {
    // json/signature/nonce/user：服务端返回的 proof、签名、nonce 和当前用户验证摘要。
    val json = JSONObject(body)
    val signature = json.optJSONObject("signature")
    val nonce = json.optJSONObject("nonce")
    val user = json.optJSONObject("user")
    val valid = json.optBoolean("valid", false)
    val summary = listOf(
        compactValue("Server valid", valid.toString()),
        compactValue("Proof valid", json.optBoolean("proofValid", json.optBoolean("valid", false)).toString()),
        compactValue("Signature valid", (signature?.optBoolean("signatureValid", false) ?: false).toString()),
        compactValue("Commitment bound", (signature?.optBoolean("commitmentBound", false) ?: false).toString()),
        compactValue("Nonce consumed", (nonce?.optBoolean("consumed", false) ?: false).toString()),
        compactValue("User", user?.optString("username").orEmpty())
    ).joinToString("\n")
    return ServerProofVerificationResponse(valid = valid, summary = summary)
}

private fun formatRegexServerProofResponse(body: String): ServerProofVerificationResponse {
    val json = JSONObject(body)
    val user = json.optJSONObject("user")
    val artifacts = json.optJSONObject("artifacts")
    val clientArtifacts = artifacts?.optJSONObject("client")
    val serverArtifacts = artifacts?.optJSONObject("server")
    val valid = json.optBoolean("valid", false)
    val summary = listOfNotNull(
        compactValue("Server regex valid", valid.toString()),
        compactValue("Proof valid", json.optBoolean("proofValid", valid).toString()),
        compactValue("Commitment", shortValue(json.optString("recordCommitment"))),
        compactValue("Public inputs", json.optInt("publicInputCount", 0).toString()),
        json.optString("acceptedFormat").takeIf { it.isNotBlank() && it != "null" }?.let {
            compactValue("Format", it)
        },
        formatServerAttempts(json.optJSONArray("attempts")).takeIf { it.isNotBlank() }?.let {
            compactValue("Attempts", it)
        },
        clientArtifacts?.optString("regexRecordZkeySha256")?.takeIf { it.isNotBlank() && it != "null" }?.let {
            compactValue("Client zkey", shortValue(it))
        },
        serverArtifacts?.optString("regexRecordZkeySha256")?.takeIf { it.isNotBlank() && it != "null" }?.let {
            compactValue("Server zkey", shortValue(it))
        },
        serverArtifacts?.optString("regexRecordVerificationKeySha256")?.takeIf { it.isNotBlank() && it != "null" }?.let {
            compactValue("Server vk", shortValue(it))
        },
        user?.optString("username")?.let { compactValue("User", it) },
        json.optString("reason").takeIf { it.isNotBlank() && it != "null" }?.let {
            compactValue("Reason", it)
        }
    ).joinToString("\n")
    return ServerProofVerificationResponse(valid = valid, summary = summary)
}

private fun formatServerAttempts(attempts: JSONArray?): String {
    if (attempts == null || attempts.length() == 0) return ""
    return (0 until attempts.length()).joinToString(", ") { index ->
        val attempt = attempts.optJSONObject(index)
        val format = attempt?.optString("format").orEmpty().ifBlank { "unknown" }
        val valid = attempt?.optBoolean("valid", false) ?: false
        "$format=$valid"
    }
}

private fun sha256Hex(file: File): String {
    val digest = MessageDigest.getInstance("SHA-256")
    file.inputStream().use { input ->
        val buffer = ByteArray(DEFAULT_BUFFER_SIZE)
        while (true) {
            val read = input.read(buffer)
            if (read <= 0) break
            digest.update(buffer, 0, read)
        }
    }
    return digest.digest().joinToString("") { byte -> "%02x".format(byte) }
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
