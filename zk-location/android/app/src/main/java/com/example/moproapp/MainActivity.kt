/*
 * 文件功能：
 * - Android 应用入口，负责启动 Compose UI。
 * - 将 APK assets 中的证明参数文件复制到 App 私有文件目录，给 Rust/mopro native prover 使用。
 *
 * 执行流程：
 * 1. MainActivity.onCreate 进入 Compose。
 * 2. MainScreen 创建全局浅色 Material 主题。
 * 3. LocationProofComponent 承载登录、GNSS、ZK proof、Keystore 签名和服务端验证主流程。
 */
package com.example.moproapp

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import java.io.File
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream

@Throws(IOException::class)
fun copyFile(inputStream: InputStream, outputStream: OutputStream) {
    // buffer：每次从 assets 读取的临时字节块，避免一次性加载大文件。
    val buffer = ByteArray(1024)
    // read：本轮读取到的字节数，-1 表示输入流结束。
    var read: Int
    while (inputStream.read(buffer).also { read = it } != -1) {
        outputStream.write(buffer, 0, read)
    }
}

@Composable
fun getFilePathFromAssets(name: String): String {
    // context：当前 Compose 所在 Android Context，用于访问 assets 和 filesDir。
    val context = LocalContext.current
    return remember {
        // file：assets 文件复制后的 App 私有目录路径，native prover 需要普通文件路径。
        val file = File(context.filesDir, name)
        if (!file.exists() || file.length() == 0L) {
            context.assets.open(name).use { inputStream ->
                file.outputStream().use { outputStream ->
                    copyFile(inputStream, outputStream)
                }
            }
        }
        file.absolutePath
    }
}

class MainActivity : ComponentActivity() {
    // savedInstanceState：Android 生命周期恢复状态，本页面不额外保存 Activity 状态。
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val autoRunPasswordRegister = intent?.getBooleanExtra("password_register_auto_test", false) == true
        val passwordRegisterUserId = intent?.getStringExtra("password_register_user_id").orEmpty()
        val passwordRegisterServerUrl = intent?.getStringExtra("password_register_server_url").orEmpty()
        val passwordRegisterNegativeTest =
            intent?.getBooleanExtra("password_register_negative_test", false) == true
        val passwordRegisterRecoveryCheck =
            intent?.getBooleanExtra("password_register_recovery_check", false) == true
        val autoRunPasswordLogin = intent?.getBooleanExtra("password_login_auto_test", false) == true
        val passwordLoginUserId = intent?.getStringExtra("password_login_user_id").orEmpty()
        val passwordLoginServerUrl = intent?.getStringExtra("password_login_server_url").orEmpty()
        setContent {
            MainScreen(
                autoRunPasswordRegister = autoRunPasswordRegister,
                passwordRegisterUserId = passwordRegisterUserId,
                passwordRegisterServerUrl = passwordRegisterServerUrl,
                passwordRegisterNegativeTest = passwordRegisterNegativeTest,
                passwordRegisterRecoveryCheck = passwordRegisterRecoveryCheck,
                autoRunPasswordLogin = autoRunPasswordLogin,
                passwordLoginUserId = passwordLoginUserId,
                passwordLoginServerUrl = passwordLoginServerUrl
            )
        }
    }
}

@Composable
fun MainScreen(
    autoRunPasswordRegister: Boolean = false,
    passwordRegisterUserId: String = "",
    passwordRegisterServerUrl: String = "",
    passwordRegisterNegativeTest: Boolean = false,
    passwordRegisterRecoveryCheck: Boolean = false,
    autoRunPasswordLogin: Boolean = false,
    passwordLoginUserId: String = "",
    passwordLoginServerUrl: String = ""
) {
    var selectedScreen by remember {
        mutableStateOf(
            when {
                autoRunPasswordRegister || passwordRegisterRecoveryCheck -> "register"
                else -> "login"
            }
        )
    }
    var loginUserId by remember { mutableStateOf(passwordLoginUserId) }
    var loginServerUrl by remember { mutableStateOf(passwordLoginServerUrl) }
    var authSession by remember { mutableStateOf<PasswordAuthSession?>(null) }
    // colorScheme：主客户端使用的简约浅色配色，覆盖默认 Material 颜色。
    val colorScheme = lightColorScheme(
        primary = Color(0xFF0F766E),
        onPrimary = Color.White,
        secondary = Color(0xFF475569),
        background = Color(0xFFF6F8FA),
        onBackground = Color(0xFF0F172A),
        surface = Color.White,
        onSurface = Color(0xFF0F172A),
        surfaceVariant = Color(0xFFEFF3F6),
        onSurfaceVariant = Color(0xFF475569),
        outline = Color(0xFFD8DEE5),
        error = Color(0xFFB42318)
    )
    MaterialTheme(colorScheme = colorScheme) {
        Scaffold(
            modifier = Modifier.fillMaxSize(),
            containerColor = MaterialTheme.colorScheme.background
        ) { innerPadding ->
            when (selectedScreen) {
                "register" -> PasswordRegisterScreen(
                    autoTest = autoRunPasswordRegister,
                    initialUserId = passwordRegisterUserId.ifBlank { loginUserId },
                    initialServerUrl = passwordRegisterServerUrl.ifBlank { loginServerUrl },
                    runNegativeTest = passwordRegisterNegativeTest,
                    recoveryCheck = passwordRegisterRecoveryCheck,
                    onBackToLogin = { userId, serverUrl ->
                        loginUserId = userId
                        loginServerUrl = serverUrl
                        selectedScreen = "login"
                    },
                    modifier = Modifier.fillMaxSize().padding(innerPadding)
                )
                "location" -> {
                    val session = authSession
                    if (session == null) {
                        selectedScreen = "login"
                    } else {
                        LocationProofComponent(
                            initialAuthToken = session.token,
                            initialAuthUsername = session.userId,
                            initialServerUrl = session.serverUrl,
                            onSessionEnded = {
                                authSession = null
                                selectedScreen = "login"
                            },
                            modifier = Modifier.fillMaxSize().padding(innerPadding)
                        )
                    }
                }
                else -> PasswordLoginScreen(
                    autoTest = autoRunPasswordLogin,
                    initialUserId = loginUserId,
                    initialServerUrl = loginServerUrl,
                    onLoginSuccess = { session ->
                        authSession = session
                        selectedScreen = "location"
                    },
                    onRegisterRequested = { userId, serverUrl ->
                        loginUserId = userId
                        loginServerUrl = serverUrl
                        selectedScreen = "register"
                    },
                    modifier = Modifier.fillMaxSize().padding(innerPadding)
                )
            }
        }
    }
}
