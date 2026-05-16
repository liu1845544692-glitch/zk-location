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
        setContent {
            MainScreen()
        }
    }
}

@Composable
fun MainScreen() {
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
            // innerPadding：Scaffold 为系统栏和内容区预留的安全边距。
            LocationProofComponent(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(innerPadding)
            )
        }
    }
}
