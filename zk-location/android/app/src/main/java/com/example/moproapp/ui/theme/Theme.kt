/*
 * 文件功能：
 * - 提供备用 Compose Material3 主题封装。
 * - 当前主界面在 MainActivity.kt 中直接创建浅色主题，但该文件保留用于测试或未来统一主题入口。
 *
 * 执行流程：
 * 1. 根据系统深色模式和 Android 版本选择动态色或静态色。
 * 2. 将 colorScheme、Typography 和页面 content 传给 MaterialTheme。
 */
package com.example.moproapp.ui.theme

import android.app.Activity
import android.os.Build
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.dynamicDarkColorScheme
import androidx.compose.material3.dynamicLightColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.platform.LocalContext

// DarkColorScheme：深色模式下使用的静态 Material3 色板。
private val DarkColorScheme = darkColorScheme(
    primary = Purple80,
    secondary = PurpleGrey80,
    tertiary = Pink80
)

// LightColorScheme：浅色模式下使用的静态 Material3 色板。
private val LightColorScheme = lightColorScheme(
    primary = Purple40,
    secondary = PurpleGrey40,
    tertiary = Pink40

    /* Other default colors to override
    background = Color(0xFFFFFBFE),
    surface = Color(0xFFFFFBFE),
    onPrimary = Color.White,
    onSecondary = Color.White,
    onTertiary = Color.White,
    onBackground = Color(0xFF1C1B1F),
    onSurface = Color(0xFF1C1B1F),
    */
)

@Composable
fun MoproAppTheme(
    // darkTheme：是否使用深色主题，默认跟随系统设置。
    darkTheme: Boolean = isSystemInDarkTheme(),
    // dynamicColor：Android 12+ 是否启用系统动态取色。
    dynamicColor: Boolean = true,
    // content：需要包裹在 MaterialTheme 内的 Compose 内容。
    content: @Composable () -> Unit
) {
    // colorScheme：最终应用到 MaterialTheme 的颜色集合。
    val colorScheme = when {
        dynamicColor && Build.VERSION.SDK_INT >= Build.VERSION_CODES.S -> {
            // context：动态色 API 需要当前 Android Context。
            val context = LocalContext.current
            if (darkTheme) dynamicDarkColorScheme(context) else dynamicLightColorScheme(context)
        }

        darkTheme -> DarkColorScheme
        else -> LightColorScheme
    }

    MaterialTheme(
        colorScheme = colorScheme,
        typography = Typography,
        content = content
    )
}
