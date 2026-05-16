/*
 * 文件功能：
 * - 保存 Compose Material3 Typography 配置。
 * - 供备用 MoproAppTheme 使用，定义应用默认文字层级。
 *
 * 执行流程：
 * 1. Theme.kt 将 Typography 传入 MaterialTheme。
 * 2. 各 Composable 使用 MaterialTheme.typography 读取这些文字样式。
 */
package com.example.moproapp.ui.theme

import androidx.compose.material3.Typography
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.sp

// Typography：应用默认文字样式集合，目前只覆盖 bodyLarge，其余沿用 Material3 默认值。
val Typography = Typography(
    bodyLarge = TextStyle(
        fontFamily = FontFamily.Default,
        fontWeight = FontWeight.Normal,
        fontSize = 16.sp,
        lineHeight = 24.sp,
        letterSpacing = 0.5.sp
    )
    /* Other default text styles to override
    titleLarge = TextStyle(
        fontFamily = FontFamily.Default,
        fontWeight = FontWeight.Normal,
        fontSize = 22.sp,
        lineHeight = 28.sp,
        letterSpacing = 0.sp
    ),
    labelSmall = TextStyle(
        fontFamily = FontFamily.Default,
        fontWeight = FontWeight.Medium,
        fontSize = 11.sp,
        lineHeight = 16.sp,
        letterSpacing = 0.5.sp
    )
    */
)
