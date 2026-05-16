/*
 * 文件功能：
 * - 保存 Compose 默认主题色变量。
 * - 当前 MainScreen 使用自定义浅色 colorScheme，这些颜色主要服务于备用 MoproAppTheme。
 *
 * 执行流程：
 * 1. Theme.kt 创建 dark/light color scheme。
 * 2. 这里的颜色变量被 Theme.kt 引用。
 */
package com.example.moproapp.ui.theme

import androidx.compose.ui.graphics.Color

// Purple80：深色主题 primary 颜色。
val Purple80 = Color(0xFFD0BCFF)
// PurpleGrey80：深色主题 secondary 颜色。
val PurpleGrey80 = Color(0xFFCCC2DC)
// Pink80：深色主题 tertiary 颜色。
val Pink80 = Color(0xFFEFB8C8)

// Purple40：浅色主题 primary 颜色。
val Purple40 = Color(0xFF6650a4)
// PurpleGrey40：浅色主题 secondary 颜色。
val PurpleGrey40 = Color(0xFF625b71)
// Pink40：浅色主题 tertiary 颜色。
val Pink40 = Color(0xFF7D5260)
