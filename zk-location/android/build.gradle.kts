// 文件功能：
// - Android 顶层 Gradle 构建文件，统一声明插件版本别名但不在根项目直接应用。
//
// 执行流程：
// 1. settings.gradle.kts 加载版本目录。
// 2. 这里声明 Android/Kotlin 插件可供 app/build.gradle.kts 使用。
plugins {
    alias(libs.plugins.android.application) apply false
    alias(libs.plugins.jetbrains.kotlin.android) apply false
}
