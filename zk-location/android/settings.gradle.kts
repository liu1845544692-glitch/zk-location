// 文件功能：
// - Android Gradle settings，声明 plugin/dependency 仓库和 app 模块。
//
// 执行流程：
// 1. Gradle 先读取 pluginManagement 查找 Android/Kotlin 插件。
// 2. dependencyResolutionManagement 限制依赖只能从 google/mavenCentral 解析。
// 3. include(":app") 将 Android app 模块加入构建。
pluginManagement {
    repositories {
        google {
            content {
                includeGroupByRegex("com\\.android.*")
                includeGroupByRegex("com\\.google.*")
                includeGroupByRegex("androidx.*")
            }
        }
        mavenCentral()
        gradlePluginPortal()
    }
}
dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        google()
        mavenCentral()
    }
}

rootProject.name = "MoproApp"
include(":app")
