#!/usr/bin/env bash
# 文件功能：
# - 构建 Rust/mopro Android UniFFI 绑定，并复制到 Android app 源码目录。
# 执行流程：
# 1. 定位 zk-location 子项目根目录。
# 2. 设置 Android SDK/NDK 环境变量。
# 3. 运行 mopro build 生成 arm64/x86_64 Android 产物。
# 4. 复制 jniLibs 和 uniffi Kotlin binding 到 app/src/main。
set -euo pipefail

# ROOT_DIR：zk-location Rust/Android 子项目根目录。
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# ANDROID_HOME/ANDROID_SDK_ROOT：Android SDK 路径。
export ANDROID_HOME="/home/lyy/Android/Sdk"
export ANDROID_SDK_ROOT="$ANDROID_HOME"

# ANDROID_NDK_HOME/ANDROID_NDK：mopro 交叉编译使用的 NDK 路径。
export ANDROID_NDK_HOME="$ANDROID_HOME/ndk/28.2.13676358"
export ANDROID_NDK="$ANDROID_NDK_HOME"

cd "$ROOT_DIR"

# mopro build：生成 Android native library 和 UniFFI binding。
GIT_CONFIG_GLOBAL=/dev/null mopro build \
  --mode release \
  --platforms android \
  --architectures x86_64-linux-android aarch64-linux-android \
  --no-auto-update

# 复制生成产物到 Android app 可编译位置。
mkdir -p android/app/src/main/java
cp -R MoproAndroidBindings/jniLibs android/app/src/main/
cp -R MoproAndroidBindings/uniffi android/app/src/main/java/
