/*
 * 文件功能：
 * - mopro Android 绑定生成入口。
 * - build-android-bindings.sh 会通过 mopro CLI/构建流程间接使用该入口生成 Android 产物。
 *
 * 执行流程：
 * 1. cargo 运行该 bin。
 * 2. 调用 mopro_ffi 的 Android build 配置。
 */
fn main() {
    // A simple wrapper around a build command provided by mopro.
    // In the future this will likely be published in the mopro crate itself.
    mopro_ffi::app_config::android::build();
}
