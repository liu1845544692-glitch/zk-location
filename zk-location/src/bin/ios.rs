/*
 * 文件功能：
 * - mopro iOS 绑定生成入口，当前项目主链路不使用。
 *
 * 执行流程：
 * 1. cargo 运行该 bin。
 * 2. 调用 mopro_ffi 的 iOS build 配置。
 */
fn main() {
    // A simple wrapper around a build command provided by mopro.
    // In the future this will likely be published in the mopro crate itself.
    mopro_ffi::app_config::ios::build();
}
