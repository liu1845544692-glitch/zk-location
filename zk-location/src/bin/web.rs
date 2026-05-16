/*
 * 文件功能：
 * - mopro Web/WASM 绑定生成入口，当前 Android 主链路不使用。
 *
 * 执行流程：
 * 1. cargo 运行该 bin。
 * 2. 调用 mopro_ffi 的 Web build 配置。
 */
fn main() {
    mopro_ffi::app_config::web::build();
}
