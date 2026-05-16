/*
 * 文件功能：
 * - Rust build script，按目标平台准备 areajudge witness 计算代码。
 *
 * 执行流程：
 * 1. cargo build 时自动执行 main。
 * 2. Android 目标使用 rust_witness 从 wasm 转译 witness，避免移动端链接 C++/GMP。
 * 3. 非 Android 目标使用 witnesscalc-adapter 链接 C++ witness calculator。
 */
fn main() {
    // CIRCOM_TEMPLATE

    // CARGO_CFG_TARGET_OS：Cargo 注入的目标平台变量。
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("android") {
        rust_witness::transpile::transpile_wasm("../circuits/areajudge_js".to_string());
    } else {
        // Use witnesscalc-adapter (C++ witness calculator) instead of rust-witness
        // for non-Android builds. The Android path uses rust-witness to avoid
        // cross-linking GMP and x86_64-specific Circom fr.asm into mobile ABIs.
        witnesscalc_adapter::build_and_link("./test-vectors/circom/witnesscalc");
    }
}
