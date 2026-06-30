/*
 * 文件功能：
 * - Rust build script，按目标平台准备 areajudge、regex_ip、regex_timestamp、port_trans、unit、protocol_regex 和 regex_record witness 计算代码。
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
        println!("cargo:rerun-if-changed=../circuits/areajudge_js/areajudge.wasm");
        println!("cargo:rerun-if-changed=../circuits/regex_ip_js/regex_ip.wasm");
        println!("cargo:rerun-if-changed=../circuits/regex_timestamp_js/regex_timestamp.wasm");
        println!("cargo:rerun-if-changed=../circuits/port_trans_js/port_trans.wasm");
        println!("cargo:rerun-if-changed=../circuits/unit_js/unit.wasm");
        println!("cargo:rerun-if-changed=../circuits/protocol_regex_js/protocol_regex.wasm");
        println!("cargo:rerun-if-changed=../circuits/regex_record_js/regex_record.wasm");
        println!("cargo:rerun-if-changed=../circuits/password_policy_commitment_js/password_policy_commitment_main.wasm");

        // rust_witness 每次 transpile_wasm 都会生成同名 libcircuit.a。
        // 因此 Android 目标必须一次性扫描包含全部 wasm 的目录；同时不能扫描整个 circuits，
        // 因为旧的 regex-ip.wasm 和新的 regex_ip.wasm 会生成重复的 regexip handler。
        let out_dir = std::path::PathBuf::from(std::env::var("OUT_DIR").expect("OUT_DIR not set"));
        let witness_wasm_dir = out_dir.join("android-witness-wasm");
        std::fs::create_dir_all(&witness_wasm_dir)
            .expect("failed to create Android witness wasm dir");
        std::fs::copy(
            "../circuits/areajudge_js/areajudge.wasm",
            witness_wasm_dir.join("areajudge.wasm"),
        )
        .expect("failed to copy areajudge.wasm");
        std::fs::copy(
            "../circuits/regex_ip_js/regex_ip.wasm",
            witness_wasm_dir.join("regex_ip.wasm"),
        )
        .expect("failed to copy regex_ip.wasm");
        std::fs::copy(
            "../circuits/regex_timestamp_js/regex_timestamp.wasm",
            witness_wasm_dir.join("regex_timestamp.wasm"),
        )
        .expect("failed to copy regex_timestamp.wasm");
        std::fs::copy(
            "../circuits/port_trans_js/port_trans.wasm",
            witness_wasm_dir.join("port_trans.wasm"),
        )
        .expect("failed to copy port_trans.wasm");
        std::fs::copy(
            "../circuits/unit_js/unit.wasm",
            witness_wasm_dir.join("unit.wasm"),
        )
        .expect("failed to copy unit.wasm");
        std::fs::copy(
            "../circuits/protocol_regex_js/protocol_regex.wasm",
            witness_wasm_dir.join("protocol_regex.wasm"),
        )
        .expect("failed to copy protocol_regex.wasm");
        std::fs::copy(
            "../circuits/regex_record_js/regex_record.wasm",
            witness_wasm_dir.join("regex_record.wasm"),
        )
        .expect("failed to copy regex_record.wasm");
        std::fs::copy(
            "../circuits/password_policy_commitment_js/password_policy_commitment_main.wasm",
            witness_wasm_dir.join("password_policy_commitment_main.wasm"),
        )
        .expect("failed to copy password_policy_commitment_main.wasm");

        rust_witness::transpile::transpile_wasm(witness_wasm_dir.to_string_lossy().to_string());
    } else {
        // Use witnesscalc-adapter (C++ witness calculator) instead of rust-witness
        // for non-Android builds. The Android path uses rust-witness to avoid
        // cross-linking GMP and x86_64-specific Circom fr.asm into mobile ABIs.
        witnesscalc_adapter::build_and_link("./test-vectors/circom/witnesscalc");
    }
}
