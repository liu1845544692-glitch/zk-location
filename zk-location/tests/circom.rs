/*
 * 文件功能：
 * - Circom UniFFI 测试初始化入口。
 * - 当前具体 proof 测试位于 src/lib.rs 内部测试，这里只保留 UniFFI setup。
 *
 * 执行流程：
 * 1. cargo test 编译该测试文件。
 * 2. uniffi_setup 宏注册 UniFFI 测试脚手架。
 */
mopro_ffi::uniffi_setup!();
