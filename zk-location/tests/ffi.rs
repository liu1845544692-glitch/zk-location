/*
 * 文件功能：
 * - UniFFI 测试初始化入口。
 * - 当前外语 binding 示例测试已删除，只保留 mopro_ffi::uniffi_setup! 让测试 crate 正常初始化。
 *
 * 执行流程：
 * 1. cargo test 编译该测试文件。
 * 2. uniffi_setup 宏注册 UniFFI 测试脚手架。
 */
mopro_ffi::uniffi_setup!();
