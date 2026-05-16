/*
 * 文件功能：
 * - 定义 Rust/mopro/UniFFI 暴露给 Android 的统一错误类型。
 * - Android 调用生成 proof、验证 proof 或位置输入生成失败时，会收到这些错误分支。
 *
 * 执行流程：
 * 1. 底层库返回具体错误。
 * 2. 业务封装将错误转换为 MoproError。
 * 3. UniFFI 将 MoproError 映射给 Kotlin 层捕获展示。
 */
#[derive(Debug, thiserror::Error)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Error))]
pub enum MoproError {
    /// CircomError：Circom witness/proof/verify 或 H3 输入生成相关错误。
    #[error("CircomError: {0}")]
    CircomError(String),
    /// Halo2Error：保留给 Mopro 模板兼容，当前主链路未启用 Halo2。
    #[error("Halo2Error: {0}")]
    Halo2Error(String),
    /// NoirError：保留给 Mopro 模板兼容，当前主链路未启用 Noir。
    #[error("NoirError: {0}")]
    NoirError(String),
}
