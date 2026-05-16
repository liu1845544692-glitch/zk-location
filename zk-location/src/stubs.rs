/*
 * 文件功能：
 * - 为未启用的 Mopro adapter 提供占位 UniFFI API。
 * - 当前项目主链路启用 Circom，Halo2/Noir 只保留兼容导出，调用会明确 panic。
 *
 * 执行流程：
 * 1. lib.rs 根据模板宏展开需要的 stub。
 * 2. 若某 adapter 未被真实实现替换，Android 调用对应函数会收到清晰错误。
 * 3. 这样可以保持生成绑定接口稳定，同时避免误以为未启用 backend 可用。
 */
#[macro_export]
macro_rules! circom_stub {
    () => {
        mod circom_stub {
            use crate::error::MoproError;

            #[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
            pub struct CircomProofResult {
                /// proof：占位 Circom proof 字段，真实 Circom 模块启用时不会使用该 stub。
                pub proof: CircomProof,
                /// inputs：占位 public inputs 字段。
                pub inputs: Vec<String>,
            }

            #[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
            pub struct G1 {
                /// x：占位 G1 x 坐标。
                pub x: String,
                /// y：占位 G1 y 坐标。
                pub y: String,
                /// z：占位 G1 z 坐标。
                pub z: String,
            }

            #[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
            pub struct G2 {
                /// x：占位 G2 x 坐标数组。
                pub x: Vec<String>,
                /// y：占位 G2 y 坐标数组。
                pub y: Vec<String>,
                /// z：占位 G2 z 坐标数组。
                pub z: Vec<String>,
            }

            #[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
            pub struct CircomProof {
                /// a：占位 Groth16 A 点。
                pub a: G1,
                /// b：占位 Groth16 B 点。
                pub b: G2,
                /// c：占位 Groth16 C 点。
                pub c: G1,
                /// protocol：占位协议名。
                pub protocol: String,
                /// curve：占位曲线名。
                pub curve: String,
            }

            #[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
            pub enum ProofLib {
                /// Arkworks：占位 backend 选项。
                Arkworks,
                /// Rapidsnark：占位 backend 选项。
                Rapidsnark,
            }

            /// 未启用 Circom 时的占位生成函数，调用即报错。
            #[cfg_attr(feature = "uniffi", uniffi::export)]
            pub fn generate_circom_proof(
                _zkey_path: String,
                _circuit_inputs: String,
                _proof_lib: ProofLib,
            ) -> Result<CircomProofResult, MoproError> {
                panic!("Circom is not enabled in this build. Please select \"circom\" adapter when initializing the project.");
            }

            /// 未启用 Circom 时的占位验证函数，调用即报错。
            #[cfg_attr(feature = "uniffi", uniffi::export)]
            pub fn verify_circom_proof(
                _zkey_path: String,
                _proof_result: CircomProofResult,
                _proof_lib: ProofLib,
            ) -> Result<bool, MoproError> {
                panic!("Circom is not enabled in this build. Please select \"circom\" adapter when initializing the project.");
            }
        }
        pub use circom_stub::{
            generate_circom_proof, verify_circom_proof, CircomProof, CircomProofResult, ProofLib,
            G1, G2,
        };
    };
}

#[macro_export]
macro_rules! halo2_stub {
    () => {
        mod halo2_stub {
            use crate::error::MoproError;

            #[derive(Debug, Clone, Default)]
            #[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
            pub struct Halo2ProofResult {
                /// proof：占位 Halo2 proof bytes。
                pub proof: Vec<u8>,
                /// inputs：占位 Halo2 public inputs bytes。
                pub inputs: Vec<u8>,
            }

            /// 未启用 Halo2 时的占位生成函数，调用即报错。
            #[cfg_attr(feature = "uniffi", uniffi::export)]
            pub fn generate_halo2_proof(
                _srs_path: String,
                _pk_path: String,
                _circuit_inputs: std::collections::HashMap<String, Vec<String>>,
            ) -> Result<Halo2ProofResult, MoproError> {
                panic!("Halo2 is not enabled in this build. Please select \"halo2\" adapter when initializing the project.");
            }

            /// 未启用 Halo2 时的占位验证函数，调用即报错。
            #[cfg_attr(feature = "uniffi", uniffi::export)]
            pub fn verify_halo2_proof(
                _srs_path: String,
                _vk_path: String,
                _proof: Vec<u8>,
                _public_input: Vec<u8>,
            ) -> Result<bool, MoproError> {
                panic!("Halo2 is not enabled in this build. Please select \"halo2\" adapter when initializing the project.");
            }
        }
        pub use halo2_stub::{generate_halo2_proof, verify_halo2_proof, Halo2ProofResult};
    };
}

#[macro_export]
macro_rules! noir_stub {
    () => {
        mod noir_stub {
            use crate::error::MoproError;

            /// 未启用 Noir 时的占位生成函数，调用即报错。
            #[cfg_attr(feature = "uniffi", uniffi::export)]
            pub fn generate_noir_proof(
                _circuit_path: String,
                _srs_path: Option<String>,
                _inputs: Vec<String>,
                _on_chain: bool,
                _vk: Vec<u8>,
                _low_memory_mode: bool,
            ) -> Result<Vec<u8>, MoproError> {
                panic!("Noir is not enabled in this build. Please select \"noir\" adapter when initializing the project.");
            }

            /// 未启用 Noir 时的占位验证函数，调用即报错。
            #[cfg_attr(feature = "uniffi", uniffi::export)]
            pub fn verify_noir_proof(
                _circuit_path: String,
                _proof: Vec<u8>,
                _on_chain: bool,
                _vk: Vec<u8>,
                _low_memory_mode: bool,
            ) -> Result<bool, MoproError> {
                panic!("Noir is not enabled in this build. Please select \"noir\" adapter when initializing the project.");

            }


            /// 未启用 Noir 时的占位 verification key 生成函数，调用即报错。
            #[cfg_attr(feature = "uniffi", uniffi::export)]
            pub fn get_noir_verification_key(
                _circuit_path: String,
                _srs_path: Option<String>,
                _on_chain: bool,
                _low_memory_mode: bool,
            ) -> Result<Vec<u8>, MoproError> {
                panic!("Noir is not enabled in this build. Please select \"noir\" adapter when initializing the project.");

            }


        }
        pub use noir_stub::{
            generate_noir_proof, get_noir_verification_key, verify_noir_proof,
        };
    };
}
