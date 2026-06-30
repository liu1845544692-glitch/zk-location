/*
 * 文件功能：
 * - 封装 mopro/circom_prover 的 proof 生成和验证接口。
 * - 定义可被 UniFFI 导出到 Android Kotlin 的 CircomProofResult、G1、G2 和 ProofLib 数据结构。
 *
 * 执行流程：
 * 1. generate_circom_proof 根据 zkey 文件名查找已注册 witness 函数。
 * 2. 调用 CircomProver::prove 生成 proof 和 public inputs。
 * 3. 将 circom_prover 内部 proof 结构转换为可跨 FFI 传输的字符串结构。
 * 4. verify_circom_proof 再把 FFI 结构转换回 circom_prover 结构并验证。
 */
use crate::MoproError;
use circom_prover::{
    prover::{
        circom::{
            Proof as CircomProverProof, CURVE_BLS12_381, CURVE_BN254, G1 as CircomProverG1,
            G2 as CircomProverG2,
        },
        ProofLib as CircomProverProofLib,
    },
    CircomProver,
};
use num_bigint::BigUint;
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::Read;
use std::str::FromStr;

//
// Data structures for Circom proof representation
//
#[derive(Debug, Clone)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct CircomProofResult {
    /// proof：Groth16 proof 的 a/b/c 曲线点和协议元数据。
    pub proof: CircomProof,
    /// inputs：公开输入数组，第一个元素是 public_commitment。
    pub inputs: Vec<String>,
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct PasswordProofDiagnostic {
    pub proof_result: CircomProofResult,
    pub native_verify: bool,
    pub proof_json_bytes: u64,
    pub proof_sha256: String,
    pub zkey_sha256: String,
}

#[derive(Debug, Clone, Default)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct G1 {
    /// x：G1 点的 x 坐标，十进制字符串格式。
    pub x: String,
    /// y：G1 点的 y 坐标，十进制字符串格式。
    pub y: String,
    /// z：G1 点的 z 坐标，十进制字符串格式。
    pub z: String,
}

#[derive(Debug, Clone, Default)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct G2 {
    /// x：G2 点的 x 坐标二元数组，十进制字符串格式。
    pub x: Vec<String>,
    /// y：G2 点的 y 坐标二元数组，十进制字符串格式。
    pub y: Vec<String>,
    /// z：G2 点的 z 坐标二元数组，十进制字符串格式。
    pub z: Vec<String>,
}

#[derive(Debug, Clone, Default)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct CircomProof {
    /// a：Groth16 proof 的 A 点。
    pub a: G1,
    /// b：Groth16 proof 的 B 点。
    pub b: G2,
    /// c：Groth16 proof 的 C 点。
    pub c: G1,
    /// protocol：proof 协议名称，当前应为 groth16。
    pub protocol: String,
    /// curve：曲线名称，当前主链路使用 bn128/bn254。
    pub curve: String,
}

#[derive(Debug, Clone, Default)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
pub enum ProofLib {
    /// Arkworks：当前 Android 主链路使用的 proof backend。
    #[default]
    Arkworks,
    /// Rapidsnark：兼容保留的 proof backend。
    Rapidsnark,
}

//
// `From` implementation for proof conversion
//
impl From<CircomProverProof> for CircomProof {
    /// 将 circom_prover proof 转为 UniFFI 友好的字符串 proof。
    fn from(proof: CircomProverProof) -> Self {
        CircomProof {
            a: proof.a.into(),
            b: proof.b.into(),
            c: proof.c.into(),
            protocol: proof.protocol,
            curve: proof.curve,
        }
    }
}

impl From<CircomProof> for CircomProverProof {
    /// 将 Android/UniFFI 传回的 proof 转回 circom_prover 内部结构。
    fn from(proof: CircomProof) -> Self {
        CircomProverProof {
            a: proof.a.into(),
            b: proof.b.into(),
            c: proof.c.into(),
            protocol: proof.protocol,
            curve: proof.curve,
        }
    }
}

impl From<CircomProverG1> for G1 {
    /// 将 G1 大整数坐标转为字符串，便于跨 FFI 和 JSON 传输。
    fn from(g1: CircomProverG1) -> Self {
        G1 {
            x: g1.x.to_string(),
            y: g1.y.to_string(),
            z: g1.z.to_string(),
        }
    }
}

impl From<G1> for CircomProverG1 {
    /// 将字符串 G1 坐标解析回大整数坐标。
    fn from(g1: G1) -> Self {
        CircomProverG1 {
            x: BigUint::from_str(g1.x.as_str()).unwrap(),
            y: BigUint::from_str(g1.y.as_str()).unwrap(),
            z: BigUint::from_str(g1.z.as_str()).unwrap(),
        }
    }
}

impl From<CircomProverG2> for G2 {
    /// 将 G2 二次扩域坐标转为字符串数组。
    fn from(g2: CircomProverG2) -> Self {
        // x/y/z：G2 每个坐标包含两个域元素。
        let x = vec![g2.x[0].to_string(), g2.x[1].to_string()];
        let y = vec![g2.y[0].to_string(), g2.y[1].to_string()];
        let z = vec![g2.z[0].to_string(), g2.z[1].to_string()];
        G2 { x, y, z }
    }
}

impl From<G2> for CircomProverG2 {
    /// 将字符串数组形式的 G2 坐标解析回 circom_prover 结构。
    fn from(g2: G2) -> Self {
        // x/y/z：把 Android 传回的十进制字符串解析为 BigUint。
        let x =
            g2.x.iter()
                .map(|p| BigUint::from_str(p.as_str()).unwrap())
                .collect::<Vec<BigUint>>();
        let y =
            g2.y.iter()
                .map(|p| BigUint::from_str(p.as_str()).unwrap())
                .collect::<Vec<BigUint>>();
        let z =
            g2.z.iter()
                .map(|p| BigUint::from_str(p.as_str()).unwrap())
                .collect::<Vec<BigUint>>();
        CircomProverG2 {
            x: [x[0].clone(), x[1].clone()],
            y: [y[0].clone(), y[1].clone()],
            z: [z[0].clone(), z[1].clone()],
        }
    }
}

impl Into<CircomProverProofLib> for ProofLib {
    /// 将项目自己的 ProofLib 枚举映射到 circom_prover backend 枚举。
    fn into(self) -> CircomProverProofLib {
        match self {
            ProofLib::Arkworks => CircomProverProofLib::Arkworks,
            ProofLib::Rapidsnark => CircomProverProofLib::Rapidsnark,
        }
    }
}

//
// Main functions for proof generation and verification
//

#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn generate_circom_proof(
    zkey_path: String,
    circuit_inputs: String,
    proof_lib: ProofLib,
) -> Result<CircomProofResult, MoproError> {
    // name：从 zkey_path 提取文件名，用于查找 witness 注册表。
    let name = std::path::Path::new(zkey_path.as_str())
        .file_name()
        .ok_or_else(|| {
            MoproError::CircomError("failed to parse file name from zkey_path".to_string())
        })?;

    // witness_fn：由 set_circom_circuits! 注册的 witness 计算函数。
    let witness_fn = crate::circom_get(name.to_str().unwrap()).ok_or_else(|| {
        MoproError::CircomError(format!("Unknown ZKEY: {}", name.to_string_lossy()))
    })?;

    // ret：底层 prover 生成的 proof 和 public inputs。
    let ret = CircomProver::prove(proof_lib.into(), witness_fn, circuit_inputs, zkey_path)
        .map_err(|e| MoproError::CircomError(format!("Generate Proof error: {}", e)))?;

    // proof/pub_inputs：只接受当前支持曲线上的 proof。
    let (proof, pub_inputs) = match ret.proof.curve.as_ref() {
        CURVE_BN254 | CURVE_BLS12_381 => (ret.proof.into(), ret.pub_inputs.into()),
        _ => {
            return Err(MoproError::CircomError(format!(
                "Unsupported curve: {}",
                ret.proof.curve
            )))
        }
    };

    Ok(CircomProofResult {
        proof,
        inputs: pub_inputs,
    })
}

#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn generate_password_circom_proof_diagnostic(
    zkey_path: String,
    circuit_inputs: String,
) -> Result<PasswordProofDiagnostic, MoproError> {
    let name = std::path::Path::new(&zkey_path)
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or_else(|| MoproError::CircomError("failed to parse zkey file name".to_string()))?;
    if name != "password_policy_commitment_final.zkey" {
        return Err(MoproError::CircomError(format!(
            "unexpected password zkey: {name}"
        )));
    }
    let witness_fn = crate::circom_get(name)
        .ok_or_else(|| MoproError::CircomError(format!("Unknown ZKEY: {name}")))?;
    let generated = CircomProver::prove(
        CircomProverProofLib::Arkworks,
        witness_fn,
        circuit_inputs,
        zkey_path.clone(),
    )
    .map_err(|e| MoproError::CircomError(format!("Generate Proof error: {e}")))?;

    let proof_json = serde_json::to_vec(&generated)
        .map_err(|e| MoproError::CircomError(format!("proof serialization failed: {e}")))?;
    let proof_sha256 = sha256_bytes(&proof_json);
    let proof_json_bytes = proof_json.len() as u64;
    let native_verify = CircomProver::verify(
        CircomProverProofLib::Arkworks,
        generated.clone(),
        zkey_path.clone(),
    )
    .map_err(|e| MoproError::CircomError(format!("Native verification error: {e}")))?;
    let zkey_sha256 = sha256_file(&zkey_path)?;

    Ok(PasswordProofDiagnostic {
        proof_result: CircomProofResult {
            proof: generated.proof.into(),
            inputs: generated.pub_inputs.into(),
        },
        native_verify,
        proof_json_bytes,
        proof_sha256,
        zkey_sha256,
    })
}

#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn hash_circom_proof_result(proof_result: CircomProofResult) -> Result<String, MoproError> {
    let internal = circom_prover::prover::CircomProof {
        proof: proof_result.proof.into(),
        pub_inputs: proof_result.inputs.into(),
    };
    let json = serde_json::to_vec(&internal)
        .map_err(|e| MoproError::CircomError(format!("proof serialization failed: {e}")))?;
    Ok(sha256_bytes(&json))
}

fn sha256_bytes(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn sha256_file(path: &str) -> Result<String, MoproError> {
    let mut file = File::open(path)
        .map_err(|e| MoproError::CircomError(format!("failed to open zkey for SHA-256: {e}")))?;
    let mut digest = Sha256::new();
    let mut buffer = [0u8; 1024 * 1024];
    loop {
        let count = file
            .read(&mut buffer)
            .map_err(|e| MoproError::CircomError(format!("failed to hash zkey: {e}")))?;
        if count == 0 {
            break;
        }
        digest.update(&buffer[..count]);
    }
    Ok(format!("{:x}", digest.finalize()))
}

#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn verify_circom_proof(
    zkey_path: String,
    proof_result: CircomProofResult,
    proof_lib: ProofLib,
) -> Result<bool, MoproError> {
    // chosen_proof_lib：验证端使用的 backend，需要与生成端兼容。
    let chosen_proof_lib = proof_lib.into();
    CircomProver::verify(
        chosen_proof_lib,
        circom_prover::prover::CircomProof {
            proof: proof_result.proof.into(),
            pub_inputs: proof_result.inputs.into(),
        },
        zkey_path,
    )
    .map_err(|e| MoproError::CircomError(format!("Verification error: {}", e)))
}

#[macro_export]
macro_rules! set_circom_circuits {
    // Accept any number of (key, func) pairs
    ($(($key:expr, $func:expr)),+ $(,)?) => {

        // Adjust the path if these types live elsewhere
        use circom_prover::witness::WitnessFn;

        const CIRCOM_CIRCUITS: &[(&'static str, WitnessFn)] = &[
            $(
                ($key, $func),
            )+
        ];

        #[inline]
        pub(crate) fn circom_get(name: &str) -> Option<WitnessFn> {
            CIRCOM_CIRCUITS.iter()
                .find(|(k, _)| *k == name)
                .map(|(_, v)| *v)
        }
    };
}
