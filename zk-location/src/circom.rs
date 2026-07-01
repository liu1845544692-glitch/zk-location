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
use ark_bn254::{Fq, Fq2, G1Affine, G2Affine};
use ark_ff::PrimeField;
use ark_serialize::CanonicalDeserialize;
use circom_prover::{
    prover::{
        circom::{
            Proof as CircomProverProof, CURVE_BN254, G1 as CircomProverG1, G2 as CircomProverG2,
        },
        ProofLib as CircomProverProofLib,
    },
    CircomProver,
};
use num_bigint::BigUint;
use sha2::{Digest, Sha256};
use std::convert::TryFrom;
use std::fs::File;
use std::io::Read;
use std::str::FromStr;

// BN254 scalar field modulus (Fr::MODULUS).
// All public inputs must be strictly less than this value.
const BN254_SCALAR_MODULUS: &str =
    "21888242871839275222246405745257275088548364400416034343698204186575808495617";

// BN254 base field modulus (Fq::MODULUS).
// G1/G2 coordinates must be strictly less than this value.
const BN254_BASE_MODULUS: &str =
    "21888242871839275222246405745257275088696311157297823662689037894645226208583";

/// 验证 public input 字符串是否为规范十进制标量：
/// - 非空；
/// - 只包含数字字符 '0'-'9'；
/// - "0" 合法，"00"、"01"、"+1"、"-1"、空字符串等拒绝；
/// - 值必须严格小于 modulus。
pub(crate) fn validate_canonical_scalar(value: &str, modulus: &BigUint) -> Result<BigUint, String> {
    if value.is_empty() {
        return Err("empty scalar string".to_string());
    }
    let bytes = value.as_bytes();
    if bytes[0] == b'+' || bytes[0] == b'-' {
        return Err(format!("scalar must not be signed: {value}"));
    }
    if !bytes.iter().all(|b| b.is_ascii_digit()) {
        return Err(format!("scalar contains non-digit characters: {value}"));
    }
    if bytes.len() > 1 && bytes[0] == b'0' {
        return Err(format!("scalar has leading zeros: {value}"));
    }
    let parsed = BigUint::from_str(value).map_err(|e| format!("scalar parse error: {e}"))?;
    if parsed >= *modulus {
        return Err(format!(
            "scalar value exceeds field modulus (got {value}, modulus {modulus})"
        ));
    }
    Ok(parsed)
}

/// 验证整个 public inputs 向量：每项必须是规范十进制标量，且严格小于 BN254 scalar modulus。
fn validate_public_inputs(inputs: &[String]) -> Result<(), String> {
    let modulus = BigUint::from_str(BN254_SCALAR_MODULUS)
        .expect("BN254_SCALAR_MODULUS constant must be valid");
    for (i, value) in inputs.iter().enumerate() {
        validate_canonical_scalar(value, &modulus)
            .map_err(|e| format!("public input [{i}] invalid: {e}"))?;
    }
    Ok(())
}

/// 验证 G1 坐标：三个分量必须都是规范十进制标量，且位于 BN254 base field 范围内。
fn validate_g1_coord(value: &str, label: &str) -> Result<BigUint, String> {
    let modulus =
        BigUint::from_str(BN254_BASE_MODULUS).expect("BN254_BASE_MODULUS constant must be valid");
    validate_canonical_scalar(value, &modulus).map_err(|e| format!("G1 {label} invalid: {e}"))
}

/// 将已验证 < modulus 的 BigUint 转为 BN254 Fq（不会 panic 或模约化）。
fn biguint_to_fq(value: &BigUint) -> Fq {
    let buf_size: usize = (Fq::MODULUS_BIT_SIZE as usize).div_ceil(8);
    let mut buf = value.to_bytes_le();
    buf.resize(buf_size, 0u8);
    let bigint =
        <Fq as PrimeField>::BigInt::deserialize_uncompressed(&buf[..]).expect("always works");
    Fq::from_bigint(bigint).expect("value < modulus always converts")
}

/// 将两个已验证 < modulus 的 BigUint 转为 BN254 Fq2（c0 + c1·u）。
fn biguint_to_fq2(c0: &BigUint, c1: &BigUint) -> Fq2 {
    Fq2::new(biguint_to_fq(c0), biguint_to_fq(c1))
}

/// 验证 G1 点 (x, y) 在 BN254 曲线上且属于正确子群。
/// identity：(0, 0) 视为合法。
fn validate_g1_curve_point(x: &BigUint, y: &BigUint) -> Result<(), String> {
    // identity 点在 BigUint 层面判断，避免 Field 类型 Zero trait 问题。
    let zero = BigUint::from(0u32);
    if *x == zero && *y == zero {
        return Ok(());
    }

    let fx = biguint_to_fq(x);
    let fy = biguint_to_fq(y);

    let point = G1Affine::new_unchecked(fx, fy);
    if !point.is_on_curve() {
        return Err("G1 point is not on BN254 curve".to_string());
    }
    if !point.is_in_correct_subgroup_assuming_on_curve() {
        return Err("G1 point is not in correct subgroup".to_string());
    }
    Ok(())
}

/// 验证 G2 点 (x_c0, x_c1, y_c0, y_c1) 在 BN254 曲线上且属于正确子群。
/// identity：(0,0, 0,0) 视为合法。
fn validate_g2_curve_point(
    x_c0: &BigUint,
    x_c1: &BigUint,
    y_c0: &BigUint,
    y_c1: &BigUint,
) -> Result<(), String> {
    // identity 点在 BigUint 层面判断。
    let zero = BigUint::from(0u32);
    if *x_c0 == zero && *x_c1 == zero && *y_c0 == zero && *y_c1 == zero {
        return Ok(());
    }

    let fx = biguint_to_fq2(x_c0, x_c1);
    let fy = biguint_to_fq2(y_c0, y_c1);

    let point = G2Affine::new_unchecked(fx, fy);
    if !point.is_on_curve() {
        return Err("G2 point is not on BN254 curve".to_string());
    }
    if !point.is_in_correct_subgroup_assuming_on_curve() {
        return Err("G2 point is not in correct subgroup".to_string());
    }
    Ok(())
}

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

//
// TryFrom：安全地将外部 proof 数据转为 circom_prover 内部结构，拒绝畸形输入。
//

impl TryFrom<CircomProof> for CircomProverProof {
    type Error = MoproError;

    fn try_from(proof: CircomProof) -> Result<Self, Self::Error> {
        Ok(CircomProverProof {
            a: CircomProverG1::try_from(proof.a)?,
            b: CircomProverG2::try_from(proof.b)?,
            c: CircomProverG1::try_from(proof.c)?,
            protocol: proof.protocol,
            curve: proof.curve,
        })
    }
}

impl From<CircomProverG1> for G1 {
    /// 将 G1 大整数坐标转为字符串，便于跨 FFI 和 JSON 传输（安全方向）。
    fn from(g1: CircomProverG1) -> Self {
        G1 {
            x: g1.x.to_string(),
            y: g1.y.to_string(),
            z: g1.z.to_string(),
        }
    }
}

impl TryFrom<G1> for CircomProverG1 {
    type Error = MoproError;

    fn try_from(g1: G1) -> Result<Self, Self::Error> {
        let x = validate_g1_coord(&g1.x, "x").map_err(|e| MoproError::CircomError(e))?;
        let y = validate_g1_coord(&g1.y, "y").map_err(|e| MoproError::CircomError(e))?;
        let z = validate_g1_coord(&g1.z, "z").map_err(|e| MoproError::CircomError(e))?;

        // 曲线点成员检查（使用 unchecked 构造 + 显式检查，避免 Arkworks assertion）。
        validate_g1_curve_point(&x, &y).map_err(|e| MoproError::CircomError(e))?;

        Ok(CircomProverG1 { x, y, z })
    }
}

impl From<CircomProverG2> for G2 {
    /// 将 G2 二次扩域坐标转为字符串数组（安全方向）。
    fn from(g2: CircomProverG2) -> Self {
        let x = vec![g2.x[0].to_string(), g2.x[1].to_string()];
        let y = vec![g2.y[0].to_string(), g2.y[1].to_string()];
        let z = vec![g2.z[0].to_string(), g2.z[1].to_string()];
        G2 { x, y, z }
    }
}

impl TryFrom<G2> for CircomProverG2 {
    type Error = MoproError;

    fn try_from(g2: G2) -> Result<Self, Self::Error> {
        if g2.x.len() != 2 {
            return Err(MoproError::CircomError(format!(
                "G2.x must have exactly 2 elements, got {}",
                g2.x.len()
            )));
        }
        if g2.y.len() != 2 {
            return Err(MoproError::CircomError(format!(
                "G2.y must have exactly 2 elements, got {}",
                g2.y.len()
            )));
        }
        if g2.z.len() != 2 {
            return Err(MoproError::CircomError(format!(
                "G2.z must have exactly 2 elements, got {}",
                g2.z.len()
            )));
        }

        let modulus = BigUint::from_str(BN254_BASE_MODULUS)
            .expect("BN254_BASE_MODULUS constant must be valid");
        let parse_pair = |values: &[String], label: &str| -> Result<[BigUint; 2], MoproError> {
            let a = validate_canonical_scalar(&values[0], &modulus)
                .map_err(|e| MoproError::CircomError(format!("G2 {label}[0] invalid: {e}")))?;
            let b = validate_canonical_scalar(&values[1], &modulus)
                .map_err(|e| MoproError::CircomError(format!("G2 {label}[1] invalid: {e}")))?;
            Ok([a, b])
        };

        let x = parse_pair(&g2.x, "x")?;
        let y = parse_pair(&g2.y, "y")?;
        let z = parse_pair(&g2.z, "z")?;

        // 曲线点成员检查（使用 unchecked 构造 + 显式检查，避免 Arkworks assertion）。
        validate_g2_curve_point(&x[0], &x[1], &y[0], &y[1])
            .map_err(|e| MoproError::CircomError(e))?;

        Ok(CircomProverG2 { x, y, z })
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
    // 用 catch_unwind 隔离依赖中可能的 panic。
    let zkey_path_clone = zkey_path.clone();
    let ret = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        CircomProver::prove(
            proof_lib.into(),
            witness_fn,
            circuit_inputs,
            zkey_path_clone,
        )
    }))
    .map_err(|_| {
        MoproError::CircomError(
            "Generate Proof panicked: zkey may be corrupt or unsupported".to_string(),
        )
    })?
    .map_err(|e| MoproError::CircomError(format!("Generate Proof error: {}", e)))?;

    // 当前项目只使用 BN254 曲线；不接受其他曲线。
    if ret.proof.curve != CURVE_BN254 {
        return Err(MoproError::CircomError(format!(
            "Unsupported curve: {}",
            ret.proof.curve
        )));
    }
    let proof = ret.proof.into();
    let pub_inputs = ret.pub_inputs.into();

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
    // 在序列化前校验所有外部 proof 数据。
    let proof: CircomProverProof = CircomProverProof::try_from(proof_result.proof)?;
    validate_public_inputs(&proof_result.inputs)
        .map_err(|e| MoproError::CircomError(format!("invalid public input: {e}")))?;
    let pub_inputs: circom_prover::prover::PublicInputs = proof_result.inputs.into();
    let internal = circom_prover::prover::CircomProof { proof, pub_inputs };
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
    // 只接受项目实际使用的 BN254 curve。
    if proof_result.proof.curve != CURVE_BN254 {
        return Err(MoproError::CircomError(format!(
            "Unsupported curve: {}",
            proof_result.proof.curve
        )));
    }

    // 在进入 circom_prover 之前校验所有外部 proof 数据和 public inputs。
    let proof: CircomProverProof = CircomProverProof::try_from(proof_result.proof)?;
    validate_public_inputs(&proof_result.inputs)
        .map_err(|e| MoproError::CircomError(format!("invalid public input: {e}")))?;
    let pub_inputs: circom_prover::prover::PublicInputs = proof_result.inputs.into();

    let chosen_proof_lib = proof_lib.into();
    // 用 catch_unwind 隔离 CircomProver::verify 中依赖可能的 panic（防御性）。
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        CircomProver::verify(
            chosen_proof_lib,
            circom_prover::prover::CircomProof { proof, pub_inputs },
            zkey_path,
        )
    }))
    .map_err(|_| {
        MoproError::CircomError(
            "Verification panicked: zkey may be corrupt or unsupported".to_string(),
        )
    })?
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

#[cfg(test)]
mod validation_tests {
    use super::*;
    use crate::MoproError;
    use num_bigint::BigUint;
    use std::convert::TryFrom;
    use std::panic;
    use std::str::FromStr;

    // =========================================================================
    // M-03: no-panic tests — malformed proof inputs must return Err, not panic
    // =========================================================================

    fn dummy_valid_g1() -> G1 {
        G1 {
            x: "1".to_string(),
            y: "2".to_string(),
            z: "1".to_string(),
        }
    }

    fn dummy_valid_g2() -> G2 {
        G2 {
            x: vec!["1".to_string(), "0".to_string()],
            y: vec!["2".to_string(), "0".to_string()],
            z: vec!["1".to_string(), "0".to_string()],
        }
    }

    macro_rules! assert_no_panic_err {
        ($expr:expr, $label:expr) => {
            let result = panic::catch_unwind(panic::AssertUnwindSafe(|| $expr));
            match result {
                Ok(Err(_)) => {} // expected: no panic, returned Err
                Ok(Ok(_)) => panic!("{}: expected Err, got Ok", $label),
                Err(_) => panic!("{}: PANICKED (should return Err)", $label),
            }
        };
    }

    #[test]
    fn m03_g1_x_empty() {
        let mut g1 = dummy_valid_g1();
        g1.x = "".to_string();
        assert_no_panic_err!(CircomProverG1::try_from(g1), "G1.x empty");
    }

    #[test]
    fn m03_g1_x_not_a_number() {
        let mut g1 = dummy_valid_g1();
        g1.x = "not-a-number".to_string();
        assert_no_panic_err!(CircomProverG1::try_from(g1), "G1.x not-a-number");
    }

    #[test]
    fn m03_g1_x_hex() {
        let mut g1 = dummy_valid_g1();
        g1.x = "0x10".to_string();
        assert_no_panic_err!(CircomProverG1::try_from(g1), "G1.x hex");
    }

    #[test]
    fn m03_g2_x_empty() {
        let mut g2 = dummy_valid_g2();
        g2.x = vec![];
        assert_no_panic_err!(CircomProverG2::try_from(g2), "G2.x empty");
    }

    #[test]
    fn m03_g2_x_one_element() {
        let mut g2 = dummy_valid_g2();
        g2.x = vec!["1".to_string()];
        assert_no_panic_err!(CircomProverG2::try_from(g2), "G2.x len=1");
    }

    #[test]
    fn m03_g2_x_three_elements() {
        let mut g2 = dummy_valid_g2();
        g2.x = vec!["1".to_string(), "2".to_string(), "3".to_string()];
        assert_no_panic_err!(CircomProverG2::try_from(g2), "G2.x len=3");
    }

    #[test]
    fn m03_g2_y_wrong_length() {
        let mut g2 = dummy_valid_g2();
        g2.y = vec!["1".to_string()];
        assert_no_panic_err!(CircomProverG2::try_from(g2), "G2.y len=1");
    }

    #[test]
    fn m03_g2_z_wrong_length() {
        let mut g2 = dummy_valid_g2();
        g2.z = vec!["1".to_string(), "2".to_string(), "3".to_string()];
        assert_no_panic_err!(CircomProverG2::try_from(g2), "G2.z len=3");
    }

    #[test]
    fn m03_public_input_empty() {
        let inputs = vec!["".to_string()];
        assert_no_panic_err!(
            validate_public_inputs(&inputs).map_err(|e| MoproError::CircomError(e)),
            "public input empty"
        );
    }

    #[test]
    fn m03_public_input_abc() {
        let inputs = vec!["abc".to_string()];
        assert_no_panic_err!(
            validate_public_inputs(&inputs).map_err(|e| MoproError::CircomError(e)),
            "public input abc"
        );
    }

    #[test]
    fn m03_public_input_negative() {
        let inputs = vec!["-1".to_string()];
        assert_no_panic_err!(
            validate_public_inputs(&inputs).map_err(|e| MoproError::CircomError(e)),
            "public input -1"
        );
    }

    // =========================================================================
    // M-05: canonical scalar tests
    // =========================================================================

    fn scalar_modulus() -> BigUint {
        BigUint::from_str(BN254_SCALAR_MODULUS).unwrap()
    }

    #[test]
    fn m05_canonical_zero() {
        assert!(validate_canonical_scalar("0", &scalar_modulus()).is_ok());
    }

    #[test]
    fn m05_canonical_q_minus_1() {
        let q_minus_1 = &scalar_modulus() - BigUint::from(1u32);
        assert!(validate_canonical_scalar(&q_minus_1.to_string(), &scalar_modulus()).is_ok());
    }

    #[test]
    fn m05_reject_modulus() {
        let q = scalar_modulus();
        assert!(validate_canonical_scalar(&q.to_string(), &scalar_modulus()).is_err());
    }

    #[test]
    fn m05_reject_numeric_x_plus_q() {
        // 实际数值 x + q：取 x=1，计算 1+q，确保数值别名被拒绝。
        let q = scalar_modulus();
        let x_plus_q = BigUint::from(1u32) + &q;
        assert!(validate_canonical_scalar(&x_plus_q.to_string(), &scalar_modulus()).is_err());
    }

    #[test]
    fn m05_reject_double_zero() {
        assert!(validate_canonical_scalar("00", &scalar_modulus()).is_err());
    }

    #[test]
    fn m05_reject_zero_one() {
        assert!(validate_canonical_scalar("01", &scalar_modulus()).is_err());
    }

    #[test]
    fn m05_reject_plus_one() {
        assert!(validate_canonical_scalar("+1", &scalar_modulus()).is_err());
    }

    #[test]
    fn m05_reject_negative_one() {
        assert!(validate_canonical_scalar("-1", &scalar_modulus()).is_err());
    }

    #[test]
    fn m05_reject_empty() {
        assert!(validate_canonical_scalar("", &scalar_modulus()).is_err());
    }

    // =========================================================================
    // M-03/M-05: verify_circom_proof integration tests
    // =========================================================================

    /// Construct a CircomProofResult that will cause verify_circom_proof to
    /// convert the proof (and thus validate G1/G2/public inputs).
    fn valid_proof_result_for_test() -> CircomProofResult {
        CircomProofResult {
            proof: CircomProof {
                a: dummy_valid_g1(),
                b: dummy_valid_g2(),
                c: dummy_valid_g1(),
                protocol: "groth16".to_string(),
                curve: "bn128".to_string(),
            },
            inputs: vec!["0".to_string()],
        }
    }

    #[test]
    fn m03_verify_g1_empty_x_returns_err() {
        let mut result = valid_proof_result_for_test();
        result.proof.a.x = "".to_string();
        let verify_result = verify_circom_proof(
            "./test-vectors/circom/areajudge_final.zkey".to_string(),
            result,
            ProofLib::Arkworks,
        );
        assert!(verify_result.is_err());
    }

    #[test]
    fn m03_verify_g2_short_x_returns_err() {
        let mut result = valid_proof_result_for_test();
        result.proof.b.x = vec!["1".to_string()];
        let verify_result = verify_circom_proof(
            "./test-vectors/circom/areajudge_final.zkey".to_string(),
            result,
            ProofLib::Arkworks,
        );
        assert!(verify_result.is_err());
    }

    #[test]
    fn m03_verify_bad_public_input_returns_err() {
        let mut result = valid_proof_result_for_test();
        result.inputs = vec!["not-a-number".to_string()];
        let verify_result = verify_circom_proof(
            "./test-vectors/circom/areajudge_final.zkey".to_string(),
            result,
            ProofLib::Arkworks,
        );
        assert!(verify_result.is_err());
    }

    // =========================================================================
    // 正常回归：合法 proof 仍然验证成功
    // =========================================================================

    #[test]
    fn regression_valid_proof_still_verifies() {
        // 使用 h3-converter 生成真实电路输入，生成 proof 并验证。
        let circuit_inputs =
            h3_converter::generate_circuit_input_with_salt(39.9042, 116.3974, 9, "987654321")
                .expect("h3-converter input 生成失败");

        let result = generate_circom_proof(
            "./test-vectors/circom/areajudge_final.zkey".to_string(),
            circuit_inputs,
            ProofLib::Arkworks,
        );
        assert!(result.is_ok(), "Proof 生成失败: {:?}", result.err());

        let proof_result = result.unwrap();
        let verified = verify_circom_proof(
            "./test-vectors/circom/areajudge_final.zkey".to_string(),
            proof_result,
            ProofLib::Arkworks,
        )
        .expect("验证调用失败");
        assert!(verified, "合法 proof 验证失败");
    }

    #[test]
    fn regression_g1_tryfrom_roundtrip() {
        // 使用真实 circuit 生成的 proof 中的 G1 点进行 round-trip 测试。
        let circuit_inputs =
            h3_converter::generate_circuit_input_with_salt(39.9042, 116.3974, 9, "987654321")
                .expect("h3-converter input 生成失败");
        let result = generate_circom_proof(
            "./test-vectors/circom/areajudge_final.zkey".to_string(),
            circuit_inputs,
            ProofLib::Arkworks,
        )
        .expect("proof 生成失败");
        // CircomProverG1 → G1 → CircomProverG1
        let g1_a: G1 = result.proof.a;
        let re_a = CircomProverG1::try_from(g1_a).expect("round-trip should succeed");
        // 再反方向验证
        let g1_a2: G1 = G1::from(re_a.clone());
        let re_a2 = CircomProverG1::try_from(g1_a2).expect("second round-trip should succeed");
        assert_eq!(re_a.x, re_a2.x);
        assert_eq!(re_a.y, re_a2.y);
        assert_eq!(re_a.z, re_a2.z);
    }

    #[test]
    fn regression_g2_tryfrom_roundtrip() {
        // 使用真实 circuit 生成的 proof 中的 G2 点进行 round-trip 测试。
        let circuit_inputs =
            h3_converter::generate_circuit_input_with_salt(39.9042, 116.3974, 9, "987654321")
                .expect("h3-converter input 生成失败");
        let result = generate_circom_proof(
            "./test-vectors/circom/areajudge_final.zkey".to_string(),
            circuit_inputs,
            ProofLib::Arkworks,
        )
        .expect("proof 生成失败");
        // CircomProverG2 → G2 → CircomProverG2
        let g2_b: G2 = result.proof.b;
        let re_b = CircomProverG2::try_from(g2_b).expect("round-trip should succeed");
        // 再反方向验证
        let g2_b2: G2 = G2::from(re_b.clone());
        let re_b2 = CircomProverG2::try_from(g2_b2).expect("second round-trip should succeed");
        assert_eq!(re_b.x, re_b2.x);
        assert_eq!(re_b.y, re_b2.y);
        assert_eq!(re_b.z, re_b2.z);
    }

    // =========================================================================
    // M-03: 非曲线点测试 — 域内但不在曲线上的点不得 panic
    // =========================================================================

    #[test]
    fn m03_g1_non_curve_no_panic() {
        // G1 (1,1,1): 域内但不在 BN254 曲线上。
        let g1 = G1 {
            x: "1".to_string(),
            y: "1".to_string(),
            z: "1".to_string(),
        };
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            CircomProverG1::try_from(g1)
        }));
        match result {
            Ok(Err(_)) => {} // 预期：返回 Err
            Ok(Ok(_)) => panic!("G1(1,1,1): expected Err, got Ok"),
            Err(_) => panic!("G1(1,1,1): PANICKED (should return Err)"),
        }
    }

    #[test]
    fn m03_g2_non_curve_no_panic() {
        // G2 x=(1,1), y=(1,1), z=(1,0): 域内但不在 BN254 曲线上。
        let g2 = G2 {
            x: vec!["1".to_string(), "1".to_string()],
            y: vec!["1".to_string(), "1".to_string()],
            z: vec!["1".to_string(), "0".to_string()],
        };
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            CircomProverG2::try_from(g2)
        }));
        match result {
            Ok(Err(_)) => {} // 预期：返回 Err
            Ok(Ok(_)) => panic!("G2(1,1,1,1,1,0): expected Err, got Ok"),
            Err(_) => panic!("G2(1,1,1,1,1,0): PANICKED (should return Err)"),
        }
    }

    #[test]
    fn m03_verify_g1_non_curve_returns_err() {
        // 生产入口：非曲线 G1 点通过 verify_circom_proof 返回 Err。
        let mut result = valid_proof_result_for_test();
        result.proof.a.x = "1".to_string();
        result.proof.a.y = "1".to_string();
        result.proof.a.z = "1".to_string();
        let verify_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            verify_circom_proof(
                "./test-vectors/circom/areajudge_final.zkey".to_string(),
                result,
                ProofLib::Arkworks,
            )
        }));
        match verify_result {
            Ok(Err(_)) => {} // 预期
            Ok(Ok(_)) => panic!("verify G1(1,1,1): expected Err"),
            Err(_) => panic!("verify G1(1,1,1): PANICKED"),
        }
    }

    #[test]
    fn m03_verify_g2_non_curve_returns_err() {
        // 生产入口：非曲线 G2 点通过 verify_circom_proof 返回 Err。
        let mut result = valid_proof_result_for_test();
        result.proof.b.x = vec!["1".to_string(), "1".to_string()];
        result.proof.b.y = vec!["1".to_string(), "1".to_string()];
        result.proof.b.z = vec!["1".to_string(), "0".to_string()];
        let verify_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            verify_circom_proof(
                "./test-vectors/circom/areajudge_final.zkey".to_string(),
                result,
                ProofLib::Arkworks,
            )
        }));
        match verify_result {
            Ok(Err(_)) => {} // 预期
            Ok(Ok(_)) => panic!("verify G2 non-curve: expected Err"),
            Err(_) => panic!("verify G2 non-curve: PANICKED"),
        }
    }

    // =========================================================================
    // M-05: 生产入口 x+q 拒绝测试
    // =========================================================================

    #[test]
    fn m05_verify_x_plus_q_rejected() {
        // 通过生产 verify_circom_proof 验证实数 x+q 被拒绝。
        let circuit_inputs =
            h3_converter::generate_circuit_input_with_salt(39.9042, 116.3974, 9, "987654321")
                .expect("h3-converter input 生成失败");
        let proof_result = generate_circom_proof(
            "./test-vectors/circom/areajudge_final.zkey".to_string(),
            circuit_inputs,
            ProofLib::Arkworks,
        )
        .expect("proof 生成失败");

        // 将第一个 public input (commitment) 替换为 x+q 别名
        let q = BigUint::from_str(BN254_SCALAR_MODULUS).unwrap();
        let original = BigUint::from_str(&proof_result.inputs[0]).unwrap();
        let aliased = &original + &q;
        let mut result = proof_result;
        result.inputs[0] = aliased.to_string();

        let verify_result = verify_circom_proof(
            "./test-vectors/circom/areajudge_final.zkey".to_string(),
            result,
            ProofLib::Arkworks,
        );
        assert!(
            verify_result.is_err(),
            "x+q alias should be rejected by production verifier"
        );
    }
}
