/*
 * 文件功能：
 * - Rust/mopro 主库入口，负责把 H3 位置输入生成、Circom proof 生成和 proof 验证导出给 Android。
 * - 注册 areajudge_final.zkey、regex_ip_final.zkey 和 regex_timestamp_final.zkey 对应的 witness 函数，让 Android 端 generateCircomProof 可以找到电路。
 *
 * 执行流程：
 * 1. mopro_ffi::app! 初始化 UniFFI 绑定。
 * 2. generate_location_circuit_input 调用 h3-converter 生成电路 input，并规范化为 witness 接受的数组格式。
 * 3. generate_circom_proof / verify_circom_proof 从 circom.rs 导出给 Kotlin。
 * 4. set_circom_circuits! 根据平台注册 Android RustWitness 或桌面 WitnessCalc。
 */
#[macro_use]
mod stubs;

mod error;
pub use error::MoproError;

// Initializes the shared UniFFI scaffolding and defines the `MoproError` enum.
#[cfg(not(target_arch = "wasm32"))]
mopro_ffi::app!();
// Skip wasm_setup!() to avoid extern crate alias conflict
// Instead, we import wasm_bindgen directly when needed
#[cfg(all(feature = "wasm", target_arch = "wasm32"))]
use mopro_ffi::prelude::wasm_bindgen;

/// You can also customize the bindings by #[uniffi::export]
/// Reference: https://mozilla.github.io/uniffi-rs/latest/proc_macro/index.html
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn mopro_hello_world() -> String {
    "Hello, World!".to_string()
}

#[cfg_attr(
    all(feature = "wasm", target_arch = "wasm32"),
    wasm_bindgen(js_name = "moproWasmHelloWorld")
)]
pub fn mopro_wasm_hello_world() -> String {
    "Hello, World!".to_string()
}

#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn generate_location_circuit_input(
    lat: f64,
    lon: f64,
    resolution: u8,
) -> Result<String, MoproError> {
    // input：h3-converter 输出的原始 JSON，其中标量字段仍是字符串。
    let input = h3_converter::generate_circuit_input(lat, lon, resolution)
        .map_err(MoproError::CircomError)?;
    normalize_rust_witness_input(&input)
}

#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn generate_location_cell_boundary(
    lat: f64,
    lon: f64,
    resolution: u8,
) -> Result<String, MoproError> {
    h3_converter::generate_cell_boundary(lat, lon, resolution).map_err(MoproError::CircomError)
}

fn normalize_rust_witness_input(input: &str) -> Result<String, MoproError> {
    // value：解析后的 JSON 输入。
    let value: serde_json::Value = serde_json::from_str(input)
        .map_err(|e| MoproError::CircomError(format!("Location input JSON 解析失败: {e}")))?;
    // object：顶层必须是对象，键名对应 Circom signal 名。
    let object = value
        .as_object()
        .ok_or_else(|| MoproError::CircomError("Location input JSON 不是对象".to_string()))?;

    // normalized：把标量字符串包装成单元素数组，兼容 rust_witness 输入格式。
    let normalized = object
        .iter()
        .map(|(key, value)| {
            // normalized_value：数组保持原样，字符串转为数组，其他类型保持原样。
            let normalized_value = match value {
                serde_json::Value::String(_) => serde_json::Value::Array(vec![value.clone()]),
                serde_json::Value::Array(_) => value.clone(),
                _ => value.clone(),
            };
            (key.clone(), normalized_value)
        })
        .collect::<serde_json::Map<_, _>>();

    serde_json::to_string(&serde_json::Value::Object(normalized))
        .map_err(|e| MoproError::CircomError(format!("Location input JSON 序列化失败: {e}")))
}

#[cfg(test)]
mod uniffi_tests {
    #[test]
    fn test_mopro_hello_world() {
        assert_eq!(super::mopro_hello_world(), "Hello, World!");
    }

    #[test]
    fn test_generate_location_circuit_input() {
        let input = super::generate_location_circuit_input(39.9042, 116.3974, 9).unwrap();
        assert!(input.contains("public_commitment"));
        assert!(input.contains("\"x\""));
        assert!(input.contains("\"y\""));

        let parsed: serde_json::Value = serde_json::from_str(&input).unwrap();
        assert!(parsed["public_commitment"].is_array());
        assert!(parsed["x"].is_array());
        assert!(parsed["y"].is_array());
        assert!(parsed["salt"].is_array());
    }

    #[test]
    fn test_generate_location_cell_boundary() {
        let boundary = super::generate_location_cell_boundary(30.75316, 103.92829, 15).unwrap();
        assert!(boundary.contains("\"vertices\""));
        assert!(boundary.contains("\"resolution\""));
    }
}

// CIRCOM_TEMPLATE
// --- Circom Example of using groth16 proving and verifying circuits ---

// Module containing the Circom circuit logic (Multiplier2)
#[macro_use]
mod circom;
pub use circom::{
    generate_circom_proof, verify_circom_proof, CircomProof, CircomProofResult, ProofLib, G1, G2,
};

#[cfg(target_os = "android")]
mod witness {
    rust_witness::witness!(areajudge);
    // w2c2/rust-witness 会把 wasm module 名中的下划线压缩掉：
    // regex_ip.wasm 导出的 C 符号是 regexipInstantiate，而不是 regex_ipInstantiate。
    rust_witness::witness!(regexip);
    // regex_timestamp.wasm 同样会压缩下划线，导出 regextimestampInstantiate。
    rust_witness::witness!(regextimestamp);
}

#[cfg(not(target_os = "android"))]
mod witness {
    witnesscalc_adapter::witness!(areajudge);
    witnesscalc_adapter::witness!(regex_ip);
}

#[cfg(target_os = "android")]
crate::set_circom_circuits! {
    ("areajudge_final.zkey", circom_prover::witness::WitnessFn::RustWitness(witness::areajudge_witness)),
    ("regex_ip_final.zkey", circom_prover::witness::WitnessFn::RustWitness(witness::regexip_witness)),
    ("regex_timestamp_final.zkey", circom_prover::witness::WitnessFn::RustWitness(witness::regextimestamp_witness)),
}

#[cfg(not(target_os = "android"))]
crate::set_circom_circuits! {
    ("areajudge_final.zkey", circom_prover::witness::WitnessFn::WitnessCalc(witness::areajudge_witness)),
    ("regex_ip_final.zkey", circom_prover::witness::WitnessFn::WitnessCalc(witness::regex_ip_witness)),
}

#[cfg(test)]
mod circom_tests {
    use crate::circom::{generate_circom_proof, verify_circom_proof, ProofLib};

    // ZKEY_PATH：测试使用的 areajudge proving key。
    const ZKEY_PATH: &str = "./test-vectors/circom/areajudge_final.zkey";

    #[test]
    fn test_areajudge() {
        // circuit_inputs：一个小整数 toy polygon，用于快速验证 proof backend 可用。
        let circuit_inputs = r#"{
            "x": "3",
            "y": "2",
            "salt": "12345",
            "public_commitment": "14781527219771935726911104342730986784538145608921172872991743849231083163924",
            "Ax_left":  ["0", "0", "2", "2", "0", "0"],
            "By_left":  ["0", "1", "0", "1", "1", "0"],
            "C_left":   ["0", "0", "0", "0", "2", "4"],
            "Ax_right": ["0", "0", "0", "0", "2", "2"],
            "By_right": ["1", "0", "1", "0", "0", "1"],
            "C_right":  ["0", "4", "8", "12", "0", "0"]
        }"#.to_string();

        let result =
            generate_circom_proof(ZKEY_PATH.to_string(), circuit_inputs, ProofLib::Arkworks);
        assert!(result.is_ok());
        let proof = result.unwrap();
        assert!(verify_circom_proof(ZKEY_PATH.to_string(), proof, ProofLib::Arkworks).is_ok());
    }

}

// HALO2_TEMPLATE
halo2_stub!();

// NOIR_TEMPLATE
noir_stub!();

#[cfg(test)]
mod h3_integration_tests {
    use crate::circom::{generate_circom_proof, verify_circom_proof, ProofLib};

    // ZKEY_PATH：H3 真实位置集成测试使用的 proving key。
    const ZKEY_PATH: &str = "./test-vectors/circom/areajudge_final.zkey";

    #[test]
    fn test_h3_real_location() {
        // 北京天安门 (39.9042, 116.3974)，使用全局绝对定点坐标生成 witness。
        let circuit_inputs =
            h3_converter::generate_circuit_input_with_salt(39.9042, 116.3974, 9, "987654321")
                .expect("h3-converter input 生成失败");

        let result =
            generate_circom_proof(ZKEY_PATH.to_string(), circuit_inputs, ProofLib::Arkworks);
        assert!(result.is_ok(), "Proof 生成失败: {:?}", result.err());

        let proof = result.unwrap();
        let verified = verify_circom_proof(ZKEY_PATH.to_string(), proof, ProofLib::Arkworks)
            .expect("验证调用失败");
        assert!(verified, "Proof 验证结果为 false，点不在六边形内！");
        println!("H3 真实坐标端到端验证通过!");
    }

    #[test]
    fn test_h3_converter_generated_input() {
        let circuit_inputs = h3_converter::generate_circuit_input(39.9042, 116.3974, 9)
            .expect("h3-converter input 生成失败");

        let proof =
            generate_circom_proof(ZKEY_PATH.to_string(), circuit_inputs, ProofLib::Arkworks)
                .expect("Proof 生成失败");

        let verified = verify_circom_proof(ZKEY_PATH.to_string(), proof, ProofLib::Arkworks)
            .expect("验证调用失败");
        assert!(verified, "h3-converter 生成的 input 未通过 proof 验证");
    }

    #[test]
    fn test_location_exported_input() {
        let circuit_inputs =
            crate::generate_location_circuit_input(39.9042, 116.3974, 9).expect("input 生成失败");

        let proof =
            generate_circom_proof(ZKEY_PATH.to_string(), circuit_inputs, ProofLib::Arkworks)
                .expect("Proof 生成失败");

        let verified = verify_circom_proof(ZKEY_PATH.to_string(), proof, ProofLib::Arkworks)
            .expect("验证调用失败");
        assert!(verified, "导出的 Location input 未通过 proof 验证");
    }
}

// #[cfg(test)]
// mod diag_tests {
//     use crate::circom::{generate_circom_proof, verify_circom_proof, ProofLib};
//     const ZKEY_PATH: &str = "./test-vectors/circom/areajudge_final.zkey";

//     #[test]
//     fn test_verify_return_value() {
//         // 小数值（原始测试用例）
//         let inputs = r#"{"x":"3","y":"2","Ax_left":["0","0","2","2","0","0"],"By_left":["0","1","0","1","1","0"],"C_left":["0","0","0","0","2","4"],"Ax_right":["0","0","0","0","2","2"],"By_right":["1","0","1","0","0","1"],"C_right":["0","4","8","12","0","0"]}"#.to_string();
//         let proof = generate_circom_proof(ZKEY_PATH.to_string(), inputs, ProofLib::Arkworks).unwrap();
//         let result = verify_circom_proof(ZKEY_PATH.to_string(), proof, ProofLib::Arkworks);
//         println!("[小数值] verify 返回值: {:?}", result);

//         // H3 真实坐标
//         let inputs_h3 = r#"{"x":"20004692","y":"20010298","Ax_left":["0","0","7947","16216","8269","0"],"By_left":["2809","0","0","0","14843","17654"],"C_left":["267896047231","461956072832","193856070022","0","0","0"],"Ax_right":["16217","8268","0","0","0","7947"],"By_right":["0","14843","17653","2810","0","0"],"C_right":["0","0","0","268383929978","462503929978","194403946194"]}"#.to_string();
//         let proof_h3 = generate_circom_proof(ZKEY_PATH.to_string(), inputs_h3, ProofLib::Arkworks).unwrap();
//         let result_h3 = verify_circom_proof(ZKEY_PATH.to_string(), proof_h3, ProofLib::Arkworks);
//         println!("[H3真实] verify 返回值: {:?}", result_h3);
//     }
// }

// #[cfg(test)]
// mod debug_inputs {
//     use crate::circom::{generate_circom_proof, verify_circom_proof, ProofLib};
//     const ZKEY_PATH: &str = "./test-vectors/circom/areajudge_final.zkey";

//     #[test]
//     fn test_debug_proof_inputs() {
//         let inputs = r#"{"x":"3","y":"2","Ax_left":["0","0","2","2","0","0"],"By_left":["0","1","0","1","1","0"],"C_left":["0","0","0","0","2","4"],"Ax_right":["0","0","0","0","2","2"],"By_right":["1","0","1","0","0","1"],"C_right":["0","4","8","12","0","0"]}"#.to_string();

//         let proof = generate_circom_proof(ZKEY_PATH.to_string(), inputs, ProofLib::Arkworks).unwrap();
//         println!("proof.inputs 长度: {}", proof.inputs.len());
//         for (i, v) in proof.inputs.iter().enumerate() {
//             println!("  inputs[{}] = {}", i, v);
//         }
//         println!("proof.proof.protocol = {}", proof.proof.protocol);
//         println!("proof.proof.curve = {}", proof.proof.curve);
//     }
// }

// #[cfg(test)]
// mod debug_proof_data {
//     use crate::circom::{generate_circom_proof, ProofLib};
//     const ZKEY_PATH: &str = "./test-vectors/circom/areajudge_final.zkey";

//     #[test]
//     fn test_dump_proof() {
//         let inputs = r#"{"x":"3","y":"2","Ax_left":["0","0","2","2","0","0"],"By_left":["0","1","0","1","1","0"],"C_left":["0","0","0","0","2","4"],"Ax_right":["0","0","0","0","2","2"],"By_right":["1","0","1","0","0","1"],"C_right":["0","4","8","12","0","0"]}"#.to_string();
//         let proof = generate_circom_proof(ZKEY_PATH.to_string(), inputs, ProofLib::Arkworks).unwrap();
//         println!("a.x = {}", proof.proof.a.x);
//         println!("a.y = {}", proof.proof.a.y);
//         println!("a.z = {}", proof.proof.a.z);
//         println!("b.x = {:?}", proof.proof.b.x);
//         println!("b.y = {:?}", proof.proof.b.y);
//         println!("b.z = {:?}", proof.proof.b.z);
//         println!("c.x = {}", proof.proof.c.x);
//         println!("c.y = {}", proof.proof.c.y);
//         println!("c.z = {}", proof.proof.c.z);
//         println!("protocol = {}", proof.proof.protocol);
//         println!("curve = {}", proof.proof.curve);

//         // 试着用同一个 proof 立即验证
//         let proof2 = proof.clone();
//         let result = crate::circom::verify_circom_proof(ZKEY_PATH.to_string(), proof2, ProofLib::Arkworks);
//         println!("立即验证结果: {:?}", result);
//     }
// }

// #[cfg(test)]
// mod debug_export_proof {
//     use crate::circom::{generate_circom_proof, ProofLib};
//     const ZKEY_PATH: &str = "./test-vectors/circom/areajudge_final.zkey";

//     #[test]
//     fn test_export_proof_json() {
//         let inputs = r#"{"x":"3","y":"2","Ax_left":["0","0","2","2","0","0"],"By_left":["0","1","0","1","1","0"],"C_left":["0","0","0","0","2","4"],"Ax_right":["0","0","0","0","2","2"],"By_right":["1","0","1","0","0","1"],"C_right":["0","4","8","12","0","0"]}"#.to_string();
//         let result = generate_circom_proof(ZKEY_PATH.to_string(), inputs, ProofLib::Arkworks);
//         match result {
//             Ok(proof) => {
//                 println!("PROOF_OK");
//                 println!("inputs_count={}", proof.inputs.len());
//                 // 打印所有 public inputs
//                 for (i, v) in proof.inputs.iter().enumerate() {
//                     println!("pub[{}]={}", i, v);
//                 }
//             }
//             Err(e) => {
//                 println!("PROOF_ERR: {:?}", e);
//             }
//         }
//     }
// }
