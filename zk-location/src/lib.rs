/*
 * 文件功能：
 * - Rust/mopro 主库入口，负责把 H3 位置输入生成、Regex record 输入生成、Circom proof 生成和 proof 验证导出给 Android。
 * - 注册 areajudge_final.zkey、regex_ip_final.zkey、regex_timestamp_final.zkey、port_trans_final.zkey、unit_final.zkey、protocol_regex_final.zkey 和 regex_record_final.zkey 对应的 witness 函数，让 Android 端 generateCircomProof 可以找到电路。
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

#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn generate_regex_record_circuit_input(
    source_ip: String,
    destination_ip: String,
    timestamp: String,
    port: String,
    trans: String,
    unit: String,
    protocol: String,
) -> Result<String, MoproError> {
    h3_converter::generate_regex_record_circuit_input(
        &source_ip,
        &destination_ip,
        &timestamp,
        &port,
        &trans,
        &unit,
        &protocol,
    )
    .map_err(MoproError::CircomError)
}

#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn generate_password_len8_benchmark_input() -> Result<String, MoproError> {
    generate_password_benchmark_input(8)
}

#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn generate_password_benchmark_input(password_length: u8) -> Result<String, MoproError> {
    let input = h3_converter::password::generate_benchmark_input_json(password_length as usize)
        .map_err(|e| MoproError::CircomError(e.to_string()))?;
    normalize_rust_witness_input(&input)
}

#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn generate_password_registration_input(
    password: String,
    salt: String,
) -> Result<String, MoproError> {
    let input = h3_converter::password::generate_registration_input_json(&password, &salt)
        .map_err(|e| MoproError::CircomError(e.to_string()))?;
    normalize_rust_witness_input(&input)
}

#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn compute_password_commitment(password: String, salt: String) -> Result<String, MoproError> {
    h3_converter::password::compute_password_commitment(&password, &salt)
        .map_err(|e| MoproError::CircomError(e.to_string()))
}

fn normalize_rust_witness_input(input: &str) -> Result<String, MoproError> {
    // value：解析后的 JSON 输入。
    let value: serde_json::Value = serde_json::from_str(input)
        .map_err(|e| MoproError::CircomError(format!("Location input JSON 解析失败: {e}")))?;
    // object：顶层必须是对象，键名对应 Circom signal 名。
    let object = value
        .as_object()
        .ok_or_else(|| MoproError::CircomError("Location input JSON 不是对象".to_string()))?;

    // rust-witness only accepts arrays of decimal strings. Circom JSON commonly
    // contains numeric scalars and numeric arrays, so normalize both forms.
    let normalized = object
        .iter()
        .map(|(key, value)| {
            let normalized_value = match value {
                serde_json::Value::Array(values) => serde_json::Value::Array(
                    values
                        .iter()
                        .map(value_to_decimal_string)
                        .collect::<Result<Vec<_>, _>>()?,
                ),
                _ => serde_json::Value::Array(vec![value_to_decimal_string(value)?]),
            };
            Ok((key.clone(), normalized_value))
        })
        .collect::<Result<serde_json::Map<_, _>, MoproError>>()?;

    serde_json::to_string(&serde_json::Value::Object(normalized))
        .map_err(|e| MoproError::CircomError(format!("Location input JSON 序列化失败: {e}")))
}

fn value_to_decimal_string(value: &serde_json::Value) -> Result<serde_json::Value, MoproError> {
    match value {
        serde_json::Value::String(text) => Ok(serde_json::Value::String(text.clone())),
        serde_json::Value::Number(number) => Ok(serde_json::Value::String(number.to_string())),
        _ => Err(MoproError::CircomError(format!(
            "Rust witness input must contain strings or numbers, got {value}"
        ))),
    }
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

    #[test]
    fn test_generate_regex_record_circuit_input() {
        let input = super::generate_regex_record_circuit_input(
            "140.80.0.121".to_string(),
            "140.80.0.11".to_string(),
            "2025-04-27 11:26:32.615683".to_string(),
            "502".to_string(),
            "19164".to_string(),
            "0".to_string(),
            "Modbus/TCP".to_string(),
        )
        .unwrap();
        assert!(input.contains("record_commitment"));
        assert!(input.contains("source_ip"));
        assert!(input.contains("schemaVersion"));
    }

    #[test]
    fn password_input_is_normalized_for_rust_witness() {
        let input = super::generate_password_len8_benchmark_input().unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&input).unwrap();
        for (name, value) in parsed.as_object().unwrap() {
            let values = value
                .as_array()
                .unwrap_or_else(|| panic!("{name} was not normalized to an array"));
            assert!(
                !values.is_empty(),
                "{name} was normalized to an empty array"
            );
            assert!(
                values.iter().all(serde_json::Value::is_string),
                "{name} contains a non-string RustWitness input"
            );
        }
        assert_eq!(parsed["matchStart"][0], "0");
        assert_eq!(parsed["matchLength"][0], "10");
        assert_eq!(parsed["inHaystack"][0], "80");
        assert_eq!(parsed["inHaystack"][1], "65");
    }

    #[test]
    fn all_password_benchmark_inputs_are_normalized() {
        for (length, expected) in [
            (
                8,
                "19506709927157339127216134994054708157265210932536273927045978637769242245953",
            ),
            (
                16,
                "11186526345370232576299025816516415797176095098189845436645573564034254234122",
            ),
            (
                32,
                "15382327428467064216367910183421615477503124169574981342044370954693189986584",
            ),
        ] {
            let input = super::generate_password_benchmark_input(length).unwrap();
            let value: serde_json::Value = serde_json::from_str(&input).unwrap();
            assert_eq!(value["matchLength"][0], (length + 2).to_string());
            assert_eq!(value["passwordCommitment"][0], expected);
            assert!(value.as_object().unwrap().values().all(|field| field
                .as_array()
                .is_some_and(|values| { values.iter().all(serde_json::Value::is_string) })));
        }
    }

    #[test]
    fn registration_input_is_normalized_and_salt_changes_commitment() {
        let first = super::generate_password_registration_input(
            "Aa1!bbbb".to_string(),
            "123456789".to_string(),
        )
        .unwrap();
        let second = super::generate_password_registration_input(
            "Aa1!bbbb".to_string(),
            "987654321".to_string(),
        )
        .unwrap();
        let first_value: serde_json::Value = serde_json::from_str(&first).unwrap();
        let second_value: serde_json::Value = serde_json::from_str(&second).unwrap();
        assert_ne!(
            first_value["passwordCommitment"],
            second_value["passwordCommitment"]
        );
        assert!(first_value.as_object().unwrap().values().all(|field| field
            .as_array()
            .is_some_and(|values| values.iter().all(serde_json::Value::is_string))));
    }

    #[test]
    fn login_commitment_export_matches_registration_commitment() {
        let input =
            super::generate_password_registration_input("Aa1!bbbb".to_string(), "1008".to_string())
                .unwrap();
        let value: serde_json::Value = serde_json::from_str(&input).unwrap();
        assert_eq!(
            super::compute_password_commitment("Aa1!bbbb".to_string(), "1008".to_string()).unwrap(),
            value["passwordCommitment"][0]
        );
    }

    #[test]
    fn rust_witness_normalization_covers_supported_shapes() {
        let normalized = super::normalize_rust_witness_input(
            r#"{
                "numericScalar": 123,
                "stringScalar": "456",
                "numericArray": [1, 2, 3],
                "stringArray": ["4", "5"],
                "emptyArray": []
            }"#,
        )
        .unwrap();
        let value: serde_json::Value = serde_json::from_str(&normalized).unwrap();
        assert_eq!(value["numericScalar"], serde_json::json!(["123"]));
        assert_eq!(value["stringScalar"], serde_json::json!(["456"]));
        assert_eq!(value["numericArray"], serde_json::json!(["1", "2", "3"]));
        assert_eq!(value["stringArray"], serde_json::json!(["4", "5"]));
        assert_eq!(value["emptyArray"], serde_json::json!([]));
    }

    #[test]
    fn rust_witness_normalization_rejects_unsupported_types() {
        for input in [
            r#"{"object":{"nested":"1"}}"#,
            r#"{"boolean":true}"#,
            r#"{"null":null}"#,
            r#"{"nestedArray":[["1"]]}"#,
        ] {
            let error = super::normalize_rust_witness_input(input).unwrap_err();
            assert!(
                error.to_string().contains("strings or numbers"),
                "unexpected error for {input}: {error}"
            );
        }
    }

    #[test]
    fn rust_witness_normalization_diagnostic() {
        let raw_location =
            h3_converter::generate_circuit_input_with_salt(39.9042, 116.3974, 9, "987654321")
                .unwrap();
        let raw_value: serde_json::Value = serde_json::from_str(&raw_location).unwrap();
        let normalized = super::normalize_rust_witness_input(&raw_location).unwrap();
        let normalized_value: serde_json::Value = serde_json::from_str(&normalized).unwrap();
        let rust_witness_map = circom_prover::witness::json_to_hashmap(&normalized).unwrap();

        for (name, raw) in raw_value.as_object().unwrap() {
            let values = normalized_value[name].as_array().unwrap();
            println!(
                "location field={name} raw_type={} normalized_len={} normalized_elements=strings",
                json_type(raw),
                values.len()
            );
            assert_eq!(rust_witness_map[name].len(), values.len());
        }
        assert_eq!(rust_witness_map.len(), raw_value.as_object().unwrap().len());

        let regex = r#"{"msg":["49","57","50","46","49","54","56","46","48","48","49","46","48","49","50"]}"#;
        let regex_value: serde_json::Value = serde_json::from_str(regex).unwrap();
        let regex_map = circom_prover::witness::json_to_hashmap(regex).unwrap();
        println!(
            "source_ip field=msg raw_type={} normalized_len={} normalized_elements=strings",
            json_type(&regex_value["msg"]),
            regex_map["msg"].len()
        );
        assert_eq!(regex_map["msg"].len(), 15);
    }

    fn json_type(value: &serde_json::Value) -> &'static str {
        match value {
            serde_json::Value::Null => "null",
            serde_json::Value::Bool(_) => "boolean",
            serde_json::Value::Number(_) => "number",
            serde_json::Value::String(_) => "string",
            serde_json::Value::Array(values) => {
                if values.iter().all(serde_json::Value::is_string) {
                    "string_array"
                } else if values.iter().all(serde_json::Value::is_number) {
                    "number_array"
                } else {
                    "mixed_array"
                }
            }
            serde_json::Value::Object(_) => "object",
        }
    }
}

// CIRCOM_TEMPLATE
// --- Circom Example of using groth16 proving and verifying circuits ---

// Module containing the Circom circuit logic (Multiplier2)
#[macro_use]
mod circom;
pub use circom::{
    generate_circom_proof, generate_password_circom_proof_diagnostic, hash_circom_proof_result,
    verify_circom_proof, CircomProof, CircomProofResult, PasswordProofDiagnostic, ProofLib, G1, G2,
};

#[cfg(target_os = "android")]
mod witness {
    rust_witness::witness!(areajudge);
    // w2c2/rust-witness 会把 wasm module 名中的下划线压缩掉：
    // regex_ip.wasm 导出的 C 符号是 regexipInstantiate，而不是 regex_ipInstantiate。
    rust_witness::witness!(regexip);
    // regex_timestamp.wasm 同样会压缩下划线，导出 regextimestampInstantiate。
    rust_witness::witness!(regextimestamp);
    // port_trans.wasm 同样会压缩下划线，导出 porttransInstantiate。
    rust_witness::witness!(porttrans);
    rust_witness::witness!(unit);
    // protocol_regex.wasm 同样会压缩下划线，导出 protocolregexInstantiate。
    rust_witness::witness!(protocolregex);
    // regex_record.wasm 同样会压缩下划线，导出 regexrecordInstantiate。
    rust_witness::witness!(regexrecord);
    // password_policy_commitment_main.wasm 同样会压缩下划线。
    rust_witness::witness!(passwordpolicycommitmentmain);
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
    ("port_trans_final.zkey", circom_prover::witness::WitnessFn::RustWitness(witness::porttrans_witness)),
    ("unit_final.zkey", circom_prover::witness::WitnessFn::RustWitness(witness::unit_witness)),
    ("protocol_regex_final.zkey", circom_prover::witness::WitnessFn::RustWitness(witness::protocolregex_witness)),
    ("regex_record_final.zkey", circom_prover::witness::WitnessFn::RustWitness(witness::regexrecord_witness)),
    ("password_policy_commitment_final.zkey", circom_prover::witness::WitnessFn::RustWitness(witness::passwordpolicycommitmentmain_witness)),
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
        let input_value: serde_json::Value = serde_json::from_str(&circuit_inputs).unwrap();
        let expected_commitment = input_value["public_commitment"][0].as_str().unwrap();

        let proof =
            generate_circom_proof(ZKEY_PATH.to_string(), circuit_inputs, ProofLib::Arkworks)
                .expect("Proof 生成失败");
        assert_eq!(proof.inputs.len(), 37);
        assert_eq!(proof.inputs[0], expected_commitment);

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
