/*
 * 文件功能：
 * - 服务端 regex_record Arkworks fallback verifier。
 * - 从 stdin 读取 Android/mopro proof payload，用当前 regex_record zkey 做 Arkworks 验证。
 *
 * 执行流程：
 * 1. 参数 1 为 regex_record_final.zkey 路径。
 * 2. stdin 为 JSON：{ proof, inputs/publicSignals/public_inputs }。
 * 3. 输出 JSON：{ valid, verifier } 或 { valid:false, error }。
 */
use std::env;
use std::io::{self, Read};

use serde_json::{json, Value};
use zk_location::{verify_circom_proof, CircomProof, CircomProofResult, ProofLib, G1, G2};

fn main() {
    let result = run();
    match result {
        Ok(valid) => {
            println!("{}", json!({ "valid": valid, "verifier": "arkworks" }));
            std::process::exit(if valid { 0 } else { 1 });
        }
        Err(error) => {
            println!(
                "{}",
                json!({ "valid": false, "verifier": "arkworks", "error": error })
            );
            std::process::exit(2);
        }
    }
}

fn run() -> Result<bool, String> {
    let zkey_path = env::args()
        .nth(1)
        .ok_or_else(|| "missing zkey path argument".to_string())?;

    let mut input = String::new();
    io::stdin()
        .read_to_string(&mut input)
        .map_err(|error| format!("failed to read stdin: {error}"))?;
    let payload: Value =
        serde_json::from_str(&input).map_err(|error| format!("invalid JSON payload: {error}"))?;

    let proof_result = parse_proof_result(&payload)?;
    let verified = std::panic::catch_unwind(|| {
        verify_circom_proof(zkey_path, proof_result, ProofLib::Arkworks)
    })
    .map_err(|_| "Arkworks verifier panicked".to_string())?
    .map_err(|error| format!("Arkworks verification error: {error}"))?;

    Ok(verified)
}

fn parse_proof_result(payload: &Value) -> Result<CircomProofResult, String> {
    let proof_value = payload
        .get("proof")
        .or_else(|| {
            payload
                .get("proofResult")
                .and_then(|value| value.get("proof"))
        })
        .ok_or_else(|| "missing proof".to_string())?;
    let inputs_value = payload
        .get("publicSignals")
        .or_else(|| payload.get("public_inputs"))
        .or_else(|| payload.get("inputs"))
        .or_else(|| {
            payload
                .get("proofResult")
                .and_then(|value| value.get("inputs"))
        })
        .ok_or_else(|| "missing publicSignals/public_inputs/inputs".to_string())?;
    let inputs = parse_string_array(inputs_value, "inputs")?;

    Ok(CircomProofResult {
        proof: parse_proof(proof_value)?,
        inputs,
    })
}

fn parse_proof(value: &Value) -> Result<CircomProof, String> {
    if value.get("pi_a").is_some() {
        return Ok(CircomProof {
            a: parse_g1_array(value.get("pi_a").ok_or("missing pi_a")?, "pi_a")?,
            b: parse_g2_array(value.get("pi_b").ok_or("missing pi_b")?, "pi_b")?,
            c: parse_g1_array(value.get("pi_c").ok_or("missing pi_c")?, "pi_c")?,
            protocol: string_field(value, "protocol").unwrap_or_else(|| "groth16".to_string()),
            curve: string_field(value, "curve").unwrap_or_else(|| "bn128".to_string()),
        });
    }

    Ok(CircomProof {
        a: parse_g1_object(value.get("a").ok_or("missing proof.a")?, "proof.a")?,
        b: parse_g2_object(value.get("b").ok_or("missing proof.b")?, "proof.b")?,
        c: parse_g1_object(value.get("c").ok_or("missing proof.c")?, "proof.c")?,
        protocol: string_field(value, "protocol").unwrap_or_else(|| "groth16".to_string()),
        curve: string_field(value, "curve").unwrap_or_else(|| "bn128".to_string()),
    })
}

fn parse_g1_object(value: &Value, label: &str) -> Result<G1, String> {
    Ok(G1 {
        x: scalar_field(value, "x").ok_or_else(|| format!("{label}.x missing"))?,
        y: scalar_field(value, "y").ok_or_else(|| format!("{label}.y missing"))?,
        z: scalar_field(value, "z").unwrap_or_else(|| "1".to_string()),
    })
}

fn parse_g1_array(value: &Value, label: &str) -> Result<G1, String> {
    let items = parse_string_array(value, label)?;
    if items.len() < 2 {
        return Err(format!("{label} must contain at least x/y"));
    }
    Ok(G1 {
        x: items[0].clone(),
        y: items[1].clone(),
        z: items.get(2).cloned().unwrap_or_else(|| "1".to_string()),
    })
}

fn parse_g2_object(value: &Value, label: &str) -> Result<G2, String> {
    Ok(G2 {
        x: parse_string_array(
            value.get("x").ok_or_else(|| format!("{label}.x missing"))?,
            "x",
        )?,
        y: parse_string_array(
            value.get("y").ok_or_else(|| format!("{label}.y missing"))?,
            "y",
        )?,
        z: value
            .get("z")
            .map(|z| parse_string_array(z, "z"))
            .transpose()?
            .unwrap_or_else(|| vec!["1".to_string(), "0".to_string()]),
    })
}

fn parse_g2_array(value: &Value, label: &str) -> Result<G2, String> {
    let array = value
        .as_array()
        .ok_or_else(|| format!("{label} must be an array"))?;
    if array.len() < 2 {
        return Err(format!("{label} must contain x/y pairs"));
    }
    Ok(G2 {
        x: parse_string_array(&array[0], "pi_b.x")?,
        y: parse_string_array(&array[1], "pi_b.y")?,
        z: array
            .get(2)
            .map(|z| parse_string_array(z, "pi_b.z"))
            .transpose()?
            .unwrap_or_else(|| vec!["1".to_string(), "0".to_string()]),
    })
}

fn parse_string_array(value: &Value, label: &str) -> Result<Vec<String>, String> {
    value
        .as_array()
        .ok_or_else(|| format!("{label} must be an array"))?
        .iter()
        .map(value_to_string)
        .collect()
}

fn scalar_field(value: &Value, field: &str) -> Option<String> {
    value
        .get(field)
        .map(value_to_string)
        .transpose()
        .ok()
        .flatten()
}

fn string_field(value: &Value, field: &str) -> Option<String> {
    value.get(field).and_then(|field_value| {
        if field_value.is_null() {
            None
        } else {
            Some(value_to_string(field_value).ok()?)
        }
    })
}

fn value_to_string(value: &Value) -> Result<String, String> {
    match value {
        Value::String(text) => Ok(text.clone()),
        Value::Number(number) => Ok(number.to_string()),
        _ => Err("expected string or number".to_string()),
    }
}
