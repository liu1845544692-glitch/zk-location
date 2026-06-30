/*
 * 文件功能：
 * - 本地命令行 proof 生成工具，用固定经纬度生成 areajudge input 和 proof JSON。
 * - 用于桌面调试 Rust/H3/Circom 链路，不参与 Android 运行时。
 *
 * 执行流程：
 * 1. 使用 lat/lon/resolution 生成电路输入 JSON。
 * 2. 调用 generate_circom_proof 生成 Groth16 proof。
 * 3. 将 input 和 proof 分别写入当前目录，便于 server 或 snarkjs 交叉验证。
 */
use std::fs;

use zk_location::{generate_circom_proof, ProofLib};

// ZKEY_PATH：本地测试使用的 proving key。
const ZKEY_PATH: &str = "./test-vectors/circom/areajudge_final.zkey";
// OUT_DIR：生成 input/proof JSON 的输出目录。
const OUT_DIR: &str = ".";

fn main() {
    // lat/lon：测试用 GNSS 坐标。
    let lat = 30.7487140;
    let lon = 103.9218760;
    // resolution：测试用 H3 resolution。
    let resolution: u8 = 8;

    // 1. 生成电路输入
    let circuit_inputs = h3_converter::generate_circuit_input(lat, lon, resolution)
        .expect("h3-converter input 生成失败");

    // input_path：保存电路输入 JSON 的文件名。
    let input_path = format!("{OUT_DIR}/input_{}_{}_r{}.json", lat, lon, resolution);
    fs::write(&input_path, &circuit_inputs).expect("写入 input 文件失败");
    println!("电路输入已保存: {input_path}");

    // 2. 生成 proof
    // result：proof 生成结果，包含 proof 和 public inputs。
    let result = generate_circom_proof(ZKEY_PATH.to_string(), circuit_inputs, ProofLib::Arkworks)
        .expect("Proof 生成失败");

    // 3. 将 proof 序列化为 JSON 并保存
    // proof_json：方便服务端或外部工具读取的 proof JSON。
    let proof_json = serde_json::json!({
        "a": {
            "x": result.proof.a.x,
            "y": result.proof.a.y,
            "z": result.proof.a.z,
        },
        "b": {
            "x": result.proof.b.x,
            "y": result.proof.b.y,
            "z": result.proof.b.z,
        },
        "c": {
            "x": result.proof.c.x,
            "y": result.proof.c.y,
            "z": result.proof.c.z,
        },
        "protocol": result.proof.protocol,
        "curve": result.proof.curve,
        "public_inputs": result.inputs,
    });

    // proof_path：保存 proof JSON 的文件名。
    let proof_path = format!("{OUT_DIR}/proof_{}_{}_r{}.json", lat, lon, resolution);
    // proof_str：格式化后的 proof JSON 字符串。
    let proof_str = serde_json::to_string_pretty(&proof_json).expect("proof 序列化失败");
    fs::write(&proof_path, &proof_str).expect("写入 proof 文件失败");
    println!("Proof 已保存: {proof_path}");
}
