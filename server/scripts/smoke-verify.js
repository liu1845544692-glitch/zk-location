"use strict";

/*
 * 文件功能：
 * - 服务端 proof-format 的烟雾测试脚本。
 * - 用 snarkjs 生成一份 areajudge proof，再分别验证 snarkjs 原生格式和 mopro-like 格式。
 *
 * 执行流程：
 * 1. 读取 verification key、wasm、zkey 和固定 circuit input。
 * 2. 调用 snarkjs.groth16.fullProve 生成 proof/publicSignals。
 * 3. 调用 verifyPayload 验证 snarkjs payload。
 * 4. 将 proof 转成 Android/mopro 提交格式，再次验证。
 */
const fs = require("node:fs");
const path = require("node:path");
const snarkjs = require("snarkjs");
const { verifyPayload } = require("../src/proof-format");

// repoRoot：项目根目录，脚本从 server/scripts 下回溯两级定位。
const repoRoot = path.resolve(__dirname, "../..");
// wasmPath/zkeyPath/vkPath：Groth16 proof 生成和验证所需文件。
const wasmPath = path.join(repoRoot, "circuits/areajudge_js/areajudge.wasm");
const zkeyPath = path.join(repoRoot, "circuits/areajudge_final.zkey");
const vkPath = path.join(repoRoot, "circuits/verification_key.json");

// circuitInput：固定 toy polygon 输入，用于快速验证 proof-format 兼容性。
const circuitInput = {
  x: "3",
  y: "2",
  salt: "12345",
  public_commitment: "14781527219771935726911104342730986784538145608921172872991743849231083163924",
  Ax_left: ["0", "0", "2", "2", "0", "0"],
  By_left: ["0", "1", "0", "1", "1", "0"],
  C_left: ["0", "0", "0", "0", "2", "4"],
  Ax_right: ["0", "0", "0", "0", "2", "2"],
  By_right: ["1", "0", "1", "0", "0", "1"],
  C_right: ["0", "4", "8", "12", "0", "0"],
};

/** 运行 smoke proof 生成和两种 payload 格式验证。 */
async function main() {
  // verificationKey：服务端 verifier 使用的 verification key。
  const verificationKey = JSON.parse(fs.readFileSync(vkPath, "utf8"));
  // proof/publicSignals：snarkjs 生成的 Groth16 proof 和公开输入。
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(
    circuitInput,
    wasmPath,
    zkeyPath
  );

  // snarkjsResult：验证原生 snarkjs payload 的结果。
  const snarkjsResult = await verifyPayload(verificationKey, {
    proof,
    publicSignals,
  });

  if (!snarkjsResult.valid) {
    throw new Error(`snarkjs payload verification failed: ${JSON.stringify(snarkjsResult)}`);
  }

  // moproLikePayload：模拟 Android/mopro 提交给服务端的 proof 结构。
  const moproLikePayload = {
    proof: {
      a: {
        x: proof.pi_a[0],
        y: proof.pi_a[1],
        z: proof.pi_a[2],
      },
      b: {
        x: proof.pi_b[0],
        y: proof.pi_b[1],
        z: proof.pi_b[2],
      },
      c: {
        x: proof.pi_c[0],
        y: proof.pi_c[1],
        z: proof.pi_c[2],
      },
      protocol: proof.protocol,
      curve: proof.curve,
    },
    inputs: publicSignals,
  };

  // moproResult：验证 mopro-like payload 的结果。
  const moproResult = await verifyPayload(verificationKey, moproLikePayload);
  if (!moproResult.valid) {
    throw new Error(`mopro-like payload verification failed: ${JSON.stringify(moproResult)}`);
  }

  console.log("Smoke verification passed");
  console.log(JSON.stringify({
    publicInputCount: publicSignals.length,
    snarkjsAcceptedFormat: snarkjsResult.acceptedFormat,
    moproAcceptedFormat: moproResult.acceptedFormat,
  }, null, 2));
  process.exit(0);
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
