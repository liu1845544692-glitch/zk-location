"use strict";

/*
 * 文件功能：
 * - 测试服务端 proof-format 对 Android/mopro 格式和 snarkjs 格式的兼容转换。
 *
 * 执行流程：
 * 1. mopro 格式输入会转换为 snarkjs pi_a/pi_b/pi_c 候选。
 * 2. snarkjs 原生格式会原样作为候选。
 * 3. public signals 会统一规范化为字符串数组。
 */
const test = require("node:test");
const assert = require("node:assert/strict");
const { normalizePublicSignals, proofCandidates } = require("../src/proof-format");

test("accepts mopro proof result shape", () => {
  // payload：Android/mopro 提交给 /verify-proof 的 proof 形状。
  const payload = {
    proof: {
      a: { x: "1", y: "2", z: "1" },
      b: { x: ["3", "4"], y: ["5", "6"], z: ["11", "12"] },
      c: { x: "7", y: "8", z: "1" },
      protocol: "groth16",
      curve: "bn128",
    },
    inputs: ["9", 10],
  };

  assert.deepEqual(normalizePublicSignals(payload), ["9", "10"]);

  // candidates：服务端尝试验证的 proof 候选格式列表。
  const candidates = proofCandidates(payload);
  assert.equal(candidates.length, 6);
  assert.equal(candidates[0].format, "mopro");
  assert.deepEqual(candidates[0].proof.pi_a, ["1", "2", "1"]);
  assert.deepEqual(candidates[0].proof.pi_b, [
    ["3", "4"],
    ["5", "6"],
    ["11", "12"],
  ]);
  assert.equal(candidates[1].format, "mopro_g2_pair_swapped");
  assert.deepEqual(candidates[1].proof.pi_b, [
    ["4", "3"],
    ["6", "5"],
    ["11", "12"],
  ]);
  assert.equal(candidates[2].format, "mopro_g2_pair_swapped_with_z");
  assert.deepEqual(candidates[2].proof.pi_b, [
    ["4", "3"],
    ["6", "5"],
    ["12", "11"],
  ]);
  assert.equal(candidates[3].format, "mopro_g2_xy_swapped");
  assert.deepEqual(candidates[3].proof.pi_b, [
    ["5", "6"],
    ["3", "4"],
    ["11", "12"],
  ]);
  assert.equal(candidates[4].format, "mopro_g2_xy_pair_swapped");
  assert.deepEqual(candidates[4].proof.pi_b, [
    ["6", "5"],
    ["4", "3"],
    ["11", "12"],
  ]);
  assert.equal(candidates[5].format, "mopro_g2_xy_pair_swapped_with_z");
  assert.deepEqual(candidates[5].proof.pi_b, [
    ["6", "5"],
    ["4", "3"],
    ["12", "11"],
  ]);
});

test("accepts snarkjs proof shape", () => {
  // proof：snarkjs 原生 proof 结构。
  const proof = {
    pi_a: ["1", "2", "1"],
    pi_b: [["3", "4"], ["5", "6"], ["1", "0"]],
    pi_c: ["7", "8", "1"],
    protocol: "groth16",
    curve: "bn128",
  };

  const candidates = proofCandidates({ proof, publicSignals: ["9"] });
  assert.equal(candidates.length, 1);
  assert.equal(candidates[0].format, "snarkjs");
  assert.equal(candidates[0].proof, proof);
});
