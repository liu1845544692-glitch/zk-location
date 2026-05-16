"use strict";

/*
 * 文件功能：
 * - 测试 interaction logger 的请求摘要、响应摘要和 JSONL 最近记录读取。
 *
 * 执行流程：
 * 1. summarizeProofRequest 确认日志不会保存完整 proof，只保存摘要。
 * 2. summarizeVerifyResponse 压缩服务端验证响应。
 * 3. createInteractionLogger 写入临时 JSONL 并读取最近日志。
 */
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const os = require("node:os");
const {
  createInteractionLogger,
  summarizeProofRequest,
  summarizeVerifyResponse,
} = require("../src/interaction-logger");

test("summarizes proof request without storing full proof", () => {
  // summary：proof 请求摘要，长字段应被截断。
  const summary = summarizeProofRequest({
    proof: {
      a: { x: "1", y: "2", z: "1" },
      b: { x: ["3", "4"], y: ["5", "6"], z: ["1", "0"] },
      c: { x: "7", y: "8", z: "1" },
      protocol: "groth16",
      curve: "bn128",
    },
    inputs: ["123", "456"],
    tee: {
      payload: "ZK_LOCATION_V1\npublic_commitment=123\nserver_nonce=nonce-1",
      signature: "a".repeat(80),
      publicKey: "b".repeat(80),
      certificateChain: ["cert1", "cert2"],
    },
  });

  assert.equal(summary.publicInputCount, 2);
  assert.equal(summary.publicCommitment, "123");
  assert.equal(summary.proofShape, "mopro");
  assert.equal(summary.tee.present, true);
  assert.equal(summary.tee.serverNonce, "nonce-1");
  assert.equal(summary.tee.certificateChainCount, 2);
  assert.match(summary.tee.signature, /\.\.\./);
});

test("summarizes verify response", () => {
  // summary：服务端 verify 响应摘要。
  const summary = summarizeVerifyResponse({
    valid: true,
    proofValid: true,
    acceptedFormat: "mopro",
    publicInputCount: 37,
    signature: {
      checked: true,
      valid: true,
      signatureValid: true,
      commitmentBound: true,
      serverNonce: "nonce-1",
    },
    nonce: {
      checked: true,
      valid: true,
      consumed: true,
      nonce: "nonce-1",
    },
  });

  assert.equal(summary.valid, true);
  assert.equal(summary.signature.signatureValid, true);
  assert.equal(summary.nonce.consumed, true);
});

test("writes and reads recent interaction records", () => {
  // dir/filePath/logger：隔离的临时 interaction log。
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "zk-location-logs-"));
  const filePath = path.join(dir, "interactions.jsonl");
  const logger = createInteractionLogger({ filePath });

  logger.log({ type: "one" });
  logger.log({ type: "two" });

  // recent：读取最近一条日志。
  const recent = logger.recent(1);
  assert.equal(recent.length, 1);
  assert.equal(recent[0].type, "two");
});
