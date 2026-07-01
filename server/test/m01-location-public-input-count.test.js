"use strict";

/*
 * 文件功能：
 * - M-01 回归测试：Location proof 必须恰好包含 37 个 publicSignals。
 * - 覆盖 35/36/37/38 项、尾部零截断、非数组、缺失、nonce 保护等场景。
 * - 验证长度错误在 Groth16 验证前被拒绝，且不消费 nonce。
 *
 * 执行流程：
 * 1. startTestServer 为每个子测试启动隔离本地 verifier server。
 * 2. registerAndBindKey 创建测试用户和 P-256 key。
 * 3. signedProofPayload 构造有效 proof + 签名请求。
 * 4. 各子测试修改 publicSignals 数量，断言被拒绝或通过。
 */
const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const http = require("node:http");
const os = require("node:os");
const path = require("node:path");
const { JsonAuthStore } = require("../src/auth-store");
const { createInteractionLogger } = require("../src/interaction-logger");
const { createVerifierServer } = require("../src/server");

// validProofFixture：预先生成的合法 areajudge proof。
const validProofFixture = JSON.parse(
  fs.readFileSync(path.join(__dirname, "fixtures/valid-areajudge-proof.json"), "utf8")
);

/** 37 项合法 proof 通过。 */
test("M-01: 37 public inputs passes", async (t) => {
  const app = await startTestServer(t);
  const alice = await registerAndBindKey(app, "alice");
  const payload = await signedProofPayload(app, alice.privateKey);

  const response = await postJson(app, "/verify-proof", payload, alice.token);
  assert.equal(response.status, 200);
  assert.equal(response.body.valid, true);
  assert.equal(response.body.proofValid, true);
  assert.equal(response.body.signature.signatureValid, true);
  assert.equal(response.body.signature.commitmentBound, true);
  assert.equal(response.body.nonce.consumed, true);
  assert.equal(response.body.publicInputCount, 37);
});

/** 36 项被拒绝。 */
test("M-01: 36 public inputs rejected", async (t) => {
  const app = await startTestServer(t);
  const alice = await registerAndBindKey(app, "alice");
  const payload = await signedProofPayload(app, alice.privateKey);
  payload.inputs = payload.inputs.slice(0, 36);

  const response = await postJson(app, "/verify-proof", payload, alice.token);
  assert.equal(response.status, 400);
  assert.equal(response.body.valid, false);
  assert.equal(response.body.code, "PROOF_VERIFY_FAILED");
  assert.match(response.body.error, /exactly 37 public inputs.*got 36/);
});

/** 35 项被拒绝。 */
test("M-01: 35 public inputs rejected", async (t) => {
  const app = await startTestServer(t);
  const alice = await registerAndBindKey(app, "alice");
  const payload = await signedProofPayload(app, alice.privateKey);
  payload.inputs = payload.inputs.slice(0, 35);

  const response = await postJson(app, "/verify-proof", payload, alice.token);
  assert.equal(response.status, 400);
  assert.equal(response.body.valid, false);
  assert.match(response.body.error, /exactly 37 public inputs.*got 35/);
});

/** 38 项被拒绝。 */
test("M-01: 38 public inputs rejected", async (t) => {
  const app = await startTestServer(t);
  const alice = await registerAndBindKey(app, "alice");
  const payload = await signedProofPayload(app, alice.privateKey);
  payload.inputs = [...payload.inputs, "0"];

  const response = await postJson(app, "/verify-proof", payload, alice.token);
  assert.equal(response.status, 400);
  assert.equal(response.body.valid, false);
  assert.match(response.body.error, /exactly 37 public inputs.*got 38/);
});

/** 尾部为 0 时截断到 36 项被拒绝。 */
test("M-01: 36 inputs with trailing zero rejected", async (t) => {
  const app = await startTestServer(t);
  const alice = await registerAndBindKey(app, "alice");
  const payload = await signedProofPayload(app, alice.privateKey);
  // 确保最后一个 signal 为 "0"（fixture 中本已是 0）
  payload.inputs[36] = "0";
  payload.inputs = payload.inputs.slice(0, 36);

  const response = await postJson(app, "/verify-proof", payload, alice.token);
  assert.equal(response.status, 400);
  assert.equal(response.body.valid, false);
  assert.match(response.body.error, /exactly 37 public inputs.*got 36/);
});

/** 尾部为非 0 时截断到 36 项被拒绝。 */
test("M-01: 36 inputs with trailing non-zero rejected", async (t) => {
  const app = await startTestServer(t);
  const alice = await registerAndBindKey(app, "alice");
  const payload = await signedProofPayload(app, alice.privateKey);
  payload.inputs[36] = "12345";
  payload.inputs = payload.inputs.slice(0, 36);

  const response = await postJson(app, "/verify-proof", payload, alice.token);
  assert.equal(response.status, 400);
  assert.equal(response.body.valid, false);
  assert.match(response.body.error, /exactly 37 public inputs.*got 36/);
});

/** publicSignals 不是数组时被拒绝。 */
test("M-01: non-array publicSignals rejected", async (t) => {
  const app = await startTestServer(t);
  const alice = await registerAndBindKey(app, "alice");
  const payload = await signedProofPayload(app, alice.privateKey);
  payload.inputs = "not-an-array";

  const response = await postJson(app, "/verify-proof", payload, alice.token);
  assert.equal(response.status, 400);
  assert.equal(response.body.valid, false);
  assert.equal(response.body.code, "PROOF_VERIFY_FAILED");
});

/** publicSignals 缺失时被拒绝。 */
test("M-01: missing publicSignals rejected", async (t) => {
  const app = await startTestServer(t);
  const alice = await registerAndBindKey(app, "alice");
  const payload = await signedProofPayload(app, alice.privateKey);
  delete payload.inputs;

  const response = await postJson(app, "/verify-proof", payload, alice.token);
  assert.equal(response.status, 400);
  assert.equal(response.body.valid, false);
  assert.equal(response.body.code, "PROOF_VERIFY_FAILED");
});

/** 长度错误在 Groth16 验证前被拒绝（通过注入抛异常的 verifier 验证）。 */
test("M-01: length error rejected before Groth16 verify", async (t) => {
  // wasCalled：捕获 Groth16 verifier 是否被调用。
  let wasCalled = false;
  const throwingVerifier = async (_vk, _payload) => {
    wasCalled = true;
    return { valid: false, publicInputCount: 0, acceptedFormat: null, attempts: [] };
  };

  const app = await startTestServer(t, { verifyPayload: throwingVerifier });
  const alice = await registerAndBindKey(app, "alice");
  const payload = await signedProofPayload(app, alice.privateKey);
  payload.inputs = payload.inputs.slice(0, 36);

  const response = await postJson(app, "/verify-proof", payload, alice.token);
  assert.equal(response.status, 400);
  assert.equal(response.body.valid, false);
  assert.match(response.body.error, /exactly 37 public inputs.*got 36/);
  // Groth16 verifier 不应被调用
  assert.equal(wasCalled, false, "Groth16 verifier was called despite length error");
});

/** 长度错误不消费 nonce。 */
test("M-01: length error does not consume nonce", async (t) => {
  const app = await startTestServer(t);
  const alice = await registerAndBindKey(app, "alice");
  const payload = await signedProofPayload(app, alice.privateKey);
  const originalNonce = payload.serverNonce;
  payload.inputs = payload.inputs.slice(0, 36);

  // 第一次：长度错误
  const first = await postJson(app, "/verify-proof", payload, alice.token);
  assert.equal(first.status, 400);
  assert.equal(first.body.valid, false);

  // 第二次：用相同 nonce 但37项合法 payload 应该通过
  const validPayload = await signedProofPayload(app, alice.privateKey);
  validPayload.inputs = [...validProofFixture.publicSignals];
  validPayload.tee.payload = canonicalPayload(validPayload.inputs[0], originalNonce);
  validPayload.tee.signature = crypto
    .sign("sha256", Buffer.from(validPayload.tee.payload, "utf8"), alice.privateKey)
    .toString("base64");
  validPayload.serverNonce = originalNonce;

  const second = await postJson(app, "/verify-proof", validPayload, alice.token);
  assert.equal(second.status, 200);
  // nonce 未被第一次错误请求消费
  assert.equal(second.body.nonce.consumed, true,
    "Nonce should still be available after length error");
});

/** Password proof 不回归（仍需要恰好 1 个 public input）。 */
test("M-01: password proof public input contract unchanged", async (t) => {
  const app = await startTestServer(t);
  // Password proof 端点不受 Location 37 项限制的影响
  // 只需确认 /password/register 仍按原有逻辑拒绝错误的 publicSignals 数量
  const registered = await postJson(app, "/auth/register", {
    username: "pwd-test-user",
    password: "correct-password",
  });
  assert.equal(registered.status, 201);

  // 用 37 个 publicSignals 请求 password/register —— 应该被其自身的校验拒绝
  const response = await postJson(app, "/password/register", {
    userId: "pwd-test-user",
    salt: "12345",
    passwordCommitment: "67890",
    proof: { pi_a: ["0", "0", "1"], pi_b: [["0", "0"], ["0", "0"], ["1", "0"]], pi_c: ["0", "0", "1"], protocol: "groth16", curve: "bn128" },
    publicSignals: new Array(37).fill("0"),
  }, registered.body.token);
  assert.equal(response.status, 400);
  assert.equal(response.body.code, "INVALID_PUBLIC_SIGNALS");
});

// =============================================================================
// 测试辅助函数
// =============================================================================

/** 启动隔离测试服务端。 */
async function startTestServer(t, options = {}) {
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "zk-location-m01-"));
  const authStore = new JsonAuthStore({
    filePath: path.join(tempDir, "auth.json"),
    sessionTtlMs: 60_000,
    keyNonceTtlMs: 60_000,
    requireKeyAttestation: false,
  });
  const interactionLogger = createInteractionLogger({
    filePath: path.join(tempDir, "interactions.jsonl"),
  });
  const server = createVerifierServer({
    authStore,
    interactionLogger,
    nonceTtlMs: 60_000,
    verifyPayload: options.verifyPayload || verifyPayloadForM01Test,
  });

  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  t.after(() => {
    server.closeIdleConnections?.();
    server.closeAllConnections?.();
    server.close();
  });

  return {
    baseUrl: `http://127.0.0.1:${server.address().port}`,
    authStore,
    interactionLogger,
    server,
  };
}

/** 测试版 verifier：publicSignals 完全匹配 fixture 才返回 valid。 */
async function verifyPayloadForM01Test(_verificationKey, payload) {
  const publicSignals = payload.inputs || payload.publicSignals || payload.public_inputs || [];
  const valid =
    Array.isArray(publicSignals) &&
    JSON.stringify(publicSignals.map((v) => v.toString())) ===
      JSON.stringify(validProofFixture.publicSignals);
  return {
    valid,
    publicInputCount: Array.isArray(publicSignals) ? publicSignals.length : 0,
    acceptedFormat: valid ? "test-fixture" : null,
    attempts: [{ format: "test-fixture", valid }],
  };
}

/** 注册用户并绑定 P-256 key。 */
async function registerAndBindKey(app, username) {
  const registered = await postJson(app, "/auth/register", { username, password: "correct-password" });
  assert.equal(registered.status, 201);

  const keyPair = crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  const keyNonce = await postJson(app, "/keys/register-nonce", {}, registered.body.token);
  assert.equal(keyNonce.status, 200);

  const publicKey = keyPair.publicKey.export({ type: "spki", format: "der" }).toString("base64");
  const key = await postJson(app, "/keys/register", {
    nonce: keyNonce.body.nonce,
    publicKey,
    certificateChain: [],
  }, registered.body.token);
  assert.equal(key.status, 201);

  return { token: registered.body.token, publicKey, privateKey: keyPair.privateKey };
}

/** 构造带签名的合法 proof 请求。 */
async function signedProofPayload(app, privateKey) {
  const { proof, publicSignals } = proofFixture();
  const nonce = await getJson(app, "/nonce");
  assert.equal(nonce.status, 200);
  const tee = signPayload(privateKey, publicSignals[0], nonce.body.nonce);
  return { proof, inputs: [...publicSignals], tee, serverNonce: nonce.body.nonce };
}

function proofFixture() {
  return {
    proof: validProofFixture.proof,
    publicSignals: [...validProofFixture.publicSignals],
  };
}

function signPayload(privateKey, publicCommitment, serverNonce) {
  const payload = canonicalPayload(publicCommitment, serverNonce);
  return {
    payload,
    signature: crypto.sign("sha256", Buffer.from(payload, "utf8"), privateKey).toString("base64"),
  };
}

function canonicalPayload(publicCommitment, serverNonce) {
  return `ZK_LOCATION_V1\npublic_commitment=${publicCommitment}\nserver_nonce=${serverNonce}`;
}

/** HTTP POST JSON helper。 */
function postJson(app, pathname, body, token) {
  return new Promise((resolve, reject) => {
    const url = new URL(pathname, app.baseUrl);
    const data = JSON.stringify(body);
    const headers = { "Content-Type": "application/json", "Content-Length": Buffer.byteLength(data) };
    if (token) headers["Authorization"] = `Bearer ${token}`;
    const req = http.request(url, { method: "POST", headers }, (res) => {
      let buf = "";
      res.on("data", (c) => (buf += c));
      res.on("end", () => {
        try { resolve({ status: res.statusCode, body: JSON.parse(buf) }); }
        catch (_) { resolve({ status: res.statusCode, body: buf }); }
      });
    });
    req.on("error", reject);
    req.end(data);
  });
}

/** HTTP GET JSON helper。 */
function getJson(app, pathname, token) {
  return new Promise((resolve, reject) => {
    const url = new URL(pathname, app.baseUrl);
    const headers = token ? { Authorization: `Bearer ${token}` } : {};
    http.get(url, { headers }, (res) => {
      let buf = "";
      res.on("data", (c) => (buf += c));
      res.on("end", () => {
        try { resolve({ status: res.statusCode, body: JSON.parse(buf) }); }
        catch (_) { resolve({ status: res.statusCode, body: buf }); }
      });
    }).on("error", reject);
  });
}
