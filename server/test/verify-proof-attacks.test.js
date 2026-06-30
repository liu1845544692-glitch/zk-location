"use strict";

/*
 * 文件功能：
 * - /verify-proof HTTP 主链路攻击/失败用例测试。
 * - 覆盖 nonce 重放、commitment 篡改、payload 篡改、跨用户签名、未登录和未绑定 key 等场景。
 *
 * 执行流程：
 * 1. startTestServer 为每个测试启动隔离的本地 verifier server。
 * 2. registerAndBindKey 创建测试用户和 P-256 key。
 * 3. signedProofPayload 构造有效 proof + Keystore-like 签名请求。
 * 4. 各测试修改 payload 的不同部分，断言服务端拒绝且不错误消费 nonce。
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

// validProofFixture：预先生成的合法 areajudge proof，避免测试依赖完整 proving 耗时。
const validProofFixture = JSON.parse(
  fs.readFileSync(path.join(__dirname, "fixtures/valid-areajudge-proof.json"), "utf8")
);

test("verify-proof accepts valid payload and rejects replayed nonce", async (t) => {
  // app：本测试独占的本地服务端。
  const app = await startTestServer(t);
  // alice：已注册并绑定 active key 的测试用户。
  const alice = await registerAndBindKey(app, "alice");
  // payload：合法 proof + 签名请求。
  const payload = await signedProofPayload(app, alice.privateKey);

  const first = await postJson(app, "/verify-proof", payload, alice.token);
  assert.equal(first.status, 200);
  assert.equal(first.body.valid, true);
  assert.equal(first.body.proofValid, true);
  assert.equal(first.body.signatureValid, true);
  assert.equal(first.body.commitmentBound, true);
  assert.equal(first.body.nonceConsumed, true);

  const replay = await postJson(app, "/verify-proof", payload, alice.token);
  assert.equal(replay.status, 200);
  assert.equal(replay.body.valid, false);
  assert.equal(replay.body.proofValid, true);
  assert.equal(replay.body.signatureValid, true);
  assert.equal(replay.body.commitmentBound, true);
  assert.equal(replay.body.nonceConsumed, false);
  assert.match(replay.body.reason, /already used nonce/);
});

test("verify-proof rejects tampered public commitment", async (t) => {
  const app = await startTestServer(t);
  const alice = await registerAndBindKey(app, "alice");
  const payload = await signedProofPayload(app, alice.privateKey);
  // tamperedCommitment：攻击者替换 proof public input 中的 commitment。
  const tamperedCommitment = "123456789";
  payload.inputs[0] = tamperedCommitment;
  payload.tee = signPayload(alice.privateKey, tamperedCommitment, payload.serverNonce);

  const response = await postJson(app, "/verify-proof", payload, alice.token);
  assert.equal(response.status, 200);
  assert.equal(response.body.valid, false);
  assert.equal(response.body.proofValid, false);
  assert.equal(response.body.signatureValid, true);
  assert.equal(response.body.commitmentBound, true);
  assert.equal(response.body.nonceConsumed, false);
});

test("verify-proof rejects signed payload commitment that differs from proof input", async (t) => {
  const app = await startTestServer(t);
  const alice = await registerAndBindKey(app, "alice");
  const payload = await signedProofPayload(app, alice.privateKey);
  payload.tee = signPayload(alice.privateKey, "987654321", payload.serverNonce);

  const response = await postJson(app, "/verify-proof", payload, alice.token);
  assert.equal(response.status, 200);
  assert.equal(response.body.valid, false);
  assert.equal(response.body.proofValid, true);
  assert.equal(response.body.signatureValid, true);
  assert.equal(response.body.commitmentBound, false);
  assert.equal(response.body.nonceConsumed, false);
});

test("verify-proof rejects unknown signed nonce", async (t) => {
  const app = await startTestServer(t);
  const alice = await registerAndBindKey(app, "alice");
  const payload = await signedProofPayload(app, alice.privateKey);
  payload.tee = signPayload(alice.privateKey, payload.inputs[0], "attacker-nonce");

  const response = await postJson(app, "/verify-proof", payload, alice.token);
  assert.equal(response.status, 200);
  assert.equal(response.body.valid, false);
  assert.equal(response.body.proofValid, true);
  assert.equal(response.body.signatureValid, true);
  assert.equal(response.body.commitmentBound, true);
  assert.equal(response.body.nonceConsumed, false);
  assert.match(response.body.reason, /Unknown, expired, or already used nonce/);
});

test("verify-proof rejects modified payload nonce without matching signature", async (t) => {
  const app = await startTestServer(t);
  const alice = await registerAndBindKey(app, "alice");
  const payload = await signedProofPayload(app, alice.privateKey);
  payload.tee.payload = canonicalPayload(payload.inputs[0], "attacker-nonce");

  const response = await postJson(app, "/verify-proof", payload, alice.token);
  assert.equal(response.status, 200);
  assert.equal(response.body.valid, false);
  assert.equal(response.body.proofValid, true);
  assert.equal(response.body.signatureValid, false);
  assert.equal(response.body.commitmentBound, true);
  assert.equal(response.body.nonceConsumed, false);
});

test("verify-proof rejects proof signed by another user's key", async (t) => {
  const app = await startTestServer(t);
  const alice = await registerAndBindKey(app, "alice");
  const bob = await registerAndBindKey(app, "bob");
  const payload = await signedProofPayload(app, alice.privateKey);

  const response = await postJson(app, "/verify-proof", payload, bob.token);
  assert.equal(response.status, 200);
  assert.equal(response.body.valid, false);
  assert.equal(response.body.proofValid, true);
  assert.equal(response.body.signatureValid, false);
  assert.equal(response.body.commitmentBound, true);
  assert.equal(response.body.nonceConsumed, false);
});

test("verify-proof rejects unauthenticated and unbound users", async (t) => {
  const app = await startTestServer(t);
  const alice = await registerAndBindKey(app, "alice");
  const payload = await signedProofPayload(app, alice.privateKey);

  const unauthenticated = await postJson(app, "/verify-proof", payload);
  assert.equal(unauthenticated.status, 401);
  assert.equal(unauthenticated.body.valid, false);
  assert.equal(unauthenticated.body.code, "PROOF_VERIFY_FAILED");

  const unbound = await postJson(app, "/auth/register", {
    username: "unbound",
    password: "correct-password",
  });
  assert.equal(unbound.status, 201);

  const noKey = await postJson(app, "/verify-proof", payload, unbound.body.token);
  assert.equal(noKey.status, 403);
  assert.equal(noKey.body.valid, false);
  assert.match(noKey.body.error, /no registered active public key/);
});

test("verify-proof ignores client-supplied public key and uses registered key", async (t) => {
  const app = await startTestServer(t);
  const alice = await registerAndBindKey(app, "alice");
  // attacker：请求体中伪造的公钥；服务端应该忽略它并使用 active key。
  const attacker = crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  const payload = await signedProofPayload(app, alice.privateKey);
  payload.tee.publicKey = attacker.publicKey
    .export({ type: "spki", format: "der" })
    .toString("base64");

  const response = await postJson(app, "/verify-proof", payload, alice.token);
  assert.equal(response.status, 200);
  assert.equal(response.body.valid, true);
  assert.equal(response.body.signatureValid, true);
  assert.equal(response.body.commitmentBound, true);
  assert.equal(response.body.nonceConsumed, true);
});

test("verify-regex-proof verifies explicit record proof without active key", async (t) => {
  const app = await startTestServer(t, { verifyPayload: verifyRegexPayloadForTest });
  const registered = await postJson(app, "/auth/register", {
    username: "regex-user",
    password: "correct-password",
  });
  assert.equal(registered.status, 201);

  const payload = {
    proof: validProofFixture.proof,
    inputs: ["42"],
    publicSignals: ["42"],
  };
  const response = await postJson(app, "/verify-regex-proof", payload, registered.body.token);
  assert.equal(response.status, 200);
  assert.equal(response.body.valid, true);
  assert.equal(response.body.proofValid, true);
  assert.equal(response.body.publicInputCount, 1);
  assert.equal(response.body.recordCommitment, "42");

  const unauthenticated = await postJson(app, "/verify-regex-proof", payload);
  assert.equal(unauthenticated.status, 401);
  assert.equal(unauthenticated.body.code, "REGEX_PROOF_VERIFY_FAILED");
});

/** 启动隔离测试服务端，并在测试结束时关闭。 */
async function startTestServer(t, options = {}) {
  // tempDir：本测试独立的 auth/log 临时目录。
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "zk-location-verify-attacks-"));
  // authStore：关闭 attestation 要求，只聚焦 verify-proof 攻击面。
  const authStore = new JsonAuthStore({
    filePath: path.join(tempDir, "auth.json"),
    sessionTtlMs: 60_000,
    keyNonceTtlMs: 60_000,
    requireKeyAttestation: false,
  });
  // interactionLogger：写入临时 JSONL，避免污染真实日志。
  const interactionLogger = createInteractionLogger({
    filePath: path.join(tempDir, "interactions.jsonl"),
  });
  // server：注入测试版 verifyPayload 的 verifier server。
  const server = createVerifierServer({
    authStore,
    interactionLogger,
    nonceTtlMs: 60_000,
    verifyPayload: options.verifyPayload || verifyPayloadForAttackTest,
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

async function verifyRegexPayloadForTest(_verificationKey, payload) {
  const publicSignals = payload.inputs || payload.publicSignals || payload.public_inputs || [];
  const valid = publicSignals.length === 1 && publicSignals[0].toString() === "42";
  return {
    valid,
    publicInputCount: publicSignals.length,
    acceptedFormat: valid ? "test-regex-fixture" : null,
    attempts: [{ format: "test-regex-fixture", valid }],
  };
}

/** 测试版 proof verifier，只校验 publicSignals 是否等于 fixture。 */
async function verifyPayloadForAttackTest(_verificationKey, payload) {
  // publicSignals：兼容多种请求字段名。
  const publicSignals = payload.inputs || payload.publicSignals || payload.public_inputs || [];
  // valid：输入完全匹配 fixture 才认为 proof 有效。
  const valid = JSON.stringify(publicSignals.map((value) => value.toString())) ===
    JSON.stringify(validProofFixture.publicSignals);
  return {
    valid,
    publicInputCount: publicSignals.length,
    acceptedFormat: valid ? "test-fixture" : null,
    attempts: [{ format: "test-fixture", valid }],
  };
}

/** 注册用户、生成 P-256 key，并绑定为 active key。 */
async function registerAndBindKey(app, username) {
  // registered：注册响应，包含 session token。
  const registered = await postJson(app, "/auth/register", {
    username,
    password: "correct-password",
  });
  assert.equal(registered.status, 201);

  // keyPair：模拟 Android Keystore leaf key 的 P-256 密钥对。
  const keyPair = crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  // keyNonce：服务端 key registration nonce。
  const keyNonce = await postJson(app, "/keys/register-nonce", {}, registered.body.token);
  assert.equal(keyNonce.status, 200);

  // publicKey：SPKI DER Base64 公钥，绑定到测试用户。
  const publicKey = keyPair.publicKey
    .export({ type: "spki", format: "der" })
    .toString("base64");
  // key：/keys/register 响应。
  const key = await postJson(app, "/keys/register", {
    nonce: keyNonce.body.nonce,
    publicKey,
    certificateChain: [],
  }, registered.body.token);
  assert.equal(key.status, 201);

  return {
    token: registered.body.token,
    publicKey,
    privateKey: keyPair.privateKey,
  };
}

/** 构造合法 proof 请求，并用给定私钥签名服务端 nonce。 */
async function signedProofPayload(app, privateKey) {
  // proof/publicSignals：从 fixture 克隆出的 proof 数据。
  const { proof, publicSignals } = await proofFixture();
  // nonce：服务端一次性签名 nonce。
  const nonce = await getJson(app, "/nonce");
  assert.equal(nonce.status, 200);
  // tee：模拟 Android Keystore 签名结果。
  const tee = signPayload(privateKey, publicSignals[0], nonce.body.nonce);
  return {
    proof,
    inputs: [...publicSignals],
    tee,
    serverNonce: nonce.body.nonce,
  };
}

/** 生成规范化 payload 并用 P-256 私钥签名。 */
function signPayload(privateKey, publicCommitment, serverNonce) {
  // payload：服务端 keystore-signature.js 会解析的规范化文本。
  const payload = canonicalPayload(publicCommitment, serverNonce);
  return {
    payload,
    signature: crypto.sign("sha256", Buffer.from(payload, "utf8"), privateKey).toString("base64"),
  };
}

/** 构造 Keystore 签名 payload，字段顺序必须与客户端一致。 */
function canonicalPayload(publicCommitment, serverNonce) {
  return `ZK_LOCATION_V1\npublic_commitment=${publicCommitment}\nserver_nonce=${serverNonce}`;
}

/** 返回 proof fixture 的深拷贝，避免测试之间相互污染。 */
async function proofFixture() {
  return {
    proof: JSON.parse(JSON.stringify(validProofFixture.proof)),
    publicSignals: [...validProofFixture.publicSignals],
  };
}

/** GET JSON 测试请求封装。 */
async function getJson(app, path) {
  return requestJson(app, "GET", path);
}

/** POST JSON 测试请求封装。 */
async function postJson(app, path, body, token = null) {
  return requestJson(app, "POST", path, body, token);
}

/** 发送 HTTP JSON 请求并解析响应。 */
function requestJson(app, method, requestPath, body = null, token = null) {
  return new Promise((resolve, reject) => {
    // url：测试服务端上的目标 URL。
    const url = new URL(`${app.baseUrl}${requestPath}`);
    // requestBody：POST body 的 JSON 字符串，GET 时为 null。
    const requestBody = body === null ? null : JSON.stringify(body);
    // req：node:http 原生请求对象。
    const req = http.request({
      hostname: url.hostname,
      port: url.port,
      path: `${url.pathname}${url.search}`,
      method,
      agent: false,
      headers: {
        "Content-Type": "application/json",
        Accept: "application/json",
        Prefer: "return=minimal",
        Connection: "close",
        ...(requestBody ? { "Content-Length": Buffer.byteLength(requestBody) } : {}),
        ...(token ? { Authorization: `Bearer ${token}` } : {}),
      },
    }, (res) => {
      // chunks：响应 body 分片。
      const chunks = [];
      res.on("data", (chunk) => chunks.push(chunk));
      res.on("end", () => {
        try {
          resolve({
            status: res.statusCode,
            body: JSON.parse(Buffer.concat(chunks).toString("utf8")),
          });
        } catch (error) {
          reject(error);
        }
      });
    });
    req.on("error", reject);
    if (requestBody) {
      req.write(requestBody);
    }
    req.end();
  });
}
