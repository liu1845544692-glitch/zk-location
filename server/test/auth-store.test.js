"use strict";

/*
 * 文件功能：
 * - 测试 JsonAuthStore 的注册、登录、session、key nonce、active key 和 attestation root 拒绝逻辑。
 *
 * 执行流程：
 * 1. 每个测试通过 tempStore 创建隔离 auth.json。
 * 2. 注册/登录测试验证 bearer session。
 * 3. key 绑定测试验证 P-256 公钥、nonce 一次性消费和登录后清空 active key。
 * 4. root trust 测试确认未知 attestation root 不会被自动信任。
 */
const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { AuthError, JsonAuthStore, validateEcPublicKey } = require("../src/auth-store");
const { loadTrustedRootFingerprints } = require("../src/key-attestation");

test("registers and logs in user with bearer session", () => {
  // store：隔离的 JSON auth store。
  const store = tempStore();

  // registered/authenticated/loggedIn：注册、token 鉴权和登录三段结果。
  const registered = store.registerUser("Alice", "correct-password");
  assert.equal(registered.user.username, "alice");
  assert.equal(typeof registered.session.token, "string");

  const authenticated = store.authenticateToken(registered.session.token);
  assert.equal(authenticated.user.id, registered.user.id);

  const loggedIn = store.loginUser("alice", "correct-password");
  assert.equal(loggedIn.user.id, registered.user.id);
  assert.equal(typeof loggedIn.session.token, "string");
});

test("rejects duplicate username and invalid password", () => {
  const store = tempStore();
  store.registerUser("alice", "correct-password");

  assert.throws(
    () => store.registerUser("ALICE", "another-password"),
    (error) => error instanceof AuthError && error.statusCode === 409
  );
  assert.throws(
    () => store.loginUser("alice", "wrong-password"),
    (error) => error instanceof AuthError && error.statusCode === 401
  );
});

test("issues key registration nonce and binds P-256 public key to user", () => {
  const store = tempStore();
  // registered：测试用户和初始 session。
  const registered = store.registerUser("alice", "correct-password");
  // publicKey：模拟 Android Keystore 生成的 P-256 公钥。
  const { publicKey } = crypto.generateKeyPairSync("ec", {
    namedCurve: "prime256v1",
  });
  // publicKeyBase64：服务端 /keys/register 接收的 SPKI DER Base64。
  const publicKeyBase64 = publicKey.export({ type: "spki", format: "der" }).toString("base64");

  // nonce/key：key registration nonce 和绑定后的 active key。
  const nonce = store.issueKeyRegistrationNonce(registered.user.id);
  const key = store.registerUserKey(registered.user.id, {
    nonce: nonce.nonce,
    publicKey: publicKeyBase64,
    certificateChain: ["cert-leaf"],
  });

  assert.equal(key.namedCurve, "prime256v1");
  assert.equal(key.certificateChainCount, 1);

  const activeKey = store.activeKeyForUser(registered.user.id);
  assert.equal(activeKey.id, key.id);
  assert.equal(activeKey.publicKeyBase64, publicKeyBase64);
});

test("login clears previously active key so a fresh binding is required", () => {
  const store = tempStore();
  const registered = store.registerUser("alice", "correct-password");
  const { publicKey } = crypto.generateKeyPairSync("ec", {
    namedCurve: "prime256v1",
  });
  const publicKeyBase64 = publicKey.export({ type: "spki", format: "der" }).toString("base64");

  const nonce = store.issueKeyRegistrationNonce(registered.user.id);
  store.registerUserKey(registered.user.id, {
    nonce: nonce.nonce,
    publicKey: publicKeyBase64,
    certificateChain: ["cert-leaf"],
  });
  assert.ok(store.activeKeyForUser(registered.user.id));

  store.loginUser("alice", "correct-password");

  assert.equal(store.activeKeyForUser(registered.user.id), null);
});

test("rejects replayed key registration nonce", () => {
  const store = tempStore();
  const registered = store.registerUser("alice", "correct-password");
  const { publicKey } = crypto.generateKeyPairSync("ec", {
    namedCurve: "prime256v1",
  });
  const publicKeyBase64 = publicKey.export({ type: "spki", format: "der" }).toString("base64");
  const nonce = store.issueKeyRegistrationNonce(registered.user.id);

  store.registerUserKey(registered.user.id, {
    nonce: nonce.nonce,
    publicKey: publicKeyBase64,
  });

  assert.throws(
    () =>
      store.registerUserKey(registered.user.id, {
        nonce: nonce.nonce,
        publicKey: publicKeyBase64,
      }),
    (error) => error instanceof AuthError && error.statusCode === 400
  );
});

test("rejects untrusted Android attestation root", () => {
  const [trustedRoot] = loadGoogleRoots();
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "zk-location-roots-"));
  const trustRootsPath = path.join(tempDir, "trusted.pem");
  fs.writeFileSync(trustRootsPath, trustedRoot, "utf8");
  const store = tempStore({
    requireKeyAttestation: true,
    attestationTrustRootsPath: trustRootsPath,
  });
  const registered = store.registerUser("alice", "correct-password");
  // M-14 committed test fixture: self-signed EC P-256 cert, not in production trust store
  const rejectedRootPath = path.resolve(
    __dirname,
    "fixtures/m14-rejected-attestation-root.pem"
  );
  const pem = fs.readFileSync(rejectedRootPath, "utf8");
  const certificate = new crypto.X509Certificate(pem);
  const trustedFingerprints = loadTrustedRootFingerprints(trustRootsPath);

  // ---- M-14 fixture 前置性质断言 ----
  // 单一证书，不含私钥
  const certBlocks = pem.match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g) ?? [];
  assert.equal(certBlocks.length, 1, "fixture must contain exactly one certificate");
  assert.doesNotMatch(pem, /PRIVATE KEY/);

  // 当前有效
  const validFrom = Date.parse(certificate.validFrom);
  const validTo = Date.parse(certificate.validTo);
  const now = Date.now();
  assert.ok(Number.isFinite(validFrom) && validFrom <= now, "certificate is currently valid (validFrom)");
  assert.ok(Number.isFinite(validTo) && now <= validTo, "certificate is currently valid (validTo)");

  // CA 自签名
  assert.equal(certificate.ca, true);
  assert.equal(certificate.subject, certificate.issuer);
  assert.equal(certificate.verify(certificate.publicKey), true);

  // EC P-256
  assert.equal(certificate.publicKey.asymmetricKeyType, "ec");
  assert.equal(certificate.publicKey.asymmetricKeyDetails?.namedCurve, "prime256v1");

  // 固定预期 fingerprint
  const fingerprint = certificate.fingerprint256.replaceAll(":", "").toLowerCase();
  const expectedFingerprint = "68e26ae06bc95d71186eea65924ee0d7bde361c3f4d09a02b731079f28067cbd";
  assert.equal(fingerprint, expectedFingerprint, "fixture fingerprint matches expected value");

  // 不在测试 trusted set 中
  assert.equal(trustedFingerprints.has(fingerprint), false, "fixture root is NOT trusted");

  // ---- 生产路径：untrusted root 必须被拒绝 ----
  const nonce = store.issueKeyRegistrationNonce(registered.user.id);

  assert.throws(
    () =>
      store.registerUserKey(registered.user.id, {
        nonce: nonce.nonce,
        publicKey: certificate.publicKey.export({ type: "spki", format: "der" }).toString("base64"),
        certificateChain: [certificate.raw.toString("base64")],
      }),
    (error) => error.statusCode === 400 && /root is not trusted/.test(error.message)
  );
});

test("validates public key is P-256 EC SPKI", () => {
  const { publicKey } = crypto.generateKeyPairSync("rsa", {
    modulusLength: 2048,
  });
  const publicKeyBase64 = publicKey.export({ type: "spki", format: "der" }).toString("base64");

  assert.throws(
    () => validateEcPublicKey(publicKeyBase64),
    (error) => error instanceof AuthError && error.statusCode === 400
  );
});

function tempStore(options = {}) {
  // dir：测试用临时数据库目录。
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "zk-location-auth-"));
  return new JsonAuthStore({
    filePath: path.join(dir, "auth.json"),
    sessionTtlMs: 60_000,
    keyNonceTtlMs: 60_000,
    requireKeyAttestation: options.requireKeyAttestation ?? false,
    attestationTrustRootsPath: options.attestationTrustRootsPath,
  });
}

function loadGoogleRoots() {
  // rootsPath/raw：Google Android Attestation root trust store 原始内容。
  const rootsPath = path.resolve(__dirname, "../trust/google_android_attestation_roots.pem");
  const raw = fs.readFileSync(rootsPath, "utf8").trim();
  return raw.startsWith("[")
    ? JSON.parse(raw)
    : raw.match(/-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/g);
}
