"use strict";

/*
 * 文件功能：
 * - 测试服务端 Keystore ECDSA payload 解析、签名验证和 commitment 绑定逻辑。
 *
 * 执行流程：
 * 1. parseCanonicalPayload 校验 Android 客户端固定 payload 格式。
 * 2. 生成 P-256 测试 key，用私钥签名 payload。
 * 3. verifyKeystoreSignature 验证签名、commitment 绑定和 active key 优先级。
 */
const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const {
  parseCanonicalPayload,
  verifyKeystoreSignature,
} = require("../src/keystore-signature");

test("parses canonical Keystore payload", () => {
  // parsed：payload 三行文本解析后的结构化字段。
  const parsed = parseCanonicalPayload(
    "ZK_LOCATION_V1\npublic_commitment=12345\nserver_nonce=nonce-1"
  );

  assert.deepEqual(parsed, {
    version: "ZK_LOCATION_V1",
    public_commitment: "12345",
    server_nonce: "nonce-1",
  });
});

test("verifies P-256 SHA256withECDSA signature and commitment binding", () => {
  // publicKey/privateKey：模拟 Android Keystore P-256 key。
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ec", {
    namedCurve: "prime256v1",
  });
  // signedPayload/signature/publicKeyDer：待验签 payload、签名和 SPKI 公钥。
  const signedPayload = "ZK_LOCATION_V1\npublic_commitment=12345\nserver_nonce=nonce-1";
  const signature = crypto.sign("sha256", Buffer.from(signedPayload, "utf8"), privateKey);
  const publicKeyDer = publicKey.export({ type: "spki", format: "der" });

  // result：服务端签名验证和 commitment 绑定检查结果。
  const result = verifyKeystoreSignature(
    {
      tee: {
        payload: signedPayload,
        signature: signature.toString("base64"),
        publicKey: publicKeyDer.toString("base64"),
      },
    },
    "12345"
  );

  assert.equal(result.checked, true);
  assert.equal(result.signatureValid, true);
  assert.equal(result.commitmentBound, true);
  assert.equal(result.valid, true);
});

test("rejects valid ECDSA signature if commitment does not match proof input", () => {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ec", {
    namedCurve: "prime256v1",
  });
  const signedPayload = "ZK_LOCATION_V1\npublic_commitment=12345\nserver_nonce=nonce-1";
  const signature = crypto.sign("sha256", Buffer.from(signedPayload, "utf8"), privateKey);
  const publicKeyDer = publicKey.export({ type: "spki", format: "der" });

  const result = verifyKeystoreSignature(
    {
      tee: {
        payload: signedPayload,
        signature: signature.toString("base64"),
        publicKey: publicKeyDer.toString("base64"),
      },
    },
    "67890"
  );

  assert.equal(result.checked, true);
  assert.equal(result.signatureValid, true);
  assert.equal(result.commitmentBound, false);
  assert.equal(result.valid, false);
});

test("uses registered public key instead of client supplied public key", () => {
  const registered = crypto.generateKeyPairSync("ec", {
    namedCurve: "prime256v1",
  });
  const attacker = crypto.generateKeyPairSync("ec", {
    namedCurve: "prime256v1",
  });
  const signedPayload = "ZK_LOCATION_V1\npublic_commitment=12345\nserver_nonce=nonce-1";
  const signature = crypto.sign(
    "sha256",
    Buffer.from(signedPayload, "utf8"),
    registered.privateKey
  );
  const registeredPublicKey = registered.publicKey
    .export({ type: "spki", format: "der" })
    .toString("base64");
  const attackerPublicKey = attacker.publicKey
    .export({ type: "spki", format: "der" })
    .toString("base64");

  const result = verifyKeystoreSignature(
    {
      tee: {
        payload: signedPayload,
        signature: signature.toString("base64"),
        publicKey: attackerPublicKey,
      },
    },
    "12345",
    {
      publicKeyBase64: registeredPublicKey,
      keySource: "registered_user_key",
    }
  );

  assert.equal(result.checked, true);
  assert.equal(result.signatureValid, true);
  assert.equal(result.commitmentBound, true);
  assert.equal(result.keySource, "registered_user_key");
  assert.equal(result.valid, true);
});

test("can verify with registered public key when payload omits public key", () => {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ec", {
    namedCurve: "prime256v1",
  });
  const signedPayload = "ZK_LOCATION_V1\npublic_commitment=12345\nserver_nonce=nonce-1";
  const signature = crypto.sign("sha256", Buffer.from(signedPayload, "utf8"), privateKey);
  const publicKeyBase64 = publicKey.export({ type: "spki", format: "der" }).toString("base64");

  const result = verifyKeystoreSignature(
    {
      tee: {
        payload: signedPayload,
        signature: signature.toString("base64"),
      },
    },
    "12345",
    {
      publicKeyBase64,
      keySource: "registered_user_key",
    }
  );

  assert.equal(result.checked, true);
  assert.equal(result.signatureValid, true);
  assert.equal(result.keySource, "registered_user_key");
  assert.equal(result.valid, true);
});
