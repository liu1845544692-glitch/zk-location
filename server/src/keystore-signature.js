"use strict";

// =============================================================================
// keystore-signature.js —— Keystore ECDSA 签名验证与 commitment 绑定
// =============================================================================
// 验证客户端使用 Android Keystore 硬件密钥对规范 payload 的 ECDSA 签名，
// 并确保签名中的 public_commitment 与 ZK proof 的公开输入一致。
// 这一步将 ZK proof（证明位置）与硬件签名（证明设备/用户）绑定在一起。

const crypto = require("node:crypto");

// ---- 验证 Keystore ECDSA 签名并检查 commitment 绑定 ----
// payload: 客户端 POST /verify-proof 的完整请求体
// proofPublicCommitment: ZK proof 的 publicSignals[0]（即 Poseidon(x,y,salt)）
// options.publicKeyBase64: 服务端存储的用户 active key（如果有则优先使用）
//
// 签名内容：canonical payload 的完整 UTF-8 字符串
// 签名算法：SHA256withECDSA（P-256）
//
// 验证通过条件：
//   1. crypto.verify() 签名验证成功
//   2. 签名 payload 中的 public_commitment === proof 的 public_commitment
//
// 公钥来源优先级（防客户端自行提供攻击者公钥）：
//   1. options.publicKeyBase64（服务端存储的 active key，最优先）
//   2. payload.tee.publicKey（客户端请求中携带）
//   3. certificateChain[0] 中的公钥（从证书 leaf 提取）
function verifyKeystoreSignature(payload, proofPublicCommitment, options = {}) {
  // ---- 1. 从多种可能字段名中提取签名相关字段 ----
  // tee: 客户端上传的 TEE 签名相关字段，优先取 tee 其次 keystore
  const tee = payload.tee ?? payload.keystore ?? {};
  // signedPayload: Keystore 签名原文（canonical payload 格式）
  const signedPayload = pickString(
    tee.payload,
    tee.teePayload,
    payload.tee_payload,
    payload.teePayload,
    payload.signedPayload
  );
  // signatureBase64: ECDSA 签名的 Base64 编码（DER 格式）
  const signatureBase64 = pickString(
    tee.signature,
    tee.signatureBase64,
    payload.tee_signature,
    payload.teeSignature,
    payload.signatureBase64
  );
  // clientPublicKeyBase64: 客户端在请求中携带的公钥（可能被攻击者伪造）
  const clientPublicKeyBase64 = pickString(
    tee.publicKey,
    tee.publicKeyBase64,
    payload.public_key,
    payload.publicKey,
    payload.publicKeyBase64
  );
  // trustedPublicKeyBase64: 服务端存储的用户 active key（可信公钥）
  const trustedPublicKeyBase64 = pickString(
    options.publicKeyBase64,
    options.trustedPublicKeyBase64
  );
  // publicKeyBase64: 验签使用的公钥，优先使用服务端可信公钥（防止攻击者提供自己的公钥），否则用客户端提供的
  const publicKeyBase64 = trustedPublicKeyBase64 || clientPublicKeyBase64;
  // certificateChainBase64: Android Keystore attestation 证书链（Base64 字符串数组）
  const certificateChainBase64 =
    tee.certificateChain ??
    tee.certificateChainBase64 ??
    payload.certificate_chain ??
    payload.certificateChain ??
    payload.certificateChainBase64;

  // ---- 2. 请求没有任何签名字段 → 报告缺少设备签名 ----
  // hasAnySignatureField: 只检查客户端请求字段；服务端已绑定的 trusted public key
  // 不能让一个未携带签名的请求被视为已进入签名校验。
  const hasAnySignatureField = Boolean(
    signedPayload || signatureBase64 || clientPublicKeyBase64 || certificateChainBase64
  );
  if (!hasAnySignatureField) {
    return {
      checked: false,
      valid: false,
      commitmentBound: false,
      reason: "No Keystore signature fields supplied",
    };
  }

  // ---- 3. 检查必要字段是否齐全 ----
  // missing: 缺失的必要字段名列表，用于错误提示
  const missing = [];
  if (!signedPayload) missing.push("tee.payload");
  if (!signatureBase64) missing.push("tee.signature");
  if (!publicKeyBase64 && !firstCertificate(certificateChainBase64)) {
    missing.push("tee.publicKey or tee.certificateChain[0]");
  }
  if (missing.length > 0) {
    return {
      checked: true,
      valid: false,
      commitmentBound: false,
      reason: `Missing ${missing.join(", ")}`,
    };
  }

  // ---- 4. 解析 canonical payload，提取 public_commitment 和 server_nonce ----
  // parsedPayload: 解析后的 canonical payload 对象 { version, public_commitment, server_nonce }
  const parsedPayload = parseCanonicalPayload(signedPayload);

  // commitmentBound: 签名中的 commitment 是否与 ZK proof 公开输入中的 commitment 一致
  // 这是将 ZK proof（证明位置）与 TEE 签名（证明设备）绑定的关键检查
  const commitmentBound =
    parsedPayload.public_commitment !== null &&
    parsedPayload.public_commitment === proofPublicCommitment;

  // ---- 5. 执行 ECDSA 签名验证 ----
  // signatureValid: crypto.verify() 返回值，true 表示签名数学上有效
  let signatureValid = false;
  // keySource: 记录验签使用的是哪个来源的公钥，用于返回给调用方
  let keySource = trustedPublicKeyBase64 ? (options.keySource || "registered_user_key") : "public_key";
  try {
    // keyObject: Node.js crypto 公钥对象，从 SPKI DER 或证书中创建
    // 如果有服务端可信公钥，从 SPKI DER 格式加载
    // 否则从证书链第一张证书中提取公钥
    const keyObject = publicKeyBase64
      ? createPublicKeyFromSpki(publicKeyBase64)
      : createPublicKeyFromCertificate(firstCertificate(certificateChainBase64));
    if (!publicKeyBase64) {
      keySource = "certificate";
    }

    // Node.js crypto.verify() 执行 SHA-256 + ECDSA 验签
    signatureValid = crypto.verify(
      "sha256",
      Buffer.from(signedPayload, "utf8"),  // 签名原文：canonical payload 的 UTF-8 字节
      keyObject,
      Buffer.from(signatureBase64, "base64")  // 签名值：Base64 解码后的 DER 编码
    );
  } catch (_error) {
    return {
      checked: true,
      valid: false,
      commitmentBound,
      payloadCommitment: parsedPayload.public_commitment,
      proofCommitment: proofPublicCommitment,
      payloadVersion: parsedPayload.version,
      serverNonce: parsedPayload.server_nonce,
      keySource,
      reason: "Signature verification failed",
    };
  }

  return {
    checked: true,
    // 整体有效 = 签名验证成功 AND commitment 绑定成功
    valid: signatureValid && commitmentBound,
    signatureValid,
    commitmentBound,
    payloadCommitment: parsedPayload.public_commitment,
    proofCommitment: proofPublicCommitment,
    payloadVersion: parsedPayload.version,
    serverNonce: parsedPayload.server_nonce,
    keySource,
  };
}

// ---- 解析 canonical payload 字符串 ----
// 格式（换行分隔）：
//   ZK_LOCATION_V1
//   public_commitment=<大整数>
//   server_nonce=<base64url 字符串>
// 第一行是协议版本号，后续行是 key=value 对
function parseCanonicalPayload(value) {
  // lines: 按换行符分割 canonical payload 字符串
  const lines = value.split(/\r?\n/);
  // result: 解析结果，第一行是协议版本号，后续行是 key=value 对
  const result = {
    version: lines[0] || null,
    public_commitment: null,
    server_nonce: null,
  };

  for (const line of lines.slice(1)) {
    // separator: "=" 符号的位置，用于分割 key 和 value
    const separator = line.indexOf("=");
    if (separator <= 0) continue;
    // key: "=" 左侧的字段名
    const key = line.slice(0, separator);
    // fieldValue: "=" 右侧的字段值
    const fieldValue = line.slice(separator + 1);
    if (key === "public_commitment") {
      result.public_commitment = fieldValue;
    } else if (key === "server_nonce") {
      result.server_nonce = fieldValue;
    }
  }

  return result;
}

// ---- 从 SPKI DER Base64 格式的公钥创建 crypto 公钥对象 ----
function createPublicKeyFromSpki(publicKeyBase64) {
  return crypto.createPublicKey({
    key: Buffer.from(publicKeyBase64, "base64"),
    format: "der",
    type: "spki",
  });
}

// ---- 从证书链第一张证书中提取公钥 ----
function createPublicKeyFromCertificate(certificateBase64) {
  const certificate = new crypto.X509Certificate(Buffer.from(certificateBase64, "base64"));
  return certificate.publicKey;
}

// ---- 获取证书链的第一张证书（leaf certificate）----
function firstCertificate(value) {
  return Array.isArray(value) && typeof value[0] === "string" ? value[0] : null;
}

// ---- 从多个候选值中取第一个非空字符串 ----
function pickString(...values) {
  return values.find((value) => typeof value === "string" && value.length > 0) ?? null;
}

module.exports = {
  parseCanonicalPayload,
  verifyKeystoreSignature,
};
