"use strict";

// =============================================================================
// interaction-logger.js —— 交互日志记录
// =============================================================================
// 使用 JSONL 格式（每行一条 JSON）记录服务端与客户端的关键交互。
// 记录内容包括 proof 验证请求/响应、key 注册请求/响应、nonce 发放。
// 日志用于调试、实验报告生成和性能统计。

const fs = require("node:fs");
const path = require("node:path");
const { normalizePublicSignals } = require("./proof-format");
const { parseCanonicalPayload } = require("./keystore-signature");

const DEFAULT_LOG_PATH = path.resolve(__dirname, "../logs/interactions.jsonl");

// ---- 创建交互日志记录器 ----
// 返回 { filePath, log(record), recent(limit) } 三个方法
// log() 追加一条 JSON 行到文件末尾
// recent() 读取文件末尾最近 N 行
function createInteractionLogger(options = {}) {
  // filePath: JSONL 日志文件完整路径，支持通过环境变量 INTERACTION_LOG_PATH 自定义
  const filePath = options.filePath || process.env.INTERACTION_LOG_PATH || DEFAULT_LOG_PATH;
  fs.mkdirSync(path.dirname(filePath), { recursive: true });

  return {
    filePath,
    // 追加一条日志（JSONL 格式：一行 JSON）
    log(record) {
      // line: 一行完整的 JSON 字符串，ts 字段为当前 ISO 时间戳
      const line = JSON.stringify({
        ts: new Date().toISOString(),
        ...record,
      });
      fs.appendFileSync(filePath, `${line}\n`, "utf8");
    },
    // 读取最近 limit 条日志
    recent(limit = 50) {
      return readRecentInteractions(filePath, limit);
    },
  };
}

// ---- 构造请求元信息（日志中记录请求来源）----
function requestMeta(req, requestId, pathname) {
  return {
    id: requestId,
    method: req.method,
    path: pathname,
    remoteAddress: req.socket.remoteAddress,
    userAgent: req.headers["user-agent"] || null,
  };
}

// ---- 提取 proof 请求摘要 ----
// 不含完整 proof 数据和全部 public inputs，只提取关键字段，
// 避免日志文件膨胀，同时可快速判断请求内容
function summarizeProofRequest(payload) {
  // summary: proof 请求摘要对象，只包含关键字段，避免日志文件膨胀
  const summary = {
    publicInputCount: null,
    publicCommitment: null,
    proofShape: "unknown",
    // tee: Keystore 签名字段摘要（payload/signature/publicKey 等）
    tee: summarizeTee(payload),
    // metrics: 客户端性能指标（如 proof 生成耗时等）
    metrics: payload.metrics || payload.clientMetrics || null,
  };

  try {
    // publicSignals: ZK 电路的公开输入数组，共 37 个值
    const publicSignals = normalizePublicSignals(payload);
    summary.publicInputCount = publicSignals.length;
    // publicSignals[0] 就是 Poseidon(x, y, salt) 的承诺值
    summary.publicCommitment = publicSignals[0] || null;
  } catch (error) {
    summary.publicSignalError = error.message || String(error);
  }

  // proof: 从请求中提取 proof 对象，兼容 snarkjs/mopro 两种格式
  const proof = payload.proof ?? payload.proofResult?.proof;
  if (proof) {
    if (Array.isArray(proof.pi_a) && Array.isArray(proof.pi_b) && Array.isArray(proof.pi_c)) {
      summary.proofShape = "snarkjs";
    } else if (proof.a && proof.b && proof.c) {
      summary.proofShape = "mopro";
    }
    summary.protocol = proof.protocol || null;
    summary.curve = proof.curve || null;
  }

  return summary;
}

// ---- 提取验证响应摘要 ----
// 从完整的验证结果中提取 proof/signature/nonce 三个子模块的关键信息
function summarizeVerifyResponse(response) {
  return {
    valid: response.valid,
    proofValid: response.proofValid ?? response.valid,
    acceptedFormat: response.acceptedFormat ?? null,
    publicInputCount: response.publicInputCount ?? null,
    signature: response.signature
      ? {
          checked: response.signature.checked,
          valid: response.signature.valid,
          signatureValid: response.signature.signatureValid,
          commitmentBound: response.signature.commitmentBound,
          payloadCommitment: response.signature.payloadCommitment ?? null,
          proofCommitment: response.signature.proofCommitment ?? null,
          serverNonce: response.signature.serverNonce ?? null,
          reason: response.signature.reason ?? null,
        }
      : null,
    nonce: response.nonce
      ? {
          checked: response.nonce.checked,
          valid: response.nonce.valid,
          consumed: response.nonce.consumed,
          nonce: response.nonce.nonce ?? null,
          reason: response.nonce.reason ?? null,
        }
      : null,
  };
}

// ---- 提取 key 注册摘要 ----
function summarizeKeyRegistration(user, key) {
  return {
    userId: user.id,
    username: user.username,
    keyId: key.id,
    publicKeyFingerprint: key.publicKeyFingerprint,
    namedCurve: key.namedCurve,
    certificateChainCount: key.certificateChainCount,
    attestation: key.attestation
      ? {
          verified: key.attestation.verified,
          challengeMatched: key.attestation.challengeMatched,
          attestationSecurityLevel: key.attestation.attestationSecurityLevel,
          keyMintSecurityLevel: key.attestation.keyMintSecurityLevel,
          certificateChainVerified: key.attestation.certificateChainVerified,
          rootTrusted: key.attestation.rootTrusted,
          rootFingerprint: key.attestation.rootFingerprint,
          authorization: key.attestation.authorization || null,
          purposeSign: key.attestation.authorization?.purposeSign ?? null,
          digestSha256: key.attestation.authorization?.digestSha256 ?? null,
          algorithmEc: key.attestation.authorization?.algorithmEc ?? null,
          ecCurveP256: key.attestation.authorization?.ecCurveP256 ?? null,
          verifiedBootState: key.attestation.authorization?.verifiedBootState ?? null,
          deviceLocked: key.attestation.authorization?.deviceLocked ?? null,
          skipped: key.attestation.skipped,
          reason: key.attestation.reason,
        }
      : null,
  };
}

// ---- 提取 key 注册请求摘要 ----
// 这里保留客户端在 bind key 时原始上传的 certificateChain（Base64 DER 字符串）。
// 这些证书是公开证书材料，不包含私钥；用于实验复核和论文截图取证。
function summarizeKeyRegistrationRequest(payload) {
  // tee: 兼容顶层字段和 tee 子对象字段。
  const tee = payload?.tee ?? {};
  // publicKey: 客户端上传的 SPKI DER Base64 公钥。
  const publicKey = pickString(
    payload?.publicKey,
    payload?.publicKeyBase64,
    tee.publicKey,
    tee.publicKeyBase64
  );
  // certificateChain: 客户端上传的 Android Keystore attestation 证书链。
  const certificateChain =
    payload?.certificateChain ??
    payload?.certificateChainBase64 ??
    tee.certificateChain ??
    tee.certificateChainBase64;

  return {
    publicKey: shortValue(publicKey),
    certificateChainCount: Array.isArray(certificateChain) ? certificateChain.length : 0,
    clientCertificateChainBase64: Array.isArray(certificateChain)
      ? certificateChain.map((certificate) => certificate.toString())
      : [],
  };
}

// ---- 提取 TEE（Keystore 签名）子字段摘要 ----
// 从多种可能字段名中提取 payload/signature/publicKey/certificateChain
function summarizeTee(payload) {
  // tee: 客户端上传的 TEE 签名字段，优先取 tee 字段，其次 keystore
  const tee = payload.tee ?? payload.keystore ?? {};
  // signedPayload: Keystore 签名原文（canonical payload 字符串）
  const signedPayload =
    pickString(tee.payload, tee.teePayload, payload.tee_payload, payload.teePayload, payload.signedPayload);
  // signature: ECDSA 签名的 Base64 编码值
  const signature =
    pickString(tee.signature, tee.signatureBase64, payload.tee_signature, payload.teeSignature, payload.signatureBase64);
  // publicKey: 客户端公钥（SPKI DER, Base64 编码）
  const publicKey =
    pickString(tee.publicKey, tee.publicKeyBase64, payload.public_key, payload.publicKey, payload.publicKeyBase64);
  // certificateChain: Android Keystore attestation 证书链（Base64 字符串数组）
  const certificateChain =
    tee.certificateChain ??
    tee.certificateChainBase64 ??
    payload.certificate_chain ??
    payload.certificateChain ??
    payload.certificateChainBase64;

  if (!signedPayload && !signature && !publicKey && !certificateChain) {
    return { present: false };
  }

  // parsedPayload: 解析后的 canonical payload，提取 version/commitment/nonce
  const parsedPayload = signedPayload
    ? parseCanonicalPayload(signedPayload)
    : { version: null, public_commitment: null, server_nonce: null };

  return {
    present: true,
    payloadVersion: parsedPayload.version,
    payloadCommitment: parsedPayload.public_commitment,
    serverNonce: parsedPayload.server_nonce,
    signature: shortValue(signature),
    publicKey: shortValue(publicKey),
    certificateChainCount: Array.isArray(certificateChain) ? certificateChain.length : 0,
  };
}

// ---- 从 JSONL 文件读取最近 limit 条日志 ----
function readRecentInteractions(filePath, limit = 50) {
  if (!fs.existsSync(filePath)) {
    return [];
  }

  // lines: JSONL 文件的每一行，取最后 limit 行（slice 负数取末尾）
  const lines = fs
    .readFileSync(filePath, "utf8")
    .split(/\r?\n/)
    .filter(Boolean)
    .slice(-Math.max(0, Number(limit) || 50));

  return lines.map((line) => {
    try {
      return JSON.parse(line);
    } catch (error) {
      return {
        parseError: error.message || String(error),
        raw: line,
      };
    }
  });
}

// ---- 长字符串截断显示（前16字符...后8字符）----
function shortValue(value) {
  if (typeof value !== "string" || value.length === 0) {
    return null;
  }
  return value.length <= 32 ? value : `${value.slice(0, 16)}...${value.slice(-8)}`;
}

// ---- 从多个候选值中取第一个非空字符串 ----
function pickString(...values) {
  return values.find((value) => typeof value === "string" && value.length > 0) ?? null;
}

module.exports = {
  DEFAULT_LOG_PATH,
  createInteractionLogger,
  readRecentInteractions,
  requestMeta,
  summarizeKeyRegistration,
  summarizeKeyRegistrationRequest,
  summarizeProofRequest,
  summarizeVerifyResponse,
};
