"use strict";

// =============================================================================
// interaction-logger.js —— 交互日志记录 (M-11: fixed minimal schema)
// =============================================================================
// 使用 JSONL 格式记录服务端关键交互。
// log() 只保存固定字段：ts, type, statusCode, durationMs, result.
// 绝不保存 token, nonce, signature, certificate, path, error, request/response body.

const fs = require("node:fs");
const path = require("node:path");

const DEFAULT_LOG_PATH = path.resolve(__dirname, "../logs/interactions.jsonl");

// ---- 不可抛出的 logger 错误报告 ----
function safeReportLoggerFailure(operation, error) {
  let code = "UNKNOWN";
  try {
    if (error && typeof error.code === "string" && error.code.length > 0) {
      code = error.code;
    }
  } catch (_unused) {}
  try {
    fs.writeSync(2, `[interaction-logger] ${operation} failed (${code})\n`);
  } catch (_unused) {}
}

// ---- 固定 logger 字段 allowlist (M-11) ----
const LOG_EVENT_TYPES = Object.freeze(new Set([
  "auth.register", "auth.login", "auth.logout",
  "password.register", "password.login",
  "proof.verify", "regex.proof.verify",
  "nonce.issue",
  "key.register", "key.revoke",
]));
const MAX_LOG_DURATION_MS = 3600_000; // 1 hour max

// ---- 安全提取 (total) ----
function safeLogType(v) {
  try { return typeof v === "string" && LOG_EVENT_TYPES.has(v) ? v : "unknown"; } catch { return "unknown"; }
}
function safeLogStatus(v) {
  try { return typeof v === "number" && Number.isSafeInteger(v) && v >= 100 && v <= 599 ? v : 500; } catch { return 500; }
}
function safeLogDuration(v) {
  try { return typeof v === "number" && Number.isFinite(v) && v >= 0 && v <= MAX_LOG_DURATION_MS ? v : null; } catch { return null; }
}

// 供 summarize helpers 使用的轻量安全提取
function safeString(v, fallback) {
  try { return typeof v === "string" ? v.slice(0, 200) : (fallback || null); } catch { return fallback || null; }
}
function safeNumber(v) {
  try { return typeof v === "number" && Number.isFinite(v) && v >= 0 ? v : null; } catch { return null; }
}
// ---- 创建交互日志记录器 ----
function createInteractionLogger(options = {}) {
  const filePath = options.filePath || process.env.INTERACTION_LOG_PATH || DEFAULT_LOG_PATH;

  let dirReady = false;
  try {
    fs.mkdirSync(path.dirname(filePath), { recursive: true });
    dirReady = true;
  } catch (error) {
    safeReportLoggerFailure("mkdir", error);
  }

  return {
    filePath,
    // log(record): 只保存固定字段 (M-11: no ...record spread)
    log(record) {
      if (!dirReady) return;
      try {
        const line = JSON.stringify({
          ts: new Date().toISOString(),
          type: safeLogType(record && record.type),
          statusCode: safeLogStatus(record && record.statusCode),
          durationMs: safeLogDuration(record && record.durationMs),
        });
        fs.appendFileSync(filePath, `${line}\n`, { encoding: "utf8", mode: 0o600 });
      } catch (error) {
        safeReportLoggerFailure("write", error);
      }
    },
    recent(limit = 50) {
      try {
        return readRecentInteractions(filePath, limit);
      } catch (error) {
        safeReportLoggerFailure("read", error);
        return [];
      }
    },
  };
}

// ---- 构造请求元信息 (M-11: 脱敏, 仅用于 caller 传递, 不入日志) ----
function requestMeta(req, requestId, pathname) {
  return {
    id: requestId,
    method: safeString((req && req.method), "UNKNOWN"),
    path: safeString(pathname, "/"),
  };
}

// ---- 提取 proof 请求摘要 (total) ----
function summarizeProofRequest(payload) {
  const summary = { publicInputCount: null, proofShape: "unknown" };
  try {
    try { const ps = require("./proof-format").normalizePublicSignals(payload); summary.publicInputCount = Array.isArray(ps) ? ps.length : null; } catch (_) {}
    const proof = payload && payload.proof;
    if (proof) {
      try { if (Array.isArray(proof.pi_a) && Array.isArray(proof.pi_b) && Array.isArray(proof.pi_c)) summary.proofShape = "snarkjs"; } catch (_) {}
      try { if (proof.a && proof.b && proof.c) summary.proofShape = "mopro"; } catch (_) {}
    }
  } catch (_) {}
  return summary;
}

// ---- 提取验证响应摘要 (M-11: minimal) ----
function summarizeVerifyResponse(response) {
  let v = false, pv = false;
  try { v = (response && response.valid) === true; } catch (_) {}
  try { pv = (response && response.proofValid) === true; } catch (_) {}
  return { valid: v, proofValid: pv };
}

// ---- 提取 key 注册摘要 (M-11: no fingerprint) ----
function summarizeKeyRegistration(user, key) {
  return {
    userId: safeString(user && user.id, null),
    keyId: safeString(key && key.id, null),
    namedCurve: safeString(key && key.namedCurve, null),
    certificateChainCount: safeNumber(key && key.certificateChainCount),
  };
}

// ---- 提取 key 注册请求摘要 (M-11: count only) ----
function summarizeKeyRegistrationRequest(payload) {
  let count = 0;
  try {
    const tee = payload && payload.tee ? payload.tee : {};
    const chain = payload && (payload.certificateChain || payload.certificateChainBase64) || tee.certificateChain || tee.certificateChainBase64;
    if (Array.isArray(chain)) count = chain.length;
  } catch (_) {}
  return { certificateChainCount: count };
}

// ---- 从 JSONL 文件读取最近 limit 条日志 ----
function readRecentInteractions(filePath, limit = 50) {
  if (!fs.existsSync(filePath)) return [];
  const lines = fs.readFileSync(filePath, "utf8").split(/\r?\n/).filter(Boolean).slice(-Math.max(0, Number(limit) || 50));
  return lines.map((line) => {
    try { return JSON.parse(line); } catch (_) { return { parseError: "Cannot parse log entry" }; }
  });
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
