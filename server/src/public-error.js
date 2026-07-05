"use strict";

// =============================================================================
// public-error.js —— 不可伪造的公共错误身份 (M-11)
// =============================================================================
// 品牌只能通过安全构造函数创建。普通对象/原型伪造/Proxy 无法取得品牌。
// 品牌只能创建一次，消息完全来自固定定义表。
// 不导出 mutation-style brandError。

const _brand = new WeakMap();

// ---- 固定公共错误定义 ----
const PUBLIC_ERRORS = Object.freeze({
  BAD_REQUEST:          Object.freeze({ statusCode: 400, code: "BAD_REQUEST",          message: "Bad request" }),
  INVALID_CREDENTIALS:  Object.freeze({ statusCode: 401, code: "INVALID_CREDENTIALS",  message: "Invalid username or password" }),
  FORBIDDEN:            Object.freeze({ statusCode: 403, code: "FORBIDDEN",            message: "Forbidden" }),
  NOT_FOUND:            Object.freeze({ statusCode: 404, code: "NOT_FOUND",            message: "Not found" }),
  CONFLICT:             Object.freeze({ statusCode: 409, code: "CONFLICT",             message: "Username already exists" }),
  UNPROCESSABLE:        Object.freeze({ statusCode: 422, code: "UNPROCESSABLE",        message: "Unprocessable" }),
  INTERNAL_ERROR:       Object.freeze({ statusCode: 500, code: "INTERNAL_ERROR",       message: "Internal error" }),
  SERVICE_UNAVAILABLE:  Object.freeze({ statusCode: 503, code: "SERVICE_UNAVAILABLE",  message: "Service unavailable" }),
  // auth-store
  USERNAME_INVALID:     Object.freeze({ statusCode: 400, code: "BAD_REQUEST",          message: "Invalid username format" }),
  INVALID_USER_ID_PW:   Object.freeze({ statusCode: 400, code: "BAD_REQUEST",          message: "userId must be 3-128 characters" }),
  PASSWORD_INVALID:     Object.freeze({ statusCode: 400, code: "BAD_REQUEST",          message: "Invalid password format" }),
  MISSING_PUBLIC_KEY:   Object.freeze({ statusCode: 400, code: "BAD_REQUEST",          message: "Missing public key" }),
  KEY_NOT_FOUND:        Object.freeze({ statusCode: 404, code: "NOT_FOUND",            message: "Key not found" }),
  USER_NOT_FOUND:       Object.freeze({ statusCode: 404, code: "NOT_FOUND",            message: "User not found" }),
  SESSION_INVALID:      Object.freeze({ statusCode: 401, code: "INVALID_CREDENTIALS",  message: "Invalid or expired session token" }),
  MISSING_TOKEN:        Object.freeze({ statusCode: 401, code: "INVALID_CREDENTIALS",  message: "Missing Authorization bearer token" }),
  NONCE_INVALID:        Object.freeze({ statusCode: 400, code: "BAD_REQUEST",          message: "Invalid key registration nonce" }),
  MISSING_NONCE:        Object.freeze({ statusCode: 400, code: "BAD_REQUEST",          message: "Missing key registration nonce" }),
  PROOF_INPUT_COUNT:    Object.freeze({ statusCode: 400, code: "BAD_REQUEST",          message: "Invalid number of public inputs" }),
  // Password
  PASSWORD_PROOF_INVALID:        Object.freeze({ statusCode: 422, code: "PASSWORD_PROOF_INVALID", message: "Password Groth16 proof verification failed" }),
  USER_ID_EXISTS:                Object.freeze({ statusCode: 409, code: "USER_ID_EXISTS",         message: "userId is already registered" }),
  INVALID_CREDENTIALS_PW:        Object.freeze({ statusCode: 401, code: "INVALID_CREDENTIALS",    message: "Invalid userId or password" }),
  ACCOUNT_REQUIRES_REREGISTRATION: Object.freeze({ statusCode: 409, code: "ACCOUNT_REQUIRES_REREGISTRATION", message: "Account requires re-registration before password login" }),
  PASSWORD_REGISTRATION_FAILED:  Object.freeze({ statusCode: 500, code: "PASSWORD_REGISTRATION_FAILED", message: "Password registration failed" }),
  PASSWORD_LOGIN_FAILED:         Object.freeze({ statusCode: 500, code: "PASSWORD_LOGIN_FAILED", message: "Password login failed" }),
  PASSWORD_LOGIN_PARAMETERS_FAILED: Object.freeze({ statusCode: 500, code: "PASSWORD_LOGIN_PARAMETERS_FAILED", message: "Password login parameters failed" }),
  PASSWORD_REGISTRATION_DB_WRITE_FAILED: Object.freeze({ statusCode: 500, code: "PASSWORD_REGISTRATION_DB_WRITE_FAILED", message: "Password registration storage failed" }),
  FORBIDDEN_PRIVATE_FIELD:       Object.freeze({ statusCode: 400, code: "FORBIDDEN_PRIVATE_FIELD", message: "Request contains forbidden field" }),
  INVALID_REQUEST:               Object.freeze({ statusCode: 400, code: "INVALID_REQUEST",         message: "Invalid request" }),
  INVALID_USER_ID:               Object.freeze({ statusCode: 400, code: "INVALID_USER_ID",         message: "Invalid user ID" }),
  INVALID_SALT:                  Object.freeze({ statusCode: 400, code: "INVALID_SALT",            message: "Invalid salt" }),
  INVALID_PUBLIC_SIGNALS:        Object.freeze({ statusCode: 400, code: "INVALID_PUBLIC_SIGNALS",  message: "Invalid public signals" }),
  COMMITMENT_MISMATCH:           Object.freeze({ statusCode: 400, code: "COMMITMENT_MISMATCH",     message: "Commitment mismatch" }),
  MISSING_PROOF:                 Object.freeze({ statusCode: 400, code: "MISSING_PROOF",           message: "Proof is required" }),
  INVALID_PROOF_FORMAT:          Object.freeze({ statusCode: 400, code: "INVALID_PROOF_FORMAT",    message: "Invalid proof format" }),
  INVALID_PROOF_COORDINATE:      Object.freeze({ statusCode: 400, code: "INVALID_PROOF_COORDINATE", message: "Invalid proof coordinate" }),
  INVALID_FIELD_ELEMENT:         Object.freeze({ statusCode: 400, code: "INVALID_FIELD_ELEMENT",   message: "Invalid field element" }),
  // auth-store
  AUTH_REGISTER_FAILED:    Object.freeze({ statusCode: 500, code: "AUTH_REGISTER_FAILED",    message: "Registration failed" }),
  AUTH_LOGIN_FAILED:       Object.freeze({ statusCode: 500, code: "AUTH_LOGIN_FAILED",       message: "Login failed" }),
  AUTH_LOGOUT_FAILED:      Object.freeze({ statusCode: 500, code: "AUTH_LOGOUT_FAILED",      message: "Logout failed" }),
  AUTH_REQUIRED:           Object.freeze({ statusCode: 401, code: "AUTH_REQUIRED",            message: "Authentication required" }),
  KEY_REGISTER_FAILED:     Object.freeze({ statusCode: 500, code: "KEY_REGISTER_FAILED",     message: "Key registration failed" }),
  KEY_ACTIVE_FAILED:       Object.freeze({ statusCode: 500, code: "KEY_ACTIVE_FAILED",       message: "Failed to get active key" }),
  KEY_LIST_FAILED:         Object.freeze({ statusCode: 500, code: "KEY_LIST_FAILED",         message: "Failed to list keys" }),
  KEY_REVOKE_FAILED:       Object.freeze({ statusCode: 500, code: "KEY_REVOKE_FAILED",       message: "Key revocation failed" }),
  KEY_NONCE_FAILED:        Object.freeze({ statusCode: 500, code: "KEY_NONCE_FAILED",        message: "Failed to issue key nonce" }),
  PROOF_VERIFY_FAILED:     Object.freeze({ statusCode: 500, code: "PROOF_VERIFY_FAILED",     message: "Proof verification failed" }),
  REGEX_PROOF_VERIFY_FAILED: Object.freeze({ statusCode: 500, code: "REGEX_PROOF_VERIFY_FAILED", message: "Regex proof verification failed" }),
  INVALID_PUBLIC_KEY:      Object.freeze({ statusCode: 400, code: "INVALID_PUBLIC_KEY",       message: "Invalid public key" }),
  PUBLIC_KEY_NOT_EC:       Object.freeze({ statusCode: 400, code: "INVALID_PUBLIC_KEY",       message: "Public key must be an EC key" }),
  PUBLIC_KEY_NOT_P256:     Object.freeze({ statusCode: 400, code: "INVALID_PUBLIC_KEY",       message: "Public key must use P-256/prime256v1" }),
  INVALID_CERTIFICATE:     Object.freeze({ statusCode: 400, code: "INVALID_CERTIFICATE",      message: "Invalid certificate" }),
  UNTRUSTED_ATTESTATION:   Object.freeze({ statusCode: 400, code: "UNTRUSTED_ATTESTATION",    message: "Untrusted or incompatible key" }),
  INVALID_ATTESTATION:     Object.freeze({ statusCode: 400, code: "INVALID_ATTESTATION",      message: "Invalid attestation" }),
  MISSING_ATTESTATION_EXT: Object.freeze({ statusCode: 400, code: "INVALID_ATTESTATION",      message: "Missing Android Key Attestation extension" }),
});

const CODE_ALIAS = Object.freeze({ "AUTH_INVALID_CREDENTIALS": "INVALID_CREDENTIALS" });
function resolveKey(key) { return CODE_ALIAS[key] || key; }

// 内部函数：为在模块内安全构造的 Error 注册品牌
function _registerBrand(error, definitionKey) {
  try {
    if (_brand.has(error)) return;
    const key = resolveKey(definitionKey);
    const def = PUBLIC_ERRORS[key];
    if (!def) return;
    _brand.set(error, Object.freeze({
      statusCode: def.statusCode,
      code: def.code,
      message: def.message,
    }));
  } catch { /* total */ }
}

// ---- PublicError: 安全基类 (M-11) ----
// 只有通过此构造函数或继承它的类创建的对象才能取得品牌。
// Object.create(PublicError.prototype) 和 Proxy wrapper 均无品牌。
class PublicError extends Error {
  constructor(definitionKey, internalMessage) {
    const key = resolveKey(definitionKey);
    const def = PUBLIC_ERRORS[key];
    if (!def) throw new Error(`Unknown public error key: ${definitionKey}`);
    super(internalMessage || def.message);
    this.statusCode = def.statusCode;
    this.code = def.code;
    _registerBrand(this, definitionKey);
  }
}

// ---- 从 WeakMap 提取 (total) ----
function extractErrorInfo(error) {
  try { return _brand.get(error) || null; } catch { return null; }
}

// ---- 安全提取 (total) ----
function safeErrorStatus(error) {
  const info = extractErrorInfo(error);
  return info ? info.statusCode : 500;
}
function safeErrorMessage(error) {
  try {
    const info = extractErrorInfo(error);
    if (info) return info.message;
    return "Internal error";
  } catch { return "Internal error"; }
}
function safeErrorCode(error) {
  const info = extractErrorInfo(error);
  return info ? info.code : "UNKNOWN";
}

module.exports = {
  PublicError,
  PUBLIC_ERRORS,
  extractErrorInfo,
  safeErrorStatus,
  safeErrorMessage,
  safeErrorCode,
};
