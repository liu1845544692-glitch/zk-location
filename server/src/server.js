"use strict";

// =============================================================================
// server.js —— ZK Location 验证服务 HTTP 入口
// =============================================================================
// 基于 Node.js 内置 http 模块的纯 HTTP JSON API 服务。
// 不依赖 Express 等框架，减小依赖面。
//
// 完整协议流程（详见 docs/protocol.md）：
//   1. POST /auth/register          - 注册
//   2. POST /auth/login             - 登录，获取 Bearer token
//   3. POST /keys/register-nonce    - 获取 key registration nonce
//   4. POST /keys/register          - 绑定 attestation key
//   5. GET/POST /nonce             - 获取 server nonce（用于签名防重放）
//   6. POST /verify-proof           - 发送位置 ZK proof + Keystore 签名
//   7. POST /verify-regex-proof     - 发送 Regex record ZK proof
//
// /verify-proof 的验证链路：
//   session token → active key → proof 验证 → 设备签名与 commitment 绑定验证 → nonce 消费
//   位置 proof 必须携带设备签名；proof、签名、commitment 绑定和 nonce 全部通过才接受。

const fs = require("node:fs");
const http = require("node:http");
const path = require("node:path");
const crypto = require("node:crypto");
const { verifyRegexRecordWithArkworks } = require("./arkworks-regex-verifier");
const { normalizePublicSignals, verifyPayload } = require("./proof-format");
const { verifyKeystoreSignature } = require("./keystore-signature");
const {
  saveRejectedAttestationRoot,
  summarizeAttestationCertificateChain,
} = require("./key-attestation");
const { DEFAULT_TTL_MS, NonceStore } = require("./nonce-store");
const { AuthError, JsonAuthStore, publicUser } = require("./auth-store");
const { PublicError, extractErrorInfo, safeErrorStatus, safeErrorMessage, safeErrorCode } = require("./public-error");
const {
  JsonPasswordRegistrationStore,
  PasswordRegistrationStoreError,
} = require("./password-registration-store");
const {
  createInteractionLogger,
  requestMeta,
  summarizeKeyRegistration,
  summarizeKeyRegistrationRequest,
  summarizeProofRequest,
  summarizeVerifyResponse,
} = require("./interaction-logger");
const {
  buildExperimentReport,
  buildPerformanceStats,
  reportToMarkdown,
} = require("./report-generator");

// 默认监听端口
const DEFAULT_PORT = 3000;
// HTTP body 最大 1MB（防止内存耗尽）
const MAX_BODY_BYTES = 1024 * 1024;
const BN254_SCALAR_MODULUS = BigInt(
  "21888242871839275222246405745257275088548364400416034343698204186575808495617"
);
const BN254_BASE_MODULUS = BigInt(
  "21888242871839275222246405745257275088696311157297823662689037894645226208583"
);
const PASSWORD_PROOF_VERSION = "groth16-bn254-v1";
const PASSWORD_CIRCUIT_VERSION = "password-policy-commitment-v1";

// ---- 创建并配置验证服务 ----
// 返回 http.Server 实例，所有依赖可注入（方便测试）
function createVerifierServer(options = {}) {
  // vkPath: Groth16 验证密钥文件路径
  const vkPath = options.vkPath || process.env.VK_PATH || defaultVerificationKeyPath();
  // verificationKey: 已加载的 snarkjs 格式验证密钥对象
  const verificationKey = options.verificationKey || loadVerificationKey(vkPath);
  // regexVkPath/regexVerificationKey: Regex record proof 的 Groth16 验证密钥。
  const regexVkPath =
    options.regexVkPath || process.env.REGEX_VK_PATH || defaultRegexRecordVerificationKeyPath();
  const regexVerificationKey =
    options.regexVerificationKey || loadVerificationKey(regexVkPath);
  // verifyProofPayload: proof 验证函数（可注入，默认用 proof-format.js 的 verifyPayload）
  const verifyProofPayload = options.verifyPayload || verifyPayload;
  const passwordVkPath =
    options.passwordVkPath ||
    process.env.PASSWORD_VK_PATH ||
    defaultPasswordVerificationKeyPath();
  const passwordVerificationKey =
    options.passwordVerificationKey || loadVerificationKey(passwordVkPath);
  const verifyPasswordProofPayload = options.verifyPasswordPayload || verifyPayload;

  // nonceStore: nonce 防重放存储实例（基于内存 Map）
  const nonceStore = options.nonceStore || new NonceStore({
    ttlMs: Number(options.nonceTtlMs ?? process.env.NONCE_TTL_MS ?? DEFAULT_TTL_MS),
  });

  // authStore: 用户认证与密钥存储实例（基于 JSON 文件）
  const authStore = options.authStore || new JsonAuthStore();
  const passwordRegistrationStore =
    options.passwordRegistrationStore || new JsonPasswordRegistrationStore();

  // interactionLogger: 交互日志记录器实例（JSONL 格式文件）
  const interactionLogger = options.interactionLogger || createInteractionLogger();

  // nextRequestId: 请求 ID 自增计数器，用于日志中追踪单次请求
  let nextRequestId = 1;

  // ---- 主 HTTP 请求处理 ----
  // 按 method + pathname 匹配路由，未匹配返回 404
  const server = http.createServer(async (req, res) => {
    // 所有响应都设置 CORS 头，允许跨域
    setCorsHeaders(res);
    // pathname: 请求 URL 的路径部分（不含 query string）
    const pathname = requestPathname(req);
    // requestId: 本次请求的唯一 ID（自增），用于日志关联
    const requestId = nextRequestId++;
    // startedAt: 请求开始处理的时刻，用于计算耗时
    const startedAt = Date.now();

    // 处理 CORS 预检请求
    if (req.method === "OPTIONS") {
      res.writeHead(204);
      res.end();
      return;
    }

    // ---- GET /health - 健康检查 (M-11: minimal, 父提交语义) ----
    if (req.method === "GET" && pathname === "/health") {
      sendJson(res, 200, { status: "ok" });
      return;
    }

    // Password registration is proof-based and intentionally independent from
    // the legacy plaintext-password /auth/register endpoint.
    if (req.method === "POST" && pathname === "/password/register") {
      let body = null;
      let requestSummary = null;
      try {
        body = await readJsonBody(req);
        const normalized = validatePasswordRegistrationRequest(body);
        requestSummary = passwordRegistrationRequestSummary(normalized);

        const verifyStarted = process.hrtime.bigint();
        const proofResult = await verifyPasswordProofPayload(passwordVerificationKey, {
          proof: normalized.proof,
          publicSignals: normalized.publicSignals,
        });
        const serverVerifyTimeMs = elapsedMonotonicMs(verifyStarted);
        if (!proofResult.valid) {
          throw passwordRegistrationError(
            422,
            "PASSWORD_PROOF_INVALID",
            "Password Groth16 proof verification failed"
          );
        }

        if (passwordRegistrationStore.find(normalized.userId)) {
          throw passwordRegistrationError(409, "USER_ID_EXISTS", "userId is already registered");
        }
        authStore.registerPasswordUser(normalized.userId);
        let record;
        try {
          record = passwordRegistrationStore.register({
            userId: normalized.userId,
            salt: normalized.salt,
            passwordCommitment: normalized.passwordCommitment,
            proofVersion: PASSWORD_PROOF_VERSION,
            circuitVersion: PASSWORD_CIRCUIT_VERSION,
          });
        } catch (error) {
          authStore.removePasswordUser(normalized.userId);
          throw error;
        }
        const response = {
          success: true,
          message: "Password registration succeeded",
          userId: record.userId,
          passwordCommitment: record.passwordCommitment,
          proofVerified: true,
          publicInputCount: normalized.publicSignals.length,
          acceptedFormat: sanitizeProofFormat(proofResult.acceptedFormat),
          serverVerifyTimeMs,
          requestTimeMs: Date.now() - startedAt,
          proofVersion: record.proofVersion,
          circuitVersion: record.circuitVersion,
        };
        sendJson(res, 201, response);
        interactionLogger.log({
          type: "password.register",
          request: requestMeta(req, requestId, pathname),
          requestSummary,
          responseSummary: {
            success: true,
            userId: record.userId,
            commitmentDigest: commitmentDigest(record.passwordCommitment),
            proofVerified: true,
            serverVerifyTimeMs,
          },
          statusCode: 201,
          durationMs: Date.now() - startedAt,
        });
      } catch (error) {
        const errMsg = safeErrorMessage(error);
        const invalidJson = /^Invalid JSON:|^Request body too large/.test(errMsg);
        const statusCode = invalidJson ? 400 : safeErrorStatus(error);
        const code = safeErrorCode(error) !== "UNKNOWN" ? safeErrorCode(error) : "PASSWORD_REGISTRATION_FAILED";
        const response = { success: false, code, error: errMsg };
        sendJson(res, statusCode, response);
        interactionLogger.log({
          type: "password.register",
          request: requestMeta(req, requestId, pathname),
          requestSummary,
          responseSummary: { success: false, code, error: response.error },
          statusCode,
          durationMs: Date.now() - startedAt,
        });
      }
      return;
    }

    if (req.method === "GET" && pathname === "/password/login-parameters") {
      try {
        const requestUrl = new URL(req.url, "http://localhost");
        const userId = validatePasswordUserId(requestUrl.searchParams.get("userId"));
        const record = passwordRegistrationStore.find(userId);
        if (!record) {
          throw passwordRegistrationError(401, "INVALID_CREDENTIALS", "Invalid userId or password");
        }
        if (record.saltMissing || typeof record.salt !== "string") {
          throw passwordRegistrationError(
            409,
            "ACCOUNT_REQUIRES_REREGISTRATION",
            "Account requires re-registration before password login"
          );
        }
        validatePasswordSalt(record.salt);
        sendJson(res, 200, {
          success: true,
          salt: record.salt,
          circuitVersion: record.circuitVersion,
        });
      } catch (error) {
        sendJson(res, safeErrorStatus(error), {
          success: false,
          code: safeErrorCode(error) !== "UNKNOWN" ? safeErrorCode(error) : "PASSWORD_LOGIN_PARAMETERS_FAILED",
          message: safeErrorMessage(error),
        });
      }
      return;
    }

    if (req.method === "POST" && pathname === "/password/login") {
      let requestSummary = null;
      try {
        const body = await readJsonBody(req);
        const normalized = validatePasswordLoginRequest(body);
        requestSummary = {
          userId: normalized.userId,
          commitmentDigest: commitmentDigest(normalized.passwordCommitment),
        };
        const record = passwordRegistrationStore.find(normalized.userId);
        const valid = constantTimeCommitmentEqual(
          normalized.passwordCommitment,
          record?.passwordCommitment || "0"
        ) && record !== null;
        if (!valid) {
          throw passwordRegistrationError(
            401,
            "INVALID_CREDENTIALS",
            "Invalid userId or password"
          );
        }

        let auth;
        try {
          auth = authStore.loginPasswordUser(normalized.userId, { createIfMissing: true });
        } catch (error) {
          if (extractErrorInfo(error) !== null && safeErrorStatus(error) === 401) {
            throw passwordRegistrationError(
              401,
              "INVALID_CREDENTIALS",
              "Invalid userId or password"
            );
          }
          throw error;
        }

        const response = {
          success: true,
          message: "Login succeeded",
          userId: normalized.userId,
          token: auth.session.token,
          expiresAt: auth.session.expiresAt,
          expiresInMs: auth.session.expiresInMs,
          requestTimeMs: Date.now() - startedAt,
          replayProtection: false,
        };
        sendJson(res, 200, response);
        interactionLogger.log({
          type: "password.login",
          request: requestMeta(req, requestId, pathname),
          requestSummary,
          responseSummary: {
            success: true,
            userId: normalized.userId,
          },
          statusCode: 200,
          durationMs: Date.now() - startedAt,
        });
      } catch (error) {
        const errMsg = safeErrorMessage(error);
        const invalidJson = /^Invalid JSON:|^Request body too large/.test(errMsg);
        const statusCode = invalidJson ? 400 : safeErrorStatus(error);
        const code = safeErrorCode(error) !== "UNKNOWN" ? safeErrorCode(error) : (invalidJson ? "INVALID_REQUEST" : "PASSWORD_LOGIN_FAILED");
        sendJson(res, statusCode, { success: false, code, message: errMsg });
        interactionLogger.log({
          type: "password.login",
          request: requestMeta(req, requestId, pathname),
          requestSummary,
          responseSummary: { success: false, code },
          statusCode,
          durationMs: Date.now() - startedAt,
        });
      }
      return;
    }

    // ---- GET /logs/interactions - 已禁用 (M-11: 无 operator 授权模型) ----
    if (req.method === "GET" && pathname === "/logs/interactions") {
      sendJson(res, 404, { error: "Not found" });
      return;
    }

    // ---- GET /stats/performance - 已禁用 (M-11) ----
    if (req.method === "GET" && pathname === "/stats/performance") {
      sendJson(res, 404, { error: "Not found" });
      return;
    }

    // ---- GET /reports/latest - 已禁用 (M-11) ----
    if (req.method === "GET" && pathname === "/reports/latest") {
      sendJson(res, 404, { error: "Not found" });
      return;
    }

    // ---- POST /auth/register - 注册新用户 ----
    if (req.method === "POST" && pathname === "/auth/register") {
      try {
        const body = await readJsonBody(req);
        const registered = authStore.registerUser(body.username, body.password);
        sendJson(res, 201, authResponse(registered));
      } catch (error) {
        sendApiError(res, error, "AUTH_REGISTER_FAILED");
      }
      return;
    }

    // ---- POST /auth/login - 用户登录 ----
    if (req.method === "POST" && pathname === "/auth/login") {
      try {
        const body = await readJsonBody(req);
        const loggedIn = authStore.loginUser(body.username, body.password);
        sendJson(res, 200, authResponse(loggedIn));
      } catch (error) {
        sendApiError(res, error, "AUTH_LOGIN_FAILED");
      }
      return;
    }

    // ---- POST /auth/logout - 用户登出 ----
    if (req.method === "POST" && pathname === "/auth/logout") {
      try {
        const result = authStore.logoutAuthorizationHeader(req.headers.authorization);
        sendJson(res, 200, {
          valid: true,
          ...result,
        });
      } catch (error) {
        sendApiError(res, error, "AUTH_LOGOUT_FAILED");
      }
      return;
    }

    // ---- GET /auth/me - 查看当前用户信息 ----
    if (req.method === "GET" && pathname === "/auth/me") {
      try {
        const { user } = authStore.authenticateAuthorizationHeader(req.headers.authorization);
        sendJson(res, 200, {
          user: publicUser(user),
        });
      } catch (error) {
        sendApiError(res, error, "AUTH_REQUIRED");
      }
      return;
    }

    // ---- GET /keys/active - 查看当前 active key ----
    if (req.method === "GET" && pathname === "/keys/active") {
      try {
        const { user } = authStore.authenticateAuthorizationHeader(req.headers.authorization);
        sendJson(res, 200, {
          key: authStore.activeKeyForUser(user.id)
            ? publicUser(authStore.requireUser(user.id)).activeKey
            : null,
        });
      } catch (error) {
        sendApiError(res, error, "KEY_ACTIVE_FAILED");
      }
      return;
    }

    // ---- GET /keys - 查看用户的所有 key 记录 ----
    if (req.method === "GET" && pathname === "/keys") {
      try {
        const { user } = authStore.authenticateAuthorizationHeader(req.headers.authorization);
        sendJson(res, 200, {
          keys: authStore.keyRecordsForUser(user.id),
        });
      } catch (error) {
        sendApiError(res, error, "KEY_LIST_FAILED");
      }
      return;
    }

    // ---- POST /keys/revoke - 撤销 key ----
    if (req.method === "POST" && pathname === "/keys/revoke") {
      try {
        const { user } = authStore.authenticateAuthorizationHeader(req.headers.authorization);
        const body = await readJsonBody(req);
        sendJson(res, 200, {
          key: authStore.revokeUserKey(user.id, body.keyId),
        });
      } catch (error) {
        sendApiError(res, error, "KEY_REVOKE_FAILED");
      }
      return;
    }

    // ---- POST /keys/register-nonce - 获取 key registration nonce ----
    if (req.method === "POST" && pathname === "/keys/register-nonce") {
      try {
        const { user } = authStore.authenticateAuthorizationHeader(req.headers.authorization);
        sendJson(res, 200, authStore.issueKeyRegistrationNonce(user.id));
      } catch (error) {
        sendApiError(res, error, "KEY_NONCE_FAILED");
      }
      return;
    }

    // ---- POST /keys/register - 注册（绑定）attestation key ----
    if (req.method === "POST" && pathname === "/keys/register") {
      let body = null;
      let keyRegisterUser = null;
      try {
        const { user } = authStore.authenticateAuthorizationHeader(req.headers.authorization);
        keyRegisterUser = user;
        body = await readJsonBody(req);
        const key = authStore.registerUserKey(user.id, body);
        const response = {
          user: publicUser(authStore.requireUser(user.id)),
          key,
        };
        sendJson(res, 201, response);
        interactionLogger.log({
          type: "key.register",
          request: requestMeta(req, requestId, pathname),
          requestSummary: summarizeKeyRegistrationRequest(body),
          responseSummary: summarizeKeyRegistration(user, authStore.activeKeyForUser(user.id)),
          statusCode: 201,
          durationMs: Date.now() - startedAt,
        });
      } catch (error) {
        const attestationDebug = summarizeFailedKeyRegistrationAttestation(body);
        const statusCode = safeErrorStatus(error);
        sendJson(res, statusCode, errorPayload(error, "KEY_REGISTER_FAILED", {
          attestation: attestationDebug,
        }));
        interactionLogger.log({
          type: "key.register",
          request: requestMeta(req, requestId, pathname),
          requestSummary: body ? summarizeKeyRegistrationRequest(body) : null,
          responseSummary: {
            valid: false,
            error: safeErrorMessage(error),
            userId: keyRegisterUser?.id || null,
            username: keyRegisterUser?.username || null,
            attestation: attestationDebug,
          },
          statusCode,
          durationMs: Date.now() - startedAt,
        });
      }
      return;
    }

    // ---- GET/POST /nonce - 获取防重放用 server nonce ----
    if ((req.method === "GET" || req.method === "POST") && pathname === "/nonce") {
      const issued = nonceStore.issue();
      sendJson(res, 200, {
        ...issued,
      });
      interactionLogger.log({
        type: "nonce.issue",
        request: requestMeta(req, requestId, pathname),
        statusCode: 200,
        durationMs: Date.now() - startedAt,
      });
      return;
    }

    // =========================================================================
    // POST /verify-regex-proof —— Regex 联合日志记录 proof 服务端验证
    // =========================================================================
    // 客户端必须显式上传 regex_record proof 和 publicSignals/inputs。
    // 该接口只验证 Regex record Groth16 proof，不验证 TEE 签名，也不消费 nonce。
    if (req.method === "POST" && pathname === "/verify-regex-proof") {
      let payload = null;
      try {
        const { user } = authStore.authenticateAuthorizationHeader(req.headers.authorization);
        payload = await readJsonBody(req);

        const publicSignals = normalizePublicSignals(payload);
        const publicInputCountValid = publicSignals.length === 1;
        const proofResult = await verifyProofPayload(regexVerificationKey, payload);
        let proofValidByVerifier = proofResult.valid;
        let finalAcceptedFormat = sanitizeProofFormat(proofResult.acceptedFormat);
        let finalAttempts = sanitizeAttempts(proofResult.attempts);

        if (!proofValidByVerifier && publicInputCountValid) {
          const arkworksResult = await verifyRegexRecordWithArkworks({
            proof: payload.proof ?? payload.proofResult?.proof,
            inputs: publicSignals,
            publicSignals,
          });
          // M-11: Arkworks fallback 保留末尾槽位
          // 主 verifier 最多保留前 4 条 + Arkworks 占第 5 位
          const arkAttempt = { format: sanitizeProofFormat(arkworksResult.format), valid: !!arkworksResult.valid, error: arkworksResult.valid ? undefined : "Verification failed" };
          const out = [];
          const primaryLimit = MAX_PUBLIC_ATTEMPTS - 1; // 4
          for (let i = 0; i < primaryLimit && i < finalAttempts.length; i++) {
            out.push(finalAttempts[i]);
          }
          out.push(arkAttempt);
          finalAttempts = out;
          if (arkworksResult.valid) {
            proofValidByVerifier = true;
            finalAcceptedFormat = sanitizeProofFormat(arkworksResult.format);
          }
        }
        const proofValid = proofValidByVerifier && publicInputCountValid;
        const result = {
          circuit: "regex_record",
          valid: proofValid,
          proofValid,
          recordCommitment: publicSignals[0] || null,
          publicInputCount: publicSignals.length,
          acceptedFormat: finalAcceptedFormat,
          attempts: finalAttempts,
          reason: publicInputCountValid ? null : "regex_record proof must have exactly one public input",
          user: {
            id: user.id,
            username: user.username,
          },
        };

        sendJson(res, 200, result);
        interactionLogger.log({
          type: "regex.proof.verify",
          request: requestMeta(req, requestId, pathname),
          requestSummary: summarizeProofRequest(payload),
          responseSummary: summarizeVerifyResponse(result),
          statusCode: 200,
          durationMs: Date.now() - startedAt,
        });
      } catch (error) {
        const status = extractErrorInfo(error) !== null ? safeErrorStatus(error) : 500;
        const errorResponse = errorPayload(error, "REGEX_PROOF_VERIFY_FAILED");
        sendJson(res, status, errorResponse);
        interactionLogger.log({
          type: "regex.proof.verify",
          request: requestMeta(req, requestId, pathname),
          requestSummary: payload ? summarizeProofRequest(payload) : null,
          responseSummary: errorResponse,
          statusCode: status,
          durationMs: Date.now() - startedAt,
        });
      }
      return;
    }

    // =========================================================================
    // POST /verify-proof —— 核心验证端点
    // =========================================================================
    // 验证流程（顺序有讲究——先不耗费 nonce，最后才消费）：
    //   1. 验证 session token（鉴权）
    //   2. 检查用户是否有 active key（必须已绑定硬件密钥）
    //   3. 用 snarkjs 验证 Groth16 ZK proof
    //   4. 验证 Keystore ECDSA 签名 + commitment 绑定
    //   5. 消费 nonce（防重放）
    //
    // 整体 valid 判定逻辑：
    //   proof、设备签名、commitment 绑定和 nonce 全部通过才接受。
    //   nonce 仅在 proof 和签名均有效时消费。
    if (req.method === "POST" && pathname === "/verify-proof") {
      let payload = null;
      try {
        // 1. session 鉴权
        // user: 通过 Bearer token 鉴权获取的当前用户对象
        const { user } = authStore.authenticateAuthorizationHeader(req.headers.authorization);

        // 2. 获取用户 active key（如果未绑定 key 则拒绝）
        // activeKey: 用户当前注册的活跃硬件密钥
        const activeKey = authStore.activeKeyForUser(user.id);
        if (!activeKey) {
          throw new AuthError("FORBIDDEN", "Current user has no registered active public key");
        }

        // payload: 客户端上传的完整 JSON 请求体
        payload = await readJsonBody(req);

        // publicSignals: ZK 电路 37 个公开输入数组
        // publicSignals[0] 是 public_commitment
        // 作为 ZK proof 和 TEE 签名之间的绑定点
        const publicSignals = normalizePublicSignals(payload);

        // M-01: 强制 Location proof 公开输入数量恰好为 37，
        // 防止尾部零截断或其他数量错误绕过验证。
        if (publicSignals.length !== 37) {
          throw new AuthError("PROOF_INPUT_COUNT",
            `Location proof requires exactly 37 public inputs, got ${publicSignals.length}`
          );
        }

        // 3. Groth16 proof 验证
        // proofResult: snarkjs proof 验证结果 { valid, publicInputCount, acceptedFormat, attempts }
        const proofResult = await verifyProofPayload(verificationKey, payload);

        // 4. Keystore 签名验证 + commitment 绑定检查
        // 使用服务端存储的 active key 公钥（忽略请求中携带的 publicKey，
        // 防止攻击者提供自己的公钥来绕过绑定）
        // signatureResult: { checked, valid, signatureValid, commitmentBound, ... }
        const signatureResult = verifyKeystoreSignature(payload, publicSignals[0], {
          publicKeyBase64: activeKey.publicKeyBase64,
          keySource: "registered_user_key",
        });

        // 5. nonce 消费（仅在 proof 和签名都通过后才消费）
        // nonceResult: { checked, valid, consumed, nonce, reason? }
        const nonceResult = verifyNonceForProof(nonceStore, signatureResult, proofResult);

        // finalValid: proof、签名/commitment 绑定和 nonce 都通过时才整体有效。
        const finalValid =
          proofResult.valid &&
          signatureResult.checked &&
          signatureResult.valid &&
          nonceResult.valid;

        // result: 组装后的完整验证结果对象 (M-11: sanitized attempts)
        const result = {
          valid: finalValid,
          proofValid: proofResult.valid,
          publicInputCount: proofResult.publicInputCount ?? null,
          acceptedFormat: sanitizeProofFormat(proofResult.acceptedFormat),
          attempts: sanitizeAttempts(proofResult.attempts),
          user: {
            id: user.id,
            username: user.username,
            keyId: activeKey.id,
            publicKeyFingerprint: activeKey.publicKeyFingerprint,
          },
          signature: signatureResult,
          nonce: nonceResult,
        };

        // responseBody: 根据 ?compact=1 决定返回精简还是完整结果
        const responseBody = wantsMinimalResponse(req) ? compactVerifyResult(result) : result;
        sendJson(res, 200, responseBody);

        interactionLogger.log({
          type: "proof.verify",
          request: requestMeta(req, requestId, pathname),
          requestSummary: summarizeProofRequest(payload),
          responseSummary: summarizeVerifyResponse(result),
          statusCode: 200,
          durationMs: Date.now() - startedAt,
        });
      } catch (error) {
        // M-11: 未知 verifier 异常 → 500，品牌错误保持原 status
        const status = extractErrorInfo(error) !== null ? safeErrorStatus(error) : 500;
        const errorResponse = errorPayload(error, "PROOF_VERIFY_FAILED");
        sendJson(res, status, errorResponse);
        interactionLogger.log({
          type: "proof.verify",
          request: requestMeta(req, requestId, pathname),
          requestSummary: payload ? summarizeProofRequest(payload) : null,
          responseSummary: errorResponse,
          statusCode: status,
          durationMs: Date.now() - startedAt,
        });
      }
      return;
    }

    // 未匹配任何路由
    sendJson(res, 404, {
      error: "Not found",
      routes: [
        "GET /health",
        "GET /nonce",
        "POST /nonce",
        "POST /verify-proof",
        "POST /verify-regex-proof",
        "POST /password/register",
        "GET /password/login-parameters",
        "POST /password/login",
        "POST /auth/register",
        "POST /auth/login",
        "POST /auth/logout",
        "GET /auth/me",
        "GET /keys/active",
        "GET /keys",
        "POST /keys/register-nonce",
        "POST /keys/register",
        "POST /keys/revoke",
        "GET /logs/interactions?limit=50",
        "GET /stats/performance?limit=200",
        "GET /reports/latest?limit=200",
      ],
    });
  });

  // 将模块实例挂到 server 对象上，方便外部访问和测试
  server.locals = {
    authStore,
    interactionLogger,
    nonceStore,
    verificationKey,
    vkPath,
    regexVerificationKey,
    regexVkPath,
    passwordRegistrationStore,
    passwordVerificationKey,
    passwordVkPath,
  };
  return server;
}

// ---- 直接运行时的入口 ----
// 只在 `node server.js` 时启动（被 require 时不做）
if (require.main === module) {
  // port: 监听端口，优先取环境变量 PORT，默认 3000
  const port = Number(process.env.PORT || DEFAULT_PORT);
  // server: 创建的验证服务实例
  const server = createVerifierServer();
  server.listen(port, "0.0.0.0", () => {
    console.log(`ZK Location verifier listening on http://0.0.0.0:${port}`);
    console.log(`Verification key: ${server.locals.vkPath}`);
    console.log(`Regex verification key: ${server.locals.regexVkPath}`);
    console.log(`Password verification key: ${server.locals.passwordVkPath}`);
    console.log(`Password verification key SHA-256: ${fileSha256(server.locals.passwordVkPath)}`);
    console.log(`Password registration DB: ${server.locals.passwordRegistrationStore.filePath}`);
    console.log(`Interaction log: ${server.locals.interactionLogger.filePath}`);
    console.log(`Auth DB: ${server.locals.authStore.filePath}`);
  });
}

// ---- key 注册失败时解析 attestation 链信息用于 debug ----
// 如果 root 不可信，自动保存到 rejected-attestation-roots 目录
function summarizeFailedKeyRegistrationAttestation(body) {
  // certificateChain: 从请求体的多种可能字段名中提取证书链
  const certificateChain =
    body?.certificateChain ??
    body?.certificateChainBase64 ??
    body?.tee?.certificateChain ??
    body?.tee?.certificateChainBase64;
  if (!Array.isArray(certificateChain) || certificateChain.length === 0) {
    return null;
  }

  try {
    // summary: attestation 证书链摘要（不验证 root 是否可信）
    const summary = summarizeAttestationCertificateChain(certificateChain);
    // M-11: 不返回 savedRejectedRootPath（绝对路径），仅返回摘要
    if (!summary.rootTrusted) {
      // 仍保存 rejected root 供本地 operator 调查，但不进入 HTTP 响应
      saveRejectedAttestationRoot(certificateChain);
    }
    return summary;
  } catch (_error) {
    return null;
  }
}

// ---- 判断客户端是否请求精简响应 ----
// 支持两种方式：URL 参数 (?compact=1) 或 HTTP header (Prefer: return=minimal)
function wantsMinimalResponse(req) {
  // url: 解析后的请求 URL 对象，用于提取 query 参数
  const url = new URL(req.url, "http://localhost");
  // compact: URL 参数 ?compact=1 或 ?minimal=1 的值
  const compact = url.searchParams.get("compact") || url.searchParams.get("minimal");
  // prefer: HTTP Prefer header 的值
  const prefer = req.headers.prefer || "";
  return compact === "1" || compact === "true" || /\breturn=minimal\b/i.test(prefer);
}

// ---- 精简验证结果（仅返回关键布尔值和摘要）----
function compactVerifyResult(result) {
  return {
    valid: result.valid,
    proofValid: result.proofValid ?? result.valid,
    signatureValid: result.signature?.signatureValid ?? false,
    commitmentBound: result.signature?.commitmentBound ?? false,
    nonceConsumed: result.nonce?.consumed ?? false,
    acceptedFormat: result.acceptedFormat ?? null,
    publicInputCount: result.publicInputCount ?? null,
    user: result.user
      ? {
          username: result.user.username,
          keyId: result.user.keyId,
          publicKeyFingerprint: result.user.publicKeyFingerprint,
        }
      : null,
    reason:
      result.signature?.reason ||
      result.nonce?.reason ||
      null,
  };
}

// ---- 获取验证密钥文件路径 ----
// 优先使用 server/keys/ 下的密钥，回退到 circuits/ 目录
function defaultVerificationKeyPath() {
  const localKey = path.resolve(__dirname, "../keys/areajudge_verification_key.json");
  if (fs.existsSync(localKey)) {
    return localKey;
  }
  return path.resolve(__dirname, "../../circuits/verification_key.json");
}

function defaultRegexRecordVerificationKeyPath() {
  return path.resolve(__dirname, "../keys/regex_record_verification_key.json");
}

function defaultPasswordVerificationKeyPath() {
  return path.resolve(__dirname, "../keys/password_policy_commitment_verification_key.json");
}

function defaultRegexRecordZkeyPath() {
  return path.resolve(__dirname, "../../circuits/regex_record_final.zkey");
}

function fileSha256(filePath) {
  try {
    return crypto.createHash("sha256").update(fs.readFileSync(filePath)).digest("hex");
  } catch (_error) {
    return null;
  }
}

// ---- 从文件加载 snarkjs 格式的验证密钥 ----
function loadVerificationKey(filePath) {
  const raw = fs.readFileSync(filePath, "utf8");
  return JSON.parse(raw);
}

function validatePasswordRegistrationRequest(body) {
  if (!body || typeof body !== "object" || Array.isArray(body)) {
    throw passwordRegistrationError(400, "INVALID_REQUEST", "Request body must be an object");
  }
  for (const field of [
    "password",
    "confirmPassword",
    "encryptedSalt",
    "witness",
    "dfa",
    "paddedPassword",
    "chunk0",
    "chunk1",
    "circuitInput",
  ]) {
    if (Object.prototype.hasOwnProperty.call(body, field)) {
      throw passwordRegistrationError(
        400,
        "FORBIDDEN_PRIVATE_FIELD",
        `Request must not contain private field: ${field}`
      );
    }
  }

  validatePasswordUserId(body.userId);
  validatePasswordSalt(body.salt);
  validateCanonicalFieldElement(body.passwordCommitment, "passwordCommitment");
  if (!Array.isArray(body.publicSignals) || body.publicSignals.length !== 1) {
    throw passwordRegistrationError(
      400,
      "INVALID_PUBLIC_SIGNALS",
      "publicSignals must contain exactly one element"
    );
  }
  validateCanonicalFieldElement(body.publicSignals[0], "publicSignals[0]");
  if (body.publicSignals[0] !== body.passwordCommitment) {
    throw passwordRegistrationError(
      400,
      "COMMITMENT_MISMATCH",
      "publicSignals[0] must equal passwordCommitment"
    );
  }
  if (!body.proof || typeof body.proof !== "object" || Array.isArray(body.proof)) {
    throw passwordRegistrationError(400, "MISSING_PROOF", "proof object is required");
  }
  validatePasswordProofCoordinates(body.proof);

  return {
    userId: body.userId,
    salt: body.salt,
    passwordCommitment: body.passwordCommitment,
    publicSignals: [...body.publicSignals],
    proof: body.proof,
  };
}

function validatePasswordLoginRequest(body) {
  if (!body || typeof body !== "object" || Array.isArray(body)) {
    throw passwordRegistrationError(400, "INVALID_REQUEST", "Request body must be an object");
  }
  for (const field of [
    "password",
    "confirmPassword",
    "salt",
    "encryptedSalt",
    "proof",
    "publicSignals",
    "witness",
    "dfa",
    "paddedPassword",
    "chunk0",
    "chunk1",
    "circuitInput",
  ]) {
    if (Object.prototype.hasOwnProperty.call(body, field)) {
      throw passwordRegistrationError(
        400,
        "FORBIDDEN_PRIVATE_FIELD",
        `Request must not contain login field: ${field}`
      );
    }
  }
  validatePasswordUserId(body.userId);
  validateCanonicalFieldElement(body.passwordCommitment, "passwordCommitment");
  return {
    userId: body.userId,
    passwordCommitment: body.passwordCommitment,
  };
}

function validatePasswordUserId(userId) {
  if (typeof userId !== "string" || !/^[A-Za-z0-9_.@:-]{3,128}$/.test(userId)) {
    throw passwordRegistrationError(
      400,
      "INVALID_USER_ID",
      "userId must be 3-128 characters: letters, numbers, _, ., @, :, or -"
    );
  }
  return userId;
}

function validatePasswordSalt(salt) {
  validateCanonicalFieldElement(salt, "salt");
  if (salt === "0") {
    throw passwordRegistrationError(400, "INVALID_SALT", "salt must be non-zero");
  }
  return salt;
}

function constantTimeCommitmentEqual(left, right) {
  const leftDigest = crypto.createHash("sha256").update(left).digest();
  const rightDigest = crypto.createHash("sha256").update(right).digest();
  return crypto.timingSafeEqual(leftDigest, rightDigest);
}

function validatePasswordProofCoordinates(proof) {
  if (Array.isArray(proof.pi_a) && Array.isArray(proof.pi_b) && Array.isArray(proof.pi_c)) {
    validateProofG1Array(proof.pi_a, "proof.pi_a");
    validateProofG2Array(proof.pi_b, "proof.pi_b");
    validateProofG1Array(proof.pi_c, "proof.pi_c");
    return;
  }
  if (!proof.a || !proof.b || !proof.c) {
    throw passwordRegistrationError(
      400,
      "INVALID_PROOF_FORMAT",
      "proof must use snarkjs pi_a/pi_b/pi_c or mopro a/b/c coordinates"
    );
  }
  validateProofG1Object(proof.a, "proof.a");
  validateProofG2Object(proof.b, "proof.b");
  validateProofG1Object(proof.c, "proof.c");
}

function validateProofG1Array(point, label) {
  if (!Array.isArray(point) || point.length !== 3) {
    throw passwordRegistrationError(400, "INVALID_PROOF_FORMAT", `${label} must have 3 coordinates`);
  }
  point.forEach((value, index) => validateProofCoordinate(value, `${label}[${index}]`));
}

function validateProofG2Array(point, label) {
  if (!Array.isArray(point) || point.length !== 3) {
    throw passwordRegistrationError(400, "INVALID_PROOF_FORMAT", `${label} must have 3 pairs`);
  }
  point.forEach((pair, index) => validateProofPair(pair, `${label}[${index}]`));
}

function validateProofG1Object(point, label) {
  if (!point || typeof point !== "object") {
    throw passwordRegistrationError(400, "INVALID_PROOF_FORMAT", `${label} must be an object`);
  }
  for (const coordinate of ["x", "y", "z"]) {
    validateProofCoordinate(point[coordinate], `${label}.${coordinate}`);
  }
}

function validateProofG2Object(point, label) {
  if (!point || typeof point !== "object") {
    throw passwordRegistrationError(400, "INVALID_PROOF_FORMAT", `${label} must be an object`);
  }
  for (const coordinate of ["x", "y", "z"]) {
    validateProofPair(point[coordinate], `${label}.${coordinate}`);
  }
}

function validateProofPair(pair, label) {
  if (!Array.isArray(pair) || pair.length !== 2) {
    throw passwordRegistrationError(400, "INVALID_PROOF_FORMAT", `${label} must have 2 elements`);
  }
  pair.forEach((value, index) => validateProofCoordinate(value, `${label}[${index}]`));
}

function validateProofCoordinate(value, label) {
  if (typeof value !== "string" || !/^(0|[1-9][0-9]*)$/.test(value)) {
    throw passwordRegistrationError(
      400,
      "INVALID_PROOF_COORDINATE",
      `${label} must be a canonical decimal string`
    );
  }
  if (BigInt(value) >= BN254_BASE_MODULUS) {
    throw passwordRegistrationError(
      400,
      "INVALID_PROOF_COORDINATE",
      `${label} must be smaller than the BN254 base field modulus`
    );
  }
}

function validateCanonicalFieldElement(value, label) {
  if (typeof value !== "string" || !/^(0|[1-9][0-9]*)$/.test(value)) {
    throw passwordRegistrationError(
      400,
      "INVALID_FIELD_ELEMENT",
      `${label} must be a canonical decimal string`
    );
  }
  if (BigInt(value) >= BN254_SCALAR_MODULUS) {
    throw passwordRegistrationError(
      400,
      "INVALID_FIELD_ELEMENT",
      `${label} must be smaller than the BN254 scalar field modulus`
    );
  }
}

function passwordRegistrationError(statusCode, code, message) {
  return new PublicError(code, message);
}

function passwordRegistrationRequestSummary(request) {
  return {
    userId: request.userId,
    commitmentDigest: commitmentDigest(request.passwordCommitment),
    publicInputCount: request.publicSignals.length,
    proofSizeBytes: Buffer.byteLength(JSON.stringify(request.proof)),
  };
}

function commitmentDigest(commitment) {
  return crypto.createHash("sha256").update(commitment).digest("hex").slice(0, 16);
}

function elapsedMonotonicMs(started) {
  return Number(process.hrtime.bigint() - started) / 1_000_000;
}

// ---- nonce 消费策略 ----
// 仅在 proof、设备签名和 commitment 绑定都通过后才消费 nonce。
// 即使攻击者反复发送无效请求也不会消耗有效 nonce。
function verifyNonceForProof(nonceStore, signatureResult, proofResult) {
  // 缺少设备签名字段 → nonce 无效且不消费
  if (!signatureResult.checked) {
    return {
      checked: false,
      valid: false,
      consumed: false,
      reason: "No Keystore signature supplied",
    };
  }

  // 签名无效 → 不消耗 nonce，攻击者可重试
  if (!signatureResult.valid) {
    return {
      checked: true,
      valid: false,
      consumed: false,
      reason: "Signature invalid; nonce not consumed",
    };
  }

  // proof 无效 → 不消耗 nonce
  if (!proofResult.valid) {
    return {
      checked: true,
      valid: false,
      consumed: false,
      reason: "Proof invalid; nonce not consumed",
    };
  }

  // 签名和 proof 都通过 → 消费 nonce（签名原文中的 server_nonce 字段）
  return nonceStore.consume(signatureResult.serverNonce);
}

module.exports = {
  createVerifierServer,
  defaultPasswordVerificationKeyPath,
  validatePasswordLoginRequest,
  validatePasswordRegistrationRequest,
  verifyNonceForProof,
};

// =============================================================================
// 辅助函数
// =============================================================================

// ---- 安全映射 proof attempts (M-11) ----
// Total function: 对任意 JS value 不抛出。不读 raw.length。
// Format allowlist, max 5 slots, 不解锁 raw error/message
// ---- 内部→公开 format 精确映射 (M-11) ----
// 只接受生产代码中明确存在的固定字符串。无宽范匹配。
const INTERNAL_TO_PUBLIC_FORMAT = Object.freeze({
  // proof-format.js
  snarkjs: "snarkjs",
  mopro: "mopro",
  mopro_g2_pair_swapped: "mopro",
  mopro_g2_pair_swapped_with_z: "mopro",
  mopro_g2_xy_swapped: "mopro",
  mopro_g2_xy_pair_swapped: "mopro",
  mopro_g2_xy_pair_swapped_with_z: "mopro",
  // arkworks-regex-verifier.js
  arkworks_mopro: "arkworks",
});
const MAX_PUBLIC_ATTEMPTS = 5;
const MAX_PUBLIC_FORMAT_LEN = 32;

function sanitizeProofFormat(value) {
  try {
    if (typeof value !== "string") return "unknown";
    if (value.length > MAX_PUBLIC_FORMAT_LEN) return "unknown";
    if (Object.prototype.hasOwnProperty.call(INTERNAL_TO_PUBLIC_FORMAT, value)) {
      return INTERNAL_TO_PUBLIC_FORMAT[value];
    }
    return "unknown";
  } catch (_) {}
  return "unknown";
}

function sanitizeAttempts(raw) {
  try {
    const result = [];
    for (let i = 0; i < MAX_PUBLIC_ATTEMPTS; i++) {
      try {
        const a = raw[i];
        if (!a || (typeof a !== "object" && typeof a !== "function")) continue;
        const format = sanitizeProofFormat(a.format);
        let valid = false;
        try { valid = a.valid === true; } catch (_) {}
        result.push({ format, valid, error: valid ? undefined : "Verification failed" });
      } catch (_) { /* skip individual attempt */ }
    }
    return result;
  } catch (_) {
    return [];
  }
}

// ---- 从 URL 中提取 pathname ----
function requestPathname(req) {
  return new URL(req.url, "http://localhost").pathname;
}

// ---- 构造 auth 路由的成功响应体 ----
// 注意：登录/注册响应不返回 activeKey 的完整 attestation 信息
function authResponse(result) {
  return {
    user: authUserWithoutActiveKey(result.user),
    token: result.session.token,
    tokenType: "Bearer",
    expiresAt: result.session.expiresAt,
    expiresInMs: result.session.expiresInMs,
  };
}

// ---- 从 user 对象中去掉 activeKey 字段 ----
function authUserWithoutActiveKey(user) {
  if (!user || typeof user !== "object") {
    return user;
  }
  // 解构去掉 activeKey 字段，其余字段保留
  const { activeKey, ...withoutActiveKey } = user;
  return withoutActiveKey;
}

// ---- 流式读取 HTTP 请求的 JSON body ----
// 限制最大 1MB，返回 Promise<object>
function readJsonBody(req) {
  return new Promise((resolve, reject) => {
    // size: 已读取的 body 字节总数，用于限制检查
    let size = 0;
    // chunks: 分块接收的 Buffer 数组，最后拼接
    const chunks = [];

    req.on("data", (chunk) => {
      size += chunk.length;
      // 超过限制立即断开连接，防止内存耗尽攻击
      if (size > MAX_BODY_BYTES) {
        reject(new AuthError("BAD_REQUEST", "Request body too large"));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });

    req.on("end", () => {
      try {
        // raw: 拼接后的完整 UTF-8 字符串
        const raw = Buffer.concat(chunks).toString("utf8");
        resolve(raw.length === 0 ? {} : JSON.parse(raw));
      } catch (_parseErr) {
        reject(new AuthError("INVALID_REQUEST", "Invalid JSON body"));
      }
    });

    req.on("error", reject);
  });
}

// ---- 设置 CORS 响应头 ----
function setCorsHeaders(res) {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET,POST,OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization, Prefer");
}

// ---- 发送 JSON 响应 ----
function sendJson(res, status, payload) {
  res.writeHead(status, { "Content-Type": "application/json; charset=utf-8" });
  res.end(JSON.stringify(payload, null, 2));
}

// ---- 发送 API 错误响应 (M-11) ----
// 安全处理任意 JavaScript throwable：null、undefined、字符串、Proxy、异常 getter 等
// 只有已知业务错误（AuthError、passwordRegistrationError 等）才返回公开消息
// ---- 发送 API 错误响应 (M-11) ----
function sendApiError(res, error, code, detail = null) {
  const status = safeErrorStatus(error);
  sendJson(res, status, { valid: false, code, error: safeErrorMessage(error), detail });
}

function errorPayload(error, code, detail = null) {
  return { valid: false, code, error: safeErrorMessage(error), detail };
}
