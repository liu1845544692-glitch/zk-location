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
//   6. POST /verify-proof           - 发送 ZK proof + Keystore 签名
//
// /verify-proof 的验证链路：
//   session token → active key → proof 验证 → 签名验证 → nonce 消费

const fs = require("node:fs");
const http = require("node:http");
const path = require("node:path");
const { normalizePublicSignals, verifyPayload } = require("./proof-format");
const { verifyKeystoreSignature } = require("./keystore-signature");
const {
  saveRejectedAttestationRoot,
  summarizeAttestationCertificateChain,
} = require("./key-attestation");
const { DEFAULT_TTL_MS, NonceStore } = require("./nonce-store");
const { AuthError, JsonAuthStore, publicUser } = require("./auth-store");
const {
  createInteractionLogger,
  requestMeta,
  summarizeKeyRegistration,
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

// ---- 创建并配置验证服务 ----
// 返回 http.Server 实例，所有依赖可注入（方便测试）
function createVerifierServer(options = {}) {
  // vkPath: Groth16 验证密钥文件路径
  const vkPath = options.vkPath || process.env.VK_PATH || defaultVerificationKeyPath();
  // verificationKey: 已加载的 snarkjs 格式验证密钥对象
  const verificationKey = options.verificationKey || loadVerificationKey(vkPath);
  // verifyProofPayload: proof 验证函数（可注入，默认用 proof-format.js 的 verifyPayload）
  const verifyProofPayload = options.verifyPayload || verifyPayload;

  // nonceStore: nonce 防重放存储实例（基于内存 Map）
  const nonceStore = options.nonceStore || new NonceStore({
    ttlMs: Number(options.nonceTtlMs ?? process.env.NONCE_TTL_MS ?? DEFAULT_TTL_MS),
  });

  // authStore: 用户认证与密钥存储实例（基于 JSON 文件）
  const authStore = options.authStore || new JsonAuthStore();

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

    // ---- GET /health - 健康检查 ----
    if (req.method === "GET" && pathname === "/health") {
      sendJson(res, 200, {
        ok: true,
        circuit: "areajudge",
        verifier: "groth16/snarkjs",
        verificationKey: vkPath,
        nonceTtlMs: nonceStore.ttlMs,
        pendingNonces: nonceStore.size(),
        interactionLog: interactionLogger.filePath,
        authDb: authStore.filePath,
      });
      return;
    }

    // ---- GET /logs/interactions - 查看交互日志 ----
    if (req.method === "GET" && pathname === "/logs/interactions") {
      const limit = Number(new URL(req.url, "http://localhost").searchParams.get("limit") || 50);
      sendJson(res, 200, {
        logPath: interactionLogger.filePath,
        entries: interactionLogger.recent(limit),
      });
      return;
    }

    // ---- GET /stats/performance - 性能统计 ----
    if (req.method === "GET" && pathname === "/stats/performance") {
      const limit = Number(new URL(req.url, "http://localhost").searchParams.get("limit") || 200);
      sendJson(res, 200, buildPerformanceStats(interactionLogger.recent(limit)));
      return;
    }

    // ---- GET /reports/latest - 实验报告导出 ----
    // 支持 ?format=md 导出 Markdown
    if (req.method === "GET" && pathname === "/reports/latest") {
      const url = new URL(req.url, "http://localhost");
      const limit = Number(url.searchParams.get("limit") || 200);
      const report = buildExperimentReport(interactionLogger.recent(limit), { limit });
      if (url.searchParams.get("format") === "md") {
        res.writeHead(200, { "Content-Type": "text/markdown; charset=utf-8" });
        res.end(reportToMarkdown(report));
      } else {
        sendJson(res, 200, report);
      }
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
          responseSummary: summarizeKeyRegistration(user, authStore.activeKeyForUser(user.id)),
          statusCode: 201,
          durationMs: Date.now() - startedAt,
        });
      } catch (error) {
        const attestationDebug = summarizeFailedKeyRegistrationAttestation(body);
        const statusCode = error instanceof AuthError ? error.statusCode : error.statusCode || 500;
        sendJson(res, statusCode, errorPayload(error, "KEY_REGISTER_FAILED", {
          attestation: attestationDebug,
        }));
        interactionLogger.log({
          type: "key.register",
          request: requestMeta(req, requestId, pathname),
          responseSummary: {
            valid: false,
            error: error.message || String(error),
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
      const response = {
        ...issued,
      };
      sendJson(res, 200, response);
      interactionLogger.log({
        type: "nonce.issue",
        request: requestMeta(req, requestId, pathname),
        response,
        statusCode: 200,
        durationMs: Date.now() - startedAt,
      });
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
    //   - 如果没有签名字段 → valid 只取决于 proof 验证结果
    //   - 如果有签名字段 → valid = proof AND signature AND nonce 三者都通过
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
          throw new AuthError(403, "Current user has no registered active public key");
        }

        // payload: 客户端上传的完整 JSON 请求体
        payload = await readJsonBody(req);

        // 3. Groth16 proof 验证
        // proofResult: snarkjs proof 验证结果 { valid, publicInputCount, acceptedFormat, attempts }
        const proofResult = await verifyProofPayload(verificationKey, payload);

        // publicSignals: ZK 电路 37 个公开输入数组
        // publicSignals[0] 是 public_commitment
        // 作为 ZK proof 和 TEE 签名之间的绑定点
        const publicSignals = normalizePublicSignals(payload);

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

        // result: 组装后的完整验证结果对象
        const result = {
          ...proofResult,
          // proofValid: proof 本身是否有效（独立于签名/nonce）
          proofValid: proofResult.valid,
          user: {
            id: user.id,
            username: user.username,
            keyId: activeKey.id,
            publicKeyFingerprint: activeKey.publicKeyFingerprint,
          },
          signature: signatureResult,
          nonce: nonceResult,
          // clientMetrics: 客户端上报的性能指标（如 proof 生成耗时）
          clientMetrics: payload.metrics || payload.clientMetrics || null,
          // valid 整体判定：有签名字段时三者都必须通过，无签名字段时只关心 proof
          valid: signatureResult.checked
            ? proofResult.valid && signatureResult.valid && nonceResult.valid
            : proofResult.valid,
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
        // status: HTTP 状态码，认证错误取其 statusCode，其他默认为 400
        const status = error instanceof AuthError ? error.statusCode : 400;
        // errorResponse: 统一错误响应体 { valid, code, error, detail }
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
    if (!summary.rootTrusted) {
      return {
        ...summary,
        // savedRejectedRootPath: 未被信任的 root 证书保存路径
        savedRejectedRootPath: saveRejectedAttestationRoot(certificateChain),
      };
    }
    return summary;
  } catch (error) {
    return {
      error: error.message || String(error),
    };
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
    clientMetrics: result.clientMetrics || null,
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

// ---- 从文件加载 snarkjs 格式的验证密钥 ----
function loadVerificationKey(filePath) {
  const raw = fs.readFileSync(filePath, "utf8");
  return JSON.parse(raw);
}

// ---- nonce 消费策略 ----
// 仅在 proof 和签名都通过后才消费 nonce
// 即使攻击者反复发送无效请求也不会消耗有效 nonce
function verifyNonceForProof(nonceStore, signatureResult, proofResult) {
  // 没有签名字段 → 跳过 nonce 检查
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
  verifyNonceForProof,
};

// =============================================================================
// 辅助函数
// =============================================================================

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
        reject(new Error("Request body too large"));
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
      } catch (error) {
        reject(new Error(`Invalid JSON: ${error.message || error}`));
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

// ---- 发送 API 错误响应 ----
// AuthError 保留其 statusCode，其他错误默认 500
function sendApiError(res, error, code, detail = null) {
  const status = error instanceof AuthError ? error.statusCode : error.statusCode || 500;
  sendJson(res, status, errorPayload(error, code, detail));
}

// ---- 构造统一错误响应体 ----
function errorPayload(error, code, detail = null) {
  return {
    valid: false,
    code,
    error: error.message || String(error),
    detail,
  };
}
