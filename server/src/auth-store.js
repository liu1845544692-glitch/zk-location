"use strict";

// =============================================================================
// auth-store.js —— 用户认证与密钥存储
// =============================================================================
// 管理用户注册/登录、session token 鉴权、Android Keystore 密钥绑定。
// 当前使用 JSON 文件存储（适合实验阶段），后续可换 SQLite。

// 引入 Node.js 内置的加密模块。这里用来做 SHA-256 哈希、随机数生成（randomBytes）、以及 scrypt 密码哈希。
const crypto = require("node:crypto");
//  引入 Node.js 内置的文件系统模块。这里用来读写 auth-store.json（用户认证数据的持久化文件）
const fs = require("node:fs");
const path = require("node:path");
const { verifyAndroidKeyAttestation } = require("./key-attestation");

// 默认 auth 数据库文件路径
const DEFAULT_AUTH_DB_PATH = path.resolve(__dirname, "../data/auth.json");
// session 默认有效期：7 天
const DEFAULT_SESSION_TTL_MS = 7 * 24 * 60 * 60 * 1000;
// key registration nonce 默认有效期：5 分钟
const DEFAULT_KEY_NONCE_TTL_MS = 5 * 60 * 1000;

// ---- 认证专用错误类型，携带 HTTP 状态码 ----
class AuthError extends Error {
  constructor(statusCode, message) {
    super(message);
    this.statusCode = statusCode;
  }
}

// ---- JSON 文件认证存储 ----
class JsonAuthStore {
  // 构造函数：加载或初始化数据库文件
  constructor(options = {}) {
    // filePath: auth 数据库 JSON 文件完整路径
    this.filePath = options.filePath || process.env.AUTH_DB_PATH || DEFAULT_AUTH_DB_PATH;
    // sessionTtlMs: session token 有效期（毫秒），默认 7 天
    this.sessionTtlMs = Number(options.sessionTtlMs ?? process.env.SESSION_TTL_MS ?? DEFAULT_SESSION_TTL_MS);
    // keyNonceTtlMs: key registration nonce 有效期（毫秒），默认 5 分钟
    this.keyNonceTtlMs = Number(
      options.keyNonceTtlMs ?? process.env.KEY_REGISTER_NONCE_TTL_MS ?? DEFAULT_KEY_NONCE_TTL_MS
    );
    // requireKeyAttestation: 是否强制验证 Android Keystore Key Attestation（默认需要）
    this.requireKeyAttestation =
      options.requireKeyAttestation ?? process.env.REQUIRE_KEY_ATTESTATION !== "false";
    // attestationTrustRootsPath: attestation root 证书文件路径
    this.attestationTrustRootsPath = options.attestationTrustRootsPath;
    // now: 当前时间函数，测试时可注入假时钟来控制时间
    this.now = options.now || (() => Date.now());
    // randomBytes: 随机数生成函数，测试时可注入确定性随机
    this.randomBytes = options.randomBytes || ((size) => crypto.randomBytes(size));
    fs.mkdirSync(path.dirname(this.filePath), { recursive: true });
    // db: 内存中的数据库对象 { users[], sessions[], keyRegistrationNonces[] }
    this.db = this.load();
  }

  // ---- 注册新用户 ----
  // 校验用户名密码 → 生成 salt → scrypt 哈希 → 存储 → 签发 session
  registerUser(username, password) {
    // normalizedUsername: 规范化后的用户名（去空格、转小写、验证格式）
    const normalizedUsername = normalizeUsername(username);
    validatePassword(password);
    this.pruneExpired();

    if (this.db.users.some((user) => user.username === normalizedUsername)) {
      throw new AuthError(409, "Username already exists");
    }

    // salt: 16 字节随机盐值（base64url 编码），用于 scrypt 密码哈希
    const salt = this.randomBytes(16).toString("base64url");
    // user: 新用户记录对象
    const user = {
      // id: 用户唯一标识，以 "usr_" 前缀开头
      id: `usr_${this.randomBytes(12).toString("base64url")}`,
      username: normalizedUsername,
      authMethod: "legacy_password",
      // passwordSalt: 此用户专用的密码盐值
      passwordSalt: salt,
      // passwordHash: scrypt 哈希后的密码（base64url 编码的 32 字节）
      passwordHash: hashPassword(password, salt),
      createdAt: new Date(this.now()).toISOString(),
      // keys: 该用户已注册的 Android Keystore 公钥列表
      keys: [],
      // activeKeyId: 当前活跃 key 的 id（用于 /verify-proof 的签名验证）
      activeKeyId: null,
    };

    this.db.users.push(user);
    // session: 注册成功后自动签发的 session { token, expiresAt, expiresInMs }
    const session = this.issueSessionForUser(user.id);
    this.save();

    return {
      user: publicUser(user),
      session,
    };
  }

  // ---- 用户登录 ----
  // 校验用户名密码 → 清空旧 active key → 签发新 session
  // 注意：登录会清空旧 active key，这是有意设计——新 session 必须重新 attest
  loginUser(username, password) {
    // normalizedUsername: 规范化后的用户名
    const normalizedUsername = normalizeUsername(username);
    this.pruneExpired();

    // user: 在数据库中按用户名查找的用户记录
    const user = this.db.users.find((candidate) => candidate.username === normalizedUsername);
    if (
      !user ||
      user.authMethod === "password_commitment" ||
      typeof user.passwordSalt !== "string" ||
      typeof user.passwordHash !== "string" ||
      user.passwordHash !== hashPassword(password, user.passwordSalt)
    ) {
      throw new AuthError(401, "Invalid username or password");
    }

    // 登录时清空旧 active key，强制新 session 必须重新 attest key
    this.clearActiveKeyForNewLogin(user);
    // session: 登录成功后签发的新 session
    const session = this.issueSessionForUser(user.id);
    this.save();

    return {
      user: publicUser(user),
      session,
    };
  }

  // Create an auth identity backed by the separately verified password commitment.
  // No plaintext password, password salt, or password hash is stored here.
  registerPasswordUser(userId) {
    const username = normalizePasswordUserId(userId);
    this.pruneExpired();
    if (this.db.users.some((user) => user.username === username)) {
      throw new AuthError(409, "Username already exists");
    }
    const user = this.createPasswordUser(username);
    this.db.users.push(user);
    this.save();
    return publicUser(user);
  }

  // A commitment is verified by /password/login before this method is called.
  // createIfMissing supports password registrations created before auth unification.
  loginPasswordUser(userId, { createIfMissing = false } = {}) {
    const username = normalizePasswordUserId(userId);
    this.pruneExpired();
    let user = this.db.users.find((candidate) => candidate.username === username);
    if (!user && createIfMissing) {
      user = this.createPasswordUser(username);
      this.db.users.push(user);
    }
    if (!user || user.authMethod !== "password_commitment") {
      throw new AuthError(401, "Invalid username or password");
    }
    this.clearActiveKeyForNewLogin(user);
    const session = this.issueSessionForUser(user.id);
    this.save();
    return { user: publicUser(user), session };
  }

  removePasswordUser(userId) {
    const username = normalizePasswordUserId(userId);
    const user = this.db.users.find((candidate) => candidate.username === username);
    if (!user || user.authMethod !== "password_commitment") return false;
    this.db.users = this.db.users.filter((candidate) => candidate.id !== user.id);
    this.db.sessions = this.db.sessions.filter((session) => session.userId !== user.id);
    this.save();
    return true;
  }

  createPasswordUser(username) {
    return {
      id: `usr_${this.randomBytes(12).toString("base64url")}`,
      username,
      authMethod: "password_commitment",
      createdAt: new Date(this.now()).toISOString(),
      keys: [],
      activeKeyId: null,
    };
  }

  // ---- 从 HTTP Authorization 头中提取并验证 Bearer token ----
  authenticateAuthorizationHeader(header) {
    const token = parseBearerToken(header);
    if (!token) {
      throw new AuthError(401, "Missing Authorization bearer token");
    }
    return this.authenticateToken(token);
  }

  // ---- 验证 session token ----
  // 通过 token 的 SHA-256 hash 查找 session，返回对应的 user 对象
  // 如果 token 不存在或过期，抛出 401
  authenticateToken(token) {
    this.pruneExpired();

    // tokenHash: 明文 token 的 SHA-256 哈希值，用于在 session 表中查找
    const tokenHash = hashToken(token);
    // session: 数据库中匹配 tokenHash 的 session 记录
    const session = this.db.sessions.find((candidate) => candidate.tokenHash === tokenHash);
    if (!session) {
      throw new AuthError(401, "Invalid or expired session token");
    }

    // user: session 所属的用户记录
    const user = this.db.users.find((candidate) => candidate.id === session.userId);
    if (!user) {
      throw new AuthError(401, "Session user no longer exists");
    }

    return {
      user,
      session,
    };
  }

  // ---- 签发 key registration nonce ----
  // 用于 Key Attestation 的 challenge 字段，防止 attestation 重放
  issueKeyRegistrationNonce(userId) {
    this.pruneExpired();
    this.requireUser(userId);

    // nonce: 32 字节随机数（base64url 编码），用作 Key Attestation 的 challenge
    const nonce = this.randomBytes(32).toString("base64url");
    // issuedAt: nonce 签发时的 Unix 毫秒时间戳
    const issuedAt = this.now();
    // expiresAt: nonce 过期时间戳
    const expiresAt = issuedAt + this.keyNonceTtlMs;
    this.db.keyRegistrationNonces.push({
      nonce,
      userId,
      issuedAt,
      expiresAt,
    });
    this.save();

    return {
      nonce,
      expiresAt,
      expiresInMs: this.keyNonceTtlMs,
    };
  }

  // ---- 注册用户密钥（核心函数）----
  // 这是整个系统中安全要求最高的操作之一：
  //   1. 验证 nonce（防重放）
  //   2. 验证公钥格式（必须是 EC P-256 SPKI DER）
  //   3. 执行 Key Attestation 验证（证书链、root trust、challenge、安全级别）
  //   4. 检查授权列表（必须包含 SIGN, SHA-256, EC, P-256）
  //   5. 拒绝 Software 安全级别的密钥
  //   6. 将之前所有 key 标记为 inactive
  //   7. 保存新 key 为 active
  registerUserKey(userId, input) {
    this.pruneExpired();

    // user: 从数据库查找的用户记录
    const user = this.requireUser(userId);
    // nonce: key registration nonce，兼容多种字段命名惯例
    const nonce = pickString(input?.nonce, input?.registerNonce, input?.registrationNonce);
    // publicKeyBase64: 客户端公钥（SPKI DER, Base64 编码），兼容多种字段命名
    const publicKeyBase64 = pickString(
      input?.publicKey,
      input?.publicKeyBase64,
      input?.tee?.publicKey,
      input?.tee?.publicKeyBase64
    );
    // certificateChain: attestation 证书链，兼容 tee 子对象和顶层字段
    const certificateChain =
      input?.certificateChain ??
      input?.certificateChainBase64 ??
      input?.tee?.certificateChain ??
      input?.tee?.certificateChainBase64 ??
      [];

    // publicKeyInfo: 公钥格式验证结果 { asymmetricKeyType, namedCurve, fingerprint }
    const publicKeyInfo = validateEcPublicKey(publicKeyBase64);
    if (!Array.isArray(certificateChain)) {
      throw new AuthError(400, "certificateChain must be an array when supplied");
    }

    // attestation: Key Attestation 验证结果，包含安全级别、授权列表、root 信任状态等
    // 如果禁用 attestation 验证则返回一个 skipped 标记的结果
    const attestation = this.requireKeyAttestation
      ? verifyAndroidKeyAttestation({
          publicKeyBase64,
          certificateChainBase64: certificateChain,
          expectedChallenge: nonce,
          trustRootsPath: this.attestationTrustRootsPath,
        })
      : {
          verified: false,
          challengeMatched: false,
          skipped: true,
          reason: "REQUIRE_KEY_ATTESTATION=false",
        };

    // 必须满足以下全部条件才认为 key 可信：
    // - root 在 trust store 中
    // - keyMintSecurityLevel 为 TrustedEnvironment 或 StrongBox（拒绝 Software）
    // - 授权列表包含 SIGN 用途
    // - 授权列表包含 SHA-256 摘要
    // - 算法为 EC
    // - 曲线为 P-256
    if (
      this.requireKeyAttestation &&
      (!attestation.rootTrusted ||
        !["TrustedEnvironment", "StrongBox"].includes(attestation.keyMintSecurityLevel) ||
        !attestation.authorization?.purposeSign ||
        !attestation.authorization?.digestSha256 ||
        !attestation.authorization?.algorithmEc ||
        !attestation.authorization?.ecCurveP256)
    ) {
      throw new AuthError(
        400,
        `Reject untrusted or incompatible key: rootTrusted=${attestation.rootTrusted}, keyMintSecurityLevel=${attestation.keyMintSecurityLevel}, purposeSign=${attestation.authorization?.purposeSign}, digestSha256=${attestation.authorization?.digestSha256}, algorithmEc=${attestation.authorization?.algorithmEc}, ecCurveP256=${attestation.authorization?.ecCurveP256}`
      );
    }

    // 消费 key registration nonce（防重放，成功后 nonce 被删除）
    this.consumeKeyRegistrationNonce(userId, nonce);

    // 将用户之前所有 key 标记为 inactive（一个用户同时只有一个 active key）
    for (const key of user.keys) {
      key.active = false;
      // revokedAt: 撤销时间，如已记录则保留原值
      key.revokedAt = key.revokedAt || new Date(this.now()).toISOString();
    }

    // key: 新创建的 key 记录对象
    const key = {
      // id: key 唯一标识，以 "key_" 前缀开头
      id: `key_${this.randomBytes(12).toString("base64url")}`,
      userId,
      publicKeyBase64,
      // publicKeyFingerprint: 公钥的 SHA-256 指纹，用于日志中的短标识
      publicKeyFingerprint: publicKeyInfo.fingerprint,
      // asymmetricKeyType: 非对称密钥类型，应为 "ec"
      asymmetricKeyType: publicKeyInfo.asymmetricKeyType,
      // namedCurve: 椭圆曲线名称，应为 "prime256v1"
      namedCurve: publicKeyInfo.namedCurve,
      // certificateChainBase64: 证书链的副本（确保全部转为字符串）
      certificateChainBase64: certificateChain.map((value) => value.toString()),
      // certificateChainCount: 证书链中的证书数量
      certificateChainCount: certificateChain.length,
      attestation,
      active: true,
      createdAt: new Date(this.now()).toISOString(),
      // revokedAt: 撤销时间，新 key 为 null
      revokedAt: null,
    };

    user.keys.push(key);
    user.activeKeyId = key.id;
    this.save();

    return publicKeyRecord(key);
  }

  // ---- 获取用户当前 active key ----
  activeKeyForUser(userId) {
    const user = this.requireUser(userId);
    // key: 在用户 key 列表中按 activeKeyId 且 active=true 查找的当前活跃 key
    const key = user.keys.find((candidate) => candidate.id === user.activeKeyId && candidate.active);
    if (!key) {
      return null;
    }
    return key;
  }

  // ---- 获取用户所有 key 记录 ----
  keyRecordsForUser(userId) {
    const user = this.requireUser(userId);
    return user.keys.map(publicKeyRecord);
  }

  // ---- 撤销 key ----
  revokeUserKey(userId, keyId) {
    const user = this.requireUser(userId);
    const key = user.keys.find((candidate) => candidate.id === keyId);
    if (!key) {
      throw new AuthError(404, "Key not found");
    }
    key.active = false;
    key.revokedAt = key.revokedAt || new Date(this.now()).toISOString();
    if (user.activeKeyId === key.id) {
      user.activeKeyId = null;
    }
    this.save();
    return publicKeyRecord(key);
  }

  // ---- 登录时清空旧 active key ----
  // 强制用户每次新登录都必须重新执行 Generate new key and bind
  clearActiveKeyForNewLogin(user) {
    if (!user.activeKeyId) {
      return;
    }
    for (const key of user.keys) {
      if (key.active || key.id === user.activeKeyId) {
        key.active = false;
        key.revokedAt = key.revokedAt || new Date(this.now()).toISOString();
      }
    }
    user.activeKeyId = null;
  }

  // ---- 登出（按 token）----
  logoutToken(token) {
    if (!token) {
      throw new AuthError(401, "Missing Authorization bearer token");
    }
    this.pruneExpired();
    // tokenHash: 明文 token 的 SHA-256 哈希值
    const tokenHash = hashToken(token);
    // before: 过滤前的 session 数量，用于判断是否实际删除了某个 session
    const before = this.db.sessions.length;
    // 过滤掉匹配 tokenHash 的 session
    this.db.sessions = this.db.sessions.filter((candidate) => candidate.tokenHash !== tokenHash);
    if (before === this.db.sessions.length) {
      throw new AuthError(401, "Invalid or expired session token");
    }
    this.save();
    return { revoked: true };
  }

  // ---- 登出（按 Authorization header）----
  logoutAuthorizationHeader(header) {
    return this.logoutToken(parseBearerToken(header));
  }

  // ---- 从 JSON 文件加载数据库 ----
  load() {
    if (!fs.existsSync(this.filePath)) {
      return emptyDb();
    }

    const parsed = JSON.parse(fs.readFileSync(this.filePath, "utf8"));
    return {
      users: Array.isArray(parsed.users) ? parsed.users : [],
      sessions: Array.isArray(parsed.sessions) ? parsed.sessions : [],
      keyRegistrationNonces: Array.isArray(parsed.keyRegistrationNonces)
        ? parsed.keyRegistrationNonces
        : [],
    };
  }

  // ---- 保存数据库到 JSON 文件 ----
  save() {
    fs.writeFileSync(this.filePath, `${JSON.stringify(this.db, null, 2)}\n`, "utf8");
  }

  // ---- 为用户签发 session token ----
  // 生成 256-bit 随机 token → 存储其 SHA-256 hash → 返回明文 token
  // 注意：服务端只存 hash，即使数据库泄露也不会直接得到有效 token
  issueSessionForUser(userId) {
    // token: 256-bit 随机 session token（明文），返回给客户端
    const token = this.randomBytes(32).toString("base64url");
    // issuedAt: session 签发时的 Unix 毫秒时间戳
    const issuedAt = this.now();
    // expiresAt: session 过期时间戳
    const expiresAt = issuedAt + this.sessionTtlMs;
    this.db.sessions.push({
      // tokenHash: token 的 SHA-256 哈希值（只存 hash，即使数据库泄露也无法直接冒用 session）
      tokenHash: hashToken(token),
      userId,
      issuedAt,
      expiresAt,
    });
    return {
      token,
      expiresAt,
      expiresInMs: this.sessionTtlMs,
    };
  }

  // ---- 消费 key registration nonce ----
  // 验证 nonce 存在、未过期、属于该用户
  // 成功后删除 nonce（一次性使用）
  consumeKeyRegistrationNonce(userId, nonce) {
    if (!nonce) {
      throw new AuthError(400, "Missing key registration nonce");
    }

    // index: 匹配的 nonce 在 keyRegistrationNonces 数组中的索引
    const index = this.db.keyRegistrationNonces.findIndex(
      (candidate) => candidate.nonce === nonce && candidate.userId === userId
    );
    if (index < 0) {
      throw new AuthError(400, "Unknown, expired, or already used key registration nonce");
    }

    // record: 找到的 nonce 记录 { nonce, userId, issuedAt, expiresAt }
    const record = this.db.keyRegistrationNonces[index];
    if (record.expiresAt <= this.now()) {
      // 已过期：删除并报错
      this.db.keyRegistrationNonces.splice(index, 1);
      this.save();
      throw new AuthError(400, "Expired key registration nonce");
    }

    // 成功消费：从数组中删除该 nonce（一次性使用）
    this.db.keyRegistrationNonces.splice(index, 1);
  }

  // ---- 断言用户存在，不存在则抛异常 ----
  requireUser(userId) {
    const user = this.db.users.find((candidate) => candidate.id === userId);
    if (!user) {
      throw new AuthError(404, "User not found");
    }
    return user;
  }

  // ---- 清理过期的 session 和 key registration nonce ----
  pruneExpired() {
    const now = this.now();
    const sessionsBefore = this.db.sessions.length;
    const keyNoncesBefore = this.db.keyRegistrationNonces.length;
    this.db.sessions = this.db.sessions.filter((session) => session.expiresAt > now);
    this.db.keyRegistrationNonces = this.db.keyRegistrationNonces.filter(
      (nonce) => nonce.expiresAt > now
    );
    if (
      sessionsBefore !== this.db.sessions.length ||
      keyNoncesBefore !== this.db.keyRegistrationNonces.length
    ) {
      this.save();
    }
  }
}

// ---- 返回空数据库结构 ----
function emptyDb() {
  return {
    users: [],
    sessions: [],
    keyRegistrationNonces: [],
  };
}

// ---- 规范化并验证用户名 ----
// 规则：3-64 字符，只允许小写字母、数字、_、@、.、-
function normalizeUsername(username) {
  if (typeof username !== "string") {
    throw new AuthError(400, "username must be a string");
  }
  const normalized = username.trim().toLowerCase();
  if (!/^[a-z0-9_@.-]{3,64}$/.test(normalized)) {
    throw new AuthError(400, "username must be 3-64 chars: letters, numbers, _, @, ., -");
  }
  return normalized;
}

function normalizePasswordUserId(userId) {
  if (typeof userId !== "string" || !/^[A-Za-z0-9_.@:-]{3,128}$/.test(userId)) {
    throw new AuthError(
      400,
      "userId must be 3-128 characters: letters, numbers, _, ., @, :, or -"
    );
  }
  return userId.toLowerCase();
}

// ---- 验证密码长度（8-256 字符）----
function validatePassword(password) {
  if (typeof password !== "string" || password.length < 8 || password.length > 256) {
    throw new AuthError(400, "password must be 8-256 chars");
  }
}

// ---- 密码哈希 ----
// 使用 scrypt (Node.js 默认参数 N=16384, r=8, p=1) + 随机 salt
// 输出 32 字节的 key，用 base64url 编码存储
function hashPassword(password, salt) {
  return crypto.scryptSync(password, salt, 32).toString("base64url");
}

// ---- Session token 哈希 ----
// 使用 SHA-256 而非 scrypt，因为 token 本身就是高熵随机数
// 存储 hash 值而非明文，即使数据库泄露也无法直接冒用 session
function hashToken(token) {
  return crypto.createHash("sha256").update(token).digest("base64url");
}

// ---- 验证公钥格式 ----
// 要求：SPKI (SubjectPublicKeyInfo) DER 格式，EC 算法，P-256 曲线
// SPKI 是 X.509 中表示公钥的标准格式
// 返回 { asymmetricKeyType, namedCurve, fingerprint }
function validateEcPublicKey(publicKeyBase64) {
  if (!publicKeyBase64) {
    throw new AuthError(400, "Missing publicKey");
  }

  // keyObject: Node.js crypto 解析后的公钥对象
  let keyObject;
  try {
    // crypto.createPublicKey 解析 SPKI DER 格式的公钥
    keyObject = crypto.createPublicKey({
      key: Buffer.from(publicKeyBase64, "base64"),
      format: "der",
      type: "spki",
    });
  } catch (error) {
    throw new AuthError(400, `Invalid publicKey SPKI DER: ${error.message || error}`);
  }

  if (keyObject.asymmetricKeyType !== "ec") {
    throw new AuthError(400, "publicKey must be an EC key");
  }

  // namedCurve: 椭圆曲线名称，"prime256v1" 即 NIST P-256
  const namedCurve = keyObject.asymmetricKeyDetails?.namedCurve || null;
  if (namedCurve !== "prime256v1") {
    throw new AuthError(400, "publicKey must use P-256/prime256v1");
  }

  return {
    // asymmetricKeyType: 非对称密钥类型，应为 "ec"
    asymmetricKeyType: keyObject.asymmetricKeyType,
    namedCurve,
    // fingerprint: 公钥的 SHA-256 指纹（base64url 编码），用于日志中的短标识
    fingerprint: crypto
      .createHash("sha256")
      .update(Buffer.from(publicKeyBase64, "base64"))
      .digest("base64url"),
  };
}

// ---- 过滤出可对外返回的用户字段 ----
// 不返回 passwordSalt、passwordHash 等敏感字段
function publicUser(user) {
  return {
    id: user.id,
    username: user.username,
    createdAt: user.createdAt,
    activeKey: user.activeKeyId
      ? publicKeyRecord(user.keys.find((key) => key.id === user.activeKeyId))
      : null,
  };
}

// ---- 过滤出可对外返回的公钥字段 ----
// 不返回 certificateChainBase64 原始数组，只保留指纹和 attestation 摘要
function publicKeyRecord(key) {
  if (!key) {
    return null;
  }
  return {
    id: key.id,
    publicKeyFingerprint: key.publicKeyFingerprint,
    asymmetricKeyType: key.asymmetricKeyType,
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
        }
      : null,
    active: key.active,
    createdAt: key.createdAt,
    revokedAt: key.revokedAt || null,
  };
}

// ---- 从 Authorization header 解析 Bearer token ----
// 格式：Authorization: Bearer <token>
function parseBearerToken(header) {
  if (typeof header !== "string") {
    return null;
  }
  // match: 正则匹配结果，match[1] 是 Bearer 后面的 token 部分
  const match = header.match(/^Bearer\s+(.+)$/i);
  return match ? match[1].trim() : null;
}

// ---- 从多个候选值中取第一个非空字符串 ----
function pickString(...values) {
  return values.find((value) => typeof value === "string" && value.length > 0) ?? null;
}

module.exports = {
  AuthError,
  DEFAULT_AUTH_DB_PATH,
  JsonAuthStore,
  parseBearerToken,
  publicKeyRecord,
  publicUser,
  validateEcPublicKey,
};
