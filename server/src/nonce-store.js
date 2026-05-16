"use strict";

// =============================================================================
// nonce-store.js —— 防重放攻击的 nonce 存储
// =============================================================================
//
// 在整个 ZK-Location 协议中的作用：
//   客户端拿到 server nonce 后，用 Keystore 私钥签名，服务端验证签名后消费
//   这个 nonce。nonce 只能被消费一次，防止攻击者截获合法请求后重放。
//
// nonce 生命周期：
//   1. 客户端 GET/POST /nonce → 服务端 issue() 生成一个 nonce
//   2. 客户端将其放入 Keystore 签名的 payload 中（server_nonce 字段）
//   3. 客户端 POST /verify-proof → 服务端 consume(nonce) 消费它
//   4. 同一个 nonce 第二次消费会失败（"already used"）
//
// 为什么 nonce 存在服务端内存中而不是数据库文件？
//   nonce 是短期有效的（默认 5 分钟），服务重启后旧 nonce 自然失效，
//   不需要持久化。用内存 Map 即可。
// =============================================================================

const crypto = require("node:crypto");

// nonce 默认有效期：5 分钟（300,000 毫秒）
// 这个时间足够客户端完成一轮 proof 生成 + 签名 + 发送
// 同时限制攻击者持有 nonce 的时间窗口
// 修改环境变量 NONCE_TTL_MS 可覆盖此默认值
const DEFAULT_TTL_MS = 5 * 60 * 1000;

class NonceStore {
  constructor(options = {}) {
    // nonce 的有效时长，可通过 options.ttlMs 或环境变量 NONCE_TTL_MS 覆盖
    this.ttlMs = Number(options.ttlMs ?? DEFAULT_TTL_MS);

    // 当前时间函数，默认用 Date.now()，测试时可以注入假时钟
    this.now = options.now ?? (() => Date.now());

    // 随机数生成函数，默认用 Node.js crypto，测试时可以注入确定性随机
    this.randomBytes = options.randomBytes ?? ((size) => crypto.randomBytes(size));

    // 核心存储：Map<nonce字符串, { issuedAt, expiresAt }>
    // 用 Map 是因为它查找/删除都是 O(1)
    this.nonces = new Map();
  }

  // ---- 发放 nonce ----
  // 生成一个 256-bit 随机 nonce（base64url 编码后约 43 字符）
  // 加 do-while 循环防止极小概率的碰撞（生成和已有 nonce 相同的值）
  issue() {
    // 先清理已过期的 nonce，避免 Map 无限增长
    this.pruneExpired();

    // nonce: 本次生成的随机 nonce 字符串（base64url 编码）
    let nonce;
    do {
      // crypto.randomBytes(32) 生成 32 字节（256 bit）加密级随机数
      // .toString("base64url") 转为 URL 安全的 base64 编码
      nonce = this.randomBytes(32).toString("base64url");
    } while (this.nonces.has(nonce));  // 如果碰撞了，重新生成

    // issuedAt: nonce 发放时的 Unix 毫秒时间戳
    const issuedAt = this.now();
    // expiresAt: nonce 过期时间，issuedAt + 有效期（默认 5 分钟）
    const expiresAt = issuedAt + this.ttlMs;

    // 存储 nonce 及其有效期信息
    this.nonces.set(nonce, { issuedAt, expiresAt });

    // 返回给客户端的信息
    // expiresAt: 绝对过期时间戳，expiresInMs: 相对有效期毫秒数，方便客户端判断有效期
    return {
      nonce,
      expiresAt,
      expiresInMs: this.ttlMs,
    };
  }

  // ---- 消费 nonce（一次性，用完即删）----
  // 返回一个描述对象，包含 checked/valid/consumed 三个布尔值
  // 调用方根据返回值判断 nonce 是否可用
  // 三种失败情况：
  //   1. nonce 为空 → "Missing server_nonce"
  //   2. nonce 不在 Map 中 → "Unknown or already used"（可能是重放攻击）
  //   3. nonce 已过期 → "Expired nonce"
  consume(nonce) {
    // 情况 1：签名的 payload 里根本没有 server_nonce
    if (typeof nonce !== "string" || nonce.length === 0) {
      return {
        checked: true,
        valid: false,
        consumed: false,
        reason: "Missing server_nonce in signed payload",
      };
    }

    // record: Map 中该 nonce 对应的记录 { issuedAt, expiresAt }
    // 在 Map 中查找
    const record = this.nonces.get(nonce);
    if (!record) {
      // nonce 不在 Map 中，可能是：
      // - 从未被 issue 过（攻击者伪造的）
      // - 已经被消费了（重放攻击）
      // - 之前被 pruneExpired() 清理了（已过期）
      return {
        checked: true,
        valid: false,
        consumed: false,
        nonce,
        reason: "Unknown, expired, or already used nonce",
      };
    }

    // now: 当前时间戳，用于与 record.expiresAt 比较判断是否过期
    // 情况 3：虽然找到但已过期
    const now = this.now();
    if (record.expiresAt <= now) {
      this.nonces.delete(nonce);  // 清理已过期的记录
      return {
        checked: true,
        valid: false,
        consumed: false,
        nonce,
        reason: "Expired nonce",
      };
    }

    // 成功：删除 nonce 并返回有效结果
    // 关键：先 delete 再返回，保证同一 nonce 第二次 consume 会失败
    this.nonces.delete(nonce);
    return {
      checked: true,
      valid: true,
      consumed: true,
      nonce,
      issuedAt: record.issuedAt,
      expiresAt: record.expiresAt,
    };
  }

  // ---- 清理过期的 nonce ----
  // 遍历整个 Map，删除所有 expiresAt <= now 的记录
  // Map 的 entries() 迭代时可以安全删除当前元素
  pruneExpired() {
    const now = this.now();
    for (const [nonce, record] of this.nonces.entries()) {
      if (record.expiresAt <= now) {
        this.nonces.delete(nonce);
      }
    }
  }

  // ---- 返回当前有效 nonce 数量 ----
  // 先清理过期 nonce，保证返回值是真实的有效数量
  size() {
    this.pruneExpired();
    return this.nonces.size;
  }
}

module.exports = {
  DEFAULT_TTL_MS,
  NonceStore,
};
