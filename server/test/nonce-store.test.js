"use strict";

/*
 * 文件功能：
 * - 测试服务端 NonceStore 的签名 nonce 生成、过期和一次性消费逻辑。
 *
 * 执行流程：
 * 1. 使用可控 now/randomBytes 构造确定性 nonce。
 * 2. 第一次 consume 应成功并移除 nonce。
 * 3. 重放、过期、缺失 nonce 都应失败且不标记 consumed。
 */
const test = require("node:test");
const assert = require("node:assert/strict");
const { NonceStore } = require("../src/nonce-store");

test("issues and consumes nonce exactly once", () => {
  // now：测试注入的当前时间。
  let now = 1_000;
  // counter：测试注入的确定性随机数序号。
  let counter = 0;
  // store：带固定 TTL、时间源和随机源的 NonceStore。
  const store = new NonceStore({
    ttlMs: 60_000,
    now: () => now,
    randomBytes: () => Buffer.from(`nonce-${counter++}`.padEnd(32, "0")),
  });

  // issued/first/replay：签发、首次消费、重放消费结果。
  const issued = store.issue();
  assert.equal(issued.expiresAt, 61_000);
  assert.equal(store.size(), 1);

  const first = store.consume(issued.nonce);
  assert.equal(first.valid, true);
  assert.equal(first.consumed, true);
  assert.equal(store.size(), 0);

  const replay = store.consume(issued.nonce);
  assert.equal(replay.valid, false);
  assert.equal(replay.consumed, false);
  assert.match(replay.reason, /already used nonce/);

  now += 1;
});

test("rejects expired nonce", () => {
  // now：通过手动推进时间模拟过期。
  let now = 1_000;
  const store = new NonceStore({
    ttlMs: 100,
    now: () => now,
    randomBytes: () => Buffer.from("expired-nonce".padEnd(32, "0")),
  });

  const issued = store.issue();
  now = 1_101;

  const result = store.consume(issued.nonce);
  assert.equal(result.valid, false);
  assert.equal(result.consumed, false);
  assert.equal(result.reason, "Expired nonce");
});

test("rejects missing nonce", () => {
  const store = new NonceStore();
  const result = store.consume(null);

  assert.equal(result.valid, false);
  assert.equal(result.consumed, false);
  assert.equal(result.reason, "Missing server_nonce in signed payload");
});
