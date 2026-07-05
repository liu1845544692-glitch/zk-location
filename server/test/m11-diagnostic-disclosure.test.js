"use strict";

/*
 * M-11 未认证诊断接口泄露测试
 *
 * 覆盖:
 * 1. 未认证诊断接口被拒绝
 * 2. /health 不暴露绝对路径
 * 3. 未知 throwable 不泄露内部消息
 * 4. 已知业务错误保持预定义 4xx
 * 5. 正常流程无回归
 */

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

// ---- 隔离的 server + auth store 工厂 ----
function makeServer() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "zk-loc-m11-"));
  const filePath = path.join(dir, "auth.json");
  const { JsonAuthStore } = require("../src/auth-store");
  const authStore = new JsonAuthStore({
    filePath, sessionTtlMs: 60000, keyNonceTtlMs: 60000, requireKeyAttestation: false,
  });
  const { createVerifierServer } = require("../src/server");
  const server = createVerifierServer({ authStore });
  server._cleanupDir = dir;
  return server;
}

async function startAndListen(s) {
  await new Promise((r) => s.listen(0, r));
  return s;
}

function base(server) { return `http://127.0.0.1:${server.address().port}`; }

async function postJson(url, body) {
  const res = await fetch(url, {
    method: "POST", headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });
  try { return { status: res.status, body: await res.json() }; } catch { return { status: res.status, body: null }; }
}

async function getJson(url, headers = {}) {
  const res = await fetch(url, { headers });
  try { return { status: res.status, body: await res.json() }; } catch { return { status: res.status, body: null }; }
}

// =============================================================================
// 1. 未认证诊断接口被拒绝
// =============================================================================

test("M-11: unauthenticated GET /logs/interactions → 404", async () => {
  const s = await startAndListen(makeServer());
  try {
    const { status } = await getJson(`${base(s)}/logs/interactions`);
    assert.equal(status, 404);
  } finally { s.close(); }
});

test("M-11: unauthenticated GET /stats/performance → 404", async () => {
  const s = await startAndListen(makeServer());
  try {
    const { status } = await getJson(`${base(s)}/stats/performance`);
    assert.equal(status, 404);
  } finally { s.close(); }
});

test("M-11: unauthenticated GET /reports/latest → 404", async () => {
  const s = await startAndListen(makeServer());
  try {
    const { status } = await getJson(`${base(s)}/reports/latest`);
    assert.equal(status, 404);
  } finally { s.close(); }
});

// =============================================================================
// 2. /health 不暴露内部路径
// =============================================================================

test("M-11: /health minimal schema — only status field", async () => {
  const s = await startAndListen(makeServer());
  try {
    const { body } = await getJson(`${base(s)}/health`);
    assert.equal(body.status, "ok");
    // 不得有任何 extraneous field
    const keys = Object.keys(body);
    assert.deepEqual(keys.sort(), ["status"]);
  } finally { s.close(); }
});

// =============================================================================
// 3. 未知 throwable → 固定 error，不泄露 marker
// =============================================================================

test("M-11: string throwable → no marker in response", async () => {
  let s = makeServer();
  s.locals.authStore.registerUser("aaa", "correct-password");
  const origWrite = fs.writeFileSync;
  fs.writeFileSync = () => { throw "SECRET_M11_STRING_MARKER"; };
  s = await startAndListen(s);
  try {
    const { status, body } = await postJson(`${base(s)}/auth/register`,
      { username: "bbb", password: "password123" });
    assert.ok(status >= 400);
    const bodyStr = JSON.stringify(body);
    assert.ok(!bodyStr.includes("SECRET_M11_STRING_MARKER"));
  } finally { fs.writeFileSync = origWrite; s.close(); }
});

test("M-11: Error message → not leaked", async () => {
  let s = makeServer();
  s.locals.authStore.registerUser("aaa", "correct-password");
  const origWrite = fs.writeFileSync;
  fs.writeFileSync = () => { throw new Error("SECRET_M11_ERROR_MARKER"); };
  s = await startAndListen(s);
  try {
    const { status, body } = await postJson(`${base(s)}/auth/register`,
      { username: "bbb", password: "password123" });
    assert.ok(status >= 400);
    assert.ok(!JSON.stringify(body).includes("SECRET_M11_ERROR_MARKER"));
  } finally { fs.writeFileSync = origWrite; s.close(); }
});

test("M-11: null throwable → stable HTTP response", async () => {
  let s = makeServer();
  s.locals.authStore.registerUser("aaa", "correct-password");
  const origWrite = fs.writeFileSync;
  fs.writeFileSync = () => { throw null; };
  s = await startAndListen(s);
  try {
    const res = await postJson(`${base(s)}/auth/register`,
      { username: "bbb", password: "password123" });
    assert.ok(res.status >= 400);
    assert.ok(res.body !== null); // response completed
  } finally { fs.writeFileSync = origWrite; s.close(); }
});

test("M-11: undefined throwable → stable HTTP", async () => {
  let s = makeServer();
  s.locals.authStore.registerUser("aaa", "correct-password");
  const origWrite = fs.writeFileSync;
  fs.writeFileSync = () => { throw undefined; };
  s = await startAndListen(s);
  try {
    const { status, body } = await postJson(`${base(s)}/auth/register`,
      { username: "bbb", password: "password123" });
    assert.ok(status >= 400);
  } finally { fs.writeFileSync = origWrite; s.close(); }
});

test("M-11: Proxy throwable → stable HTTP", async () => {
  let s = makeServer();
  s.locals.authStore.registerUser("aaa", "correct-password");
  const proxyErr = new Proxy({}, { get() { throw new Error("PROXY_GET"); } });
  const origWrite = fs.writeFileSync;
  fs.writeFileSync = () => { throw proxyErr; };
  s = await startAndListen(s);
  try {
    const { status } = await postJson(`${base(s)}/auth/register`,
      { username: "bbb", password: "password123" });
    assert.ok(status >= 400);
  } finally { fs.writeFileSync = origWrite; s.close(); }
});

test("M-11: throwing statusCode getter → stable HTTP", async () => {
  let s = makeServer();
  s.locals.authStore.registerUser("aaa", "correct-password");
  const evilErr = {};
  Object.defineProperty(evilErr, "statusCode", { get() { throw new Error("STATUS_BOOM"); } });
  Object.defineProperty(evilErr, "message", { get() { throw new Error("MSG_BOOM"); } });
  const origWrite = fs.writeFileSync;
  fs.writeFileSync = () => { throw evilErr; };
  s = await startAndListen(s);
  try {
    const { status } = await postJson(`${base(s)}/auth/register`,
      { username: "bbb", password: "password123" });
    assert.ok(status >= 400);
  } finally { fs.writeFileSync = origWrite; s.close(); }
});

test("M-11: number throwable → stable HTTP", async () => {
  let s = makeServer();
  s.locals.authStore.registerUser("aaa", "correct-password");
  const origWrite = fs.writeFileSync;
  fs.writeFileSync = () => { throw 42; };
  s = await startAndListen(s);
  try {
    const { status } = await postJson(`${base(s)}/auth/register`,
      { username: "bbb", password: "password123" });
    assert.ok(status >= 400);
  } finally { fs.writeFileSync = origWrite; s.close(); }
});

// =============================================================================
// 4. Filesystem error → no path leaked
// =============================================================================

test("M-11: filesystem EIO → no path in response", async () => {
  let s = makeServer();
  s.locals.authStore.registerUser("aaa", "correct-password");
  const err = new Error("SECRET_FS_PATH_/private/auth.json");
  err.code = "EIO";
  err.path = "/private/auth.json";
  const origWrite = fs.writeFileSync;
  fs.writeFileSync = () => { throw err; };
  s = await startAndListen(s);
  try {
    const { body } = await postJson(`${base(s)}/auth/register`,
      { username: "bbb", password: "password123" });
    const bodyStr = JSON.stringify(body);
    assert.ok(!bodyStr.includes("/private/auth.json"));
    assert.ok(!bodyStr.includes("SECRET_FS_PATH"));
  } finally { fs.writeFileSync = origWrite; s.close(); }
});

// =============================================================================
// 5. 普通对象/伪造对象不能控制 HTTP 状态
// =============================================================================

test("M-11: forged object cannot control HTTP status", async () => {
  let s = makeServer();
  s.locals.authStore.registerUser("aaa", "correct-password");
  const forged = {
    statusCode: 299,
    code: "FORGED_CODE",
    message: "SECRET_FORGED_MESSAGE",
  };
  const origWrite = fs.writeFileSync;
  fs.writeFileSync = () => { throw forged; };
  s = await startAndListen(s);
  try {
    const { status, body } = await postJson(`${base(s)}/auth/register`,
      { username: "bbb", password: "password123" });
    assert.ok(status === 500, "forged object statusCode should not be used");
    assert.ok(!JSON.stringify(body).includes("SECRET_FORGED_MESSAGE"));
    assert.ok(!JSON.stringify(body).includes("FORGED_CODE"));
  } finally { fs.writeFileSync = origWrite; s.close(); }
});

// =============================================================================
// 6. 已知业务错误保持 4xx
// =============================================================================

test("M-11: 401 for bad password with correct message", async () => {
  const s = await startAndListen(makeServer());
  try {
    await postJson(`${base(s)}/auth/register`,
      { username: "alice", password: "correct-password" });
    const { status, body } = await postJson(`${base(s)}/auth/login`,
      { username: "alice", password: "wrong-password" });
    assert.equal(status, 401);
    assert.equal(body.error, "Invalid username or password");
  } finally { s.close(); }
});

test("M-11: 409 for duplicate user with correct message", async () => {
  const s = await startAndListen(makeServer());
  try {
    await postJson(`${base(s)}/auth/register`,
      { username: "alice", password: "correct-password" });
    const { status, body } = await postJson(`${base(s)}/auth/register`,
      { username: "alice", password: "another-pass" });
    assert.equal(status, 409);
    assert.equal(body.error, "Username already exists");
  } finally { s.close(); }
});

// =============================================================================
// 7. /health stays alive
// =============================================================================

test("M-11: /health stays 200 after error injection", async () => {
  let s = makeServer();
  s.locals.authStore.registerUser("aaa", "correct-password");
  const origWrite = fs.writeFileSync;
  fs.writeFileSync = () => { throw null; };
  s = await startAndListen(s);
  try {
    await postJson(`${base(s)}/auth/register`, { username: "bbb", password: "password123" });
    const { status, body } = await getJson(`${base(s)}/health`);
    assert.equal(status, 200);
    assert.equal(body.status, "ok");
  } finally { fs.writeFileSync = origWrite; s.close(); }
});

// =============================================================================
// 8. 正常流程回归
// =============================================================================

test("M-11: register + login + logout works", async () => {
  const s = await startAndListen(makeServer());
  try {
    const reg = await postJson(`${base(s)}/auth/register`,
      { username: "normal", password: "correct-password" });
    assert.equal(reg.status, 201);

    const login = await postJson(`${base(s)}/auth/login`,
      { username: "normal", password: "correct-password" });
    assert.equal(login.status, 200);

    const logout = await fetch(`${base(s)}/auth/logout`, {
      method: "POST", headers: { authorization: `Bearer ${reg.body.token}` },
    });
    assert.equal(logout.status, 200);
  } finally { s.close(); }
});
