"use strict";

/*
 * M-12 sensitive file permissions
 * 验证 auth.json 和 interactions.jsonl 在宽松 umask 下仍为 0600。
 */

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

// =============================================================================
// 1. auth-store.js — auth.json 权限
// =============================================================================

test("M-12: auth.json new file is 0600 under permissive umask", () => {
  const prevUmask = process.umask(0);
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "zk-m12-auth-"));
  const filePath = path.join(dir, "auth.json");
  try {
    const { JsonAuthStore } = require("../src/auth-store");
    const store = new JsonAuthStore({
      filePath, sessionTtlMs: 60_000, keyNonceTtlMs: 60_000, requireKeyAttestation: false,
    });
    store.registerUser("alice", "correct-password");

    const mode = fs.statSync(filePath).mode & 0o777;
    assert.equal(mode, 0o600, `expected 0600 got 0${mode.toString(8)}`);
  } finally {
    process.umask(prevUmask);
  }
});

test("M-12: auth.json stays 0600 after save and restart", () => {
  const prevUmask = process.umask(0);
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "zk-m12-auth2-"));
  const filePath = path.join(dir, "auth.json");
  try {
    const { JsonAuthStore } = require("../src/auth-store");
    const s1 = new JsonAuthStore({
      filePath, sessionTtlMs: 60_000, keyNonceTtlMs: 60_000, requireKeyAttestation: false,
    });
    s1.registerUser("alice", "correct-password");
    assert.equal(fs.statSync(filePath).mode & 0o777, 0o600);

    s1.registerUser("bob", "another-pass");
    assert.equal(fs.statSync(filePath).mode & 0o777, 0o600);

    // restart
    const s2 = new JsonAuthStore({
      filePath, sessionTtlMs: 60_000, keyNonceTtlMs: 60_000, requireKeyAttestation: false,
    });
    s2.loginUser("alice", "correct-password");
    assert.equal(fs.statSync(filePath).mode & 0o777, 0o600);
  } finally {
    process.umask(prevUmask);
  }
});

test("M-12: auth.json content unchanged after mode change", () => {
  const prevUmask = process.umask(0);
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "zk-m12-auth3-"));
  const filePath = path.join(dir, "auth.json");
  try {
    const { JsonAuthStore } = require("../src/auth-store");
    const s1 = new JsonAuthStore({
      filePath, sessionTtlMs: 60_000, keyNonceTtlMs: 60_000, requireKeyAttestation: false,
    });
    s1.registerUser("alice", "correct-password");
    const content1 = fs.readFileSync(filePath, "utf8");
    const parsed = JSON.parse(content1);
    assert.ok(Array.isArray(parsed.users));
    assert.equal(parsed.users.length, 1);
    assert.equal(parsed.users[0].username, "alice");
  } finally {
    process.umask(prevUmask);
  }
});

// =============================================================================
// 2. interaction-logger.js — interactions.jsonl 权限
// =============================================================================

test("M-12: log file is 0600 under permissive umask", () => {
  const prevUmask = process.umask(0);
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "zk-m12-log-"));
  const filePath = path.join(dir, "interactions.jsonl");
  try {
    const { createInteractionLogger } = require("../src/interaction-logger");
    const logger = createInteractionLogger({ filePath });
    logger.log({ type: "auth.register", statusCode: 201, durationMs: 10 });

    const mode = fs.statSync(filePath).mode & 0o777;
    assert.equal(mode, 0o600, `expected 0600 got 0${mode.toString(8)}`);
  } finally {
    process.umask(prevUmask);
  }
});

test("M-12: log file stays 0600 after append", () => {
  const prevUmask = process.umask(0);
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "zk-m12-log2-"));
  const filePath = path.join(dir, "interactions.jsonl");
  try {
    const { createInteractionLogger } = require("../src/interaction-logger");
    const logger = createInteractionLogger({ filePath });
    logger.log({ type: "auth.register", statusCode: 201, durationMs: 10 });
    assert.equal(fs.statSync(filePath).mode & 0o777, 0o600);

    logger.log({ type: "auth.login", statusCode: 200, durationMs: 5 });
    assert.equal(fs.statSync(filePath).mode & 0o777, 0o600);
  } finally {
    process.umask(prevUmask);
  }
});

test("M-12: log file content valid and minimal schema", () => {
  const prevUmask = process.umask(0);
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "zk-m12-log3-"));
  const filePath = path.join(dir, "interactions.jsonl");
  try {
    const { createInteractionLogger } = require("../src/interaction-logger");
    const logger = createInteractionLogger({ filePath });
    logger.log({ type: "auth.register", statusCode: 201, durationMs: 10 });
    // 日志 schema 不变：仅 ts/type/statusCode/durationMs
    const raw = fs.readFileSync(filePath, "utf8").trim();
    const entry = JSON.parse(raw);
    assert.equal(entry.type, "auth.register");
    assert.equal(entry.statusCode, 201);
    assert.equal(typeof entry.durationMs, "number");
    assert.ok(typeof entry.ts === "string");
    // 无敏感字段
    assert.equal(Object.prototype.hasOwnProperty.call(entry, "token"), false);
    assert.equal(Object.prototype.hasOwnProperty.call(entry, "nonce"), false);
  } finally {
    process.umask(prevUmask);
  }
});

// =============================================================================
// 3. password-registration-store.js — password-registrations.json 权限
// =============================================================================

test("M-12: password-registrations.json is 0600 under permissive umask", () => {
  const prevUmask = process.umask(0);
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "zk-m12-pwd-"));
  const filePath = path.join(dir, "pwreg.json");
  try {
    const { JsonPasswordRegistrationStore } = require("../src/password-registration-store");
    const store = new JsonPasswordRegistrationStore({ filePath });
    store.register({
      userId: "test-user",
      salt: "1008",
      passwordCommitment: "12345",
      proofVersion: "v1",
      circuitVersion: "v1",
    });

    const mode = fs.statSync(filePath).mode & 0o777;
    assert.equal(mode, 0o600, `expected 0600 got 0${mode.toString(8)}`);
  } finally {
    process.umask(prevUmask);
  }
});
