"use strict";

/*
 * 文件功能：
 * - 测试 interaction logger 的请求摘要、响应摘要和 JSONL 最近记录读取。
 * - M-09 回归测试：I/O 故障隔离、序列化故障隔离、错误报告安全性。
 *
 * 执行流程：
 * 1. summarizeProofRequest 确认日志不会保存完整 proof，只保存摘要。
 * 2. summarizeVerifyResponse 压缩服务端验证响应。
 * 3. createInteractionLogger 写入临时 JSONL 并读取最近日志。
 * 4. M-09 回归：EISDIR、mkdir 失败、ENOSPC、读取失败。
 * 5. M-09 回归：循环引用、BigInt、异常 getter 不抛出。
 * 6. M-09 回归：子进程级 /dev/full + 序列化失败安全验证。
 * 7. M-09 回归：敏感信息和绝对路径不进入 stderr。
 */
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const os = require("node:os");
const { spawnSync } = require("node:child_process");
const {
  createInteractionLogger,
  summarizeKeyRegistrationRequest,
  summarizeProofRequest,
  summarizeVerifyResponse,
} = require("../src/interaction-logger");

// ---- 原始测试 ----

test("summarizes proof request without storing full proof", () => {
  const summary = summarizeProofRequest({
    proof: {
      a: { x: "1", y: "2", z: "1" },
      b: { x: ["3", "4"], y: ["5", "6"], z: ["1", "0"] },
      c: { x: "7", y: "8", z: "1" },
      protocol: "groth16",
      curve: "bn128",
    },
    inputs: ["123", "456"],
    tee: {
      payload: "ZK_LOCATION_V1\npublic_commitment=123\nserver_nonce=nonce-1",
      signature: "a".repeat(80),
      publicKey: "b".repeat(80),
      certificateChain: ["cert1", "cert2"],
    },
  });

  assert.equal(summary.publicInputCount, 2);
  assert.equal(summary.publicCommitment, "123");
  assert.equal(summary.proofShape, "mopro");
  assert.equal(summary.tee.present, true);
  assert.equal(summary.tee.serverNonce, "nonce-1");
  assert.equal(summary.tee.certificateChainCount, 2);
  assert.match(summary.tee.signature, /\.\.\./);
});

test("summarizes verify response", () => {
  const summary = summarizeVerifyResponse({
    valid: true,
    proofValid: true,
    acceptedFormat: "mopro",
    publicInputCount: 37,
    signature: {
      checked: true,
      valid: true,
      signatureValid: true,
      commitmentBound: true,
      serverNonce: "nonce-1",
    },
    nonce: {
      checked: true,
      valid: true,
      consumed: true,
      nonce: "nonce-1",
    },
  });

  assert.equal(summary.valid, true);
  assert.equal(summary.signature.signatureValid, true);
  assert.equal(summary.nonce.consumed, true);
});

test("summarizes key registration request with client certificate chain", () => {
  const summary = summarizeKeyRegistrationRequest({
    publicKey: "p".repeat(80),
    certificateChain: ["leaf-cert-base64", "intermediate-cert-base64", "root-cert-base64"],
  });

  assert.equal(summary.certificateChainCount, 3);
  assert.deepEqual(summary.clientCertificateChainBase64, [
    "leaf-cert-base64",
    "intermediate-cert-base64",
    "root-cert-base64",
  ]);
  assert.match(summary.publicKey, /\.\.\./);
});

test("writes and reads recent interaction records", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "zk-location-logs-"));
  const filePath = path.join(dir, "interactions.jsonl");
  const logger = createInteractionLogger({ filePath });

  logger.log({ type: "one" });
  logger.log({ type: "two" });

  const recent = logger.recent(1);
  assert.equal(recent.length, 1);
  assert.equal(recent[0].type, "two");
});

// =============================================================================
// M-09 回归测试：interaction logger I/O 故障隔离
// =============================================================================

// ---- 子进程测试 helper ----
// 在独立子进程中执行 logger 操作，使用 --unhandled-rejections=strict
// 确保任何未处理 rejection 都会导致非零退出。
// 返回 { exitCode, stdout, stderr }。

const LOGGER_MODULE_PATH = path.resolve(__dirname, "../src/interaction-logger.js");

function spawnLogSubprocess({ setup, recordExpr, redirectStderrToFull = false, timeout = 5000, extraCalls = "" }) {
  // 构建子进程脚本
  const script = [
    '"use strict";',
    'const fs = require("node:fs");',
    'const path = require("node:path");',
    'const os = require("node:os");',
    `const { createInteractionLogger } = require(${JSON.stringify(LOGGER_MODULE_PATH)});`,
    setup,
    "async function handler() {",
    `  logger.log(${recordExpr});`,
    "}",
    "handler();",
    extraCalls,
    "setTimeout(() => {",
    '  process.stdout.write("BUSINESS_OK\\n");',
    "}, 50);",
  ].join("\n");

  const scriptPath = path.join(os.tmpdir(), `m09-subprocess-${Date.now()}-${Math.random().toString(36).slice(2)}.js`);
  fs.writeFileSync(scriptPath, script, "utf8");

  let stdioOpts;
  if (redirectStderrToFull) {
    let fullFd;
    try {
      fullFd = fs.openSync("/dev/full", "w");
    } catch (_e) {
      // /dev/full not available — use pipe for stderr
      fullFd = "pipe";
    }
    stdioOpts = ["ignore", "pipe", fullFd];
  } else {
    stdioOpts = ["ignore", "pipe", "pipe"];
  }

  let result;
  try {
    result = spawnSync(process.execPath, ["--unhandled-rejections=strict", scriptPath], {
      cwd: path.resolve(__dirname, ".."),
      stdio: stdioOpts,
      timeout,
      encoding: "utf8",
      maxBuffer: 1024 * 1024,
    });
  } finally {
    if (redirectStderrToFull && typeof stdioOpts[2] === "number") {
      try { fs.closeSync(stdioOpts[2]); } catch (_e) { /* ignore */ }
    }
    try { fs.unlinkSync(scriptPath); } catch (_e) { /* ignore */ }
  }

  return {
    exitCode: result.status,
    stdout: (result.stdout || "").trim(),
    stderr: (result.stderr || "").trim(),
    error: result.error,
  };
}

// ---- M-09: I/O 故障不抛出 ----

test("M-09: log() does not throw when log path is a directory (EISDIR)", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "zk-loc-m09-eisdir-"));
  const filePath = path.join(dir, "interactions.jsonl");
  fs.mkdirSync(filePath);

  const logger = createInteractionLogger({ filePath });
  assert.doesNotThrow(() => {
    logger.log({ type: "should-not-crash" });
  });
});

test("M-09: createInteractionLogger survives mkdir failure gracefully", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "zk-loc-m09-mkdir-"));
  const blockFile = path.join(dir, "blocker");
  fs.writeFileSync(blockFile, "block");

  const logPath = path.join(blockFile, "subdir", "interactions.jsonl");

  assert.doesNotThrow(() => {
    const logger = createInteractionLogger({ filePath: logPath });
    assert.doesNotThrow(() => {
      logger.log({ type: "should-be-silent" });
    });
  });
});

test("M-09: log() does not throw on appendFileSync failure (mock fs)", async (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "zk-loc-m09-mock-"));
  const filePath = path.join(dir, "interactions.jsonl");
  const logger = createInteractionLogger({ filePath });

  assert.doesNotThrow(() => {
    logger.log({ type: "pre-mock" });
  });

  const appendMock = t.mock.method(fs, "appendFileSync", () => {
    const err = new Error("ENOSPC: no space left on device");
    err.code = "ENOSPC";
    throw err;
  });

  try {
    assert.doesNotThrow(() => {
      logger.log({ type: "should-be-caught" });
    });
  } finally {
    appendMock.mock.restore();
  }

  assert.doesNotThrow(() => {
    logger.log({ type: "post-mock" });
  });
});

test("M-09: recent() returns empty array on read failure (mock fs)", async (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "zk-loc-m09-recent-"));
  const filePath = path.join(dir, "interactions.jsonl");
  const logger = createInteractionLogger({ filePath });
  logger.log({ type: "one" });

  const readMock = t.mock.method(fs, "readFileSync", () => {
    const err = new Error("EACCES: permission denied");
    err.code = "EACCES";
    throw err;
  });

  try {
    const entries = logger.recent(10);
    assert.deepEqual(entries, []);
  } finally {
    readMock.mock.restore();
  }
});

// ---- M-09: JSON 序列化故障不抛出 ----

test("M-09: log() does not throw on cyclic reference", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "zk-loc-m09-cyclic-"));
  const filePath = path.join(dir, "interactions.jsonl");
  const logger = createInteractionLogger({ filePath });

  const record = { type: "cyclic" };
  record.self = record;

  assert.doesNotThrow(() => {
    logger.log(record);
  });
});

test("M-09: log() does not throw on BigInt value", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "zk-loc-m09-bigint-"));
  const filePath = path.join(dir, "interactions.jsonl");
  const logger = createInteractionLogger({ filePath });

  assert.doesNotThrow(() => {
    logger.log({ type: "bigint", value: 1n });
  });
});

test("M-09: log() does not throw on getter that throws", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "zk-loc-m09-getter-"));
  const filePath = path.join(dir, "interactions.jsonl");
  const logger = createInteractionLogger({ filePath });

  const record = { type: "getter" };
  Object.defineProperty(record, "badField", {
    enumerable: true,
    get() {
      throw new Error("getter failure");
    },
  });

  assert.doesNotThrow(() => {
    logger.log(record);
  });
});

// ---- M-09: 故障恢复测试 ----
// 制造一次真实的写入失败，然后验证后续写入仍正常。

test("M-09: subsequent log calls succeed after a real write failure", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "zk-loc-m09-recover-"));
  const filePath = path.join(dir, "interactions.jsonl");
  const logger = createInteractionLogger({ filePath });

  // 第一次写入：正常
  assert.doesNotThrow(() => {
    logger.log({ type: "first" });
  });
  assert.equal(fs.existsSync(filePath), true);

  // 保留原始文件内容，用目录替换制造 EISDIR 故障
  const backupPath = filePath + ".backup";
  fs.renameSync(filePath, backupPath);
  fs.mkdirSync(filePath);

  // 第二次写入：EISDIR 失败但不抛出
  assert.doesNotThrow(() => {
    logger.log({ type: "lost" });
  });

  // 恢复：删除目录，还原日志文件
  fs.rmdirSync(filePath);
  fs.renameSync(backupPath, filePath);

  // 第三次写入：恢复正常，应追加到原有文件
  assert.doesNotThrow(() => {
    logger.log({ type: "third" });
  });

  // recent 应包含第一次和第三次
  const entries = logger.recent(2);
  assert.equal(entries.length, 2);
  assert.equal(entries[0].type, "first");
  assert.equal(entries[1].type, "third");
});

// ---- M-09: 安全错误报告 ----

test("M-09: error output does not contain user data or absolute paths", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "zk-loc-m09-stderr-"));
  const filePath = path.join(dir, "interactions.jsonl");
  fs.mkdirSync(filePath); // 制造 EISDIR

  const logger = createInteractionLogger({ filePath });

  // 捕获 safeReportLoggerFailure 的 stderr 输出。
  // safeReportLoggerFailure 使用 fs.writeSync(2, ...) 而非 process.stderr.write，
  // 因此需要 mock fs.writeSync 来截获 fd 2 的写入内容。
  const originalWriteSync = fs.writeSync;
  let capturedStderr = "";
  fs.writeSync = (fd, data, ...args) => {
    if (fd === 2 && typeof data === "string") {
      capturedStderr += data;
      return data.length;
    }
    return originalWriteSync(fd, data, ...args);
  };

  try {
    logger.log({
      type: "proof.verify",
      userId: "M09_SECRET_USER_MUST_NOT_LEAK",
      nonce: "M09_SECRET_NONCE_MUST_NOT_LEAK",
      password: "M09_SECRET_PASSWORD_MUST_NOT_LEAK",
    });
  } finally {
    fs.writeSync = originalWriteSync;
  }

  // 敏感用户数据不应出现在错误输出
  assert.ok(!capturedStderr.includes("M09_SECRET_USER_MUST_NOT_LEAK"));
  assert.ok(!capturedStderr.includes("M09_SECRET_NONCE_MUST_NOT_LEAK"));
  assert.ok(!capturedStderr.includes("M09_SECRET_PASSWORD_MUST_NOT_LEAK"));
  // 日志文件的绝对路径不应出现在错误输出（safeReportLoggerFailure 仅输出 error.code）
  assert.ok(!capturedStderr.includes(dir));
  assert.ok(!capturedStderr.includes("interactions.jsonl"));
  // 应包含 logger tag 和错误码
  assert.ok(capturedStderr.includes("[interaction-logger]"));
  assert.ok(capturedStderr.includes("EISDIR"));
  // 不应包含完整 error.message（含路径）
  assert.ok(!capturedStderr.includes("illegal operation on a directory"));
});

// ---- M-09: 子进程级安全验证 ----
// 这些测试在独立子进程中运行，使用 --unhandled-rejections=strict。
// 验证 fire-and-forget async handler 中的 logger 故障不会导致进程退出。

test("M-09 subprocess: stderr /dev/full + EISDIR survives", () => {
  if (!fs.existsSync("/dev/full")) {
    // 平台没有 /dev/full，跳过
    return;
  }

  const result = spawnLogSubprocess({
    setup: `
      const dir = fs.mkdtempSync(path.join(os.tmpdir(), "m09-full-"));
      const logPath = path.join(dir, "interactions.jsonl");
      fs.mkdirSync(logPath);
      const logger = createInteractionLogger({ filePath: logPath });
    `,
    recordExpr: '{ type: "nonce.issue" }',
    redirectStderrToFull: true,
  });

  assert.equal(result.exitCode, 0, `expected exit 0, got ${result.exitCode}, stderr: ${result.stderr}`);
  assert.ok(result.stdout.includes("BUSINESS_OK"), "business should continue after log failure");
});

test("M-09 subprocess: cyclic reference in fire-and-forget async survives", () => {
  const result = spawnLogSubprocess({
    setup: `
      const dir = fs.mkdtempSync(path.join(os.tmpdir(), "m09-sub-cyclic-"));
      const logPath = path.join(dir, "interactions.jsonl");
      const logger = createInteractionLogger({ filePath: logPath });
    `,
    recordExpr: '(() => { const r = { type: "cyclic" }; r.self = r; return r; })()',
  });

  assert.equal(result.exitCode, 0, `expected exit 0, got ${result.exitCode}, stderr: ${result.stderr}`);
  assert.ok(result.stdout.includes("BUSINESS_OK"), "business should continue after cyclic reference");
});

test("M-09 subprocess: BigInt in fire-and-forget async survives", () => {
  const result = spawnLogSubprocess({
    setup: `
      const dir = fs.mkdtempSync(path.join(os.tmpdir(), "m09-sub-bigint-"));
      const logPath = path.join(dir, "interactions.jsonl");
      const logger = createInteractionLogger({ filePath: logPath });
    `,
    recordExpr: '{ type: "bigint", value: 1n }',
  });

  assert.equal(result.exitCode, 0, `expected exit 0, got ${result.exitCode}, stderr: ${result.stderr}`);
  assert.ok(result.stdout.includes("BUSINESS_OK"), "business should continue after BigInt");
});

test("M-09 subprocess: throwing getter in fire-and-forget async survives", () => {
  const result = spawnLogSubprocess({
    setup: `
      const dir = fs.mkdtempSync(path.join(os.tmpdir(), "m09-sub-getter-"));
      const logPath = path.join(dir, "interactions.jsonl");
      const logger = createInteractionLogger({ filePath: logPath });
    `,
    recordExpr: `(() => {
      const r = { type: "getter" };
      Object.defineProperty(r, "badField", {
        enumerable: true,
        get() { throw new Error("getter failure"); },
      });
      return r;
    })()`,
  });

  assert.equal(result.exitCode, 0, `expected exit 0, got ${result.exitCode}, stderr: ${result.stderr}`);
  assert.ok(result.stdout.includes("BUSINESS_OK"), "business should continue after throwing getter");
});

test("M-09 subprocess: business processes two requests after log failure", () => {
  // 验证日志失败后第二个业务请求也能正常处理。
  // 模拟 /nonce 场景：两次 fire-and-forget handler 调用都因 EISDIR 失败，
  // 但进程不退出，BUSINESS_OK 仍输出。
  const result = spawnLogSubprocess({
    setup: `
      const dir = fs.mkdtempSync(path.join(os.tmpdir(), "m09-sub-two-"));
      const logPath = path.join(dir, "interactions.jsonl");
      fs.mkdirSync(logPath);
      const logger = createInteractionLogger({ filePath: logPath });
    `,
    recordExpr: '{ type: "first" }',
    extraCalls: [
      "async function handler2() {",
      '  logger.log({ type: "second" });',
      "}",
      "handler2();",
    ].join("\n"),
  });

  assert.equal(result.exitCode, 0, `expected exit 0, got ${result.exitCode}, stderr: ${result.stderr}`);
  assert.ok(result.stdout.includes("BUSINESS_OK"), "business should continue after two log failures");
});
