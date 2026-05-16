"use strict";

/*
 * 文件功能：
 * - 实时 tail 服务端 interaction JSONL 日志。
 * - 把 nonce、key registration、proof verify 等日志压缩为终端可读的一行摘要。
 *
 * 执行流程：
 * 1. 根据 INTERACTION_LOG_PATH 找到日志文件，不存在则创建。
 * 2. 先打印末尾 LOG_TAIL_LIMIT 条历史日志。
 * 3. 每 LOG_POLL_MS 轮询新增内容。
 * 4. printLine 根据日志 type 格式化输出关键验证字段。
 */
const fs = require("node:fs");
const path = require("node:path");

// logPath：interaction log 文件路径，默认 server/logs/interactions.jsonl。
const logPath =
  process.env.INTERACTION_LOG_PATH ||
  path.resolve(__dirname, "../logs/interactions.jsonl");
// pollMs：轮询日志新增内容的间隔。
const pollMs = Number(process.env.LOG_POLL_MS || 500);
// initialLimit：启动时先打印的历史行数。
const initialLimit = Number(process.env.LOG_TAIL_LIMIT || 20);

fs.mkdirSync(path.dirname(logPath), { recursive: true });
if (!fs.existsSync(logPath)) {
  fs.writeFileSync(logPath, "", "utf8");
}

console.log(`Watching ${logPath}`);

// offset：已经读取到的文件字节偏移。
let offset = 0;
// initialLines：启动时展示的最后若干条历史日志。
const initialLines = fs
  .readFileSync(logPath, "utf8")
  .split(/\r?\n/)
  .filter(Boolean)
  .slice(-initialLimit);

for (const line of initialLines) {
  printLine(line);
}

offset = fs.statSync(logPath).size;

setInterval(() => {
  // size：当前日志文件大小。
  const size = fs.statSync(logPath).size;
  if (size < offset) {
    offset = 0;
  }
  if (size === offset) {
    return;
  }

  // stream：只读取 offset 之后新追加的片段。
  const stream = fs.createReadStream(logPath, {
    start: offset,
    end: size - 1,
    encoding: "utf8",
  });
  // buffer：本轮新增日志片段。
  let buffer = "";
  stream.on("data", (chunk) => {
    buffer += chunk;
  });
  stream.on("end", () => {
    offset = size;
    for (const line of buffer.split(/\r?\n/).filter(Boolean)) {
      printLine(line);
    }
  });
}, pollMs);

/** 将单行 JSONL interaction 日志转换为简洁终端输出。 */
function printLine(line) {
  try {
    // entry：单条 interaction 日志对象。
    const entry = JSON.parse(line);
    if (entry.type === "nonce.issue") {
      console.log(
        `[${entry.ts}] nonce.issue ${entry.request?.remoteAddress || "-"} ` +
          `nonce=${entry.response?.nonce || "-"} expiresInMs=${entry.response?.expiresInMs || "-"} ` +
          `duration=${entry.durationMs}ms`
      );
      return;
    }

    if (entry.type === "key.register") {
      // response/attestation：key.register 的服务端摘要。
      const response = entry.responseSummary || {};
      const attestation = response.attestation || {};
      console.log(
        `[${entry.ts}] key.register ${entry.request?.remoteAddress || "-"} ` +
          `status=${entry.statusCode} user=${response.username || "-"} key=${response.keyId || "-"} ` +
          `curve=${response.namedCurve || "-"} chain=${response.certificateChainCount ?? "-"} ` +
          `attested=${attestation.verified} keyMint=${attestation.keyMintSecurityLevel || "-"} ` +
          `attestation=${attestation.attestationSecurityLevel || "-"} challenge=${attestation.challengeMatched} ` +
          `rootTrusted=${attestation.rootTrusted} root=${shortValue(attestation.rootFingerprint)} ` +
          `duration=${entry.durationMs}ms`
      );
      if (response.error || attestation.reason) {
        console.log(`  reason=${response.error || attestation.reason}`);
      }
      if (attestation.rootSubject || attestation.rootIssuer || attestation.savedRejectedRootPath) {
        console.log(
          `  rootSubject=${attestation.rootSubject || "-"} rootIssuer=${attestation.rootIssuer || "-"} ` +
            `savedRejectedRoot=${attestation.savedRejectedRootPath || "-"}`
        );
      }
      return;
    }

    // response/signature/nonce/request：proof.verify 的关键请求和响应摘要。
    const response = entry.responseSummary || {};
    const signature = response.signature || {};
    const nonce = response.nonce || {};
    const request = entry.requestSummary || {};
    console.log(
      `[${entry.ts}] proof.verify ${entry.request?.remoteAddress || "-"} ` +
        `status=${entry.statusCode} valid=${response.valid} proof=${response.proofValid} ` +
        `sig=${signature.valid} nonce=${nonce.valid}/${nonce.consumed} ` +
        `commitment=${shortValue(request.publicCommitment)} ` +
        `serverNonce=${shortValue(signature.serverNonce || request.tee?.serverNonce)} ` +
        `duration=${entry.durationMs}ms`
    );
    if (signature.reason || nonce.reason || response.error) {
      console.log(`  reason=${signature.reason || nonce.reason || response.error}`);
    }
  } catch (error) {
    console.log(line);
  }
}

/** 缩短 nonce、commitment、fingerprint 等长字符串。 */
function shortValue(value) {
  if (typeof value !== "string" || value.length === 0) {
    return "-";
  }
  return value.length <= 24 ? value : `${value.slice(0, 12)}...${value.slice(-8)}`;
}
