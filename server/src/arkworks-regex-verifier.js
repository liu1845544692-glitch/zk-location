"use strict";

const fs = require("node:fs");
const path = require("node:path");
const { spawn } = require("node:child_process");

const DEFAULT_TIMEOUT_MS = 20_000;

function arkworksRegexVerifierPath() {
  if (process.env.ARKWORKS_REGEX_VERIFIER_BIN) {
    return process.env.ARKWORKS_REGEX_VERIFIER_BIN;
  }
  const repoRoot = path.resolve(__dirname, "../..");
  const releasePath = path.join(
    repoRoot,
    "zk-location/target/release/verify_regex_record_arkworks"
  );
  if (fs.existsSync(releasePath)) {
    return releasePath;
  }
  return path.join(repoRoot, "zk-location/target/debug/verify_regex_record_arkworks");
}

function regexRecordZkeyPath() {
  return path.resolve(__dirname, "../../circuits/regex_record_final.zkey");
}

async function verifyRegexRecordWithArkworks(payload, options = {}) {
  const verifierPath = options.verifierPath || arkworksRegexVerifierPath();
  if (!fs.existsSync(verifierPath)) {
    return {
      checked: false,
      valid: false,
      format: "arkworks_mopro",
      error: `Arkworks verifier binary not found: ${verifierPath}`,
    };
  }

  const timeoutMs = options.timeoutMs || DEFAULT_TIMEOUT_MS;
  const zkeyPath = options.zkeyPath || regexRecordZkeyPath();
  const child = spawn(verifierPath, [zkeyPath], {
    stdio: ["pipe", "pipe", "pipe"],
  });

  let stdout = "";
  let stderr = "";
  let settled = false;

  const resultPromise = new Promise((resolve) => {
    const timeout = setTimeout(() => {
      if (!settled) {
        settled = true;
        child.kill("SIGKILL");
        resolve({
          checked: true,
          valid: false,
          format: "arkworks_mopro",
          error: `Arkworks verifier timed out after ${timeoutMs} ms`,
        });
      }
    }, timeoutMs);

    child.stdout.on("data", (chunk) => {
      stdout += chunk.toString("utf8");
    });
    child.stderr.on("data", (chunk) => {
      stderr += chunk.toString("utf8");
    });
    child.on("error", (error) => {
      if (!settled) {
        settled = true;
        clearTimeout(timeout);
        resolve({
          checked: true,
          valid: false,
          format: "arkworks_mopro",
          error: error.message || String(error),
        });
      }
    });
    child.on("close", (code) => {
      if (settled) return;
      settled = true;
      clearTimeout(timeout);
      resolve(parseVerifierOutput(stdout, stderr, code));
    });
  });

  child.stdin.end(JSON.stringify(payload));
  return resultPromise;
}

function parseVerifierOutput(stdout, stderr, code) {
  try {
    const parsed = JSON.parse(stdout.trim());
    return {
      checked: true,
      valid: parsed.valid === true,
      format: "arkworks_mopro",
      error: parsed.error || (code === 0 ? null : stderr.trim() || `exit ${code}`),
    };
  } catch (error) {
    return {
      checked: true,
      valid: false,
      format: "arkworks_mopro",
      error: stderr.trim() || stdout.trim() || error.message || String(error),
    };
  }
}

module.exports = {
  arkworksRegexVerifierPath,
  verifyRegexRecordWithArkworks,
};
