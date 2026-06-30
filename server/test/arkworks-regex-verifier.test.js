"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { verifyRegexRecordWithArkworks } = require("../src/arkworks-regex-verifier");

test("arkworks regex verifier wrapper accepts valid child result", async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "zk-location-arkworks-"));
  const verifierPath = path.join(dir, "fake-verifier");
  fs.writeFileSync(
    verifierPath,
    "#!/usr/bin/env node\nprocess.stdin.resume(); process.stdin.on('end', () => console.log(JSON.stringify({ valid: true, verifier: 'arkworks' })));\n"
  );
  fs.chmodSync(verifierPath, 0o755);

  const result = await verifyRegexRecordWithArkworks(
    { proof: {}, inputs: ["1"], publicSignals: ["1"] },
    { verifierPath, zkeyPath: "/tmp/fake.zkey", timeoutMs: 5000 }
  );

  assert.deepEqual(result, {
    checked: true,
    valid: true,
    format: "arkworks_mopro",
    error: null,
  });
});

test("arkworks regex verifier wrapper reports missing binary", async () => {
  const result = await verifyRegexRecordWithArkworks(
    { proof: {}, inputs: ["1"], publicSignals: ["1"] },
    { verifierPath: "/tmp/zk-location-missing-verifier", timeoutMs: 5000 }
  );

  assert.equal(result.checked, false);
  assert.equal(result.valid, false);
  assert.equal(result.format, "arkworks_mopro");
  assert.match(result.error, /not found/);
});
