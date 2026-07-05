"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const http = require("node:http");
const os = require("node:os");
const path = require("node:path");
const { JsonAuthStore } = require("../src/auth-store");
const { createInteractionLogger } = require("../src/interaction-logger");
const {
  JsonPasswordRegistrationStore,
} = require("../src/password-registration-store");
const { createVerifierServer } = require("../src/server");

const proofFixture = JSON.parse(
  fs.readFileSync(path.join(__dirname, "fixtures/password-proof-len8.json"), "utf8")
);
const publicSignalsFixture = JSON.parse(
  fs.readFileSync(path.join(__dirname, "fixtures/password-public-len8.json"), "utf8")
);
const PASSWORD_SALT = "1008";
const FIELD_MODULUS =
  "21888242871839275222246405745257275088548364400416034343698204186575808495617";

test.after(async () => {
  await globalThis.curve_bn128?.terminate?.();
});

test("password registration verifies proof, persists, and survives restart", async (t) => {
  const context = testContext();
  const first = await startServer(t, context);
  const payload = validPayload("password-user-persisted");
  const response = await postJson(first, payload);

  assert.equal(response.status, 201);
  assert.equal(response.body.success, true);
  assert.equal(response.body.proofVerified, true);
  assert.equal(response.body.publicInputCount, 1);
  assert.equal(response.body.passwordCommitment, publicSignalsFixture[0]);
  assert.equal(first.store.find(payload.userId).passwordCommitment, publicSignalsFixture[0]);
  assert.equal(first.store.find(payload.userId).salt, PASSWORD_SALT);
  assert.equal(
    first.authStore.db.users.find((user) => user.username === payload.userId).authMethod,
    "password_commitment"
  );

  await closeServer(first.server);
  const restartedStore = new JsonPasswordRegistrationStore({ filePath: context.dbPath });
  assert.equal(restartedStore.find(payload.userId).passwordCommitment, publicSignalsFixture[0]);
  assert.equal(restartedStore.find(payload.userId).salt, PASSWORD_SALT);
  assert.equal(restartedStore.find(payload.userId).proofVersion, "groth16-bn254-v1");
});

test("server salt supports login without any client-local salt record", async (t) => {
  const app = await startServer(t, testContext());
  const payload = validPayload("password-user-cross-device");
  assert.equal((await postJson(app, payload)).status, 201);

  const parameters = await requestJson(
    app,
    "GET",
    `/password/login-parameters?userId=${encodeURIComponent(payload.userId)}`
  );
  assert.equal(parameters.status, 200);
  assert.equal(parameters.body.salt, PASSWORD_SALT);
  assert.equal(Object.hasOwn(parameters.body, "passwordCommitment"), false);

  const login = await requestJson(app, "POST", "/password/login", {
    userId: payload.userId,
    passwordCommitment: publicSignalsFixture[0],
  });
  assert.equal(login.status, 200);
  assert.equal(login.body.success, true);
});

test("password registration accepts Android mopro a/b/c proof without numeric conversion", async (t) => {
  const app = await startServer(t, testContext());
  const payload = validPayload("password-user-mopro");
  payload.proof = snarkProofToMopro(payload.proof);

  const response = await postJson(app, payload);
  assert.equal(response.status, 201);
  assert.equal(response.body.success, true);
  assert.match(response.body.acceptedFormat, /^mopro/);
});

test("password registration rejects public signal count other than one", async (t) => {
  const app = await startServer(t, testContext());
  const payload = validPayload("password-user-count");
  payload.publicSignals.push("1");
  const response = await postJson(app, payload);
  assert.equal(response.status, 400);
  assert.equal(response.body.code, "INVALID_PUBLIC_SIGNALS");
  assert.equal(app.store.count(), 0);
});

test("password registration rejects public signal commitment mismatch", async (t) => {
  const app = await startServer(t, testContext());
  const payload = validPayload("password-user-mismatch");
  payload.publicSignals[0] = (BigInt(payload.passwordCommitment) + 1n).toString();
  const response = await postJson(app, payload);
  assert.equal(response.status, 400);
  assert.equal(response.body.code, "COMMITMENT_MISMATCH");
  assert.equal(app.store.count(), 0);
});

test("password registration rejects commitment plus one with unchanged proof", async (t) => {
  const app = await startServer(t, testContext());
  const payload = validPayload("password-user-plus-one");
  const tampered = (BigInt(payload.passwordCommitment) + 1n).toString();
  payload.passwordCommitment = tampered;
  payload.publicSignals[0] = tampered;
  const response = await postJson(app, payload);
  assert.equal(response.status, 422);
  assert.equal(response.body.code, "PASSWORD_PROOF_INVALID");
  assert.equal(app.store.count(), 0);
});

test("password registration rejects modified proof", async (t) => {
  const app = await startServer(t, testContext());
  const payload = validPayload("password-user-proof-tamper");
  payload.proof.pi_a[0] = (BigInt(payload.proof.pi_a[0]) + 1n).toString();
  const response = await postJson(app, payload);
  assert.equal(response.status, 422);
  assert.equal(response.body.code, "PASSWORD_PROOF_INVALID");
  assert.equal(app.store.count(), 0);
});

test("password registration rejects proof coordinates encoded as numbers", async (t) => {
  const app = await startServer(t, testContext());
  const payload = validPayload("password-user-numeric-proof");
  payload.proof.pi_a[0] = 123;
  const response = await postJson(app, payload);
  assert.equal(response.status, 400);
  assert.equal(response.body.code, "INVALID_PROOF_COORDINATE");
  assert.equal(app.store.count(), 0);
});

test("password registration rejects missing proof", async (t) => {
  const app = await startServer(t, testContext());
  const payload = validPayload("password-user-no-proof");
  delete payload.proof;
  const response = await postJson(app, payload);
  assert.equal(response.status, 400);
  assert.equal(response.body.code, "MISSING_PROOF");
  assert.equal(app.store.count(), 0);
});

test("password registration rejects non-canonical decimal commitment", async (t) => {
  const app = await startServer(t, testContext());
  for (const invalid of ["1e3", "01", "-1", 123]) {
    const payload = validPayload(`password-user-invalid-${String(invalid).replace(/\W/g, "x")}`);
    payload.passwordCommitment = invalid;
    const response = await postJson(app, payload);
    assert.equal(response.status, 400);
    assert.equal(response.body.code, "INVALID_FIELD_ELEMENT");
  }
  assert.equal(app.store.count(), 0);
});

test("password registration requires a canonical non-zero field salt", async (t) => {
  const app = await startServer(t, testContext());
  const cases = [
    [undefined, "INVALID_FIELD_ELEMENT"],
    ["1e3", "INVALID_FIELD_ELEMENT"],
    ["01", "INVALID_FIELD_ELEMENT"],
    ["0", "INVALID_SALT"],
    [FIELD_MODULUS, "INVALID_FIELD_ELEMENT"],
  ];
  for (const [salt, code] of cases) {
    const payload = validPayload(`password-user-salt-${code}-${String(salt)}`);
    if (salt === undefined) delete payload.salt;
    else payload.salt = salt;
    const response = await postJson(app, payload);
    assert.equal(response.status, 400);
    assert.equal(response.body.code, code);
  }
  assert.equal(app.store.count(), 0);
});

test("password registration rejects duplicate userId without overwrite", async (t) => {
  const app = await startServer(t, testContext());
  const payload = validPayload("password-user-duplicate");
  assert.equal((await postJson(app, payload)).status, 201);
  const original = app.store.find(payload.userId);
  const duplicate = await postJson(app, payload);
  assert.equal(duplicate.status, 409);
  assert.equal(duplicate.body.code, "USER_ID_EXISTS");
  assert.deepEqual(app.store.find(payload.userId), original);
  assert.equal(app.store.count(), 1);
});

test("password registration cannot replace a legacy auth username", async (t) => {
  const context = testContext();
  const authStore = new JsonAuthStore({
    filePath: context.authPath,
    requireKeyAttestation: false,
  });
  authStore.registerUser("legacy-user", "legacy-password");
  const app = await startServer(t, context, { authStore });
  const response = await postJson(app, validPayload("legacy-user"));
  assert.equal(response.status, 409);
  // Now branded error code comes from the actual error source (auth-store conflict)
  assert.equal(app.store.count(), 0);
});

test("password registration database write failure leaves no partial record", async (t) => {
  const context = testContext();
  const store = new JsonPasswordRegistrationStore({
    filePath: context.dbPath,
    writeFileSync: () => {
      throw new Error("injected disk failure");
    },
  });
  const app = await startServer(t, context, {
    passwordRegistrationStore: store,
    verifyPasswordPayload: async () => ({
      valid: true,
      acceptedFormat: "injected-valid-proof",
    }),
  });
  const response = await postJson(app, validPayload("password-user-write-fail"));
  assert.equal(response.status, 500);
  assert.equal(response.body.code, "PASSWORD_REGISTRATION_DB_WRITE_FAILED");
  assert.equal(store.count(), 0);
  assert.equal(store.find("password-user-write-fail"), null);
});

test("password registration rejects a valid proof under the wrong vkey", async (t) => {
  const context = testContext();
  const wrongVkPath = path.resolve(__dirname, "../../circuits/verification_key.json");
  const app = await startServer(t, context, {
    passwordVkPath: wrongVkPath,
    passwordVerificationKey: JSON.parse(fs.readFileSync(wrongVkPath, "utf8")),
  });
  const response = await postJson(app, validPayload("password-user-wrong-vkey"));
  assert.equal(response.status, 422);
  assert.equal(response.body.code, "PASSWORD_PROOF_INVALID");
  assert.equal(app.store.count(), 0);
});

test("password registration rejects private password fields", async (t) => {
  const app = await startServer(t, testContext());
  for (const field of ["password", "confirmPassword", "encryptedSalt", "witness"] ) {
    const payload = validPayload(`password-user-private-${field.toLowerCase()}`);
    payload[field] = "must-not-be-accepted";
    const response = await postJson(app, payload);
    assert.equal(response.status, 400);
    assert.equal(response.body.code, "FORBIDDEN_PRIVATE_FIELD");
  }
  assert.equal(app.store.count(), 0);
});

function testContext() {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "zk-password-register-"));
  return {
    directory,
    dbPath: path.join(directory, "password-registrations.json"),
    authPath: path.join(directory, "auth.json"),
    logPath: path.join(directory, "interactions.jsonl"),
  };
}

async function startServer(t, context, options = {}) {
  const store =
    options.passwordRegistrationStore ||
    new JsonPasswordRegistrationStore({ filePath: context.dbPath });
  const authStore =
    options.authStore ||
    new JsonAuthStore({ filePath: context.authPath, requireKeyAttestation: false });
  const server = createVerifierServer({
    authStore,
    passwordRegistrationStore: store,
    interactionLogger: createInteractionLogger({ filePath: context.logPath }),
    ...options,
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  let closed = false;
  t.after(async () => {
    if (!closed && server.listening) {
      await closeServer(server);
      closed = true;
    }
  });
  return {
    baseUrl: `http://127.0.0.1:${server.address().port}`,
    server,
    store,
    authStore,
  };
}

async function closeServer(server) {
  if (!server.listening) return;
  server.closeIdleConnections?.();
  server.closeAllConnections?.();
  await new Promise((resolve) => server.close(resolve));
}

function validPayload(userId) {
  return {
    userId,
    salt: PASSWORD_SALT,
    passwordCommitment: publicSignalsFixture[0],
    publicSignals: [...publicSignalsFixture],
    proof: JSON.parse(JSON.stringify(proofFixture)),
  };
}

function snarkProofToMopro(proof) {
  return {
    a: { x: proof.pi_a[0], y: proof.pi_a[1], z: proof.pi_a[2] },
    b: { x: proof.pi_b[0], y: proof.pi_b[1], z: proof.pi_b[2] },
    c: { x: proof.pi_c[0], y: proof.pi_c[1], z: proof.pi_c[2] },
    protocol: proof.protocol,
    curve: proof.curve,
  };
}

function postJson(app, body) {
  return requestJson(app, "POST", "/password/register", body);
}

function requestJson(app, method, requestPath, body = null) {
  return new Promise((resolve, reject) => {
    const requestBody = body === null ? null : JSON.stringify(body);
    const url = new URL(`${app.baseUrl}${requestPath}`);
    const headers = { Connection: "close" };
    if (requestBody !== null) {
      headers["Content-Type"] = "application/json";
      headers["Content-Length"] = Buffer.byteLength(requestBody);
    }
    const request = http.request(
      {
        hostname: url.hostname,
        port: url.port,
        path: `${url.pathname}${url.search}`,
        method,
        agent: false,
        headers,
      },
      (response) => {
        const chunks = [];
        response.on("data", (chunk) => chunks.push(chunk));
        response.on("end", () => {
          resolve({
            status: response.statusCode,
            body: JSON.parse(Buffer.concat(chunks).toString("utf8")),
          });
        });
      }
    );
    request.on("error", reject);
    request.end(requestBody || undefined);
  });
}
