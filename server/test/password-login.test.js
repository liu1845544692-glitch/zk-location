"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const http = require("node:http");
const os = require("node:os");
const path = require("node:path");
const { JsonAuthStore } = require("../src/auth-store");
const { createInteractionLogger } = require("../src/interaction-logger");
const { JsonPasswordRegistrationStore } = require("../src/password-registration-store");
const { createVerifierServer } = require("../src/server");

const USER_ID = "login-test-user";
const COMMITMENT =
  "13693940417314820178939160679535645246900772969026069298266182188455278063402";
const FIELD_MODULUS =
  "21888242871839275222246405745257275088548364400416034343698204186575808495617";
const SALT = "1008";

test("password login succeeds for registered userId and commitment", async (t) => {
  const app = await startServer(t, testContext());
  const response = await postLogin(app, { userId: USER_ID, passwordCommitment: COMMITMENT });
  assert.equal(response.status, 200);
  assert.equal(response.body.success, true);
  assert.equal(response.body.userId, USER_ID);
  assert.equal(response.body.replayProtection, false);
  assert.match(response.body.token, /^[A-Za-z0-9_-]+$/);
  assert.ok(response.body.expiresAt > Date.now());
  assert.equal(app.authStore.authenticateToken(response.body.token).user.username, USER_ID);
});

test("password login parameters returns only the registered salt and circuit version", async (t) => {
  const app = await startServer(t, testContext());
  const response = await getLoginParameters(app, USER_ID);
  assert.equal(response.status, 200);
  assert.deepEqual(response.body, {
    success: true,
    salt: SALT,
    circuitVersion: "password-policy-commitment-v1",
  });
  assert.equal(Object.hasOwn(response.body, "passwordCommitment"), false);
  assert.equal(Object.hasOwn(response.body, "proof"), false);
});

test("password login parameters hides an unknown user", async (t) => {
  const app = await startServer(t, testContext());
  const response = await getLoginParameters(app, "unknown-login-user");
  assert.equal(response.status, 401);
  assert.equal(response.body.code, "INVALID_CREDENTIALS");
});

test("password login parameters requires re-registration for a legacy saltless record", async (t) => {
  const context = testContext();
  fs.writeFileSync(context.dbPath, JSON.stringify({
    version: 1,
    registrations: [{
      userId: USER_ID,
      passwordCommitment: COMMITMENT,
      circuitVersion: "password-policy-commitment-v1",
      proofVersion: "groth16-bn254-v1",
    }],
  }));
  const app = await startServer(t, context, { seed: false });
  assert.equal(app.store.find(USER_ID).saltMissing, true);
  const response = await getLoginParameters(app, USER_ID);
  assert.equal(response.status, 409);
  assert.equal(response.body.code, "ACCOUNT_REQUIRES_REREGISTRATION");
  assert.equal(app.store.find(USER_ID).passwordCommitment, COMMITMENT);
});

test("password login rejects wrong commitment", async (t) => {
  const app = await startServer(t, testContext());
  const response = await postLogin(app, { userId: USER_ID, passwordCommitment: "1" });
  assertInvalidCredentials(response);
  assert.equal(app.store.count(), 1);
});

test("password login cannot take over a legacy auth username", async (t) => {
  const app = await startServer(t, testContext());
  app.authStore.registerUser(USER_ID, "legacy-password");
  const response = await postLogin(app, {
    userId: USER_ID,
    passwordCommitment: COMMITMENT,
  });
  assertInvalidCredentials(response);
});

test("password login rejects commitment plus one", async (t) => {
  const app = await startServer(t, testContext());
  const response = await postLogin(app, {
    userId: USER_ID,
    passwordCommitment: (BigInt(COMMITMENT) + 1n).toString(),
  });
  assertInvalidCredentials(response);
});

test("password login hides whether userId exists", async (t) => {
  const app = await startServer(t, testContext());
  const wrong = await postLogin(app, { userId: USER_ID, passwordCommitment: "1" });
  const missing = await postLogin(app, {
    userId: "unknown-login-user",
    passwordCommitment: COMMITMENT,
  });
  assertInvalidCredentials(missing);
  assert.equal(missing.status, wrong.status);
  assert.equal(missing.body.code, wrong.body.code);
  assert.equal(missing.body.message, wrong.body.message);
});

test("password login rejects missing userId", async (t) => {
  const app = await startServer(t, testContext());
  const response = await postLogin(app, { passwordCommitment: COMMITMENT });
  assert.equal(response.status, 400);
  assert.equal(response.body.code, "INVALID_USER_ID");
});

test("password login rejects missing commitment", async (t) => {
  const app = await startServer(t, testContext());
  const response = await postLogin(app, { userId: USER_ID });
  assert.equal(response.status, 400);
  assert.equal(response.body.code, "INVALID_FIELD_ELEMENT");
});

test("password login rejects non-canonical decimal commitment", async (t) => {
  const app = await startServer(t, testContext());
  for (const invalid of ["1e3", "01", "-1", 123]) {
    const response = await postLogin(app, { userId: USER_ID, passwordCommitment: invalid });
    assert.equal(response.status, 400);
    assert.equal(response.body.code, "INVALID_FIELD_ELEMENT");
  }
});

test("password login rejects commitment outside BN254 scalar field", async (t) => {
  const app = await startServer(t, testContext());
  const response = await postLogin(app, {
    userId: USER_ID,
    passwordCommitment: FIELD_MODULUS,
  });
  assert.equal(response.status, 400);
  assert.equal(response.body.code, "INVALID_FIELD_ELEMENT");
});

test("password login rejects and never uses password or salt fields", async (t) => {
  const app = await startServer(t, testContext());
  const before = app.store.find(USER_ID);
  for (const field of ["password", "salt", "encryptedSalt", "proof", "publicSignals"]) {
    const response = await postLogin(app, {
      userId: USER_ID,
      passwordCommitment: COMMITMENT,
      [field]: "must-not-be-used",
    });
    assert.equal(response.status, 400);
    assert.equal(response.body.code, "FORBIDDEN_PRIVATE_FIELD");
  }
  assert.deepEqual(app.store.find(USER_ID), before);
});

test("password login still succeeds after server store restart", async (t) => {
  const context = testContext();
  const first = await startServer(t, context);
  assert.equal(
    (await postLogin(first, { userId: USER_ID, passwordCommitment: COMMITMENT })).status,
    200
  );
  await closeServer(first.server);

  const restarted = await startServer(t, context, { seed: false });
  const parameters = await getLoginParameters(restarted, USER_ID);
  assert.equal(parameters.status, 200);
  assert.equal(parameters.body.salt, SALT);
  const response = await postLogin(restarted, {
    userId: USER_ID,
    passwordCommitment: COMMITMENT,
  });
  assert.equal(response.status, 200);
  assert.equal(response.body.success, true);
  assert.equal(restarted.store.count(), 1);
});

function assertInvalidCredentials(response) {
  assert.equal(response.status, 401);
  assert.deepEqual(
    {
      success: response.body.success,
      code: response.body.code,
      message: response.body.message,
    },
    {
      success: false,
      code: "INVALID_CREDENTIALS",
      message: "Invalid username or password",
    }
  );
}

function testContext() {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "zk-password-login-"));
  return {
    dbPath: path.join(directory, "password-registrations.json"),
    authPath: path.join(directory, "auth.json"),
    logPath: path.join(directory, "interactions.jsonl"),
  };
}

async function startServer(t, context, options = {}) {
  const store = new JsonPasswordRegistrationStore({ filePath: context.dbPath });
  const authStore = new JsonAuthStore({
    filePath: context.authPath,
    requireKeyAttestation: false,
  });
  if (options.seed !== false && store.count() === 0) {
    store.register({
      userId: USER_ID,
      salt: SALT,
      passwordCommitment: COMMITMENT,
      proofVersion: "groth16-bn254-v1",
      circuitVersion: "password-policy-commitment-v1",
    });
  }
  const server = createVerifierServer({
    authStore,
    passwordRegistrationStore: store,
    interactionLogger: createInteractionLogger({ filePath: context.logPath }),
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  t.after(async () => {
    if (server.listening) await closeServer(server);
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

function postLogin(app, body) {
  return new Promise((resolve, reject) => {
    const requestBody = JSON.stringify(body);
    const url = new URL(`${app.baseUrl}/password/login`);
    const request = http.request(
      {
        hostname: url.hostname,
        port: url.port,
        path: url.pathname,
        method: "POST",
        agent: false,
        headers: {
          "Content-Type": "application/json",
          "Content-Length": Buffer.byteLength(requestBody),
          Connection: "close",
        },
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
    request.end(requestBody);
  });
}

function getLoginParameters(app, userId) {
  return new Promise((resolve, reject) => {
    const url = new URL(`${app.baseUrl}/password/login-parameters`);
    url.searchParams.set("userId", userId);
    const request = http.request(
      {
        hostname: url.hostname,
        port: url.port,
        path: `${url.pathname}${url.search}`,
        method: "GET",
        agent: false,
        headers: { Connection: "close" },
      },
      (response) => {
        const chunks = [];
        response.on("data", (chunk) => chunks.push(chunk));
        response.on("end", () => resolve({
          status: response.statusCode,
          body: JSON.parse(Buffer.concat(chunks).toString("utf8")),
        }));
      }
    );
    request.on("error", reject);
    request.end();
  });
}
