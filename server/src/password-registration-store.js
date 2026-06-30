"use strict";

const fs = require("node:fs");
const path = require("node:path");

const DEFAULT_PASSWORD_REGISTRATION_DB_PATH = path.resolve(
  __dirname,
  "../data/password-registrations.json"
);

class PasswordRegistrationStoreError extends Error {
  constructor(statusCode, code, message) {
    super(message);
    this.statusCode = statusCode;
    this.code = code;
  }
}

class JsonPasswordRegistrationStore {
  constructor(options = {}) {
    this.filePath =
      options.filePath ||
      process.env.PASSWORD_REGISTRATION_DB_PATH ||
      DEFAULT_PASSWORD_REGISTRATION_DB_PATH;
    this.now = options.now || (() => Date.now());
    this.writeFileSync = options.writeFileSync || fs.writeFileSync;
    this.renameSync = options.renameSync || fs.renameSync;
    fs.mkdirSync(path.dirname(this.filePath), { recursive: true });
    this.db = this.load();
  }

  register({ userId, salt, passwordCommitment, proofVersion, circuitVersion }) {
    if (this.db.registrations.some((record) => record.userId === userId)) {
      throw new PasswordRegistrationStoreError(
        409,
        "USER_ID_EXISTS",
        "userId already has a password registration"
      );
    }

    const now = new Date(this.now()).toISOString();
    const record = {
      userId,
      salt,
      passwordCommitment,
      createdAt: now,
      updatedAt: now,
      proofVersion,
      circuitVersion,
    };
    const nextDb = {
      version: 2,
      registrations: [...this.db.registrations, record],
    };

    this.persist(nextDb);
    this.db = nextDb;
    return { ...record };
  }

  find(userId) {
    const record = this.db.registrations.find((candidate) => candidate.userId === userId);
    return record ? { ...record } : null;
  }

  count() {
    return this.db.registrations.length;
  }

  load() {
    if (!fs.existsSync(this.filePath)) {
      return { version: 2, registrations: [] };
    }
    const parsed = JSON.parse(fs.readFileSync(this.filePath, "utf8"));
    if (!Array.isArray(parsed.registrations)) {
      throw new Error("Password registration database is missing registrations array");
    }
    return {
      version: 2,
      registrations: parsed.registrations.map((record) => {
        if (typeof record.salt === "string") return record;
        return { ...record, saltMissing: true };
      }),
    };
  }

  persist(nextDb) {
    const temporaryPath = `${this.filePath}.tmp`;
    try {
      this.writeFileSync(temporaryPath, `${JSON.stringify(nextDb, null, 2)}\n`, {
        encoding: "utf8",
        mode: 0o600,
      });
      this.renameSync(temporaryPath, this.filePath);
    } catch (error) {
      try {
        fs.rmSync(temporaryPath, { force: true });
      } catch (_cleanupError) {
        // Preserve the original persistence error.
      }
      throw new PasswordRegistrationStoreError(
        500,
        "PASSWORD_REGISTRATION_DB_WRITE_FAILED",
        `Password registration database write failed: ${error.message || error}`
      );
    }
  }
}

module.exports = {
  DEFAULT_PASSWORD_REGISTRATION_DB_PATH,
  JsonPasswordRegistrationStore,
  PasswordRegistrationStoreError,
};
