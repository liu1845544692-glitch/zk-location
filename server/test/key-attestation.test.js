"use strict";

/*
 * 文件功能：
 * - 测试 Android Key Attestation ASN.1 key description 解析和 trust root 加载。
 *
 * 执行流程：
 * 1. 构造最小 DER key description，确认 challenge/security level 解析正确。
 * 2. 加载 Google root trust store，确认根证书和 fingerprint 数量匹配。
 * 3. 加载逗号分隔的本地额外 root 文件，确认不破坏官方 trust store 解析。
 */
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const {
  DEFAULT_TRUST_ROOTS_PATH,
  certificateToPem,
  loadTrustedRootCertificates,
  loadTrustedRootFingerprints,
  parseKeyDescription,
} = require("../src/key-attestation");

test("parses Android Key Attestation key description challenge", () => {
  // challenge：模拟服务端 key registration nonce。
  const challenge = Buffer.from("nonce-1", "utf8");
  // keyDescription：最小 Android attestation extension keyDescription DER。
  const keyDescription = derSequence([
    derInteger(4),
    derEnumerated(1),
    derInteger(200),
    derEnumerated(2),
    derOctetString(challenge),
    derOctetString(Buffer.alloc(0)),
    derSequence([]),
    derSequence([]),
  ]);

  // parsed：服务端解析出的 attestation 字段。
  const parsed = parseKeyDescription(keyDescription);
  assert.equal(parsed.attestationVersion, 4);
  assert.equal(parsed.attestationSecurityLevel, "TrustedEnvironment");
  assert.equal(parsed.keyMintVersion, 200);
  assert.equal(parsed.keyMintSecurityLevel, "StrongBox");
  assert.equal(parsed.attestationChallenge.toString("utf8"), "nonce-1");
});

test("loads Google Android Attestation root trust store", () => {
  // certificates/fingerprints：官方 trust store 证书和对应 sha256 fingerprint。
  const certificates = loadTrustedRootCertificates(DEFAULT_TRUST_ROOTS_PATH);
  const fingerprints = loadTrustedRootFingerprints(DEFAULT_TRUST_ROOTS_PATH);

  assert.ok(certificates.length >= 2);
  assert.equal(fingerprints.size, certificates.length);
  assert.ok(
    certificates.some((certificate) =>
      certificate.subject.includes("Key Attestation CA")
    )
  );
});

test("loads comma-separated attestation trust root stores", () => {
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "zk-location-roots-"));
  const extraRootPath = path.join(tempDir, "extra.pem");
  const [firstGoogleRoot] = loadTrustedRootCertificates(DEFAULT_TRUST_ROOTS_PATH);
  fs.writeFileSync(extraRootPath, certificateToPem(firstGoogleRoot), "utf8");

  const certificates = loadTrustedRootCertificates(`${DEFAULT_TRUST_ROOTS_PATH},${extraRootPath}`);
  const fingerprints = loadTrustedRootFingerprints(`${DEFAULT_TRUST_ROOTS_PATH},${extraRootPath}`);

  assert.ok(certificates.length >= 3);
  assert.equal(fingerprints.size, loadTrustedRootCertificates(DEFAULT_TRUST_ROOTS_PATH).length);
});

/** 构造 DER SEQUENCE。 */
function derSequence(children) {
  return derTlv(0x30, Buffer.concat(children));
}

/** 构造 DER INTEGER。 */
function derInteger(value) {
  return derTlv(0x02, Buffer.from([value]));
}

/** 构造 DER ENUMERATED。 */
function derEnumerated(value) {
  return derTlv(0x0a, Buffer.from([value]));
}

/** 构造 DER OCTET STRING。 */
function derOctetString(value) {
  return derTlv(0x04, value);
}

/** 构造通用 DER TLV。 */
function derTlv(tag, value) {
  return Buffer.concat([Buffer.from([tag]), derLength(value.length), value]);
}

/** 构造短长度或单字节长格式 DER length。 */
function derLength(length) {
  if (length < 128) {
    return Buffer.from([length]);
  }
  return Buffer.from([0x81, length]);
}
