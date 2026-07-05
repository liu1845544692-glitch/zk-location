"use strict";

// =============================================================================
// key-attestation.js —— Android Keystore Key Attestation 验证
// =============================================================================
//
// 背景知识：
//   Android Keystore 在生成硬件支持的密钥对时，可以同时生成一个 X.509 证书链，
//   其中包含 Key Attestation 扩展（OID 1.3.6.1.4.1.11129.2.1.17）。
//   这个扩展里嵌入了 KeyDescription 结构，描述了：
//     - 密钥是在什么安全环境中生成的（Software / TrustedEnvironment / StrongBox）
//     - 密钥的授权用途（SIGN / ENCRYPT 等）
//     - 设备的 Root of Trust（Verified Boot 状态等）
//     - attestationChallenge（服务端下发的随机数，防止 attestation 重放）
//
// 本文件的职责：
//   1. 解析 X.509 证书链，验证签名关系
//   2. 验证 root 证书在服务端 trust store 中
//   3. 手动解析 DER 编码的 Key Attestation 扩展（因为 Node.js 不直接支持）
//   4. 提取 KeyDescription 中的安全级别、授权列表等信息
//
// DER 解析说明：
//   之所以手写 DER 解析而不是用成熟的 ASN.1 库，是因为：
//   - Node.js 内置的 crypto 模块只支持有限的操作
//   - 我们只需要解析 Key Attestation 这一个特定结构
//   - 避免引入重量级依赖
//   DER (Distinguished Encoding Rules) 是 ASN.1 的一种编码方式，
//   使用 TLV (Tag-Length-Value) 三元组结构。

const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const { PublicError } = require("./public-error");

// Android Key Attestation 扩展的 OID
// 当 X.509 证书的扩展中携带此 OID 时，说明该证书包含 KeyDescription 结构
const ANDROID_KEY_ATTESTATION_OID = "1.3.6.1.4.1.11129.2.1.17";

// Google 官方 Android Keystore Attestation Root 证书存储位置
const DEFAULT_TRUST_ROOTS_PATH = path.resolve(
  __dirname,
  "../trust/google_android_attestation_roots.pem"
);

// 本地额外信任的 OEM root 证书（如 Huawei）
const DEFAULT_LOCAL_TRUST_ROOTS_PATH = path.resolve(
  __dirname,
  "../trust/local_android_attestation_roots.pem"
);

// 被拒绝的 root 证书保存目录（用于手动审核后加入 trust store）
const DEFAULT_REJECTED_ROOTS_DIR = path.resolve(
  __dirname,
  "../logs/rejected-attestation-roots"
);

// ---- Android Keystore 枚举值映射 ----

// KeyDescription.attestationSecurityLevel / keyMintSecurityLevel
const SECURITY_LEVEL = {
  0: "Software",           // 纯软件实现，不可信
  1: "TrustedEnvironment", // TEE 可信执行环境
  2: "StrongBox",          // 独立安全芯片，最高安全级别
};

// AuthorizationList.purposes 中的 key purpose 枚举
const PURPOSE = {
  0: "ENCRYPT",
  1: "DECRYPT",
  2: "SIGN",
  3: "VERIFY",
  4: "WRAP_KEY",
  5: "AGREE_KEY",
  6: "ATTEST_KEY",
};

// AuthorizationList.digests 中的摘要算法枚举
const DIGEST = {
  0: "NONE",
  1: "MD5",
  2: "SHA-1",
  3: "SHA-224",
  4: "SHA-256",
  5: "SHA-384",
  6: "SHA-512",
};

// AuthorizationList.algorithm 中的非对称算法枚举
const KEY_ALGORITHM = {
  1: "RSA",
  3: "EC",
  32: "AES",
  33: "3DES",
  128: "HMAC",
};

// AuthorizationList.ecCurve 中的椭圆曲线枚举
const EC_CURVE = {
  0: "P-224",
  1: "P-256",
  2: "P-384",
  3: "P-521",
};

// RootOfTrust.verifiedBootState 枚举
const VERIFIED_BOOT_STATE = {
  0: "Verified",    // bootloader 验证通过
  1: "SelfSigned",  // 用户自签名 bootloader
  2: "Unverified",  // bootloader 未验证
  3: "Failed",      // 验证失败
};

// ---- Attestation 专用错误类型 (M-11: 继承 PublicError) ----
class AttestationError extends PublicError {
  constructor(message, defKey) {
    super(defKey || "INVALID_ATTESTATION", message);
  }
}

// =============================================================================
// 主入口：验证 Android Keystore Key Attestation
// =============================================================================
// 参数：
//   publicKeyBase64       - 客户端上传的公钥（SPKI DER, Base64 编码）
//   certificateChainBase64 - 证书链数组（每个元素是 DER 证书的 Base64 字符串）
//   expectedChallenge     - 期望的 attestation challenge（服务端下发的 nonce）
//   trustRootsPath        - 可选，指定 trust store 路径
//
// 返回：attestation 的详细信息对象
//
// 验证流程：
//   1. Base64 字符串 → crypto.X509Certificate 对象
//   2. 防篡改：上传的公钥必须等于 leaf 证书中的公钥
//   3. 验证证书链签名关系（每张证书由下一张签名）
//   4. 验证 root 证书在 trust store 中
//   5. 提取 KeyDescription 扩展
//   6. 验证 challenge 与服务端 nonce 一致
//   7. 返回完整的 attestation 信息，供上层判断安全级别和授权
function verifyAndroidKeyAttestation({
  publicKeyBase64,       // 客户端上传的公钥（SPKI DER, Base64 编码）
  certificateChainBase64, // attestation 证书链（DER 证书的 Base64 字符串数组）
  expectedChallenge,     // 期望的 attestation challenge（服务端下发的 key registration nonce）
  trustRootsPath,        // 可选，自定义 trust store 路径
}) {
  // 必须有证书链
  if (!Array.isArray(certificateChainBase64) || certificateChainBase64.length === 0) {
    throw new AttestationError("Missing Android Keystore attestation certificateChain");
  }

  // certificates: X509Certificate 对象数组，certificates[0] 为 leaf，最后一个为 root
  const certificates = certificateChainBase64.map((value, index) => {
    try {
      return new crypto.X509Certificate(Buffer.from(value, "base64"));
    } catch (error) {
      throw new AttestationError("Invalid certificate chain entry", "INVALID_ATTESTATION");
    }
  });

  // uploadedPublicKeyDer: 客户端上传公钥的 DER 编码
  const uploadedPublicKeyDer = Buffer.from(publicKeyBase64, "base64");
  // leafPublicKeyDer: leaf 证书中公钥的 SPKI DER 编码，用于与上传公钥比对
  const leafPublicKeyDer = certificates[0].publicKey.export({ type: "spki", format: "der" });
  if (!leafPublicKeyDer.equals(uploadedPublicKeyDer)) {
    throw new AttestationError("publicKey does not match attestation leaf certificate public key");
  }

  // chain: 证书链验证结果 { verified, rootSelfSigned, rootTrusted, rootFingerprint }
  const chain = verifyCertificateChain(certificates, trustRootsPath);

  // attestation: 解析后的 KeyDescription 对象，包含安全级别、授权列表等
  const attestation = extractFirstAttestation(certificateChainBase64);

  // expectedChallengeBytes: 服务端 nonce 的 UTF-8 字节，与 attestation 中的 challenge 比对
  // 这防止了 attestation 重放攻击（攻击者不能重放旧的 attestation 因为 nonce 不同）
  const expectedChallengeBytes = Buffer.from(expectedChallenge, "utf8");
  if (!attestation.attestationChallenge.equals(expectedChallengeBytes)) {
    throw new AttestationError("Attestation challenge does not match key registration nonce");
  }

  return {
    verified: true,
    challengeMatched: true,
    attestationVersion: attestation.attestationVersion,
    attestationSecurityLevel: attestation.attestationSecurityLevel,
    keyMintVersion: attestation.keyMintVersion,
    keyMintSecurityLevel: attestation.keyMintSecurityLevel,
    softwareEnforced: attestation.softwareEnforced,
    teeEnforced: attestation.teeEnforced,
    authorization: attestation.authorization,
    certificateChainLength: certificates.length,
    certificateChainVerified: chain.verified,
    rootSelfSigned: chain.rootSelfSigned,
    rootTrusted: chain.rootTrusted,
  };
}

// ---- 验证证书链签名关系 + root 是否在 trust store 中 ----
// 证书链中 certificates[i] 由 certificates[i+1] 的私钥签名
// 最后一枚证书（root）必须自签名且在 trust store 中
function verifyCertificateChain(certificates, trustRootsPath) {
  // 逐对验证签名关系：certificates[i] 由 certificates[i+1] 的私钥签名
  for (let index = 0; index < certificates.length - 1; index += 1) {
    if (!certificates[index].verify(certificates[index + 1].publicKey)) {
      throw new AttestationError(
        `certificateChain[${index}] is not signed by certificateChain[${index + 1}]`
      );
    }
  }

  // root: 证书链中最后一枚证书（根证书）
  const root = certificates[certificates.length - 1];
  // rootFingerprint: root 证书的 SHA-256 指纹
  const rootFingerprint = certificateFingerprint(root);
  // trustedFingerprints: trust store 中所有 root 证书指纹的 Set
  const trustedFingerprints = loadTrustedRootFingerprints(trustRootsPath);
  if (!trustedFingerprints.has(rootFingerprint)) {
    throw new AttestationError(
      `Attestation root is not trusted: sha256=${rootFingerprint}`
    );
  }

  return {
    verified: true,
    rootSelfSigned: root.verify(root.publicKey),
    rootTrusted: true,
    rootFingerprint,
  };
}

// ---- 加载 trust store 中所有 root 证书的 SHA-256 指纹集合 ----
function loadTrustedRootFingerprints(filePath) {
  const certificates = loadTrustedRootCertificates(filePath);
  return new Set(certificates.map(certificateFingerprint));
}

// ---- 加载 trust store 中的 root 证书 ----
// 支持 PEM 文件（单个或多个证书）和 JSON 数组格式
function loadTrustedRootCertificates(filePath) {
  // trustRootSpecs: 规范化后的 trust root 文件路径列表 [{ filePath, required }]
  const trustRootSpecs = normalizeTrustRootSpecs(filePath);
  // certificates: 解析后的 X509Certificate 对象数组
  const certificates = [];

  for (const spec of trustRootSpecs) {
    // 可选文件不存在时跳过（例如 local_android_attestation_roots.pem）
    if (!fs.existsSync(spec.filePath)) {
      if (spec.required) {
        throw new AttestationError(`Attestation trust roots file not found: ${spec.filePath}`);
      }
      continue;
    }

    // raw: 文件的原始内容字符串
    const raw = fs.readFileSync(spec.filePath, "utf8").trim();
    if (!raw) {
      if (spec.required) {
        throw new AttestationError(`No trusted attestation roots found in ${spec.filePath}`);
      }
      continue;
    }

    // pemBlocks: 提取出的 PEM 证书块数组
    // 支持两种格式：JSON 数组 ["-----BEGIN CERTIFICATE-----...", ...] 或 PEM 文本
    const pemBlocks = raw.startsWith("[")
      ? JSON.parse(raw)
      : raw.match(/-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/g);
    if (!Array.isArray(pemBlocks) || pemBlocks.length === 0) {
      throw new AttestationError(`No trusted attestation roots found in ${spec.filePath}`);
    }

    for (const [index, pem] of pemBlocks.entries()) {
      try {
        certificates.push(new crypto.X509Certificate(pem));
      } catch (error) {
        throw new AttestationError(
          `Invalid attestation trust root[${index}] in ${spec.filePath}: ${error.message || error}`
        );
      }
    }
  }

  if (certificates.length === 0) {
    throw new AttestationError("No trusted attestation roots configured");
  }

  return certificates;
}

// ---- 规范化 trust root 文件路径配置 ----
// 支持：
//   - 未指定 → 使用默认 Google + 本地 OEM root（后者可选）
//   - 字符串 → 逗号分隔的多路径
//   - 数组 → 路径数组
//   - 环境变量 ATTESTATION_ROOTS_PATHS / ATTESTATION_ROOTS_PATH
function normalizeTrustRootSpecs(filePath) {
  if (filePath === undefined || filePath === null || filePath === "") {
    const configured = process.env.ATTESTATION_ROOTS_PATHS || process.env.ATTESTATION_ROOTS_PATH;
    if (configured) {
      return splitConfiguredTrustPaths(configured).map((configuredPath) => ({
        filePath: configuredPath,
        required: true,
      }));
    }
    return [
      { filePath: DEFAULT_TRUST_ROOTS_PATH, required: true },
      { filePath: DEFAULT_LOCAL_TRUST_ROOTS_PATH, required: false },
    ];
  }

  if (Array.isArray(filePath)) {
    return filePath.map((value) => ({
      filePath: value,
      required: true,
    }));
  }

  return splitConfiguredTrustPaths(filePath).map((value) => ({
    filePath: value,
    required: true,
  }));
}

// ---- 按逗号分割环境变量中的 trust 路径列表 ----
function splitConfiguredTrustPaths(value) {
  return value
    .toString()
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean);
}

// ---- 摘要证书链信息（不验证 root 是否可信，仅做信息提取）----
function summarizeAttestationCertificateChain(certificateChainBase64, trustRootsPath) {
  if (!Array.isArray(certificateChainBase64) || certificateChainBase64.length === 0) {
    return null;
  }

  // certificates: 解析后的 X509Certificate 对象数组
  const certificates = certificateChainBase64.map((value, index) => {
    try {
      return new crypto.X509Certificate(Buffer.from(value, "base64"));
    } catch (error) {
      throw new AttestationError("Invalid certificate chain entry", "INVALID_ATTESTATION");
    }
  });

  // root: 证书链最后一枚（根证书）
  const root = certificates[certificates.length - 1];
  // rootFingerprint: root 证书的 SHA-256 指纹
  const rootFingerprint = certificateFingerprint(root);
  // rootTrusted: root 是否在 trust store 中
  let rootTrusted = false;
  // trustStoreError: 加载 trust store 失败时的错误信息
  let trustStoreError = null;
  try {
    rootTrusted = loadTrustedRootFingerprints(trustRootsPath).has(rootFingerprint);
  } catch (_error) {
    trustStoreError = "Trust store unavailable";
  }

  return {
    certificateChainLength: certificates.length,
    rootSelfSigned: root.verify(root.publicKey),
    rootTrusted,
    trustStoreError,
  };
}

// ---- 将不被信任的 root 证书保存到 rejected-attestation-roots 目录 ----
// 用于后续人工审查，确认后可手动加入 local_android_attestation_roots.pem
function saveRejectedAttestationRoot(certificateChainBase64, outputDir = DEFAULT_REJECTED_ROOTS_DIR) {
  const summary = summarizeAttestationCertificateChain(certificateChainBase64);
  if (!summary || summary.rootTrusted) {
    return null;
  }

  const rootBase64 = certificateChainBase64[certificateChainBase64.length - 1];
  const root = new crypto.X509Certificate(Buffer.from(rootBase64, "base64"));
  // M-11: 内部 fingerprint 仅用于文件命名，不公开
  const fp = certificateFingerprint(root);
  if (typeof fp !== "string" || fp.length === 0) {
    return null; // 安全拒绝，不创建 undefined.pem
  }
  fs.mkdirSync(outputDir, { recursive: true });
  const outputPath = path.join(outputDir, `${fp}.pem`);
  fs.writeFileSync(outputPath, certificateToPem(root), "utf8");
  return outputPath;
}

// ---- 将 X509Certificate 对象转为 PEM 格式字符串 ----
function certificateToPem(certificate) {
  // base64: 证书 DER 编码的 Base64 表示，每 64 字符换行
  const base64 = certificate.raw.toString("base64").match(/.{1,64}/g).join("\n");
  return `-----BEGIN CERTIFICATE-----\n${base64}\n-----END CERTIFICATE-----\n`;
}

// ---- 计算证书的 SHA-256 指纹（十六进制字符串）----
function certificateFingerprint(certificate) {
  return crypto.createHash("sha256").update(certificate.raw).digest("hex");
}

// ---- 遍历证书链，从第一张包含 Key Attestation 扩展的证书中提取 KeyDescription ----
function extractFirstAttestation(certificateChainBase64) {
  for (const certificateBase64 of certificateChainBase64) {
    // certificateDer: 证书的 DER 编码 Buffer
    const certificateDer = Buffer.from(certificateBase64, "base64");
    // extensionValue: Key Attestation 扩展的 extnValue（OCTET STRING 的 value 部分）
    const extensionValue = findCertificateExtension(certificateDer, ANDROID_KEY_ATTESTATION_OID);
    if (extensionValue) {
      return parseKeyDescription(extensionValue);
    }
  }

  throw new AttestationError("Missing Android Key Attestation extension");
}

// ---- 在 X.509 DER 证书中查找指定 OID 的扩展 ----
// X.509 证书结构（简化）：
//   SEQUENCE
//     TBSCertificate (SEQUENCE)
//       ...
//       [3] Extensions (tag 0xa3, context-specific constructed)
//         SEQUENCE OF Extension
//           Extension SEQUENCE {
//             extnId: OID,
//             critical?: BOOLEAN,
//             extnValue: OCTET STRING (tag 0x04)  ← 这里包含嵌套的 DER 数据
//           }
// extnValue 的 value 就是 KeyDescription 的 DER 编码
function findCertificateExtension(certificateDer, oid) {
  // certificate: 根 SEQUENCE 解析节点
  const certificate = parseDer(certificateDer);
  // certificateChildren: Certificate SEQUENCE 的直接子节点
  const certificateChildren = childrenOf(certificate);
  // tbsCertificate: 证书的第一个子节点 = TBSCertificate SEQUENCE
  const tbsCertificate = certificateChildren[0];
  // tbsChildren: TBSCertificate 的子节点，包括 version, serial, signature, issuer, ..., extensions
  const tbsChildren = childrenOf(tbsCertificate);

  // extensionsWrapper: tag 0xa3 = context-specific constructed [3]，在 X.509 中是 extensions 字段
  const extensionsWrapper = tbsChildren.find((node) => node.tag === 0xa3);
  if (!extensionsWrapper) {
    return null;
  }

  // extensions: Extensions SEQUENCE（extensionsWrapper 的第一个子节点）
  const extensions = childrenOf(extensionsWrapper)[0];
  for (const extension of childrenOf(extensions)) {
    // fields: Extension SEQUENCE 的子节点 [extnId OID, critical? BOOLEAN, extnValue OCTET_STRING]
    const fields = childrenOf(extension);
    if (fields.length < 2) continue;
    // extnId: 扩展的 OID 字符串（如 "1.3.6.1.4.1.11129.2.1.17"）
    const extnId = decodeOid(fields[0].value);
    if (extnId !== oid) continue;
    // extnValueNode: extnValue 是 OCTET STRING (tag 0x04)，其 value 是嵌套的 KeyDescription DER 数据
    const extnValueNode = fields.find((node) => node.tag === 0x04);
    if (!extnValueNode) {
      throw new AttestationError("Attestation extension has no extnValue");
    }
    return extnValueNode.value;
  }

  return null;
}

// ---- 解析 KeyDescription SEQUENCE ----
// Android Keystore KeyDescription 结构（Android 文档定义）：
//   SEQUENCE {
//     [0] attestationVersion       INTEGER
//     [1] attestationSecurityLevel ENUMERATED (Software=0, TEE=1, StrongBox=2)
//     [2] keyMintVersion           INTEGER
//     [3] keyMintSecurityLevel     ENUMERATED
//     [4] attestationChallenge     OCTET STRING
//     [5] uniqueId                 OCTET STRING (可能不存在)
//     [6] softwareEnforced         AuthorizationList
//     [7] teeEnforced              AuthorizationList
//   }
//
// 注意：字段编号 5 (uniqueId) 不是所有设备都提供，所以 fields[5] 被跳过，
// fields[6] 是软件授权列表，fields[7] 是 TEE 授权列表
function parseKeyDescription(attestationDer) {
  // sequence: KeyDescription 的根 SEQUENCE 节点
  const sequence = parseDer(attestationDer);
  // fields: KeyDescription SEQUENCE 的 8 个子字段 [0]..[7]
  const fields = childrenOf(sequence);
  if (fields.length < 8) {
    throw new AttestationError("Invalid Android Key Attestation extension schema");
  }

  return {
    // fields[0]: attestationVersion - Key Attestation 格式版本号
    attestationVersion: decodeInteger(fields[0].value),
    // fields[1]: attestationSecurityLevel - 密钥的安全级别（Software/TEE/StrongBox）
    attestationSecurityLevel: securityLevelName(decodeInteger(fields[1].value)),
    // fields[2]: keyMintVersion - KeyMint HAL 版本号
    keyMintVersion: decodeInteger(fields[2].value),
    // fields[3]: keyMintSecurityLevel - KeyMint 的安全级别
    keyMintSecurityLevel: securityLevelName(decodeInteger(fields[3].value)),
    // fields[4]: attestationChallenge - Attestation 的 challenge 字段（服务端 nonce）
    attestationChallenge: fields[4].value,
    // fields[6]: softwareEnforced - 软件层面的授权限制
    softwareEnforced: parseAuthorizationList(fields[6]),
    // fields[7]: teeEnforced - TEE 强制执行的授权限制
    teeEnforced: parseAuthorizationList(fields[7]),
    // authorization: 合并 softwareEnforced 和 teeEnforced，TEE 值优先级更高
    authorization: combineAuthorizationLists(
      parseAuthorizationList(fields[6]),
      parseAuthorizationList(fields[7])
    ),
  };
}

// =============================================================================
// 轻量 DER 解析器
// =============================================================================
// DER 是 ASN.1 的编码格式，每个数据项以 TLV 三元组编码：
//   Tag   (1+ 字节) - 数据类型标识
//   Length (1+ 字节) - 数据内容长度
//   Value (可变长度) - 实际数据内容
//
// Tag 字节结构（第一个字节）：
//   bits 7-6: class (00=UNIVERSAL, 01=APPLICATION, 10=context-specific, 11=PRIVATE)
//   bit 5:    constructed (1=包含子节点, 0=原始值)
//   bits 4-0: tag number (如果全为1则是长格式，后续字节继续编码)

// ---- 解析单个 ASN.1 DER TLV 节点 ----
function parseDer(buffer, offset = 0) {
  // tagInfo: Tag 字节解析结果 { firstByte, tagClass, constructed, tagNumber, bytesRead }
  const tagInfo = readTag(buffer, offset);
  // lengthInfo: Length 字节解析结果 { length, bytesRead }
  const lengthInfo = readLength(buffer, offset + tagInfo.bytesRead);
  // headerLength: Tag + Length 的总字节数
  const headerLength = tagInfo.bytesRead + lengthInfo.bytesRead;
  // valueStart: Value 数据开始的偏移量
  const valueStart = offset + headerLength;
  // valueEnd: Value 数据结束的偏移量（exclusive）
  const valueEnd = valueStart + lengthInfo.length;
  if (valueEnd > buffer.length) {
    throw new AttestationError("Invalid DER length");
  }
  return {
    tag: tagInfo.firstByte,       // Tag 的第一个字节
    tagClass: tagInfo.tagClass,   // Tag class (0=UNIVERSAL, 1=APPLICATION, 2=context-specific, 3=PRIVATE)
    tagNumber: tagInfo.tagNumber, // Tag number（低 5 位或长格式解析后的值）
    constructed: tagInfo.constructed, // constructed 位（是否有子节点）
    start: offset,                // 此节点在 buffer 中的起始偏移
    headerLength,                 // 头部（Tag + Length）的字节数
    length: lengthInfo.length,    // Value 部分的字节数
    valueStart,                   // Value 数据起始偏移
    valueEnd,                     // Value 数据结束偏移（exclusive）
    value: buffer.subarray(valueStart, valueEnd), // Value 部分的 Buffer 视图
  };
}

// ---- 递归解析 constructed 节点的所有子节点 ----
function childrenOf(node) {
  // children: 子节点数组
  const children = [];
  // offset: 当前在 node.value 中的解析偏移
  let offset = 0;
  while (offset < node.value.length) {
    // child: 解析出的子节点
    const child = parseDer(node.value, offset);
    children.push(child);
    // 移动到下一个子节点的起始位置
    offset = child.valueEnd;
  }
  return children;
}

// ---- 读取 DER Tag 字节 ----
function readTag(buffer, offset) {
  // firstByte: DER Tag 部分的第一个字节
  const firstByte = buffer[offset];
  if (firstByte === undefined) {
    throw new AttestationError("Invalid DER tag");
  }
  // tagClass: 高 2 位表示 class（UNIVERSAL=0, APPLICATION=1, context-specific=2, PRIVATE=3）
  const tagClass = (firstByte & 0xc0) >> 6;
  // constructed: bit 5 为 1 表示该节点包含子节点（SEQUENCE, SET 等）
  const constructed = (firstByte & 0x20) !== 0;
  // tagNumber: 低 5 位表示 tag 编号，0x1f 为长格式标志
  let tagNumber = firstByte & 0x1f;
  // bytesRead: Tag 部分已读取的字节数
  let bytesRead = 1;

  // 处理长格式 tag number：tagNumber=0x1f 时，后续字节的 bit7=1 表示还有更多字节
  if (tagNumber === 0x1f) {
    tagNumber = 0;
    while (true) {
      // next: 长格式 tag 的后续字节
      const next = buffer[offset + bytesRead];
      if (next === undefined) {
        throw new AttestationError("Invalid DER long-form tag");
      }
      tagNumber = (tagNumber << 7) | (next & 0x7f);
      bytesRead += 1;
      if ((next & 0x80) === 0) {
        break;
      }
      if (bytesRead > 6) {
        throw new AttestationError("Unsupported DER long-form tag");
      }
    }
  }

  return {
    firstByte,
    tagClass,
    constructed,
    tagNumber,
    bytesRead,
  };
}

// ---- 读取 DER Length 字段 ----
// 短格式（bit7=0）：该字节本身即长度值 (0-127)
// 长格式（bit7=1）：bit6-0 为后续字节数，这些字节组成大端长度值
function readLength(buffer, offset) {
  // first: DER Length 部分的第一个字节
  const first = buffer[offset];
  if ((first & 0x80) === 0) {
    // 短格式：bit7=0，该字节本身即长度值（0-127）
    return { length: first, bytesRead: 1 };
  }
  // byteCount: 长格式时，低 7 位表示后续用于编码长度的字节数
  const byteCount = first & 0x7f;
  if (byteCount === 0 || byteCount > 4) {
    throw new AttestationError("Unsupported DER length form");
  }
  // length: 大端序累加计算的实际长度值
  let length = 0;
  for (let index = 0; index < byteCount; index += 1) {
    length = (length << 8) | buffer[offset + 1 + index];
  }
  return { length, bytesRead: 1 + byteCount };
}

// ---- 将 DER INTEGER 值解码为 JavaScript 整数 ----
function decodeInteger(value) {
  // result: 累加解码的整数值
  let result = 0;
  for (const byte of value) {
    // 大端序：每读一个字节，左移 8 位后累加
    result = (result << 8) | byte;
  }
  return result;
}

// ---- 将 DER OID 值解码为点分数字字符串（如 "1.3.6.1.4.1.11129.2.1.17"）----
// OID 编码规则：第一个字节 = 前两个分量 * 40 + 第二个分量
// 后续每个分量用变长 7-bit 编码，bit7=1 表示还有更多字节
function decodeOid(value) {
  // first: OID 的第一个字节，前两个分量由此编码：first = 分量1*40 + 分量2
  const first = value[0];
  // parts: OID 各分量的数值数组
  const parts = [Math.floor(first / 40), first % 40];
  // current: 变长 7-bit 编码中当前正在累加的分量值
  let current = 0;
  for (const byte of value.subarray(1)) {
    // 每字节低 7 位是有效数据，bit7=1 表示还有更多字节
    current = (current << 7) | (byte & 0x7f);
    if ((byte & 0x80) === 0) {
      // bit7=0 表示当前分量结束
      parts.push(current);
      current = 0;
    }
  }
  return parts.join(".");
}

// ---- 将 security level 数值转为可读字符串 ----
function securityLevelName(value) {
  return SECURITY_LEVEL[value] || `Unknown(${value})`;
}

// ---- 解析 AuthorizationList ----
// AuthorizationList 是一个 SEQUENCE，其中每个元素是 context-specific tagged value。
// Android Keystore 定义的 tag 编号（部分）：
//   Tag 1:  PURPOSE (SET OF INTEGER)
//   Tag 2:  ALGORITHM (INTEGER)
//   Tag 5:  DIGEST (SET OF INTEGER)
//   Tag 10: EC_CURVE (INTEGER)
//   Tag 702: ORIGIN (INTEGER)
//   Tag 704: ROOT_OF_TRUST (SEQUENCE)
//   Tag 705: OS_VERSION (INTEGER)
//   Tag 706: OS_PATCH_LEVEL (INTEGER)
//   Tag 718: VENDOR_PATCH_LEVEL (INTEGER)
//   Tag 719: BOOT_PATCH_LEVEL (INTEGER)
// 完整列表见: https://source.android.com/docs/security/features/keystore-attestation
function parseAuthorizationList(node) {
  // result: 解析后的授权列表对象
  const result = {
    purposes: [],           // 密钥用途集合（SIGN, ENCRYPT 等）
    algorithm: null,        // 非对称算法（EC, RSA 等）
    digests: [],            // 摘要算法集合（SHA-256, SHA-384 等）
    ecCurve: null,          // 椭圆曲线名称（P-256, P-384 等）
    origin: null,           // 密钥来源
    osVersion: null,        // 操作系统版本
    osPatchLevel: null,     // 操作系统安全补丁级别
    vendorPatchLevel: null, // 厂商安全补丁级别
    bootPatchLevel: null,   // bootloader 安全补丁级别
    rootOfTrust: null,      // Root of Trust 信息
    rawTags: [],            // 原始 tag 编号列表（用于调试）
  };

  for (const child of childrenOf(node)) {
    // 只处理 context-specific class 的元素（AuthorizationList 中所有 tag 都是 context-specific）
    if (child.tagClass !== 2) {
      continue;
    }
    result.rawTags.push(child.tagNumber);
    if (child.tagNumber === 1) {
      result.purposes = decodeExplicitIntegerSet(child).map((value) => enumName(PURPOSE, value));
    } else if (child.tagNumber === 2) {
      result.algorithm = enumName(KEY_ALGORITHM, decodeExplicitInteger(child));
    } else if (child.tagNumber === 5) {
      result.digests = decodeExplicitIntegerSet(child).map((value) => enumName(DIGEST, value));
    } else if (child.tagNumber === 10) {
      result.ecCurve = enumName(EC_CURVE, decodeExplicitInteger(child));
    } else if (child.tagNumber === 702) {
      result.origin = decodeExplicitInteger(child);
    } else if (child.tagNumber === 704) {
      result.rootOfTrust = parseRootOfTrust(child);
    } else if (child.tagNumber === 705) {
      result.osVersion = decodeExplicitInteger(child);
    } else if (child.tagNumber === 706) {
      result.osPatchLevel = decodeExplicitInteger(child);
    } else if (child.tagNumber === 718) {
      result.vendorPatchLevel = decodeExplicitInteger(child);
    } else if (child.tagNumber === 719) {
      result.bootPatchLevel = decodeExplicitInteger(child);
    }
  }

  return result;
}

// ---- 合并 softwareEnforced 和 teeEnforced 两个 AuthorizationList ----
// TEE enforced 的项权威性更高（因为是在安全环境中强制执行的），
// 优先取 TEE 值；对于集合类字段取并集。
// 同时生成常见字段的布尔判断，方便上层 if 条件直接使用
function combineAuthorizationLists(softwareEnforced, teeEnforced) {
  // purposes: 两个列表中 purposes 的去重并集
  const purposes = uniqueStrings([...softwareEnforced.purposes, ...teeEnforced.purposes]);
  // digests: 两个列表中 digests 的去重并集
  const digests = uniqueStrings([...softwareEnforced.digests, ...teeEnforced.digests]);
  // algorithm: 算法优先取 TEE 实施的，回退到软件实施的
  const algorithm = teeEnforced.algorithm || softwareEnforced.algorithm || null;
  // ecCurve: 曲线优先取 TEE 实施的
  const ecCurve = teeEnforced.ecCurve || softwareEnforced.ecCurve || null;
  // rootOfTrust: Root of Trust 优先取 TEE 实施的
  const rootOfTrust = teeEnforced.rootOfTrust || softwareEnforced.rootOfTrust || null;
  return {
    purposes,
    digests,
    algorithm,
    ecCurve,
    rootOfTrust,
    // 以下为常用判断的布尔快捷方式
    purposeSign: purposes.includes("SIGN"),          // 是否包含签名用途
    digestSha256: digests.includes("SHA-256"),       // 是否包含 SHA-256 摘要
    algorithmEc: algorithm === "EC",                  // 是否为 EC 算法
    ecCurveP256: ecCurve === "P-256",                 // 是否为 P-256 曲线
    verifiedBootState: rootOfTrust?.verifiedBootState || null, // Verified Boot 状态
    deviceLocked: rootOfTrust?.deviceLocked ?? null,  // 设备是否锁定
  };
}

// ---- 解码 context-specific constructed 节点中的单个 INTEGER 值 ----
function decodeExplicitInteger(node) {
  // children: context-specific 包裹节点的子节点
  const children = childrenOf(node);
  if (children.length === 0) {
    return null;
  }
  // 第一个子节点即为实际的 INTEGER 值
  return decodeInteger(children[0].value);
}

// ---- 解码 context-specific constructed 节点中的 INTEGER SET 值 ----
function decodeExplicitIntegerSet(node) {
  // children: context-specific 包裹节点的子节点
  const children = childrenOf(node);
  if (children.length === 0) {
    return [];
  }
  // inner: 第一个子节点，可能是 SET(0x31) 或 SEQUENCE(0x30) 或单个 INTEGER
  const inner = children[0];
  // SET (0x31) 或 SEQUENCE (0x30) 包含多个 INTEGER
  if (inner.tag !== 0x31 && inner.tag !== 0x30) {
    return [decodeInteger(inner.value)];
  }
  return childrenOf(inner).map((valueNode) => decodeInteger(valueNode.value));
}

// ---- 解析 RootOfTrust SEQUENCE (tag 704) ----
// 结构：
//   SEQUENCE {
//     verifiedBootKey   OCTET STRING  - boot 验证公钥的 SHA-256
//     deviceLocked      BOOLEAN       - 设备是否已锁定
//     verifiedBootState ENUMERATED    - Verified Boot 状态
//     verifiedBootHash  OCTET STRING  - boot 镜像摘要值
//   }
function parseRootOfTrust(node) {
  // children: context-specific 包裹节点的子节点
  const children = childrenOf(node);
  if (children.length === 0) {
    return null;
  }
  // sequence: RootOfTrust SEQUENCE 节点
  const sequence = children[0];
  // fields: RootOfTrust 的 4 个子字段 [verifiedBootKey, deviceLocked, verifiedBootState, verifiedBootHash]
  const fields = childrenOf(sequence);
  return {
    // verifiedBootKeySha256: boot 验证公钥的 SHA-256 指纹（十六进制）
    verifiedBootKeySha256:
      fields[0]?.value ? crypto.createHash("sha256").update(fields[0].value).digest("hex") : null,
    // deviceLocked: 设备是否锁定，BOOLEAN 在 DER 中编码为 0x00 (false) 或 0xff (true)
    deviceLocked: fields[1] ? fields[1].value[0] !== 0 : null,
    // verifiedBootState: Verified Boot 状态（Verified/SelfSigned/Unverified/Failed）
    verifiedBootState: fields[2]
      ? enumName(VERIFIED_BOOT_STATE, decodeInteger(fields[2].value))
      : null,
    // verifiedBootHashSha256: boot 镜像摘要的 SHA-256 指纹
    verifiedBootHashSha256:
      fields[3]?.value ? crypto.createHash("sha256").update(fields[3].value).digest("hex") : null,
  };
}

// ---- 将枚举数值映射为可读字符串名 ----
function enumName(map, value) {
  return map[value] || `Unknown(${value})`;
}

// ---- 字符串数组去重并过滤空值 ----
function uniqueStrings(values) {
  return [...new Set(values.filter((value) => typeof value === "string" && value.length > 0))];
}

module.exports = {
  ANDROID_KEY_ATTESTATION_OID,
  AttestationError,
  DEFAULT_LOCAL_TRUST_ROOTS_PATH,
  DEFAULT_REJECTED_ROOTS_DIR,
  DEFAULT_TRUST_ROOTS_PATH,
  certificateFingerprint,
  certificateToPem,
  loadTrustedRootCertificates,
  loadTrustedRootFingerprints,
  parseKeyDescription,
  parseAuthorizationList,
  saveRejectedAttestationRoot,
  summarizeAttestationCertificateChain,
  verifyAndroidKeyAttestation,
};
