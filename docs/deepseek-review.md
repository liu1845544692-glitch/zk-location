# ZK-Location 项目代码审查报告

审查时间：2026-05-12
审查范围：全项目代码阅读 + 全部测试运行 + smoke 测试

## 1. 测试验证结果

| 测试套件 | 结果 | 备注 |
|----------|------|------|
| server `npm test` | 21/21 通过 | auth-store, nonce-store, proof-format, keystore-signature, key-attestation, interaction-logger |
| server `npm run smoke` | 通过 | snarkjs 格式和 mopro 格式均验证通过 |
| h3-converter `cargo test` | 11/11 通过 | 含坐标映射、Poseidon、跨经线拒绝、分辨率范围等 |
| zk-location `cargo test` | 7/7 通过 | 含真实坐标端到端 proof 生成和验证 |

## 2. 与 ChatGPT 状态文档的对照

逐项验证 `docs/current-status.md` 的声明：

### 2.1 总体协议流程 — 一致

- 注册/登录、Bind key、GNSS 获取、Rust 预处理、ZK proof 生成、Keystore 签名、Send proof 到服务端验证 —— 整个流程代码完整存在且运行通过。
- Payload 格式 `ZK_LOCATION_V1\npublic_commitment=<C>\nserver_nonce=<nonce>` 在 Android 和 server 两端一致（`KeystoreLocationSigner.kt:160-162`，`keystore-signature.js:115-136`）。

### 2.2 关键安全决策 — 一致

- **不在电路内验证 ECDSA**：`areajudge.circom` 确实只有 Poseidon commitment 约束和六边形半平面不等式的 `LessEqThan`，无 ECDSA 相关电路。
- **使用全局绝对定点坐标**：`global_lat_int` / `global_lon_int` 实现方式与文档描述一致（`lat+90 * 1e7`，`lon+180 * 1e7`），无动态 offset 或相对坐标。
- **certificateChain 只在 Bind key 阶段上传**：Android 的 `proofResultToServerPayload`（`LocationProofComponent.kt:1225-1252`）tee 对象只含 `payload` 和 `signature`，不含 `publicKey` 和 `certificateChain`。服务端使用 `activeKeyForUser` 获取已绑定公钥验签（`server.js:178`）。

### 2.3 Circom 电路 — 一致

- `circuits/areajudge.circom`：Poseidon(3) commitment、6 条边半平面约束（pentagon 缺边由 Rust 层补 0=0 恒真约束）、128-bit `LessEqThan` 比较器。
- 公开输入：`public_commitment` + 6 组 `Ax_left/By_left/C_left/Ax_right/By_right/C_right`（共 37 个 public signals）。

### 2.4 Rust 预处理层 — 一致

- `h3-converter/src/lib.rs`：实现 GNSS→H3 cell→边界顶点→全局整数坐标→半平面系数拆分→Poseidon commitment。
- 使用 `h3o` crate、`light-poseidon`（circom 兼容模式）、`getrandom` 生成 salt（范围 `< Fr::MODULUS`）。
- `split_coeff` 将系数拆分为非负左右侧（v>=0 → (0,v)，v<0 → (-v,0)）。
- pentagon 补全逻辑：补 `0<=0` 恒真约束凑满 6 条（`while ax_left.len() < CIRCOM_EDGE_COUNT`）。
- `generate_cell_boundary` 用于 Android 地图展示，返回原始经纬度顶点（非全局整数坐标）。
- H3 resolution 范围已测试 6-15（`test_supported_resolution_range`），低分辨率（返回 7+ 顶点）会正确报错。

### 2.5 Android 客户端 — 一致

- 登录/注册页面、地图显示、GNSS 获取、H3 分辨率选择、Keystore 签名、proof 生成/本地验证、Send proof 均有实现。
- 发送 `/verify-proof` 的数据格式：`{ proof: {a,b,c,protocol,curve}, inputs: [...], tee: {payload, signature} }`，与文档 JSON 一致。
- 输出字段有中文解释（`explainedValue` 函数，`LocationProofComponent.kt:920-923`）。
- 显示兼容完整响应和精简响应（`formatServerProofResponse` 同时处理两种格式）。

### 2.6 服务端 — 一致

- 所有 9 个路由（`/health`、`/auth/register`、`/auth/login`、`/auth/me`、`/keys/register-nonce`、`/keys/register`、`/nonce`、`/verify-proof`、`/logs/interactions`）均已实现。
- snarkjs Groth16 proof 验证、ECDSA P-256 SHA-256 签名验证、commitment 绑定检查、nonce 一次性消费均已实现。
- proof 格式兼容 snarkjs 和 mopro 两种 proof shape（`proofCandidates` 生成两种候选）。
- 支持 `?compact=1` 或 `Prefer: return=minimal` 精简响应。
- Key Attestation 验证：解析 certificateChain、验证 leaf public key 匹配、证书链签名验证、root trust 检查、challenge 匹配、keyMint security level 检查（拒绝 Software）。

### 2.7 Key Attestation — 部分一致

文档说 "Huawei/OEM root 已手动加入本地 trust store"，但实际 `server/trust/local_android_attestation_roots.pem` 中的证书是 **Google 的 "Android Keystore Software Attestation Root"**（Subject: `CN=Android Keystore Software Attestation Root, OU=Android, O=Google, Inc.`），并非 Huawei/OEM root。

这个 Software Attestation Root 用于签发 software-backed 的 attestation 证书链。虽然该 root 已加入 trust store，但 server 在 `registerUserKey` 中仍然会检查 `keyMintSecurityLevel` 是否为 `TrustedEnvironment` 或 `StrongBox`，因此即使 root 可信，software key 依然会被拒绝。这是一个 **安全正确的行为**。

值得注意：被拒绝的 root 目录 `logs/rejected-attestation-roots/51d496ad...pem` 的内容与此 root 完全相同，说明该 root 最初被拒绝后又被手动加入。这与文档描述的工作流一致：**"注意：该文件不会自动变成可信 root，必须人工确认后手动加入"**。

Google root trust store（`google_android_attestation_roots.pem`）存储为 **JSON 数组格式**（每项是一个 PEM 字符串），服务端 `loadTrustedRootCertificates` 中通过 `raw.startsWith("[")` 判断并 JSON.parse 处理，实现正确。

### 2.8 未完成事项 — 一致

文档列出的 5 项未完成事项（攻击/失败用例测试、Key Attestation 解析增强、存储增强、UI 整理、地图离线化）目前均未在代码中找到对应实现，与文档描述一致。

## 3. 发现的 Bug 和问题

### 3.1 [中等] `KeystoreLocationSigner.signCommitment` 传入 `serverNonce` 作为 attestation challenge

**位置**：`KeystoreLocationSigner.kt:59`
```kotlin
fun signCommitment(publicCommitment: String, serverNonce: String): LocationCommitmentSignature {
    ensureKey(serverNonce.toByteArray(StandardCharsets.UTF_8))
```

**问题**：如果 key 在绑定后被意外删除（如 Android Keystore 被系统清理），`signCommitment` 中的 `ensureKey` 会重新生成 key，但 attestation challenge 是当前的 server nonce（用于签名防重放），而非服务端当初签发的 key registration nonce。服务端绑定 key 时期望 registration nonce 作为 challenge（`verifyAndroidKeyAttestation` 中的 `expectedChallenge`），两者不匹配，新生成的 key 无法通过服务端的 Key Attestation 验证。

**影响**：在实际使用中发生概率低（需要 key 被删除 + 用户恰好点击 Sign + 然后再尝试绑定），但逻辑上不够严谨。

### 3.2 [低] `key-attestation.js` 中 `decodeInteger` 使用 JS Number 可能丢失大整数精度

**位置**：`key-attestation.js:358-363`
```js
function decodeInteger(value) {
    let result = 0;
    for (const byte of value) {
        result = (result << 8) | byte;
    }
    return result;
}
```

**问题**：DER 整数可以为任意大小，JS Number 为 53-bit 精度。若 attestation extension 中出现 > 2^53 的整数，会丢失精度。

**影响**：实际 Android Key Attestation 中的版本号和安全级别字段都很小（< 1000），不受影响。但代码健壮性不足。

### 3.3 [低] `childrenOf` 中的 Buffer 处理存在混淆的三元判断

**位置**：`key-attestation.js:329`
```js
const child = parseDer(
    node.value.buffer === undefined
        ? node.value
        : Buffer.from(node.value.buffer, node.value.byteOffset, node.value.byteLength),
    offset - node.valueStart
);
```

**问题**：Node.js 的 Buffer 始终有 `.buffer` 属性（指向底层 ArrayBuffer），因此三元判断永远走 `Buffer.from(...)` 分支。在 Node.js 环境工作正常。代码意图可能是想兼容不同的 Buffer/Uint8Array 类型，但条件判断形式上容易让人疑惑。

**影响**：当前环境无问题。

### 3.4 [低] Google root trust store 为 JSON 数组格式，非传统 PEM

**位置**：`server/trust/google_android_attestation_roots.pem`

整个文件是一个 JSON 数组，每项是 PEM 字符串。服务端通过 `raw.startsWith("[")` 判断并用 `JSON.parse` 处理（`key-attestation.js:131-132`），逻辑正确。但文件名 `.pem` 暗示传统 PEM 格式（多个 `-----BEGIN/END-----` 块），实际是 JSON。

**影响**：无功能影响，但手动维护时可能造成混淆。

### 3.5 [低] `CampusOfflineMap` 使用在线高德瓦片

**位置**：`CampusOfflineMap.kt:50-69`

类名和注释暗示"离线地图"，但实际使用高德在线瓦片 `wprd01.is.autonavi.com`。同时坐标显示时做了 WGS84→GCJ02 偏移转换以匹配高德瓦片的坐标系统，但 ZK proof 中使用的是原始 WGS84 坐标。两者之间仅显示偏移，不影响 proof 正确性。

文档已指出"当前 osmdroid 在线显示已用于验证 UI 和定位点"。

### 3.6 [信息] `onSignCommitment` 中冗余的 `ensureKey` 调用

**位置**：`LocationProofComponent.kt:396-400`
```kotlin
signatureResult = KeystoreLocationSigner.signCommitment(...)
keyRegistration = KeystoreLocationSigner.ensureKey(...)
```

`signCommitment` 内部已调用 `ensureKey`（`KeystoreLocationSigner.kt:59`），外部又调用一次。不影响正确性，但属于冗余调用。

### 3.7 [信息] `/health` 端点泄露内部状态

**位置**：`server.js:48-58`

`GET /health` 返回 `pendingNonces` 数量、`authDb` 路径、`interactionLog` 路径等内部信息。对开发/实验项目无直接影响。

### 3.8 [信息] session token 无过期自动清理

**位置**：`auth-store.js:280-294`

`pruneExpired()` 仅在每次请求时被动清理过期 session。如果长期无请求，过期 session 数据会残留在 JSON 文件中。文档已将此列为待改进项。

## 4. 安全设计审查

### 4.1 正确实现的安全点

- nonce 只有在 signature 和 proof 都通过时才消费（`server.js:327-356`），防止攻击者通过提交无效 proof 消耗 nonce。
- 服务端签名验证使用已绑定的 `activeKey` 公钥（`server.js:178-179`），不接受客户端自带的公钥（当存在已绑定 key 时，`options.publicKeyBase64` 会覆盖客户端提供的公钥）。
- 重放攻击防护：同一 nonce 被消费后，`NonceStore.consume` 已将其删除，再次使用会返回 "Unknown, expired, or already used nonce"。
- 密码存储使用 scrypt + salt（`auth-store.js:322-324`）。
- session token 存储为 SHA-256 哈希（`auth-store.js:326-328`），即使数据库泄露，攻击者也无法直接获取有效 token。
- `verifyAndroidKeyAttestation` 在检查 challenge 匹配时使用 `Buffer.equals`。
- certificateChain 每个证书的签名关系逐个验证（`key-attestation.js:82-86`）。

### 4.2 值得注意的设计选择

- **`verifyNonceForProof` 中，proof 无效时不消费 nonce**：这意味着攻击者可以重复使用同一 nonce 提交多个不同的无效 proof。这是有意为之的设计，因为消费 nonce 后再告知 proof 无效会导致用户需要重新签名（nonce 已废）。当前设计避免了这种 DoS。有效 proof+signature 组合在第一次提交时就消耗 nonce，之后同 nonce 重放会被拒绝。

- **`verifyKeystoreSignature` 的字段别名兼容**：支持 `tee.payload`、`tee.teePayload`、`payload.signedPayload` 等多种字段名。灵活性高但增加了代码复杂度。所有字段在语义上等价，不存在通过选择不同字段名注入不同数据的攻击面。

- **客户端发送 proof 时不携带 `publicKey` 和 `certificateChain`**：服务端完全依赖已绑定的 key 验签。这意味着如果服务端 auth.json 数据丢失，重新绑定后需要新的 key 才能验证之前的证明（proof 本身不依赖 key，但签名验证需要）。

## 5. 代码质量观察

- 服务端代码组织清晰，各模块职责分明，测试覆盖充分。
- Rust 预处理层有丰富的单元测试和集成测试（11+7 个），覆盖正常路径和异常路径。
- Android 代码为单一 Activity 结构，所有 Compose UI 在 `LocationProofComponent.kt` 中，约 1280 行。后续可考虑拆分为独立 Composable 文件。
- Circom 电路注释清晰，约束拆分符合 R1CS 规范（乘法→加法→`LessEqThan`）。
- h3-converter 的 `reject_antimeridian_spanning_cell` 和 pentagon 补全逻辑有防御性检查。

## 6. 总结

**项目实际状态与 `current-status.md` 描述基本一致**。端到端链路（注册/登录→Bind key→GNSS→Poseidon commitment→ZK proof→Keystore 签名→服务端验证）代码完整、测试通过。

**发现的实质性问题**：

1. `local_android_attestation_roots.pem` 包含的是 Google Software Attestation Root 而非 Huawei/OEM root，与文档描述不完全一致（但不影响安全，因为 Software key 仍会被 keyMintSecurityLevel 检查拒绝）。
2. `signCommitment` 中用 server nonce 作为 attestation challenge 在边界情况下可能导致重新生成的 key 无法通过服务端验证。

**无严重安全漏洞**。重放防护、commitment 绑定、Keystore 签名验证、nonce 消费等核心安全逻辑实现正确。代码处于可实验状态。
