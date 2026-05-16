# API 与数据字段说明

更新时间：2026-05-16

本文档用于阅读代码时查字段含义。更完整的协议格式见 `docs/protocol.md`。

## 1. 接口总览

| 接口 | 调用方 | 是否需要 token | 主要作用 |
|---|---|---:|---|
| `POST /auth/register` | Android | 否 | 注册用户并返回 bearer token |
| `POST /auth/login` | Android | 否 | 登录并返回 bearer token，同时清空旧 active key |
| `POST /auth/logout` | Android | 是 | 注销当前 session |
| `GET /auth/me` | Android/调试 | 是 | 查询当前登录用户 |
| `POST /keys/register-nonce` | Android | 是 | 获取 key attestation challenge |
| `POST /keys/register` | Android | 是 | 上传 publicKey 和 certificateChain，绑定 active key |
| `GET /keys/active` | Android | 是 | 查询本次登录后是否已经绑定 active key |
| `GET /keys` | 调试 | 是 | 查询用户 key 记录 |
| `POST /keys/revoke` | 调试 | 是 | 撤销指定 key |
| `GET/POST /nonce` | Android | 否 | 获取 proof 签名防重放 nonce |
| `POST /verify-proof` | Android | 是 | 提交 proof、公开输入和 Keystore 签名给服务端验证 |
| `GET /logs/interactions` | 调试 | 否 | 查看最近交互日志 |
| `GET /stats/performance` | Android/调试 | 否 | 查看性能统计 |
| `GET /reports/latest` | Android/调试 | 否 | 导出实验报告 |

## 2. 登录接口

### `POST /auth/register`

请求字段：

| 字段 | 类型 | 生成位置 | 说明 |
|---|---|---|---|
| `username` | string | Android UI | 用户名，服务端会规范化 |
| `password` | string | Android UI | 实验账号密码 |

响应关键字段：

| 字段 | 类型 | 说明 |
|---|---|---|
| `user.id` | string | 服务端用户 ID |
| `user.username` | string | 规范化后的用户名 |
| `token` | string | bearer session token |
| `expiresAt` | number | session 过期时间戳 |

### `POST /auth/login`

请求字段同注册接口。关键行为是：登录成功后服务端清空该用户旧 active key，所以 Android 登录后不能显示上一次登录留下的 attestation 状态。

## 3. Key 绑定接口

### `POST /keys/register-nonce`

请求体为空 `{}`，需要 bearer token。

响应字段：

| 字段 | 类型 | 说明 |
|---|---|---|
| `nonce` | string | key registration nonce，必须写入 Android Key Attestation challenge |
| `expiresAt` | number | nonce 过期时间 |
| `expiresInMs` | number | 剩余有效毫秒数 |

### `POST /keys/register`

请求字段：

| 字段 | 类型 | 生成位置 | 说明 |
|---|---|---|---|
| `nonce` | string | 服务端 `/keys/register-nonce` | attestation challenge 的期望值 |
| `publicKey` | string | Android Keystore leaf cert | SPKI DER Base64 公钥 |
| `certificateChain` | string[] | Android Keystore | attestation 证书链，每项是 DER Base64 |

服务端验证：

| 检查项 | 文件 | 失败含义 |
|---|---|---|
| `publicKey` 是 EC P-256 SPKI | `server/src/auth-store.js` | 不是项目支持的签名 key |
| leaf cert public key 等于上传 `publicKey` | `server/src/key-attestation.js` | 证书链和公钥不匹配 |
| 证书链签名关系有效 | `server/src/key-attestation.js` | 链被篡改或不完整 |
| root 在 trust store | `server/src/key-attestation.js` | 未知 root，不自动信任 |
| challenge 等于 `nonce` | `server/src/key-attestation.js` | 重放旧 attestation |
| `keyMintSecurityLevel` 是 TEE/StrongBox | `server/src/key-attestation.js` | Software key 被拒绝 |
| 授权包含 `SIGN`、`SHA-256`、EC、P-256 | `server/src/key-attestation.js` | key 用途或算法不符合协议 |

响应字段：

| 字段 | 类型 | 说明 |
|---|---|---|
| `key.id` | string | 服务端 key 记录 ID |
| `key.publicKeyFingerprint` | string | 公钥指纹，用于展示和日志 |
| `key.active` | boolean | 是否成为当前用户 active key |
| `key.certificateChainCount` | number | 上传的证书数量 |
| `key.attestation.rootTrusted` | boolean | root 是否在 trust store |
| `key.attestation.keyMintSecurityLevel` | string | `TrustedEnvironment` 或 `StrongBox` |
| `key.attestation.authorization.purposeSign` | boolean | 授权是否包含签名用途 |
| `key.attestation.authorization.digestSha256` | boolean | 授权是否包含 SHA-256 |
| `key.attestation.authorization.ecCurveP256` | boolean | 授权是否声明 P-256 |

## 4. Proof nonce 和签名字段

### `GET/POST /nonce`

响应字段：

| 字段 | 类型 | 说明 |
|---|---|---|
| `nonce` | string | proof 签名 nonce |
| `expiresAt` | number | nonce 过期时间 |
| `expiresInMs` | number | 剩余有效毫秒数 |

这个 nonce 只用于 `tee.payload` 中的 `server_nonce`，和 key registration nonce 不是同一个东西。

### `tee.payload`

Android Keystore 签名的原文固定为：

```text
ZK_LOCATION_V1
public_commitment=<C>
server_nonce=<nonce>
```

| 字段 | 含义 | 服务端检查 |
|---|---|---|
| `ZK_LOCATION_V1` | payload 版本 | 必须等于固定版本 |
| `public_commitment` | ZK proof 第一个公开输入 | 必须等于 `inputs[0]` |
| `server_nonce` | `/nonce` 下发的一次性 nonce | proof 和签名都通过后消费 |

### `tee.signature`

| 字段 | 类型 | 生成位置 | 说明 |
|---|---|---|---|
| `tee.signature` | string | Android Keystore | ECDSA P-256 + SHA-256 签名，Base64 DER |

服务端使用当前用户 active key 验签，不信任 `/verify-proof` 请求体里额外携带的 public key。

## 5. `/verify-proof` 请求

请求字段：

| 字段 | 类型 | 来源 | 是否公开 | 说明 |
|---|---|---|---:|---|
| `proof` | object | mopro/Circom | 是 | Groth16 proof |
| `inputs` | string[] | mopro/Circom | 是 | 公开输入，`inputs[0]` 是 `public_commitment` |
| `metrics.h3Resolution` | number | Android UI | 是 | 实验统计字段 |
| `metrics.clientProvingTimeMs` | number/null | Android UI | 是 | 客户端证明耗时 |
| `tee.payload` | string | Android 客户端 | 是 | Keystore 签名原文 |
| `tee.signature` | string | Android Keystore | 是 | Keystore 签名 |

当前 Android 最小请求不包含：

- `publicKey`
- `certificateChain`
- 明文经纬度
- `salt`
- Android Keystore 私钥

## 6. `/verify-proof` 响应

精简响应字段：

| 字段 | 类型 | 含义 |
|---|---|---|
| `valid` | boolean | 最终结果，全部检查通过才为 true |
| `proofValid` | boolean | Groth16 proof 是否通过 |
| `signatureValid` | boolean | ECDSA 签名是否通过 |
| `commitmentBound` | boolean | payload commitment 是否等于 proof commitment |
| `nonceConsumed` | boolean | nonce 是否成功消费 |
| `acceptedFormat` | string | 服务端接受的 proof 格式，通常为 `mopro` |
| `publicInputCount` | number | 公开输入数量 |
| `user.username` | string | 当前登录用户 |
| `user.keyId` | string | 服务端使用的 active key ID |
| `reason` | string/null | 失败原因或补充说明 |

最终判断公式：

```text
valid = proofValid && signatureValid && commitmentBound && nonceConsumed
```

## 7. 坐标和电路字段

当前代码里的坐标对应关系：

| 字段 | 来源 | 是否私有 | 说明 |
|---|---|---:|---|
| `x` | `global_lon_int(lon)` | 是 | 经度转全局非负整数 |
| `y` | `global_lat_int(lat)` | 是 | 纬度转全局非负整数 |
| `salt` | 随机数 | 是 | Poseidon commitment 盲化值 |
| `public_commitment` | `Poseidon(x, y, salt)` | 否 | 公开承诺 |
| `Ax_left` | H3 边界预处理 | 否 | left side 的 x 系数 |
| `By_left` | H3 边界预处理 | 否 | left side 的 y 系数 |
| `C_left` | H3 边界预处理 | 否 | left side 常数项 |
| `Ax_right` | H3 边界预处理 | 否 | right side 的 x 系数 |
| `By_right` | H3 边界预处理 | 否 | right side 的 y 系数 |
| `C_right` | H3 边界预处理 | 否 | right side 常数项 |

坐标转换公式：

```text
x = round((lon + 180.0) * 1e7)
y = round((lat + 90.0) * 1e7)
```

电路验证：

```text
Poseidon(x, y, salt) === public_commitment
Ax_left[i] * x + By_left[i] * y + C_left[i]
  <=
Ax_right[i] * x + By_right[i] * y + C_right[i]
```

## 8. 字段从哪里读代码

| 你想理解的字段 | 首先看 |
|---|---|
| `token` | `server/src/auth-store.js`、`LocationProofComponent.kt::postAuth` |
| `nonce` for key binding | `server/src/auth-store.js::issueKeyRegistrationNonce` |
| `certificateChain` | `KeystoreLocationSigner.kt`、`server/src/key-attestation.js` |
| `public_commitment` | `h3-converter/src/lib.rs::poseidon_commitment` |
| `proof.inputs` | `zk-location/src/circom.rs::generate_circom_proof` |
| `tee.payload` | `KeystoreLocationSigner.kt::canonicalPayload` |
| `tee.signature` | `KeystoreLocationSigner.kt::signCommitment` |
| `signatureValid` | `server/src/keystore-signature.js::verifyKeystoreSignature` |
| `nonceConsumed` | `server/src/server.js::verifyNonceForProof` |
| `rootTrusted` | `server/src/key-attestation.js::verifyAndroidKeyAttestation` |

