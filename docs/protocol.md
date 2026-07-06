# ZK-Location 协议文档

更新时间：2026-05-16

本文档固化当前 ZK-Location 主链路协议。当前系统为：

```text
GNSS + Android Keystore/TEE ECDSA + Poseidon commitment + Circom/mopro ZK proof + 服务端 verifier
```

Play Integrity 已删除，不属于当前协议。

## 1. 参与方和信任边界

- Android 客户端：获取 GNSS，经 Rust/mopro 生成 Poseidon commitment 和 ZK proof，调用 Android Keystore/TEE 私钥签名。
- Android Keystore/TEE/StrongBox：生成并保护 ECDSA P-256 私钥，输出 attestation 证书链，后续对 canonical payload 签名。
- 服务端 verifier：管理用户、session、绑定公钥、attestation root trust store、nonce、proof 验证和 ECDSA 验签。

服务端只信任已配置的 attestation root：

- `server/trust/google_android_attestation_roots.pem`
- `server/trust/local_android_attestation_roots.pem`

未知 root 只会被保存到 `server/logs/rejected-attestation-roots/<sha256>.pem` 供人工审查，不会自动加入 trust store。

## 2. 坐标、承诺和电路字段

客户端把 GNSS 经纬度转换为全局绝对定点整数：

```text
global_lat_int = round((lat + 90.0) * 1e7)
global_lon_int = round((lon + 180.0) * 1e7)
```

Poseidon commitment：

```text
x = global_lon_int
y = global_lat_int
public_commitment = Poseidon(x, y, salt)
```

电路私有输入：

- `x`：全局经度定点整数。
- `y`：全局纬度定点整数。
- `salt`：客户端生成的随机盐。

电路公开输入：

- `public_commitment`。
- H3 六边形六条边的半平面系数：`Ax_left`、`By_left`、`C_left`、`Ax_right`、`By_right`、`C_right`。

当前服务端把 `inputs[0]` 视为 proof 的 `public_commitment`，并要求它等于 TEE 签名 payload 中的 `public_commitment`。

## 3. 认证接口

### `POST /auth/register`

请求：

```json
{
  "username": "alice",
  "password": "correct-password"
}
```

成功响应为 `201`：

```json
{
  "user": {
    "id": "usr_...",
    "username": "alice",
    "createdAt": "..."
  },
  "token": "...",
  "tokenType": "Bearer",
  "expiresAt": 1760000000000,
  "expiresInMs": 604800000
}
```

登录/注册响应不返回历史 `activeKey` attestation 摘要。登录成功时服务端会清空该用户旧的 active key，因此当前 Android 客户端登录后不会自动复用之前登录绑定的 key。`Verify key` 只查询当前用户服务端是否已有本次登录后重新绑定的 active key；如果没有，则显示还未生成。只有 `Generate new key and bind` 会请求新的 key registration nonce、重新生成 attested Keystore key 并提交服务端验证。绑定成功后，再点击 `Verify key` 才会显示当前 active key 的 attestation 可信性结果。

### `POST /auth/login`

请求字段同 `/auth/register`。成功响应为 `200`，结构同注册接口。

### `POST /auth/logout`

需要：

```text
Authorization: Bearer <token>
```

成功响应：

```json
{
  "valid": true,
  "revoked": true
}
```

### `GET /auth/me`

需要 bearer token。返回当前用户公开信息。

## 4. 绑定 Android Keystore 公钥

绑定 key 是唯一上传 `certificateChain` 的阶段。后续 `/verify-proof` 不再上传公钥和证书链。

### `POST /keys/register-nonce`

需要 bearer token。

请求体可为空：

```json
{}
```

成功响应：

```json
{
  "nonce": "...",
  "expiresAt": 1760000000000,
  "expiresInMs": 300000
}
```

该 nonce 必须作为 Android Key Attestation challenge 使用。

### `POST /keys/register`

需要 bearer token。

请求：

```json
{
  "nonce": "<register nonce>",
  "publicKey": "<SPKI DER base64>",
  "certificateChain": [
    "<leaf cert DER base64>",
    "<intermediate cert DER base64>",
    "<root cert DER base64>"
  ]
}
```

服务端兼容字段：

- `nonce`、`registerNonce`、`registrationNonce`
- `publicKey`、`publicKeyBase64`、`tee.publicKey`、`tee.publicKeyBase64`
- `certificateChain`、`certificateChainBase64`、`tee.certificateChain`、`tee.certificateChainBase64`

服务端检查：

- `publicKey` 是 EC P-256/prime256v1 SPKI DER。
- leaf certificate public key 等于上传的 `publicKey`。
- 证书链签名关系有效。
- root 在服务端 trust store 中。
- attestation challenge 等于 `/keys/register-nonce` 下发的 nonce。
- `keyMintSecurityLevel` 是 `TrustedEnvironment` 或 `StrongBox`。
- 授权列表包含 `SIGN`、`SHA-256`、EC、P-256。
- 拒绝 Software key。

成功响应为 `201`，核心结构：

```json
{
  "user": {
    "id": "usr_...",
    "username": "alice",
    "activeKey": {
      "id": "key_...",
      "publicKeyFingerprint": "...",
      "active": true,
      "attestation": {
        "rootTrusted": true,
        "keyMintSecurityLevel": "TrustedEnvironment",
        "authorization": {
          "purposeSign": true,
          "digestSha256": true,
          "algorithmEc": true,
          "ecCurveP256": true
        }
      }
    }
  },
  "key": {
    "id": "key_...",
    "publicKeyFingerprint": "...",
    "active": true,
    "certificateChainCount": 3,
    "attestation": {}
  }
}
```

## 5. Key 管理接口

以下接口都需要 bearer token。

### `GET /keys/active`

返回当前用户 active key：

```json
{
  "key": {}
}
```

没有 active key 时：

```json
{
  "key": null
}
```

### `GET /keys`

返回当前用户全部 key 的公开记录：

```json
{
  "keys": []
}
```

### `POST /keys/revoke`

请求：

```json
{
  "keyId": "key_..."
}
```

成功响应：

```json
{
  "key": {
    "id": "key_...",
    "active": false,
    "revokedAt": "..."
  }
}
```

## 6. Proof nonce

### `GET /nonce` 或 `POST /nonce`

不要求登录。返回 proof 签名 nonce：

```json
{
  "nonce": "...",
  "expiresAt": 1760000000000,
  "expiresInMs": 300000
}
```

该 nonce 只用于 `/verify-proof` 的 signed payload。服务端只在 proof 验证通过且签名验证通过后消费 nonce。消费后同一个 nonce 再次提交会被拒绝。

## 7. TEE 签名 payload

Android Keystore 使用用户已绑定私钥签名以下 UTF-8 文本：

```text
ZK_LOCATION_V1
public_commitment=<C>
server_nonce=<nonce>
```

要求：

- 第一行固定为 `ZK_LOCATION_V1`。
- `public_commitment` 必须等于 ZK proof 公开输入 `inputs[0]`。
- `server_nonce` 必须来自 `/nonce`，未过期且未消费。
- 签名算法为 ECDSA P-256 + SHA-256。

服务端使用当前登录用户的 active key 验签；客户端 proof 请求中的公钥字段不会作为信任依据。

## 8. 提交 proof

### `POST /verify-proof`

需要 bearer token。客户端当前请求头：

```text
Content-Type: application/json; charset=utf-8
Accept: application/json
Authorization: Bearer <token>
Prefer: return=minimal
```

当前 Android 发送的最小请求：

```json
{
  "proof": {
    "a": { "x": "...", "y": "...", "z": "..." },
    "b": { "x": ["...", "..."], "y": ["...", "..."], "z": ["...", "..."] },
    "c": { "x": "...", "y": "...", "z": "..." },
    "protocol": "groth16",
    "curve": "bn128"
  },
  "inputs": ["<public_commitment>", "..."],
  "metrics": {
    "h3Resolution": 12,
    "clientProvingTimeMs": 1234
  },
  "tee": {
    "payload": "ZK_LOCATION_V1\npublic_commitment=<C>\nserver_nonce=<nonce>",
    "signature": "<ECDSA signature base64>"
  }
}
```

服务端兼容的公开输入字段：

- `publicSignals`
- `public_inputs`
- `inputs`
- `proofResult.inputs`

服务端兼容的 proof 形态：

- snarkjs：`proof.pi_a`、`proof.pi_b`、`proof.pi_c`
- mopro：`proof.a`、`proof.b`、`proof.c`

服务端验证顺序：

1. bearer token 有效。
2. 当前用户存在 active key。
3. Groth16 proof 验证。
4. 使用 active key 验证 `tee.payload` 和 `tee.signature`。
5. `tee.payload.public_commitment` 等于 `inputs[0]`。
6. proof 和签名均通过后，消费 `tee.payload.server_nonce`。
7. `valid = proofValid && signatureValid && commitmentBound && nonceConsumed`。

`Prefer: return=minimal` 或 `?compact=true` / `?minimal=true` 会返回精简响应：

```json
{
  "valid": true,
  "proofValid": true,
  "signatureValid": true,
  "commitmentBound": true,
  "nonceConsumed": true,
  "acceptedFormat": "mopro",
  "publicInputCount": 37,
  "clientMetrics": {
    "h3Resolution": 12,
    "clientProvingTimeMs": 1234
  },
  "user": {
    "username": "alice",
    "keyId": "key_...",
    "publicKeyFingerprint": "..."
  },
  "reason": null
}
```

不请求 minimal 时，响应会包含 `signature`、`nonce`、`attempts` 等更完整的调试字段。

## 9. 日志、统计和报告

### `GET /health`

返回最小健康状态：

```json
{"status":"ok"}
```

不返回内部路径、密钥指纹、运行指标或诊断信息。

### `GET /logs/interactions?limit=50`（已禁用）

诊断交互日志接口已在 M-11 安全修复中禁用。

### `GET /stats/performance?limit=200`（已禁用）

性能统计接口已在 M-11 安全修复中禁用。

### `GET /reports/latest?limit=200`（已禁用）

实验报告导出接口已在 M-11 安全修复中禁用。

## 10. 错误响应

服务端错误响应统一为：

```json
{
  "valid": false,
  "code": "PROOF_VERIFY_FAILED",
  "error": "Human readable reason",
  "detail": null
}
```

常见错误码：

- `AUTH_REGISTER_FAILED`
- `AUTH_LOGIN_FAILED`
- `AUTH_LOGOUT_FAILED`
- `AUTH_REQUIRED`
- `KEY_NONCE_FAILED`
- `KEY_REGISTER_FAILED`
- `KEY_ACTIVE_FAILED`
- `KEY_LIST_FAILED`
- `KEY_REVOKE_FAILED`
- `PROOF_VERIFY_FAILED`

## 11. 公开字段、私有字段和只用于调试的字段

公开提交给服务端：

- ZK proof。
- `inputs` 中的公开输入，包括 `public_commitment` 和 H3 半平面系数。
- TEE signed payload。
- ECDSA signature。
- bearer token。
- 可选客户端 metrics。

不提交给服务端：

- 明文经纬度。
- `global_lat_int`、`global_lon_int`。
- `salt`。
- Android Keystore 私钥。

只在绑定 key 阶段提交：

- `publicKey`。
- `certificateChain`。

只用于实验展示或调试：

- `publicKeyFingerprint`。
- `acceptedFormat`。
- proof verify attempts。
- interaction logs。
- performance stats。
