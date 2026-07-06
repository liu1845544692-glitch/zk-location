# ZK Location Verifier

最小可用服务端，验证 Groth16 ZK proof，并验证 Android Keystore ECDSA 签名、commitment 绑定关系、服务端 nonce 防重放和 Key Attestation 证书链信任。Play Integrity 已移除。

## 启动

```bash
cd server
npm install
npm start
```

默认端口是 `3000`，可用环境变量覆盖：

```bash
PORT=8080 npm start
```

签名 nonce 默认 5 分钟过期，可用环境变量覆盖：

```bash
NONCE_TTL_MS=300000 npm start
```

用户、session 和用户公钥默认保存到：

```text
server/data/auth.json
```

也可以显式指定：

```bash
AUTH_DB_PATH=/tmp/zk-location-auth.json npm start
```

Android Key Attestation trusted roots 默认读取：

```text
server/trust/google_android_attestation_roots.pem
```

该文件来自 Android 官方 root bundle：

```text
https://android.googleapis.com/attestation/root
```

也可以显式指定：

```bash
ATTESTATION_ROOTS_PATH=/absolute/path/to/google_android_attestation_roots.pem npm start
```

默认还会额外读取这个本地实验根文件；文件不存在时会自动跳过：

```text
server/trust/local_android_attestation_roots.pem
```

如果你的真机不是 Google attestation root，例如部分国产 Android/OEM 设备，可以在确认该 OEM root 可信后，把 PEM 证书追加到这个文件。也可以用逗号配置多个 trust store：

```bash
ATTESTATION_ROOTS_PATHS=/absolute/path/to/google_roots.pem,/absolute/path/to/local_roots.pem npm start
```

当 `/keys/register` 因 root 不可信失败时，服务端会把被拒绝的 root 证书保存到：

```text
server/logs/rejected-attestation-roots/<sha256>.pem
```

这个文件只是诊断材料，不会自动变成可信根。只有你确认该 root 的来源和指纹后，才应该手动追加到 `server/trust/local_android_attestation_roots.pem`。

默认 verification key 读取顺序：

1. `server/keys/areajudge_verification_key.json`
2. `circuits/verification_key.json`

也可以显式指定：

```bash
VK_PATH=/absolute/path/to/verification_key.json npm start
```

## 重新导出 Verification Key

如果重新生成了 `areajudge_final.zkey`，运行：

```bash
cd server
npm run export:vk
```

这会生成：

```text
server/keys/areajudge_verification_key.json
```

## 交互日志

服务端会把客户端和服务端之间的关键交互写入 JSONL 文件，默认路径：

```text
server/logs/interactions.jsonl
```

HTTP 交互日志接口已在生产环境中禁用（未提供 operator 权限模型）。日志只保存固定字段（时间戳、事件类型、状态码、耗时），不保存完整 proof、签名、证书链、nonce、token 或客户端 IP。

如果要换日志路径：

```bash
INTERACTION_LOG_PATH=/tmp/zk-location-interactions.jsonl npm start
```

## 接口

健康检查：

```bash
curl http://127.0.0.1:3000/health
```

用户注册：

```bash
curl -X POST http://127.0.0.1:3000/auth/register \
  -H 'Content-Type: application/json' \
  -d '{"username":"alice","password":"correct-password"}'
```

响应会返回登录 token：

```json
{
  "user": {
    "id": "usr_...",
    "username": "alice",
    "createdAt": "..."
  },
  "token": "...",
  "tokenType": "Bearer",
  "expiresAt": 1779091200000,
  "expiresInMs": 604800000
}
```

用户登录：

```bash
curl -X POST http://127.0.0.1:3000/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"alice","password":"correct-password"}'
```

查看当前登录用户：

```bash
curl http://127.0.0.1:3000/auth/me \
  -H "Authorization: Bearer $TOKEN"
```

登出当前 session：

```bash
curl -X POST http://127.0.0.1:3000/auth/logout \
  -H "Authorization: Bearer $TOKEN"
```

查看当前用户 active key：

```bash
curl http://127.0.0.1:3000/keys/active \
  -H "Authorization: Bearer $TOKEN"
```

查看当前用户 key 历史：

```bash
curl http://127.0.0.1:3000/keys \
  -H "Authorization: Bearer $TOKEN"
```

撤销某个 key：

```bash
curl -X POST http://127.0.0.1:3000/keys/revoke \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"keyId":"key_..."}'
```

请求用户公钥绑定 nonce：

```bash
curl -X POST http://127.0.0.1:3000/keys/register-nonce \
  -H "Authorization: Bearer $TOKEN"
```

绑定当前用户的 Keystore 公钥：

```bash
curl -X POST http://127.0.0.1:3000/keys/register \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{
    "nonce": "...",
    "publicKey": "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQg...",
    "certificateChain": ["MIIC..."]
  }'
```

当前最小版本会检查：

- 登录 token 有效。
- key 注册 nonce 属于当前用户，未过期且未使用。
- `publicKey` 是 P-256 EC SubjectPublicKeyInfo DER 的 Base64。
- `certificateChain` 可以解析为 X.509 链。
- 证书链签名关系有效。
- leaf certificate 公钥等于上传的 `publicKey`。
- Android Key Attestation 扩展里的 `attestationChallenge` 等于 key 注册 nonce。
- 证书链 root 必须匹配本地 trust store 里的 Google Android Attestation Root。
- `keyMintSecurityLevel` 必须是 `TrustedEnvironment` 或 `StrongBox`；拒绝 `Software` key。
- 授权列表必须包含 `purpose=SIGN`。
- 授权列表必须包含 `digest=SHA-256`。
- 授权列表必须声明 EC/P-256。

默认要求 Key Attestation 验证通过。如果只是模拟器或调试环境，可以临时关闭：

```bash
REQUIRE_KEY_ATTESTATION=false npm start
```

生产环境还应继续补齐 Google attestation root trust store 和证书吊销列表检查。

获取一次性 nonce：

```bash
curl http://127.0.0.1:3000/nonce
```

响应示例：

```json
{
  "nonce": "mXex0Voo6PKkWorE4kFh1aKoL3dr0eDY3BuimB7z0L4",
  "expiresAt": 1778496123456,
  "expiresInMs": 300000
}
```

客户端必须把这个 `nonce` 写入 Keystore 签名 payload 的 `server_nonce` 字段。服务端验证成功后会立即消费该 nonce，同一个签名请求第二次提交会失败。

验证 proof：

```bash
curl -X POST http://127.0.0.1:3000/verify-proof \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  --data @payload.json
```

`/verify-proof` 必须登录，并且当前用户必须已经绑定 active public key。服务端会用该用户保存的公钥验签，不再信任请求里携带的 `tee.publicKey`。

支持两种 payload 形状。

Mopro/Android 原始结构：

```json
{
  "proof": {
    "a": { "x": "...", "y": "...", "z": "..." },
    "b": { "x": ["...", "..."], "y": ["...", "..."], "z": ["...", "..."] },
    "c": { "x": "...", "y": "...", "z": "..." },
    "protocol": "groth16",
    "curve": "bn128"
  },
  "inputs": ["..."]
}
```

Android 可以在同一个请求中附带 Keystore 签名。服务端会验证：

- `tee.signature` 是对 `tee.payload` 原文的 `SHA256withECDSA` 签名。
- 签名公钥来自当前登录用户已绑定的 active public key。
- `tee.payload` 中的 `public_commitment` 等于 proof 的第 0 个公开输入。
- `tee.payload` 中的 `server_nonce` 是服务端 `/nonce` 下发的、未过期且未使用过的一次性 nonce。

```json
{
  "proof": {},
  "inputs": ["18927644135937333428586709000136612019732301258628226719231923099443446417845"],
  "tee": {
    "payload": "ZK_LOCATION_V1\npublic_commitment=18927644135937333428586709000136612019732301258628226719231923099443446417845\nserver_nonce=demo-server-nonce-2026-04-27",
    "signature": "MEUCI..."
  },
  "metrics": {
    "h3Resolution": 9,
    "clientProvingTimeMs": 52
  }
}
```

SnarkJS 标准结构：

```json
{
  "proof": {
    "pi_a": ["...", "...", "..."],
    "pi_b": [["...", "..."], ["...", "..."], ["...", "..."]],
    "pi_c": ["...", "...", "..."],
    "protocol": "groth16",
    "curve": "bn128"
  },
  "publicSignals": ["..."]
}
```

成功响应：

```json
{
  "valid": true,
  "proofValid": true,
  "user": {
    "id": "usr_...",
    "username": "alice",
    "keyId": "key_...",
    "publicKeyFingerprint": "..."
  },
  "publicInputCount": 37,
  "acceptedFormat": "mopro",
  "signature": {
    "checked": true,
    "valid": true,
    "signatureValid": true,
    "commitmentBound": true,
    "payloadCommitment": "...",
    "proofCommitment": "...",
    "payloadVersion": "ZK_LOCATION_V1",
    "serverNonce": "demo-server-nonce-2026-04-27",
    "keySource": "registered_user_key"
  },
  "nonce": {
    "checked": true,
    "valid": true,
    "consumed": true,
    "nonce": "...",
    "issuedAt": 1778495823456,
    "expiresAt": 1778496123456
  },
  "attempts": []
}
```

错误响应统一为：

```json
{
  "valid": false,
  "code": "PROOF_VERIFY_FAILED",
  "error": "...",
  "detail": null
}
```
