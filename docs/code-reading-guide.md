# ZK-Location 代码阅读指南

更新时间：2026-05-16

本文档用于帮助从零阅读当前代码。建议按主链路顺序阅读，不要一开始就钻 UI 或 ASN.1 细节。

## 1. 先看项目背景文档

### `docs/architecture.md`

先建立全局图：

- Android、Rust/mopro、Circom、Keystore、Server 分别负责什么。
- 一次完整 proof 从点击按钮到服务端返回 `valid=true` 的时序。
- 哪些数据是私有，哪些会发给服务端。
- 两个 nonce 的区别。

### `docs/api-and-data.md`

再查字段表：

- 每个 HTTP 接口由谁调用。
- 每个请求/响应字段从哪里生成。
- `public_commitment`、`salt`、`certificateChain`、`tee.payload`、`tee.signature`、`nonce` 分别是什么。
- `valid`、`proofValid`、`signatureValid`、`commitmentBound`、`nonceConsumed` 的关系。

### `docs/current-status.md`

先理解：

- 项目目标。
- 总体协议流程。
- 当前已完成模块。
- Key Attestation 当前状态。
- 当前安全假设和限制。

### `docs/protocol.md`

重点理解：

- `/auth/register`
- `/auth/login`
- `/keys/register-nonce`
- `/keys/register`
- `/nonce`
- `/verify-proof`
- TEE 签名 payload 格式。
- 哪些字段公开，哪些字段私有。

## 2. 看服务端主入口

### `server/src/server.js`

这是服务端 HTTP 路由入口。建议按接口顺序读：

1. `/auth/register`
2. `/auth/login`
3. `/keys/register-nonce`
4. `/keys/register`
5. `/nonce`
6. `/verify-proof`

重点看 `/verify-proof`，它是最终验证入口。

主要理解：

- 服务端如何读取 bearer token。
- 服务端如何查当前用户 active key。
- 服务端如何验证 ZK proof。
- 服务端如何验证 Keystore ECDSA 签名。
- 服务端如何检查 commitment 绑定。
- 服务端如何消费 nonce 防重放。

建议用 `rg` 先定位：

```bash
rg -n "POST /verify-proof|verifyPayload|verifyKeystoreSignature|verifyNonceForProof|activeKeyForUser" server/src/server.js
```

## 3. 看用户、session 和 key 绑定

### `server/src/auth-store.js`

重点函数：

- `registerUser`
- `loginUser`
- `issueKeyRegistrationNonce`
- `registerUserKey`
- `activeKeyForUser`
- `clearActiveKeyForNewLogin`

主要理解：

- 用户和 session token 如何保存。
- 登录成功后为什么会清空旧 active key。
- key registration nonce 如何下发和消费。
- 新 key 如何绑定到当前用户。
- 为什么每次登录后需要重新执行 `Generate new key and bind`。

建议用 `rg` 先定位：

```bash
rg -n "registerUser|loginUser|clearActiveKey|issueKeyRegistrationNonce|registerUserKey|activeKeyForUser" server/src/auth-store.js
```

## 4. 看 Keystore 签名验证

### `server/src/keystore-signature.js`

重点函数：

- `parseCanonicalPayload`
- `verifyKeystoreSignature`

主要理解：

- 服务端如何解析签名 payload：

  ```text
  ZK_LOCATION_V1
  public_commitment=<C>
  server_nonce=<nonce>
  ```

- 服务端如何用当前用户 active key 验证 ECDSA 签名。
- 服务端如何检查 payload 中的 commitment 是否等于 proof 的公开输入。
- 为什么服务端不信任 proof 请求里客户端自带的 public key。

建议用 `rg` 先定位：

```bash
rg -n "parseCanonicalPayload|verifyKeystoreSignature|registeredPublicKey|commitmentBound|serverNonce" server/src/keystore-signature.js
```

## 5. 看 nonce 防重放

### `server/src/nonce-store.js`

重点函数：

- `issue`
- `consume`

主要理解：

- `/nonce` 如何生成一次性 nonce。
- nonce 如何过期。
- 同一个 nonce 为什么只能消费一次。
- 为什么 proof 或签名失败时 nonce 不会被消费。

## 6. 看 Key Attestation 验证

### `server/src/key-attestation.js`

重点函数：

- `verifyAndroidKeyAttestation`
- `verifyCertificateChain`
- `parseKeyDescription`
- `combineAuthorizationLists`

主要理解：

- `certificateChain` 如何解析。
- leaf certificate public key 如何和客户端上传的 public key 对比。
- 证书链签名关系如何检查。
- root 是否在 trust store 中。
- attestation challenge 是否等于 `/keys/register-nonce` 下发的 nonce。
- `keyMintSecurityLevel` 如何检查。
- `SIGN`、`SHA-256`、EC、P-256 授权如何检查。

注意：

- 未知 root 不会自动信任。
- Huawei/OEM root 是人工加入 `server/trust/local_android_attestation_roots.pem` 的实验信任假设。

建议用 `rg` 先定位：

```bash
rg -n "verifyAndroidKeyAttestation|verifyCertificateChain|rootTrusted|challengeMatched|keyMintSecurityLevel|purposeSign|digestSha256|ecCurveP256" server/src/key-attestation.js
```

## 7. 看 Android 主界面和客户端流程

### `zk-location/android/app/src/main/java/com/example/moproapp/LocationProofComponent.kt`

建议不要先从 UI 细节看，而是先搜索这些函数：

- `requestKeyRegistrationNonce`
- `postKeyRegistration`
- `requestServerNonce`
- `postProofToServer`
- `proofResultToServerPayload`
- `formatServerProofResponse`

再看按钮触发逻辑：

- `onVerifyKey`
- `onBindKey`
- `onGenerateProof`
- `onSignCommitment`
- `onSendProofToServer`

主要理解：

- 登录后客户端不会自动生成 key。
- `Verify key` 只查询当前服务端 active key。
- `Generate new key and bind` 会重新生成 Android Keystore key 并上传证书链。
- GNSS 改变后为什么要清空旧 proof 和 signature。
- proof 重新生成后为什么要重新签名。
- 发送 proof 到服务端时请求体包含哪些字段。

建议用 `rg` 先定位：

```bash
rg -n "onBindKey|onVerifyKey|onGetGnss|onGenerateProof|onSignCommitment|onSendProofToServer|postProofToServer|proofResultToServerPayload" zk-location/android/app/src/main/java/com/example/moproapp/LocationProofComponent.kt
```

## 8. 看 Android Keystore 生成和签名

### `zk-location/android/app/src/main/java/com/example/moproapp/KeystoreLocationSigner.kt`

重点函数：

- `createOrReplaceKey`
- `generateKey`
- `signCommitment`
- `canonicalPayload`

主要理解：

- Android Keystore key 如何生成。
- attestation challenge 如何写入 key 生成参数。
- 为什么重新绑定 key 时会删除旧 alias。
- ECDSA P-256 + SHA-256 如何签名 payload。
- 客户端如何本地自检签名。

## 9. 看 GNSS 和地图

### `zk-location/android/app/src/main/java/com/example/moproapp/GnssLocationReader.kt`

主要理解：

- 客户端如何请求一次 GNSS 定位。
- 失败或权限不足时如何回调 UI。

### `zk-location/android/app/src/main/java/com/example/moproapp/CampusOfflineMap.kt`

主要理解：

- 地图如何显示当前位置。
- H3 六边形如何绘制。
- 当前 UI 只用于展示，不参与服务端可信验证。

## 10. 看 Rust 预处理和 H3 输入生成

### `h3-converter/src/lib.rs`

重点理解：

- 经纬度如何转为全局绝对定点整数。
- H3 cell 和六边形顶点如何生成。
- 半平面系数如何生成。
- Poseidon commitment 如何计算。

关键坐标公式：

```text
x = global_lon_int = round((lon + 180.0) * 1e7)
y = global_lat_int = round((lat + 90.0) * 1e7)
```

建议用 `rg` 先定位：

```bash
rg -n "generate_circuit_input|generate_location_parts|global_lon_int|global_lat_int|poseidon_commitment|split_coeff" h3-converter/src/lib.rs
```

## 11. 看 Circom 电路

### `circuits/areajudge.circom`

重点理解：

- 私有输入：位置坐标、salt。
- 公开输入：`public_commitment`、H3 半平面系数。
- 电路如何约束：

  ```text
  Poseidon(x, y, salt) === public_commitment
  ```

- 电路如何判断点是否在目标 H3 六边形内。

注意：

- 电路内不验证 ECDSA。
- ECDSA 签名由服务端普通代码验证。
- `public_commitment` 是 ZK proof 和 TEE 签名之间的绑定点。

## 12. 看测试

### `server/test/verify-proof-attacks.test.js`

这是攻击/失败用例测试。重点看：

- 重放同一个 proof/signature。
- 篡改 commitment。
- 篡改 nonce。
- 换用户提交 proof/signature。
- 未登录提交 proof。
- 登录但未绑定 key 提交 proof。
- 客户端带攻击者 public key 时服务端仍使用 active key。

### `server/test/auth-store.test.js`

重点看：

- 用户注册和登录。
- key registration nonce。
- key 绑定。
- 登录后清空旧 active key。
- 不可信 attestation root 被拒绝。

### 其他测试

- `server/test/keystore-signature.test.js`
- `server/test/nonce-store.test.js`
- `server/test/proof-format.test.js`
- `server/test/key-attestation.test.js`

这些是较小的单元测试，适合在理解对应模块后再看。

## 13. 推荐阅读顺序总结

建议按以下顺序：

1. `docs/current-status.md`
2. `docs/architecture.md`
3. `docs/api-and-data.md`
4. `docs/protocol.md`
5. `server/src/server.js`
6. `server/src/auth-store.js`
7. `server/src/keystore-signature.js`
8. `server/src/nonce-store.js`
9. `server/src/key-attestation.js`
10. `zk-location/android/app/src/main/java/com/example/moproapp/LocationProofComponent.kt`
11. `zk-location/android/app/src/main/java/com/example/moproapp/KeystoreLocationSigner.kt`
12. `zk-location/android/app/src/main/java/com/example/moproapp/GnssLocationReader.kt`
13. `zk-location/android/app/src/main/java/com/example/moproapp/CampusOfflineMap.kt`
14. `h3-converter/src/lib.rs`
15. `zk-location/src/lib.rs`
16. `zk-location/src/circom.rs`
17. `circuits/areajudge.circom`
18. `server/test/verify-proof-attacks.test.js`

## 14. 主链路心智模型

读代码时始终围绕这条线：

```text
登录
-> Generate new key and bind
-> 服务端验证 Key Attestation 并绑定 active key
-> GNSS
-> 生成 Poseidon commitment 和 ZK proof
-> 请求 /nonce
-> Android Keystore 签名 commitment + nonce
-> Send proof to server
-> 服务端验证 proof + signature + commitment binding + nonce
```

每看一个文件，只问一个问题：

```text
这个文件负责主链路里的哪一步？
```

这样最容易把代码读通。

## 15. 按功能阅读路线

如果你不想按文件顺序读，可以按问题来读。

### 路线 A：为什么登录后没有历史 key

目标：理解“每次登录重新验证”的逻辑。

阅读顺序：

1. `server/src/server.js` 中 `/auth/login`
2. `server/src/auth-store.js` 中 `loginUser`
3. `server/src/auth-store.js` 中 `clearActiveKeyForNewLogin`
4. `LocationProofComponent.kt` 中 `loginAction`
5. `LocationProofComponent.kt` 中 `onVerifyKey`

搜索命令：

```bash
rg -n "loginUser|clearActiveKey|activeKey|onVerifyKey|fetchActiveKeySummary" server/src zk-location/android/app/src/main/java/com/example/moproapp/LocationProofComponent.kt
```

读完应该能回答：

- 为什么登录后 `Verify key` 可能显示没有 key。
- 为什么只有 `Generate new key and bind` 会产生新的 attestation 结果。

### 路线 B：key attestation 为什么可信

目标：理解 Android Keystore key 如何被服务端信任。

阅读顺序：

1. `LocationProofComponent.kt` 中 `onBindKey`
2. `LocationProofComponent.kt` 中 `generateNewKeyAndBind`
3. `KeystoreLocationSigner.kt` 中 `createOrReplaceKey`
4. `KeystoreLocationSigner.kt` 中 `generateKeyOnce`
5. `server/src/auth-store.js` 中 `registerUserKey`
6. `server/src/key-attestation.js` 中 `verifyAndroidKeyAttestation`

搜索命令：

```bash
rg -n "onBindKey|generateNewKeyAndBind|createOrReplaceKey|setAttestationChallenge|registerUserKey|verifyAndroidKeyAttestation" zk-location/android/app/src/main/java server/src
```

读完应该能回答：

- `certificateChain` 什么时候上传。
- root trust 在哪里检查。
- 为什么未知 root 不能自动信任。

### 路线 C：位置隐私 proof 怎么生成

目标：理解经纬度如何变成 ZK proof。

阅读顺序：

1. `GnssLocationReader.kt`
2. `LocationProofComponent.kt` 中 `onGenerateProof`
3. `zk-location/src/lib.rs` 中 `generate_location_circuit_input`
4. `h3-converter/src/lib.rs` 中 `generate_circuit_input`
5. `h3-converter/src/lib.rs` 中 `generate_location_parts`
6. `circuits/areajudge.circom`
7. `zk-location/src/circom.rs` 中 `generate_circom_proof`

搜索命令：

```bash
rg -n "requestSingleFix|onGenerateProof|generateLocationCircuitInput|generate_location_circuit_input|generate_circuit_input|generate_location_parts|generate_circom_proof" zk-location h3-converter circuits
```

读完应该能回答：

- 明文经纬度为什么不发给服务端。
- `public_commitment` 如何绑定私有坐标和 salt。
- H3 六边形约束如何变成公开输入。

### 路线 D：proof 和签名如何绑定

目标：理解服务端为什么能确认 proof 是由已绑定 Keystore key 签名。

阅读顺序：

1. `LocationProofComponent.kt` 中 `onSignCommitment`
2. `KeystoreLocationSigner.kt` 中 `signCommitment`
3. `KeystoreLocationSigner.kt` 中 `canonicalPayload`
4. `LocationProofComponent.kt` 中 `proofResultToServerPayload`
5. `server/src/keystore-signature.js` 中 `parseCanonicalPayload`
6. `server/src/keystore-signature.js` 中 `verifyKeystoreSignature`
7. `server/src/server.js` 中 `/verify-proof`

搜索命令：

```bash
rg -n "onSignCommitment|signCommitment|canonicalPayload|proofResultToServerPayload|parseCanonicalPayload|verifyKeystoreSignature|commitmentBound" zk-location/android/app/src/main/java server/src
```

读完应该能回答：

- `inputs[0]` 和 `tee.payload.public_commitment` 为什么必须相等。
- 服务端为什么不用请求里自带的 public key。
- `commitmentBound=false` 代表什么攻击或错误。

### 路线 E：nonce 防重放如何工作

目标：理解同一个 proof/signature 为什么不能重复提交。

阅读顺序：

1. `LocationProofComponent.kt` 中 `requestServerNonce`
2. `KeystoreLocationSigner.kt` 中 `canonicalPayload`
3. `server/src/nonce-store.js`
4. `server/src/server.js` 中 `verifyNonceForProof`
5. `server/test/verify-proof-attacks.test.js` 中 replay 测试

搜索命令：

```bash
rg -n "requestServerNonce|server_nonce|NonceStore|consume|verifyNonceForProof|replay" zk-location/android/app/src/main/java server/src server/test
```

读完应该能回答：

- nonce 为什么放进签名 payload。
- 为什么 proof 或签名失败时不消费 nonce。
- 重放攻击测试断言了哪些字段。
