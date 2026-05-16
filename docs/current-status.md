# ZK-Location 项目状态文档

更新时间：2026-05-16

本文档用于记录当前项目状态。后续每次修改关键功能、协议、接口、安全假设或实验流程时，应同步更新本文档，方便在新对话或上下文压缩后快速恢复项目背景。

## 1. 项目目标

本项目实现一个移动端零知识位置隐私证明系统：

```text
GNSS 定位 + Android Keystore/TEE 硬件签名 + Poseidon 承诺 + ZK proof + 服务端验证
```

核心目标：

- 用户证明自己位于目标 H3 地理围栏内。
- 服务端不直接获得用户明文经纬度。
- 服务端确认 proof 对应的 `public_commitment` 由已绑定的 Android Keystore 硬件密钥签名。
- 服务端通过 nonce 防重放。
- 证书链验证用于确认用户绑定的签名公钥来自可信 Android Keystore/TEE/StrongBox 环境。

## 2. 总体协议流程

当前主流程：

1. 用户在 Android 客户端注册/登录，服务端返回 session token。
2. 客户端点击 `Generate new key and bind`：
   - 服务端下发 key registration nonce（密钥注册随机数）。
   - Android Keystore 生成或使用 attested ECDSA P-256 key。
   - 客户端上传 `publicKey`、`certificateChain`、registration nonce。
   - 服务端验证 Key Attestation、证书链、root trust、challenge、keyMint security level。
   - 服务端将公钥绑定到当前用户。
3. 客户端获取 GNSS 经纬度。
4. Rust 预处理层将经纬度转换为全局绝对定点坐标，并生成 salt 和 Poseidon commitment。
5. 客户端生成 ZK proof：
   - 私有输入：坐标、salt。
   - 公开输入：`public_commitment`、H3 六边形半平面系数。
6. 客户端请求服务端签名 nonce。
7. Android Keystore 使用用户已绑定的私钥签名规范化 payload：

   ```text
   ZK_LOCATION_V1
   public_commitment=<C>
   server_nonce=<nonce>
   ```

8. 客户端发送 proof 到服务端：
   - `proof`
   - `inputs`
   - `tee.payload`
   - `tee.signature`
   - `Authorization: Bearer <token>`
9. 服务端验证：
   - session token。
   - 当前用户是否绑定 active public key。
   - ZK proof。
   - ECDSA 签名。
   - payload 中 commitment 是否等于 proof 公开输入。
   - nonce 是否存在、未过期、未消费。

## 3. 关键安全决策

### 3.1 不在电路内验证 ECDSA

已放弃 Circom 内部验证 TEE ECDSA 签名。原因是 ECDSA 非原生算术约束过高，不适合移动端。

当前方案：

- 电路只证明位置关系和 commitment 一致性。
- ECDSA 签名在服务端普通代码里验证。
- `public_commitment` 作为 ZK proof 和 TEE 签名之间的绑定点。

### 3.2 使用全局绝对定点坐标

已废弃局部中心坐标和动态 offset，避免：

- 相对坐标平移攻击。
- 动态 offset 泄露隐私或阻断服务端独立计算。

当前转换公式：

```text
global_lat_int = round((lat + 90.0) * 1e7)
global_lon_int = round((lon + 180.0) * 1e7)
```

Poseidon commitment 直接使用全局坐标：

```text
x = global_lon_int
y = global_lat_int
C = Poseidon(x, y, salt)
```

### 3.3 certificateChain 只在绑定公钥时发送

`certificateChain` 只在 `Generate new key and bind` 阶段上传一次。

后续 `Send proof to server` 不再发送 `publicKey` 和 `certificateChain`，服务端使用当前登录用户已绑定的公钥验签。

## 4. 已完成模块

### 4.1 Circom 电路

状态：已完成基础版本。

已实现：

- 引入 Poseidon commitment。
- 私有输入包含坐标和 `salt`。
- 公开输入包含 `public_commitment` 和六条边的半平面系数。
- 约束 `Poseidon(x, y, salt) === public_commitment`。
- 进行 H3 六边形范围判断。
- 未引入 ECDSA/签名验证电路。

关键文件：

- `circuits/areajudge.circom`

### 4.2 Rust 预处理层

状态：已完成基础版本。

已实现：

- GNSS 经纬度到全局绝对定点整数。
- salt 生成。
- Poseidon commitment 计算。
- H3 cell 和六边形顶点计算。
- H3 resolution 当前 UI 范围：6-15。
- 使用全局顶点计算半平面系数。

关键文件：

- `h3-converter/src/lib.rs`
- `h3-converter/Cargo.toml`
- `zk-location/src/lib.rs`

### 4.3 Android 客户端

状态：基础功能已完成。

已实现：

- 登录/注册页面。
- 登录后进入主客户端页面。
- 地图显示。
- GNSS 获取。
- H3 分辨率选择。
- 当前定位点、箭头、H3 六边形绘制。
- `Generate new key and bind`。
- Keystore ECDSA P-256 签名。
- proof 生成和本地验证。
- `Send proof to server`。
- 服务端交互结果精简显示。
- 关键输出增加中文解释。

关键文件：

- `zk-location/android/app/src/main/java/com/example/moproapp/LocationProofComponent.kt`
- `zk-location/android/app/src/main/java/com/example/moproapp/KeystoreLocationSigner.kt`
- `zk-location/android/app/src/main/java/com/example/moproapp/GnssLocationReader.kt`
- `zk-location/android/app/src/main/java/com/example/moproapp/CampusOfflineMap.kt`

当前客户端发送 `/verify-proof` 的最小数据：

```json
{
  "proof": "...",
  "inputs": ["..."],
  "tee": {
    "payload": "...",
    "signature": "..."
  }
}
```

### 4.4 服务端 Verifier

状态：基础功能已完成。

已实现：

- `POST /auth/register`
- `POST /auth/login`
- `GET /auth/me`
- `POST /keys/register-nonce`
- `POST /keys/register`
- `GET|POST /nonce`
- `POST /verify-proof`
- `GET /health`
- `GET /logs/interactions`

服务端能力：

- JSON 文件保存 users/sessions/keys。
- session token 鉴权。
- 用户公钥绑定。
- snarkjs Groth16 proof 验证。
- ECDSA P-256 SHA-256 签名验证。
- commitment 绑定检查。
- nonce 一次性消费，防重放。
- Key Attestation 基础解析。
- Android attestation root trust store。
- 拒绝 Software key。
- 支持本地额外 OEM attestation root。
- 交互日志记录。

关键文件：

- `server/src/server.js`
- `server/src/auth-store.js`
- `server/src/key-attestation.js`
- `server/src/keystore-signature.js`
- `server/src/nonce-store.js`
- `server/src/proof-format.js`
- `server/src/interaction-logger.js`

## 5. Key Attestation 当前状态

当前服务端会检查：

- `certificateChain` 是否存在且可解析。
- leaf certificate public key 是否等于客户端上传的 `publicKey`。
- 证书链签名关系。
- 证书链 root 是否在服务端 trust store。
- attestation challenge 是否等于服务端 key registration nonce。
- `keyMintSecurityLevel` 是否为 `TrustedEnvironment` 或 `StrongBox`。
- 拒绝 `Software` key。

Google root trust store：

- `server/trust/google_android_attestation_roots.pem`

本地额外 root trust store：

- `server/trust/local_android_attestation_roots.pem`

当前实验中 Huawei/OEM root 已手动加入本地 trust store，`Generate new key and bind` 已实验成功。

如果 root 不可信，服务端会保存被拒绝 root：

```text
server/logs/rejected-attestation-roots/<sha256>.pem
```

注意：该文件不会自动变成可信 root，必须人工确认后手动加入 `local_android_attestation_roots.pem`。

## 6. 已删除或不再计划实现

### Play Integrity

已从当前方案中删除，后续也不做。

原因：

- 当前项目重点是 Keystore/TEE attestation、ZK proof 和服务端验证链路。
- Play Integrity 依赖 Google 服务和账号配置，不适合作为当前论文主线。

## 7. 当前实验状态

已完成的端到端链路：

```text
注册/登录
-> Generate new key and bind
-> Key Attestation root trust 验证
-> GNSS
-> Poseidon commitment
-> ZK proof
-> Keystore 签名
-> Send proof to server
-> 服务端 proof + signature + nonce 验证
```

已观察到的正常成功结果应包括：

```text
Valid: true
Proof: true
Signature: true
Commitment bound: true
Nonce consumed: true
Root trusted: true
Hardware backed: true
KeyMint security: TrustedEnvironment 或 StrongBox
```

如果 UI 中 `Valid: true` 但 `Signature/Commitment bound/Nonce consumed` 显示 false，通常是客户端兼容旧服务端完整响应的显示解析问题；当前 Android 已修复为兼容完整响应和精简响应。

## 8. 运行方式

### 8.1 启动服务端

```bash
cd server
npm start
```

默认监听：

```text
http://0.0.0.0:3000
```

手机与电脑在同一 WiFi 下，Android 端 server URL 通常填写：

```text
http://<电脑内网 IP>:3000/verify-proof
```

例如：

```text
http://192.168.2.217:3000/verify-proof
```

### 8.2 查看服务端日志

```bash
cd server
npm run logs
```

或：

```bash
curl http://127.0.0.1:3000/logs/interactions?limit=20
```

### 8.3 Android 构建

```bash
cd zk-location/android
ANDROID_HOME=/home/lyy/Android/Sdk ANDROID_SDK_ROOT=/home/lyy/Android/Sdk ./gradlew assembleDebug
```

## 9. 最近验证结果

最近一次已通过：

```text
server npm test: 31 tests passed
server npm run smoke: passed
Android assembleDebug: BUILD SUCCESSFUL
```

## 10. 还需要改进的地方

本节按优先级整理后续改进点。当前主链路已经跑通，接下来重点不是继续堆功能，而是补强安全验证、实验可复现性和论文展示材料。

### 功能性代码状态

用户当前希望先完成所有功能性代码，暂时不做系统性测试。以下功能性代码已实现：

1. Key Attestation 授权列表解析增强。
   - 已解析 key purpose 是否包含 `SIGN`。
   - 已解析 digest 是否包含 `SHA-256`。
   - 已解析 algorithm/curve 是否为 EC/P-256。
   - 已尝试解析 verified boot/device locked 字段。
   - 已将解析结果返回给 Android，并在 Verify key/Generate new key and bind 结果中显示。
   - 服务端现在会拒绝缺少 `SIGN`、`SHA-256`、EC、P-256 授权的 key。

2. 服务端错误响应规范化。
   - 已统一错误结构为 `{ valid, code, error, detail }`。
   - 已为 auth、key registration、proof、key 管理等路径加入稳定错误码。

3. 客户端流程状态约束。
   - GNSS 改变后，会清空旧 proof、旧 signature 和旧 server response。
   - H3 resolution 改变后，会清空旧 proof、旧 signature 和旧 server response。
   - proof 重新生成后，会清空旧 signature。
   - 未完成前置步骤时会禁用或提示对应按钮。
   - 登录/注册成功后，Android 不会自动生成或绑定 key；服务端登录时会清空该用户旧的 active key，避免复用之前登录绑定的 attestation 结果。
   - `Re-verify key` 已改为 `Verify key`，点击后只查询当前用户服务端是否已有本次登录后重新绑定的 active key；如果没有 key，则显示还未生成。
   - `Generate new key and bind` 成功后，再点击 `Verify key` 会显示当前 active key 的 attestation 可信性结果。
   - 只有 `Generate new key and bind` 会请求新的 key registration nonce，重新生成 attested Keystore key，并重新提交 `/keys/register`。
   - Verify key/Generate new key and bind 等操作结果弹窗已支持滚动，避免长字段被窗口遮挡。
   - Android UI 已整理为简约浅色主题：登录卡片、地图主视图、顶部状态栏、proof pipeline 状态条、统一 8dp 圆角按钮和弹窗。
   - Key 摘要中已移除重复的 `Curve` 行，仅保留 attestation 授权中的 `Curve P-256`。
   - 客户端默认显示已精简：隐藏 token、完整 public inputs、完整 payload/signature、公钥指纹等长调试字段。
   - Proof 默认只显示 proving time、public commitment 短摘要和公开输入数量。
   - Signature 默认只显示 signed、commitment 短摘要、nonce 短摘要和本地验签结果。

4. 服务端账号/密钥能力增强。
   - 已增加 `POST /auth/logout`。
   - 已增加 `GET /keys/active`。
   - 已增加 `GET /keys`。
   - 已增加 `POST /keys/revoke`。
   - `POST /auth/register` 和 `POST /auth/login` 响应不再返回历史 `activeKey` attestation 摘要。
   - `POST /auth/login` 成功后会清空该用户旧的 active key，要求本次登录重新执行 `Generate new key and bind`。
   - 仍使用 JSON 文件存储，SQLite 尚未实现。

5. 实验报告导出功能。
   - 已增加 `GET /reports/latest`。
   - 支持 `GET /reports/latest?format=md` 导出 Markdown。
   - Android 已增加 `Export report` 按钮和 Report 查看区。

6. 性能统计功能。
   - Android 端记录本次会话内 proof 生成耗时。
   - Android 端记录发送 proof 到服务端的响应耗时。
   - 服务端已增加 `GET /stats/performance`。
   - Android 已增加 `Server stats` 按钮和 Stats 查看区。

7. 协议文档。
   - 已编写独立 `docs/protocol.md`。
   - 固化 `/keys/register`、`/verify-proof`、nonce、payload、公开/私有字段说明。

剩余功能性代码主要是：

1. UI 结果展示继续整理。
   - 将 Auth、Keystore、Signature、Server Verify 结果组织成更稳定的结果页。
   - 对长字符串增加折叠和复制能力。
   - 保留中文解释，避免主页面被大段日志占满。

2. 可选：地图离线化。
   - 仅在正式实验需要无外网环境时实现。
   - 建议使用自建或授权瓦片源，不直接离线打包未授权公开瓦片。

### P0：必须优先补齐

1. 攻击/失败用例测试。
   - 已新增 `server/test/verify-proof-attacks.test.js`，覆盖 `/verify-proof` HTTP 主链路攻击/失败用例。
   - 已覆盖重放同一个 proof/signature，服务端拒绝并不再次消费 nonce。
   - 已覆盖修改 `public_commitment`，服务端拒绝。
   - 已覆盖修改 `tee.payload` 里的 nonce，服务端拒绝。
   - 已覆盖修改 `tee.payload` 里的 commitment，服务端拒绝。
   - 已覆盖换用户提交别人的 proof/signature，服务端拒绝。
   - 已覆盖未登录提交 proof，服务端拒绝。
   - 已覆盖登录但未绑定 key 提交 proof，服务端拒绝。
   - 已覆盖请求里携带攻击者 public key 时，服务端仍使用当前用户 active key。
   - 已覆盖不可信 Android attestation root 注册被拒绝。
   - 当前 `server npm test`：31 tests passed。

2. Key Attestation 真机复测。
   - 重新执行 `Generate new key and bind`，确认新解析出的 `Purpose SIGN`、`Digest SHA-256`、`Algorithm EC`、`Curve P-256` 都为 true。
   - 记录 `verifiedBootState` 和 `deviceLocked` 是否能在当前 Huawei/OEM 设备上解析出来。
   - 如果真机证书未暴露某些字段，需要在论文中说明字段可用性和设备差异。

3. 实验记录固化。
   - 记录手机型号、Android 版本、Keystore/KeyMint security level。
   - 记录 proof 生成耗时。
   - 记录服务端 proof 验证耗时。
   - 记录签名验证、nonce 消费、root trust 的成功日志。
   - 保存正常通过和攻击失败的截图。

### P1：建议尽快改进

1. 服务端存储正式化。
   - 当前 users/sessions/keys 使用 JSON 文件，实验可用。
   - 后续建议换 SQLite，避免并发写入和数据损坏风险。
   - 增加 key 撤销、重新绑定和 active key 历史记录。
   - 增加 session 过期提示和登出逻辑。

2. 服务端错误响应规范化。
   - 当前错误已经可读，但还可以统一成 `{ valid, code, error, detail }`。
   - 客户端根据 `code` 展示更清楚的错误原因。
   - 区分 proof 错误、签名错误、nonce 错误、auth 错误和 attestation 错误。

3. 客户端流程约束。
   - 当前 UI 已要求登录和绑定 key 后再签名/发送。
   - 还可以进一步限制按钮状态，使流程更难误操作。
   - 例如：GNSS 改变后必须重新生成 proof；proof 改变后必须重新签名。

4. 交互日志和论文材料。
   - 当前 `npm run logs` 已能查看关键交互。
   - 后续可以增加一键导出实验报告 JSON/Markdown。
   - 报告中包含参数、耗时、验证结果和失败原因。

### P2：实验展示和工程体验改进

1. UI 继续整理。
   - 当前 UI 可用，且关键字段已增加中文说明。
   - 后续可把 Auth、Keystore、Signature、Server Verify 分成更清楚的卡片或结果页。
   - 对长字符串继续做折叠/复制按钮。

2. 地图离线化。
   - 当前 osmdroid 在线显示已用于验证 UI 和定位点。
   - 正式实验如需无外网，可做授权/自建瓦片源离线包。
   - 不建议直接离线打包未授权的公开瓦片源。

3. 性能统计。
   - 增加移动端 proof 生成平均耗时统计。
   - 增加不同 H3 resolution 下的耗时和公开输入规模对比。
   - 增加服务端 verify 平均耗时统计。

4. 协议文档化。
   - 已在 `docs/protocol.md` 固化 `/keys/register`、`/verify-proof`、nonce 和 payload 格式。
   - 已明确公开数据、私有数据、只用于调试展示的字段。

### 暂不建议做

- 暂不重新引入 Play Integrity。
- 暂不在 Circom 电路里验证 ECDSA。
- 暂不声称 GNSS 数据能绕过 Android 系统直接进入 TEE。
- 暂不把未知 OEM root 自动加入 trust store。

## 11. 当前安全假设和限制

- 服务端必须保护用户数据库和 trust store。
- 用户 session token 当前是 bearer token，泄露后可冒用登录态。
- 当前 Key Attestation 验证为基础实现，尚未完整覆盖 Android attestation ASN.1 授权列表全部字段。
- Huawei/OEM root 是实验中手动加入本地 trust store 的，论文中需要说明来源和实验信任假设。
- GNSS 原始数据仍经过 Android 系统和应用层，当前项目不声称 GNSS 数据能绕过 Android 系统直接进入 TEE。
- 目前未使用 Play Integrity。

## 12. 后续维护规则

后续每次涉及以下内容时，应更新本文档：

- 协议字段变化。
- Android UI 或交互流程变化。
- 服务端接口变化。
- Key Attestation 验证逻辑变化。
- 电路公开输入或私有输入变化。
- Rust 预处理坐标、H3、Poseidon 逻辑变化。
- 实验结果和测试结论变化。
- 新增或删除安全假设。
