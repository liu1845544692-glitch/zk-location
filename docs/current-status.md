# ZK-Location 项目状态文档

更新时间：2026-06-29

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

> 2026-06-18 更新：Android 移动端 UI 仍不显示位置证明 `Proof pipeline` 状态条，但 `Location` 面板已恢复 `Generate proof`、`Verify proof`、`Sign commitment` 和 `Send proof to server`。手机端可用当前 GNSS 经纬度和 H3 resolution 生成/本地验证 `areajudge_final.zkey` 位置 proof，随后获取服务端 nonce，用已绑定 Android Keystore key 签名 `public_commitment`，并把 proof + signature 发送到服务端 `/verify-proof`。

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
- `circuits/regex-ip.circom`
- `circuits/uint_decimal_field.circom`
- `circuits/port_trans.circom`
- `circuits/unit.circom`
- `circuits/protocol_regex.circom`
- `circuits/regex_record.circom`

新增 IPv4 正则 proof 电路：

- 客户端输入 IPv4 字符串。
- Android 端把每段左补零为固定格式 `ddd.ddd.ddd.ddd`，例如 `192.168.1.12 -> 192.168.001.012`。
- 电路私有输入为 15 个 ASCII 字节 `msg[15]`。
- 电路约束：
  - 数字位必须是 ASCII `'0'..'9'`。
  - 固定位置 3、7、11 必须是点号 `'.'`。
  - 四个三位段分别解析为十进制整数。
  - 每段必须满足 `0 <= octet <= 255`。
- 电路公开输出 `valid = 1`。如果格式或范围不满足约束，则无法生成有效 witness/proof。
- 当前该功能只在 Android 本地生成并验证 proof，不接入服务端接口。

新增时间戳正则 proof 电路：

- 关键文件：`circuits/regex_timestamp.circom`。
- 已生成 Groth16 proving artifacts，并接入 Android 客户端 Regex 模块进行本地 proof 生成和本地验证。
- 私有输入为固定 26 个 ASCII 字节：`YYYY-MM-DD HH:mm:ss.ffffff`。
- 电路保留 zkregex 状态机用于验证数字位数和分隔符，并增加日期时间语义约束：
  - `1 <= month <= 12`。
  - `1 <= day <= 31`。
  - `0 <= hour <= 23`。
  - `0 <= minute <= 59`。
  - `0 <= second <= 59`。
  - `0 <= microsecond <= 999999`。
  - 4、6、9、11 月最多 30 天。
  - 2 月按公历闰年规则最多 28 或 29 天：年份能被 400 整除，或能被 4 整除但不能被 100 整除时为闰年。
- 任一格式或范围约束失败时，无法生成有效 witness/proof。
- Android native witness 构建使用 `regex_timestamp_js/regex_timestamp.wasm`，注册 `regextimestamp_witness` 给 `regex_timestamp_final.zkey`。
- 已通过 snarkjs 正反测试：
  - `2024-02-29 23:59:59.999999` 和 `2000-02-29 00:00:00.000000` 可生成 witness，Groth16 proof 验证成功。
  - `2023-02-29`、`1900-02-29`、`2024-02-30`、`2026-04-31`、`13 月`、`24 时`、`60 分`、`60 秒` 均被约束拒绝。

新增通用数字字段 proof 电路：

- 公共模板文件：`circuits/uint_decimal_field.circom`。
- 模板 `UintDecimalField(DIGITS, MAX_VALUE)` 负责复用同一套逻辑：
  - 私有输入为固定 `DIGITS` 个 ASCII 数字字节 `msg[DIGITS]`。
  - 每一位必须是 ASCII `'0'..'9'`。
  - 按十进制解析出 `value`。
  - 约束 `0 <= value <= MAX_VALUE`。
  - 公开输出 `valid = 1`。如果格式或范围不满足约束，则无法生成有效 witness/proof。
- Port 和 Trans 共用入口文件：`circuits/port_trans.circom`。
  - 实例化为 `UintDecimalField(5, 65535)`。
  - Android 端 Port 输入默认 `502`，Trans 输入默认 `19164`。
  - 用户输入 1 到 5 位数字，进入电路前左补零为固定 5 位，例如 `502 -> 00502`。
  - Port 和 Trans 共用 `port_trans_final.zkey`、`port_trans_js/port_trans.wasm` 和 Android `porttrans_witness`。
- Unit 独立入口文件：`circuits/unit.circom`。
  - 实例化为 `UintDecimalField(3, 255)`。
  - Android 端 Unit 输入默认 `0`。
  - 用户输入 1 到 3 位数字，进入电路前左补零为固定 3 位，例如 `12 -> 012`。
  - Unit 使用 `unit_final.zkey`、`unit_js/unit.wasm` 和 Android `unit_witness`。
- 当前这些功能只在 Android 本地生成并验证 proof，不接入服务端接口，也暂不检查 `Modbus/TCP` 的 `502` 业务语义或 Query/Response 配对关系。
- 已通过 snarkjs 正反测试：
  - Port/Trans：`00502` 和 `19164` 可生成 witness，Groth16 proof 验证成功。
  - Port/Trans：`65536` 在 witness 生成阶段被 `value <= 65535` 约束拒绝。
  - Unit：`000` 和 `012` 可生成 witness，Groth16 proof 验证成功。
  - Unit：`256` 在 witness 生成阶段被 `value <= 255` 约束拒绝。

新增协议成员 proof 电路：

- 关键文件：`circuits/protocol_regex.circom`。
- 客户端输入协议名称，当前允许集合为 `Modbus/TCP`、`ARP`、`DHCP`、`TCP`。
- 原始 zkregex 生成版本会偏向子串匹配，且依赖当前项目未使用的 `@zk-email/zk-regex-circom` helper；已改为固定字段精确成员查询电路。
- Android 端先检查输入精确属于允许集合，再转换为固定 10 个 ASCII/0 字节：
  - `Modbus/TCP` 保持 10 字节。
  - `ARP`、`DHCP`、`TCP` 右侧用 `0` 补齐到 10 字节。
- 电路私有输入为固定 10 个字节 `msg[10]`。
- 电路约束：
  - 每个输入值必须是 8-bit 字节。
  - `msg[10]` 必须精确等于四个允许协议字节序列之一。
- 电路公开输出 `valid = 1`。如果未命中允许集合，则无法生成有效 witness/proof。
- 当前该功能只在 Android 本地生成并验证 proof，不接入服务端接口。
- 已通过 snarkjs 正反测试：
  - `Modbus/TCP` 和 `ARP` 可生成 witness，Groth16 proof 验证成功。
  - `XARP` 在 witness 生成阶段被精确成员约束拒绝，确认不会把协议名子串误判为合法协议字段。

新增联合日志记录 proof 电路：

- 关键文件：`circuits/regex_record.circom`。
- 该电路不替代七个独立 Regex proof；Source IP、Destination IP、Timestamp、Port、Trans、Unit、Protocol 的独立 proof 继续保留用于回归和单字段验证。
- Android 端从 JSON 文本/文件中严格提取七个逻辑字段：
  - 缺少任一字段会拒绝。
  - 任一字段为空会拒绝。
  - 同一逻辑字段命中多个别名会拒绝，不静默选择。
  - 未知额外字段会忽略。
- Rust 预处理层规范化七个字段：
  - Source IP / Destination IP：固定 `ddd.ddd.ddd.ddd`，15 字节。
  - Timestamp：固定 `YYYY-MM-DD HH:mm:ss.ffffff`，26 字节。
  - Port / Trans：十进制左补零到 5 字节。
  - Unit：十进制左补零到 3 字节。
  - Protocol：固定 10 字节，`Modbus/TCP`、`ARP`、`DHCP`、`TCP` 右侧使用数值 `0` 字节补齐，不使用字符 `'0'`。
- Rust 把每个字段字节数组按 little-endian 打包成一个 BN254 field element；时间戳 26 字节单独打包，避免把全部 79 字节作为一个 field element。
- Commitment 使用 `Poseidon(10)`：

  ```text
  Poseidon(
    DOMAIN_TAG,
    1,
    srcPacked,
    dstPacked,
    timestampPacked,
    portPacked,
    transPacked,
    unitPacked,
    protocolPacked,
    salt
  )
  ```

- `DOMAIN_TAG` 为 ASCII little-endian 打包的 `ZK_LOCATION_REGEX_RECORD_V1`：

  ```text
  20296225498894752749272715267568488755079289184582638838394866522
  ```

- `SCHEMA_VERSION = 1`。
- `salt` 是私有输入，由现有 Rust 随机 salt 逻辑生成，正常 UI 不展示 salt。
- 电路公开输入/public input：`record_commitment`。
- 电路私有输入：七个规范化字段字节数组和 `salt`，其中 Source IP 和 Destination IP 输入名为 `source_ip`、`destination_ip`。
- 电路内部约束：`hash.out === record_commitment`；不能只在 Android 或服务端做电路外比较。
- 安全边界：该 proof 证明七个规范化字段在同一个 witness 中满足格式/范围/成员约束，并绑定到同一个公开 `recordCommitment`；它不证明 Circom 在电路内解析了原始 JSON 字节串。
- 生成产物：
  - `circuits/regex_record_js/regex_record.wasm`
  - `circuits/regex_record_final.zkey`
  - `zk-location/android/app/src/main/assets/regex_record_final.zkey`
  - `circuits/pot13_final.ptau`（该电路约束数超过现有 `pot12_final.ptau` 能力，保留 pot13 便于后续重建）
- 已通过 snarkjs 固定向量 proof/verify：`OK!`。
- 2026-06-23 修复 Android 真机 record proof 本地验证失败：
  - 现象：生成 proof 成功，但验证失败；摘要中 `Public input: 0`。
  - 根因：mopro/rust-witness 的 JSON 导入只读取数组值，旧 `record_commitment` 和 `salt` 以标量字符串传入时会被忽略，公开输入保持默认 0；只把输入名改为 snake_case 后仍会失败。
  - 修复：保留 `record_commitment` 为电路 `signal input` 且 `component main { public [record_commitment] }`，并在电路内约束 `hash.out === record_commitment`；Rust 返回给 Android prover 的嵌套 `circuitInput` 将 `"record_commitment"` 和 `"salt"` 包装成一元素数组，七个字段仍为数组。
  - 已重新生成 `circuits/regex_record_js/regex_record.wasm`、`circuits/regex_record_final.zkey`、Android `regex_record_final.zkey` asset 和 Android native bindings。
  - Android 生成 record proof 后新增保护：立即检查公开输入 `proof.inputs[0] == recordCommitment`，不一致则生成阶段报错。

### 4.2 Rust 预处理层

状态：已完成基础版本。

已实现：

- GNSS 经纬度到全局绝对定点整数。
- salt 生成。
- Poseidon commitment 计算。
- H3 cell 和六边形顶点计算。
- H3 resolution 当前 UI 范围：6-15。
- 使用全局顶点计算半平面系数。
- 联合日志记录 proof 的七字段规范化、little-endian 打包和 `Poseidon(10)` record commitment 生成。

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
- Key Attestation 和服务端 key 绑定状态查看。
- 位置 proof pipeline 的移动端 UI 入口已部分保留：
  - 不再显示 `Proof pipeline` 状态条。
  - Location 弹窗提供 `Generate proof`，用当前 GNSS 经纬度和 H3 resolution 本地生成 `areajudge_final.zkey` proof，证明点位在当前 H3 六边形内。
  - Location 弹窗提供 `Verify proof`，用同一个 `areajudge_final.zkey` 在手机端本地验证已生成的位置 proof。
  - 生成和验证结果分别写入 `Results -> Proof` 与 `Results -> Verification`，展示 proving/verifying time、public commitment 短摘要、公开输入数量和本地验证结果。
  - Location 弹窗提供 `Sign commitment`，要求已登录、已 `Generate new key and bind`、已生成位置 proof；客户端会请求服务端 `/nonce`，再用 Android Keystore 私钥签名当前 proof 的 `public_commitment` 和 nonce。
  - Location 弹窗提供 `Send proof to server`，要求已签名；客户端提交 `proof`、`inputs/publicSignals`、`tee.payload`、`tee.signature` 和 bearer token 到 `/verify-proof`。提交时不重新上传 `certificateChain`，服务端使用当前登录用户已绑定 active key 验签。
  - Logout 已从 Location 弹窗移到主页面顶部，替代旧 Ready/Working 状态标签；顶部栏不再接收或计算 Ready/Working busy 状态。
  - 服务端 `/verify-proof` 现在可由当前手机端界面的 `Send proof to server` 直接触发。
  - Android 端已删除 `Server stats`、`Export report`、`Results -> Server`、`Results -> Stats` 和 `Results -> Report`；对应 Android state/helper/UI 分区已清理。
- 位置和 Regex proof 的生成/验证/发送操作弹窗已精简为关键摘要，避免显示过多解释性字段；详细结果页仍保留必要状态。
- 新增 Source IP、Destination IP、时间戳、Port/Trans/Unit 数字字段和协议 proof 本地验证：
  - 登录页默认服务端地址为 `http://192.168.2.217:3000/verify-proof`，默认用户名为 `alice`，默认密码为 `123456789`。
  - 主页面将 `Actions` 改为 `Location`，只放账号、key、GNSS、resolution 和位置 proof 本地生成/验证。
  - 主页面新增并列的 `Regex` 按钮，专门放格式正确性 proof 操作。
  - Regex 弹窗顶部新增 JSON 文本/文件导入：
    - 可直接粘贴 JSON 文本并点击 `Apply JSON`。
    - 可点击 `Pick file` 从手机选择 JSON/text 文件。
    - 客户端会识别 `sourceIp/srcIp/source`、`destinationIp/dstIp/destination`、`timestamp/time`、`port/srcPort/dstPort`、`trans/transactionId`、`unit/unitId`、`protocol` 等字段。
    - JSON 导入阶段不做格式和范围过滤；只要字段存在且非空，就先填入对应输入框。
    - JSON 导入阶段会把 `UDP` 等未知协议原样填入 Protocol 输入框；后续 proof 生成阶段仍由 `protocol_regex` 电路按当前允许集合判断是否合法。
    - 识别后只负责填入现有输入框，并清空对应旧 proof；不会自动生成 proof，也不在输入框下方显示 imported fields 列表。
	  - Regex 弹窗当前只保留联合日志记录 proof 操作：
	    - `Generate record proof`：从当前 JSON 导入文本严格提取七个字段，生成一个 `regex_record_final.zkey` proof。
	    - `View record proof`：显示 record commitment、关键规范化字段和本地 proof 状态，不显示 salt。
	    - `Verify record proof`：用同一个 `regex_record_final.zkey` 在 Android 本地验证已生成的联合 proof。
	    - `Send record proof to server`：显式把当前已生成的 `regex_record` proof 和 `publicSignals/inputs` 提交到服务端 `/verify-regex-proof`。
	    - 2026-06-18 后续更新：已删除 `Generate all proofs`、`View generated proofs`、`Verify proofs` 和对应一键生成/一键验证后台逻辑。
	    - `Generate record proof` 使用 Android 当前支持的 `ProofLib.ARKWORKS` 生成 proof；`Verify record proof` 优先 Arkworks，本地 Rapidsnark 只作为兼容 fallback。
	    - 2026-06-23：record proof 保持公开输入/public input，并在电路内部约束 `hash.out === record_commitment`；Android/rust-witness 输入改为用一元素数组填充 `record_commitment` 和 `salt`，避免真机上公开输入读取为 `0`。
	    - 2026-06-23：服务端新增 `/verify-regex-proof`，加载 `server/keys/regex_record_verification_key.json` 验证客户端显式提交的 record proof；该端点要求登录 session，但不要求 Keystore 签名、不消费 nonce。
	    - 2026-06-23 后续修复：真机 record proof 本地验证通过但服务端 `proofValid=false` 时，服务端 proof 格式兼容已扩展为 4 种 mopro G2 候选：原始、Fp2 pair 内交换、G2 x/y 坐标交换、两者同时交换；服务端日志和 Android 失败摘要会显示 attempts。
	    - 2026-06-23 再修复：4 种候选仍失败时，确认原服务端只交换 G2 `x/y` 的 Fp2 limb，未覆盖 G2 `z` 坐标。`proof-format.js` 已新增包含 `z` limb 交换的 mopro 候选，并保留旧候选兼容既有 proof；修复后需重启服务端生效。
	    - 2026-06-24 修复：曾尝试把 Android Regex record 生成改成 Rapidsnark，但当前 Android native `circom-prover` 未启用 `rapidsnark` feature，会报 `Unsupported proof library`，因此已恢复 Arkworks 生成。
	    - 2026-06-24 服务端修复：`/verify-regex-proof` 在 snarkjs 候选全部失败时，会调用 `zk-location/target/release/verify_regex_record_arkworks` 做 Arkworks fallback；成功时返回 `acceptedFormat=arkworks_mopro`。
	    - 2026-06-24 诊断增强：Android 发送 record proof 时会上报本地 `regex_record_final.zkey` SHA-256，服务端响应会返回客户端 zkey、服务端 zkey、服务端 verification key 的 SHA-256 摘要。若本地验证通过但服务端失败，优先检查 Client zkey 和 Server zkey 是否一致。
	    - 2026-06-24 真机诊断结论：用户截图中 Client zkey 为 `0450ccaf...9484bedf`，Server zkey 为 `7d27d9da...760f69f6d`；当前源码 Android asset、当前 `app-debug.apk` asset 和服务端 `circuits/regex_record_final.zkey` 均为 `7d27d9da...760f69f6d`。该类失败不是电路 witness 约束问题，而是手机运行的 APK/asset 与服务端 proving/verifying artifact 不一致；需重新安装当前 APK、重启服务端，并重新生成 proof。
	    - 联合 proof 和七个独立 proof 的电路/artifact 互不替代；但当前 Regex UI 只暴露联合 proof 操作。修改 JSON 或任一字段输入会清空旧 record proof。
	  - Source IP 和 Destination IP 都复用 `regex_ip_final.zkey` proof。
  - Regex proof 的生成/验证使用较大线程栈的后台 worker，避免 native witness/prover 在默认 Java Thread 栈上崩溃。
  - Regex 输入在调用 native prover 前会先检查段数、数字字符和 `0..255` 范围，非法输入直接显示错误，不进入 native witness。
  - Android native witness 构建已修复：
	    - `rust_witness::transpile_wasm` 只扫描临时目录中的 `areajudge.wasm`、`regex_ip.wasm`、`regex_timestamp.wasm`、`port_trans.wasm`、`unit.wasm`、`protocol_regex.wasm` 和 `regex_record.wasm`，避免旧 wasm 造成重复 handler。
	    - Android 端注册 `regexip_witness` 给 `regex_ip_final.zkey`，匹配 w2c2 生成的 `regexipInstantiate` 符号。
	    - Android 端注册 `regextimestamp_witness` 给 `regex_timestamp_final.zkey`，注册 `porttrans_witness` 给 `port_trans_final.zkey`，注册 `unit_witness` 给 `unit_final.zkey`，注册 `protocolregex_witness` 给 `protocol_regex_final.zkey`。
	    - Android 端注册 `regexrecord_witness` 给 `regex_record_final.zkey`，匹配 w2c2 生成的 `regexrecordInstantiate` 符号。
	    - 已通过 `readelf` 确认 `libzk_location.so` 中 `areajudgeInstantiate`、`regexipInstantiate`、`regextimestampInstantiate`、`porttransInstantiate`、`unitInstantiate`、`protocolregexInstantiate` 和 `regexrecordInstantiate` 均为本地定义符号。
  - Results 中新增 `Source IP` 和 `Destination IP` 输出区，显示原始输入、规范化输入、公开输出、proof 生成/验证耗时和失败原因。
  - Regex 弹窗新增时间戳 proof：
    - 输入固定格式 `YYYY-MM-DD HH:mm:ss.ffffff`。
    - 独立 proof 电路和 artifact 保留用于回归；当前 Regex UI 不再暴露单字段生成/验证入口。
    - 调用 native prover 前，Kotlin 会先执行与电路一致的字段范围、月份天数和公历闰年校验。
    - Results 中新增 `Timestamp` 输出区，显示输入、公开输出、proof 生成/验证耗时和失败原因。
  - Regex 弹窗新增端口 proof：
    - 输入 1 到 5 位数字端口。
    - 使用 `port_trans_final.zkey`；独立 proof 电路和 artifact 保留用于回归，当前 Regex UI 不再暴露单字段生成/验证入口。
    - 调用 native prover 前，Kotlin 会先执行数字格式和 `0..65535` 范围校验，并把输入左补零为固定 5 位。
    - Results 中新增 `Port` 输出区，显示输入、规范化输入、公开输出、proof 生成/验证耗时和失败原因。
  - Regex 弹窗新增 Trans proof：
    - 输入 1 到 5 位数字事务 ID，默认 `19164`。
    - 复用 `port_trans_final.zkey` 和 `porttrans_witness`，因为 Trans 与 Port 当前都按 16-bit 数字字段处理。
    - 独立 proof 电路和 artifact 保留用于回归；当前 Regex UI 不再暴露单字段生成/验证入口。
    - 调用 native prover 前，Kotlin 会先执行数字格式和 `0..65535` 范围校验，并把输入左补零为固定 5 位。
    - Results 中新增 `Trans` 输出区，显示输入、规范化输入、公开输出、proof 生成/验证耗时和失败原因。
  - Regex 弹窗新增 Unit proof：
    - 输入 1 到 3 位数字设备编号，默认 `0`。
    - 使用 `unit_final.zkey`；独立 proof 电路和 artifact 保留用于回归，当前 Regex UI 不再暴露单字段生成/验证入口。
    - 调用 native prover 前，Kotlin 会先执行数字格式和 `0..255` 范围校验，并把输入左补零为固定 3 位。
    - Results 中新增 `Unit` 输出区，显示输入、规范化输入、公开输出、proof 生成/验证耗时和失败原因。
  - Regex 弹窗新增协议 proof：
    - 输入协议名称，当前允许 `Modbus/TCP`、`ARP`、`DHCP`、`TCP`。
    - 使用 `protocol_regex_final.zkey`；独立 proof 电路和 artifact 保留用于回归，当前 Regex UI 不再暴露单字段生成/验证入口。
    - 调用 native prover 前，Kotlin 会先执行允许集合检查，并把协议转换为固定 10 字节 ASCII/0 数组。
    - Results 中新增 `Protocol` 输出区，显示输入、固定字节数组、公开输出、proof 生成/验证耗时和失败原因。

关键文件：

- `zk-location/android/app/src/main/java/com/example/moproapp/LocationProofComponent.kt`
- `zk-location/android/app/src/main/java/com/example/moproapp/RegexRecordProof.kt`
- `zk-location/android/app/src/main/java/com/example/moproapp/KeystoreLocationSigner.kt`
- `zk-location/android/app/src/main/java/com/example/moproapp/GnssLocationReader.kt`
- `zk-location/android/app/src/main/java/com/example/moproapp/CampusOfflineMap.kt`

新增 Regex proof 相关产物：

- `zk-location/android/app/src/main/assets/regex_ip_final.zkey`
- `zk-location/android/app/src/main/assets/regex_timestamp_final.zkey`
- `zk-location/android/app/src/main/assets/port_trans_final.zkey`
- `zk-location/android/app/src/main/assets/unit_final.zkey`
- `zk-location/android/app/src/main/assets/protocol_regex_final.zkey`
- `zk-location/android/app/src/main/assets/regex_record_final.zkey`
- `circuits/regex_ip_js/regex_ip.wasm`
- `circuits/regex_timestamp_js/regex_timestamp.wasm`
- `circuits/port_trans_js/port_trans.wasm`
- `circuits/unit_js/unit.wasm`
- `circuits/protocol_regex_js/protocol_regex.wasm`
- `circuits/regex_record_js/regex_record.wasm`
- `circuits/regex_record_final.zkey`
- `circuits/pot13_final.ptau`
- `zk-location/test-vectors/circom/regex_ip_final.zkey`

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
- `GET /logs/interactions`（已禁用，返回 404）
- `POST /verify-regex-proof`
- `GET /password/login-parameters`
- `POST /password/login`
- `POST /auth/logout`
- `GET /keys/active`
- `GET /keys`
- `POST /keys/revoke`

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

### 4.5 密码策略证明注册与跨设备登录

状态：注册、服务端 salt 持久化和基于服务端 salt 的登录代码已完成。

- Android 注册生成 128-bit 非零随机 salt；Rust 使用同一个 salt 构造密码策略 witness 和 `Poseidon(chunk0, chunk1, passwordLength, salt)` commitment。
- `POST /password/register` 接收 `userId`、十进制非零 `salt`、`passwordCommitment`、唯一 public signal 和 Groth16 proof。
- 服务端先验证请求、salt、commitment 和 proof，再将 salt 与 commitment 原子写入同一注册记录。
- `GET /password/login-parameters?userId=...` 只返回 salt 和 circuit version，不返回 commitment、proof 或私有输入。
- Android 登录必须先获取服务端 salt，再由 Rust 本地计算 commitment；不生成登录 proof，也不上传密码或 salt。
- Android Keystore AES-GCM 本地 salt 记录继续保留为缓存，但本地记录缺失或与服务端不一致均不阻断登录，服务端 salt 始终优先。
- 旧注册记录缺少 salt 时保留原 commitment，并返回 `ACCOUNT_REQUIRES_REREGISTRATION`；不会猜测、生成或覆盖 salt。
- salt 是非秘密参数。当前密码登录 commitment 仍可重放，生产环境需要 HTTPS 和 challenge/nonce 绑定协议。
- 2026-06-30 真机验证：HUAWEI EBG-AN00（Android 12/API 31）注册 HTTP 201；删除该测试 userId 的单个本地 salt 文件后，正确密码仍 HTTP 200；服务端重启后再次登录仍为 HTTP 200。错误密码和未知用户均返回 HTTP 401 `INVALID_CREDENTIALS`，未观察到 OOM、ANR、应用/native crash 或 Rust panic。

关键文件：

- `h3-converter/src/password.rs`
- `h3-converter/password-dfa/`
- `circuits/password_policy_commitment_main.circom`
- `circuits/password_policy_generated/`
- `circuits/password_policy_commitment_js/password_policy_commitment_main.wasm`
- `server/src/password-registration-store.js`
- `server/src/server.js`
- `zk-location/android/app/src/main/java/com/example/moproapp/PasswordRegisterScreen.kt`
- `zk-location/android/app/src/main/java/com/example/moproapp/PasswordLoginScreen.kt`
- `zk-location/android/app/src/main/java/com/example/moproapp/PasswordLoginApi.kt`

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

### 无用生成文件清理

2026-06-17 已清理确认无运行依赖的生成/废弃文件：

- Circom phase-1 临时 proving key：`circuits/*_0000.zkey`。
- 旧 Port proof artifact：`zk-location/android/app/src/main/assets/port_final.zkey`。
- 手工位置 proof 调试输出：`zk-location/input_*.json`、`zk-location/proof_*.json`、`zk-location/public_*.json`。

同时补充 `.gitignore`，避免后续手工位置 proof JSON 再进入工作区。以下内容不作为普通无用文件删除：

- Android assets 中当前 Regex 使用的 final zkey。
- Native witness 需要的 wasm。
- Android `jniLibs` 中当前 native library。
- `server/node_modules/`、`circuits/node_modules/`、Android `.gradle/`、`app/build/` 等会影响本机立即运行或取得现有 APK 的目录。
- `server/data/auth.json` 等本地账号/session/key 状态文件。

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

交互日志以 JSONL 格式持久化在 `server/logs/interactions.jsonl`。诊断 HTTP 接口已在生产环境中禁用。

### 8.3 Android 构建

```bash
cd zk-location/android
ANDROID_HOME=/home/lyy/Android/Sdk ANDROID_SDK_ROOT=/home/lyy/Android/Sdk ./gradlew assembleDebug
```

## 9. 最近验证结果

当前状态（2026-07）：

```text
server node --test: 114/114 tests passed
h3-converter cargo test: passed
zk-location cargo test: passed
Android assembleDebug: BUILD SUCCESSFUL

M-11 诊断信息泄露: Fixed (PASS WITH FOLLOW-UP)
M-12 文件权限: Fixed (PASS WITH FOLLOW-UP)
M-14 缺少 test fixture: Fixed (PASS WITH FOLLOW-UP)
M-01/M-03/M-04/M-05/M-09: Fixed

历史里程碑:
- 2026-06-30: password server-salt 跨设备登录真机验证通过
- 2026-06-24: Arkworks fallback + artifact hash 诊断完成
- 2026-06-23: regex record public input 约束和 mopro G2 候选修复完成
- 2026-06-18: Android 服务端 stats/report 入口清理完成
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
   - 未完成前置步骤时会禁用或提示对应按钮；位置 proof 本地生成、本地验证、签名和发送按钮已恢复。
   - 登录/注册成功后，Android 不会自动生成或绑定 key；服务端登录时会清空该用户旧的 active key，避免复用之前登录绑定的 attestation 结果。
   - `Re-verify key` 已改为 `Verify key`，点击后只查询当前用户服务端是否已有本次登录后重新绑定的 active key；如果没有 key，则显示还未生成。
   - `Generate new key and bind` 成功后，再点击 `Verify key` 会显示当前 active key 的 attestation 可信性结果。
   - 只有 `Generate new key and bind` 会请求新的 key registration nonce，重新生成 attested Keystore key，并重新提交 `/keys/register`。
   - Verify key/Generate new key and bind 等操作结果弹窗已支持滚动，避免长字段被窗口遮挡。
   - Android UI 已整理为简约浅色主题：登录卡片、地图主视图、顶部栏、Location/Regex/Results 三个主入口、统一 8dp 圆角按钮和弹窗；主页面顶部 Logout 替代旧 Ready/Working 状态标签，且顶部栏对应 busy 状态逻辑已删除。
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

5. 实验报告导出功能（已禁用）。
   - 服务端 `/reports/latest` 已在 M-11 安全修复中禁用（返回 404）。
   - 2026-06-18：Android 端 `Export report` 按钮、Report 结果页和对应 helper/state 已删除。

6. 性能统计功能（已禁用）。
   - 服务端 `/stats/performance` 已在 M-11 安全修复中禁用（返回 404）。
   - 2026-06-18：Android 端 `Server stats` 按钮、Stats 结果页、本地 proof/send 采样状态和对应 helper 已删除。

7. 协议文档。
   - 已编写独立 `docs/protocol.md`。
   - 固化 `/keys/register`、`/verify-proof`、nonce、payload、公开/私有字段说明。

剩余功能性代码主要是：

1. UI 结果展示继续整理。
   - 将 Auth、Keystore、Signature、本地 proof 生成/验证和 Regex 结果组织成更稳定的结果页。
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
   - 已覆盖 `/verify-regex-proof` 接收已登录客户端显式提交的 record proof，且不要求 active key。
   - 已覆盖不可信 Android attestation root 注册被拒绝。
   - 已覆盖 key.register 日志会保留客户端 bind key 时上传的 certificateChain。
   - 当前 `server npm test`：35 tests passed。

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
   - 当前 `npm run logs`（直接读取本地 interactions.jsonl）已能查看关键交互。
   - HTTP 交互日志、性能统计和实验报告接口已在 M-11 中禁用（返回 404）；
     需要使用直接文件读取和离线脚本整理实验材料。
   - Android 端 report/stats 入口已删除，当前手机 UI 不再承载实验报告导出。

### P2：实验展示和工程体验改进

1. UI 继续整理。
   - 当前 UI 可用，且关键字段已增加中文说明。
   - 后续可把 Auth、Keystore、Signature 和本地 proof 结果分成更清楚的卡片或结果页。
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
- Regex 联合日志记录 proof 的 JSON 解析发生在 Android/Kotlin 层；Circom 电路只验证七个规范化字段和 record commitment 的一致性，不证明原始 JSON 字节串在电路内被解析。

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
