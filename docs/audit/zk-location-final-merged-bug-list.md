# zk-location 最终合并 Bug 清单

**文档状态**：后续修复与审查的统一事实来源  
**统一审计基线**：`deabbbf88c2c555229a323fd671db849f3c4de7d`  
**业务代码基线等价提交**：`c17a5455f2a88589a53be2c21c663ed357e6cb9e`  
**生成依据**：

- `codex-audit-report.md`
- `claude-audit-report.md`
- `codex-merged-reproduction-report.md`
- `claude-merged-reproduction-report.md`

两轮审计均基于 `deabbbf88c2c555229a323fd671db849f3c4de7d`。该提交相较此前稳定提交只修改 Markdown 审计指导文件，业务代码未变化。

---

## 1. 使用规则

本文件是 Claude 修复、Codex 审查以及后续人工决策的统一问题清单。

后续 Agent 必须：

1. 以本文件中的 ID、分类和范围为准；
2. 不重新引用各自旧报告中的数量作为最终结果；
3. 修复前重新确认目标问题仍存在于指定基线；
4. 每个修复提交只处理一个问题或同一根因的一组问题；
5. 修复后补回归测试，并由另一 Agent 独立复现；
6. 不把“已知原型限制”重新计入 Bug；
7. 不修改 Circom、DFA、R1CS、WASM、zkey、vkey、ptau 或 native library，除非某个修复任务明确授权。

结论状态：

- **Confirmed Bug**：已有动态复现，或代码路径确定且不存在合理行为歧义；
- **High-confidence Potential Risk**：代码缺陷迹象强，但缺少真实 Android、instrumentation 或故障注入验证；
- **Known Limitation / Hardening**：当前原型明确不支持，或仅属于部署加固；
- **Not a Bug**：已验证正确，或原报告依据不足。

---

## 2. 最终 Confirmed Bug

### 2.1 核心安全与功能问题

| ID | 严重度 | 模块 | 合并后问题 | 主要证据 | 修复批次 |
|---|---|---|---|---|---|
| M-01 | High | Server / Location | Location 必须恰好包含 37 个公开输入；35/36 项尾部截断仍可被 Groth16 verifier 接受 | 两边复核均确认；真实 `snarkjs` 验证矩阵中 35/36/37 为 true | Batch 1 |
| M-03 | Medium | Rust / Android FFI | 非数字 proof 坐标、短 G2、非法 public input、非曲线点可触发 native panic | Codex Rust 最小复现；Claude 静态确认 `unwrap` 和越界路径 | Batch 2 |
| M-04 | Medium | Rust / Android | 缺失、空、截断或损坏 zkey 可触发依赖 panic | Codex 对 missing/empty/corrupt zkey 动态复现 | Batch 2 |
| M-05 | Medium | Rust / Regex verifier | 外部 public signal 未做规范域元素校验，`x + q` 会被约简为与 `x` 相同的 field element | Codex 临时 Groth16 proof 动态复现 | Batch 2 |
| M-09 | High | Server logging | interaction logger 发生 ENOSPC/EACCES 等写入错误时可终止 Node 进程 | Codex 子进程故障注入复现 exit 1；Claude确认无异常隔离 | Batch 3 |
| M-10 | High | Server persistence | AuthStore 非原子写入、保存失败无内存回滚、损坏 JSON 导致启动失败 | 两边动态复现；Codex额外复现 ghost state | Batch 3 |
| M-11 | Medium | Server diagnostics | 未认证诊断接口泄露 userId、nonce、证书链、IP、绝对路径和运行指标 | Codex真实 handler复现；默认监听 `0.0.0.0` 且 CORS `*` | Batch 3 |
| M-12 | Low | Server file permissions | `auth.json` 和 `interactions.jsonl` 在 umask 0022 下默认创建为 0644 | Codex动态 `stat` 复现 | Batch 3 |
| M-13 | Low | Android Password Register | Password Register 早期失败路径不清除 password 和 confirmation | 两边代码路径确认；仅成功路径执行清理 | Batch 5 |
| P-03 | Medium | Server logging | `limit=1` 仍同步读取、split 整个日志文件，导致延迟和内存线性增长 | Codex 64 MiB 日志动态复现 | Batch 4 |
| P-04 | Medium | Server registration | 密码注册跨 AuthStore 和 PasswordRegistrationStore 存在单进程崩溃半事务状态 | Codex在两次持久化之间强制退出，复现两库不一致 | Batch 4 |
| P-05 | Medium | Server nonce | 未认证 `/nonce` 无速率和容量上限，TTL 内 Map 和内存可线性增长 | Codex 50,000 次请求动态复现 | Batch 4 |
| P-08 | Low | Server authentication | 用户存在性可由 login-parameters 状态码和 legacy scrypt 时序可靠区分 | Codex状态码和计时动态复现 | Batch 4 |
| P-09 | Low | Server signature protocol | canonical Keystore payload 未强制版本、字段唯一性和未知字段拒绝 | Codex使用可信 P-256 key 动态复现错误版本和重复字段仍被接受 | Batch 4 |

### 2.2 工程质量问题

| ID | 严重度 | 模块 | 问题 | 主要证据 | 修复批次 |
|---|---|---|---|---|---|
| M-14 | Low | Server tests | 干净 checkout 执行完整 Server 测试时依赖未跟踪 fixture，导致 64/65 | 两边复核均得到 1 项失败；Codex定位到 ignored runtime fixture | Batch 6 |
| M-15 | Low | Rust formatting | `h3-converter cargo fmt --check` 存在一处格式差异 | Codex分别检查两个 crate；`zk-location` 通过，`h3-converter` 失败 | Batch 6 |

---

## 3. High-confidence Potential Risk

以下问题应保留，但在没有 Android 真机、instrumentation 或故障注入证据前，不与动态复现的 Confirmed Bug 使用相同证据等级。

| ID | 严重度 | 模块 | 问题 | 当前缺少的证据 |
|---|---|---|---|---|
| M-06 | Medium | Android artifacts | Location/Regex zkey 缓存只检查 `exists && length > 0`，可能复用截断、损坏或旧版本文件 | 真实 Android `Context.assets` 或 Robolectric/instrumentation 测试 |
| M-07 | Medium | Android / Server | 注册已落盘但 201 响应丢失后，客户端重试得到 409，无法幂等恢复 | MockWebServer 响应丢失故障注入 |
| M-08 | Medium | Android Keystore | 重绑失败或 alias 丢失后，UI 仍可能保持假绑定状态；签名路径会静默生成未绑定新 key | 真机或可控 Keystore fake 测试 |
| P-01 | Medium | Android lifecycle | Location 裸 Thread 不绑定生命周期，旋转、返回或 logout 后可能回写旧状态 | instrumentation 的 rotate/back/logout 测试 |
| P-02 | Low | Android concurrency | Location 快速重复点击可能启动多个 proof worker | Compose 双击或并发点击测试 |
| P-06 | Medium | Android networking | 响应体和 salt 十进制长度缺少客户端上限，可能引发 OOM/ANR | MockWebServer 超大 body/salt 测试 |
| P-07 | Low | Android backup | 备份恢复后 salt ciphertext 与新 Keystore key 不匹配，缓存不会自动清理 | 真实 backup/restore 或删 key 恢复测试 |
| P-11 | Low | Android cache | 本地 salt cache 保存失败被吞掉，UI 仍显示完整成功 | 注入 store/load 失败的 UI/逻辑测试 |
| P-12 | Low | Android UI | Location HTTP helper 将完整错误响应体写入异常并可能展示给用户 | 恶意 MockWebServer UI 测试 |

---

## 4. Known Limitation / Hardening

以下内容不作为当前 Bug 计数，但可在后续生产化阶段处理：

1. Password Login 当前没有 nonce、防重放、改密和账户恢复；
2. 当前不要求 JWT；现有 opaque token/session 设计不因“不是 JWT”而构成 Bug；
3. 文件数据库不支持多 Node 实例或水平扩展；
4. 测试和原型部署可能使用 HTTP，生产环境必须使用 HTTPS；
5. 普通网络请求没有自动重试；
6. Compose 进程死亡后页面状态丢失；
7. 调试 CLI 默认输出 private witness 文件，属于 debug hardening，正式产品路径不依赖该 CLI；
8. 日志使用同步文件 I/O，当前原型规模可接受，但生产环境应迁移到受控持久化方案；
9. Android salt cache 是可恢复缓存，不是认证真值；缓存损坏时登录仍应以服务端 salt 为准。

---

## 5. Not a Bug / 已排除

1. Regex Record 跳过某个 normalization 函数本身不是 Bug；真实 `fullProve + verify` 已通过；
2. `PIPE_BUF` 不能直接用作普通文件 append 原子性的依据，原 Claude BUG-007 不成立；
3. 有限域内部对 `x + q` 模约化是正常数学行为；M-05 的问题是外部 API 缺少 canonical encoding gate，而不是 Arkworks 数学错误；
4. Password proof 只有 1 个 public signal，Android 与 Server 均绑定 commitment；
5. 七个 Regex artifact 映射、zkey/vkey/WASM/LFS 一致性已验证；
6. salt 是公开参数，服务端保存 salt 不构成秘密泄露；
7. Password Login 按当前设计不生成 Groth16 proof；
8. 已绑定用户省略 TEE 字段不能绕过服务端 active key 验证；
9. FFI 类型 `derive Default` 本身不是独立 Bug；
10. 仅在未来代码加入 `await` 后才可能出现的 TOCTOU 不作为当前 Bug。
11. M-02：Location 的 36 个区域边界参数未绑定到服务端授权区域。经项目负责人确认，当前协议设计目标是证明私有位置位于由当前位置和 resolution 决定的公开 H3 六边形内，不存在服务端预先授权区域的要求。客户端提交公开六边形参数属于预期行为，不构成缺陷。

---

## 6. 修复优先级和批次

### Batch 1：Location 输入契约

- M-01

要求单独 commit，先通过 Codex 独立复核。

### Batch 2：Rust 和 field 输入边界

- M-03
- M-04
- M-05

建议同一批、多个小 commit：

1. proof/G1/G2/public input `TryFrom`；
2. zkey 错误隔离；
3. canonical BN254 scalar gate。

### Batch 3：Server 可用性、持久化和数据暴露

- M-09
- M-10
- M-11
- M-12

M-10 建议独立 commit；诊断接口和文件权限可分别提交。

### Batch 4：Server 资源、事务和协议加固

- P-03
- P-04
- P-05
- P-08
- P-09

### Batch 5：Android 修复

- M-13
- 评估并尽可能修复 M-06、M-07、M-08、P-01、P-02、P-06、P-07、P-11、P-12

Android Potential Risk 在升级为 Confirmed Bug 前，应补充真机、Robolectric、Compose UI 或 MockWebServer 证据。

### Batch 6：工程质量

- M-14
- M-15

不得与核心安全修复混在同一个 commit 中。

---

## 7. Agent 分工

### Claude Code

角色：修复者。

要求：

- 读取本文件；
- 按批次修复；
- 每个 commit 范围最小；
- 补回归测试；
- 不 push；
- 输出精确 commit hash；
- 不读取 Codex 后续审查报告，直到当前修复提交完成。

### Codex

角色：独立审查者。

要求：

- 读取本文件；
- 检出 Claude 提供的精确 commit；
- 不修改修复代码；
- 重新执行原始攻击复现；
- 验证合法路径；
- 检查新增测试；
- 输出 `PASS / PASS WITH FOLLOW-UP / FAIL / UNABLE TO VERIFY`；
- 只提交审查报告，不提交修复。

---

## 8. 每个修复的完成标准

一个问题只有同时满足以下条件，才能标记为已修复：

1. 原始触发路径不再成立；
2. 合法流程仍然通过；
3. 新增回归测试；
4. 现有相关测试通过；
5. 没有修改受保护的密码学 artifact；
6. Codex 独立复现确认；
7. 修复 commit 范围清晰；
8. 遗留兼容性问题明确记录。

---

## 9. 状态记录模板

后续在本文件末尾追加，不要修改历史结论：

```text
ID:
修复分支:
修复 commit:
修复者:
审查 commit/HEAD:
审查者:
审查结论:
执行的测试:
遗留问题:
状态: Open / In Progress / Fixed / Rejected / Deferred
```

---

## 10. 状态记录

### M-01

```text
ID: M-01
原修复 commit: 96d120bad4dcb25b831c34a483e705a7e036c7f9
main 合并 commit: f6ef60dcb2a3c9d914f7dfd55a5256ec5f7bb7a6
修复者: Claude
审查者: Codex
审查结论: PASS
测试结果: M-01 定向测试 11/11 通过；Server 76/76 全部通过
状态: Fixed
```

### M-02

```text
ID: M-02
最终分类: Not a Bug
决定者: 项目负责人
理由: 当前协议按设计证明私有位置位于由当前位置和 resolution
      决定的公开 H3 六边形内，不存在服务端授权区域要求。
状态: Rejected
```

### M-03

```text
ID: M-03
状态: Fixed
修复者: Claude
独立审查者: Codex
审查结论: PASS WITH FOLLOW-UP
原修复 commit: b7bf6674b0a1c74bd1c1a5bf05cce6012d53cdd0
main 合并 commit: 7941ec62dcca55fb6466a802f63399c700476249

核心结果:
- malformed G1/G2 和错误数组长度受控拒绝；
- 域内非曲线 G1/G2 受控拒绝；
- G2 错误子群点受控拒绝；
- 相关生产入口不再 panic 或 unwind 穿过 FFI；
- 合法 Location/Regex proof 无回归。

非阻断 follow-up:
- F-M03-01：增加 G2 错误子群生产入口回归测试
- F-M03-02：明确或规范外部 proof 的 z 字段语义
- F-M03-03：评估移除非必要的 ark-ec 直接依赖

这些是非阻断 follow-up，不影响 M-03 的 Fixed 状态。
```

### M-05

```text
ID: M-05
状态: Fixed
修复者: Claude
独立审查者: Codex
审查结论: PASS
原修复 commit: b7bf6674b0a1c74bd1c1a5bf05cce6012d53cdd0
main 合并 commit: 7941ec62dcca55fb6466a802f63399c700476249

核心结果:
- 外部 public signal 采用唯一规范的 BN254 scalar 十进制编码；
- q、q+1、真实 x+q、符号、前导零和非十进制输入均拒绝；
- Location 和 Regex 的真实 x+q 动态复现均已阻止；
- 合法 proof 无回归。
```

### M-04

```text
ID: M-04
状态: Confirmed Bug / Pending
说明: 缺失、截断或损坏 zkey 导致 panic。
      旧 commit 6ed4c8ff9dea0fa60fb3c8413cc515938b149153 未经独立审查，不得合并。
      将在 Codex 对 M-03/M-05 给出 PASS 后单独重做和审查。
```
