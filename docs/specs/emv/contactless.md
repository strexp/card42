# 非接触 Entry Point / PPSE 与终端内核规范

本文描述 Card42 当前实现的**非接触卡侧 Entry Point / PPSE** 与**终端侧内核
（RSA profile）**行为与范围。依据 **EMV Contactless Book A/B v2.12**
（`tools/specs-contactless-v2.12/`）与 **EMV Contactless Book C-8 v1.2**
（`tools/specs-contactless-c8-1.2/`，仅作流程结构参照），Book B/C 引用 EMV Book 1/3/4
**v4.4**。

## 1. 范围声明

### 1.1 卡侧 Entry Point / PPSE

只实现卡侧 Entry Point / PPSE 的候选列表（Book B §3.3.1），即让一张非接触卡能被符合
Book B 的读卡器发现并选中其支付应用：

- PPSE（`2PAY.SYS.DDF01`）的 FCI 结构与候选列表（Table 3-2）。
- 每条 Directory Entry（`61`）的 `4F` / `50` / `87` / `9F2A`。
- 多条 Directory Entry 与 Application Priority Indicator 语义（Table 3-3）。
- 接触接口拒选 PPSE（`6A82`）不变。

### 1.2 终端侧内核（RSA profile）

终端侧内核以 **EMV v4.4 Book 3/4 的通用终端流程**实现，采用 **RSA profile**（SDA/DDA/CDA），
覆盖：Entry Point → ADF 选择 → GPO（PDOL/TTQ）→ READ RECORD → RSA ODA → Processing
Restrictions → CVM → Terminal Risk Management → Terminal Action Analysis →
GENERATE AC → 在线 → 第二 AC。C-8 仅作概念参照。

**明确范围外**（本阶段不实现，也不声称 C-8 合规）：

- **ECC / XDA / ODE**：Book C-8 的 EC-SDSA、Book E 安全通道（BDH+AES）、blinding
  factor、EDA-MAC、IAD-MAC。Java Card 3.0.5 classic API 与 J3R180 默认卡不支持这些
  能力（见 [research-notes.md](../common/research-notes.md) §12），故内核只做 RSA ODA。
- **fDDA / dCVV / CVC3**、**Relay Resistance Protocol（RRP）**、**Data Exchange /
  Data Storage（DE/DS）**、**Privacy Protection**（Book E）。
- **Level 1 通信**（主机侧仅实现 EMV T=0 GET RESPONSE 检索，见
  [architecture.md](../common/architecture.md)）、**Torn transaction**、**云/分体内核**、
  **生物识别 CVM**。
- **Book C-8 专属项**：Kernel Configuration（§3.9）、卡选 CVM（§3.8）、加密记录
  （`DA` 模板 / AES-CTR）、Extended SDA Tag List、Card TVR / Kernel Reserved TVR Mask、
  `9F2C` Card Qualifier、§6 状态机、`9F8102`/`9F8105` 等 C-8 对象均未实现。
- **国别 / 区域变体**：PBOC、SM2/SM3/SM4、ECC 国密等品牌/国别专有算法与流程，范围外，预留。
- **CDCVM**：Book C-8 §3.8 列出，但属终端/设备侧，本项目不实现；非接触内核只做
  No CVM（`CvmPerformer=null`，`onlinePinSupported`/`signatureSupported` 均为 false，见 §6）。
- **SELECT (ADF Name) 失败的 End Application 分支 / Start B 携带 issuer 响应数据**
  （Book B §3.3.3.5 / §3.3.2.1）：Entry Point 层不持有联机响应数据，故未建模「SELECT
  返回非 `9000` 或格式错误且有待发 Issuer Authentication Data/Script 时产生 End Application
  Outcome」以及 Start B 用上次 Combination 继续的 issuer 响应数据路径；已登记 `TODO.emv.md`。

**已纳入范围**（见 §8 设计小节）：

- **Book A Entry Point 配置与预处理（Start A，§5.6.4/§5.7、Table 5-1/5-2/5-3）**：
  Combination Table、Entry Point Configuration Data、Pre-Processing Indicators 由
  `host/emv/kernel/entry/` 的 `CombinationTable`/`EntryPointConfiguration`/
  `PreProcessingIndicators` 建模；内核按 EMV v4.4 Book 3/4 的 TVR/TSI 判定照旧。
- **Book B Kernel Activation（§3.4）与 Outcome Processing（§3.5）**：`KernelActivation`
  携带 ADF Name/AID/Kernel ID/PPSE FCI/SELECT (ADF) FCI+SW/Start A/B 指标与 Start，
  并可按 §3.4.1.4 构建 Kernel Identifier–Terminal（tag `96`）；Select Next / Try Again /
  End Application / Try Another Interface / Final Outcome 由 Entry Point 状态机（§8）产出，
  Outcome Table 6-2 的 ADF Name / Data Record / Discretionary Data / Receipt /
  Field Off / Removal Timeout 字段已填充（§8.4）。**非目标**：品牌内核 C-2/3/4/7/8 的卡交互
  细节、CVM 内部执行（performer 已实现，但不属于本状态机）、fDDA/ECC、Level 1、
  UI 实际渲染（仅建模 Field Off / Removal Timeout 请求）。
- **SPI（Annex C，`CLA=80 INS=1A`）与 `9F3E`/`9F3F`**：**卡侧已实现**；终端侧在
  Entry Point 选择前按需发送（§8）。
- **Entry Point 的 *End Application* Outcome**（§3.3.2.7/§3.3.3.5，候选表为空或全部
  SELECT 失败）以 `kernel.core.EndApplicationException` 上报，携带 UI Request message
  identifier `1C`（"Insert, Swipe or Try Another Card"）。
- 每次内核激活刷新 Unpredictable Number（§8.1.1.8）**已实现**（`TransactionRequest` 的
  `unpredictableNumberFixed` 为 false 时，`TransactionFlow.beginTransaction` 与 Start C
  Restart 均重新抽取）。
- **终端发卡行脚本处理**（`71`/`72` 模板 → 逐条下发 `86` → 汇总 `9F5B` 并置 TVR byte 5
  脚本位，EMV v4.4 Book 3 §10.10 / EMV v4.4 Book 4 §6.3.9/Annex A5）：**已实现**——tag `71`
  在 final GENERATE AC **之前**处理、tag `72` 之后（`TransactionFlow`）；`IssuerScriptProcessor`
  解析模板、转发每个 `86`、只检查 SW1（normal/warning 继续）、按 Book 4 Annex A5 汇总 `9F5B`，
  置 TSI byte1 b3 与 TVR byte 5 的失败位（`card42.host.emv.kernel.core.Authorization`
  的可选 `issuerScripts`；用例 `ContactlessTest.issuerScriptTransaction` /
  `issuerScriptBeforeFinalAcFailure`）。

内核不持有 ICC 主密钥：在线授权由 `Issuer` 回调提供（ARC + `91`），ODA 由卡返回的
证书链验证。

## 2. PPSE FCI（Book B Table 3-2）

`SELECT 2PAY.SYS.DDF01` 的响应：

```
6F L
  84 0E 325041592E5359532E4444463031      DF Name (2PAY.SYS.DDF01)
  A5 L                                    FCI Proprietary Template (M)
    BF0C L                                FCI Issuer Discretionary Data (M)
      61 L                                Directory Entry (M)
        4F L  <payment AID>               ADF Name (M)
        50 L  <label>                     Application Label (O)
        87 01 <priority>                  Application Priority Indicator (C)
        9F2A L <kernel>                   Kernel Identifier (C)
      ...                                 (可多条 61)
```

- `6F` / `84` / `A5` / `BF0C` / `61` / `4F` 为强制；`50`/`87`/`9F2A` 为可选/条件。
- `84` 从读卡器角度可选，从卡角度必须个性化（Table 3-2 脚注 6）。
- 默认（未个性化）PPSE 由 `DirectoryBuilder` 构造单条 `61`；个性化 `9102` 提供整块 `A5`
  模板时按原文提供，可含多条 `61`。

`TEST_CONTACTLESS=1` 构建放行 PPSE 在接触接口被选中以便模拟器验证；默认构建在接触接口
返回 `6A82`（[architecture.md](../common/architecture.md) §7）。

## 3. Kernel Identifier（`9F2A`，Book B Table 3-4/3-5）

- 编码：字节 1 的 b8-b7 为内核类型，b6-b1 为 Short Kernel ID。读卡器按 Book B §3.3.2.5
  bullet C 解码：b8b7=`00b`/`01b` 时 **Requested Kernel ID 恒为字节 1**（即 b8b7‖Short
  Kernel ID），与值域总长度无关；b8b7=`10b`/`11b` 时若长度 < 3 跳过该条目，Short Kernel ID
  非 0 时字节 1–3 为 Extended Kernel ID。`9F2A` 值域 > 8 字节不是 Kernel Identifier，跳过。
  （Table A-1 的「1 或 3–8 字节」是**卡侧**编码约束；读卡器按 bullet C 取字节 1，故 2 字节的
  `00 xx` 仍解码为 Requested Kernel ID `0`。）
- **Card42 无内核**，故取 `9F2A = 00`：b8-b7=`00b`（国际内核）且 Short Kernel ID=`000000b`，
  语义为「内核与对应 ADF Name 关联」。读卡器按 Book B §3.3.2 bullet C 用 ADF Name 解析
  内核；对非品牌 AID，Table 3-6 的默认 Requested Kernel ID 为 `00000000b`，任何读卡器
  都接受该 Combination。
- `9F2A` 缺省与 `9F2A = 00` 对读卡器等价；卡选择显式携带 `00` 以便逐字段核对 Table 3-2。

## 4. 可选数据对象

- **`9F29` Extended Selection**（Table A-1）：`ADF Name 长度 + ES 长度 ≤ 16`。卡侧不生成；
  若个性化 `9102` 模板携带 `9F29`，则随原文提供。按 Book B §3.3.3.3，符合规范的读卡器在
  所选 Combination 含 `9F29`、且其 Extended Selection Support flag 存在并为 1 时，把 ES
  追加到 SELECT 的 ADF Name 之后。本项目内核已实现该行为：`EntryPointConfiguration.extendedSelectionSupported`
  为真且候选携带 `9F29` 时，`PpseSelection` 在 `SELECT (ADF Name)` 时把 ES 值追加到 ADF Name
  之后（§8.3）；未启用（默认 `false`）时不追加。卡侧在个性化 `9102` 时校验该 ≤16 约束
  （`PersoRules`，`adfLength+extendedLength>16` → `6A80`）。
- **`9F0A` ASRPD**（§3.3.1.2）：值域为 `ID‖L‖V` 序列。目录（PPSE/PSE）不生成；支付实例
  经 DGI `3001` 个性化后由卡追加到其 FCI 的 `BF0C`（见 [personalization.md](personalization.md) §4）。
  内核不解析 `9F0A`。
- **SPI（`9F3E` Terminal Categories / `9F3F` SDOL）**：卡侧已实现 SPI 命令
  （`CLA=80 INS=1A`，Book B §C.1）并在 PPSE FCI 广告这两个对象（见 §1 与
  `DirectoryApplet`）。读卡器只有在终端类别在 `9F3E` 列表中、或卡返回 `9F3F` 时才发 SPI
  （§3.3.2 Step 1/1a）。

## 5. 多条 Directory Entry 与优先级（Book B §3.3.2、Table 3-3）

- PPSE 的 `BF0C` 可含多条 `61`；卡不排序，按原文/构造顺序提供。
- `87`（Application Priority Indicator）：b8-b5 RFU，b4-b1 为 1–15 的优先级（1 最高），
  `0000` 表示未分配（等价于最低 15）。卡构造时把 b8-b5 清 0。
- 读卡器为每个读卡器 Combination `{AID, Kernel ID}` 处理每条 Directory Entry，构成
  Candidate List，再选优先级最高者（数值最小）并 `SELECT (ADF Name)`。内核的 Entry Point 实现
  该匹配（`EntryPoint.selectCandidates` 返回按优先级稳定排序的候选，`selectCandidate` 取首个）；
  每个 `Candidate` 按 §3.3.2.5 bullet E 携带 ADF Name、匹配的读卡器 AID、Kernel ID、Application
  Priority Indicator 是否出现（`priorityPresent`，缺省时优先级按最低 15）与 Extended Selection
  （`9F29`，仅保留不追加到 ADF Name）。候选按 ADF Name **全等或前缀（部分）匹配**（Book B §3.3.2.5 bullet B），ADF Name 长度须为 5–16
  （RID 5 B + PIX 0–11 B，畸形条目跳过，§3.3.2.5 bullet A）、解码 `9F2A`（缺省/单字节 `00` 按
  Table 3-6 品牌默认，其它取类型位；卡侧编码长度 1 或 3–8，读卡器按 bullet C 取字节 1，故 2 字节
  `00 xx` 仍解码为 Requested Kernel ID 0，>8 非法跳过），取 `87` b4-b1 最小者；
  只收集 `BF0C` 的直接子 `61`，专有模板内嵌套的 `61` 忽略（Table 3-2 后注）。**Requested
   Kernel ID 匹配（Book B §3.3.2.5 bullet D）**：值为 0（kernel-by-ADF-Name）一律接受；非 0 时
   仅当等于该匹配 AID 的读卡器 Combination Kernel ID 才接受。本读卡器只实现**单一通用内核**
   （kernel 0 / kernel-by-ADF-Name，见 `EntryPoint.READER_KERNEL_ID`），故其 Combination 一律
   携带 kernel 0，**不采用 Table 3-6 的品牌默认**：真实品牌卡（例如 Visa 未带 `9F2A` → 缺省
   Requested Kernel ID 3）与 kernel 0 不匹配，在 Entry Point 即被移出 Candidate List，交易以
   End Application Outcome（UI `1C`）干净结束，而不会激活读卡器未实现的内核。Table 3-6 的品牌
   默认仅在**解码卡侧 Requested Kernel ID**（`EntryPoint.defaultKernelId`）时使用。
- **Final Combination Selection**（Book B §3.3.3.5）：内核按优先级逐个 `SELECT (ADF Name)`，
  非 `9000`、DF Name（`84`）缺失/不匹配、或命中 §3.3.3.6 的候选从 Candidate List 移除并尝试
  下一候选；全部失败抛 `EndApplicationException`（End Application Outcome）。
- **§3.3.3.6**：Visa AID + Kernel 3 且所选 FCI 的 PDOL 缺失或不含 `9F66` 时，移除该候选并回到
  Start C（`EntryPoint.visaKernel3WithoutTtq`）。
- **GPO `6985` 重选**（Book 4 §6.3.1）：GPO 回 `6985` 时，内核通过 `Selection.reselect` 移除当前
  应用并选下一候选，重发 GPO；无候选则抛 `EndApplicationException`。

## 6. 终端内核流程（RSA profile）

内核是一个独立模块 `host/emv/kernel/`（package `card42.host.emv.kernel`，对位卡侧 `card/emv/applet/`），
顶层 `ContactlessKernel` 只做编排，终端数据模型、Entry Point 选择与终端侧算法各自成子模块：

| 类 | 模块 | 职责 |
|----|------|------|
| `TerminalConfig` / `TransactionRequest` / `TerminalState` | `kernel/data` | 不可变终端常驻配置（`9F66` TTQ、`9F33`/`9F40` 能力、`9F35` 类型、TAC、floor limit、random selection、CVM 配置、exception file）/ 每笔交易输入（金额/日期/币种/类型/UN、`9F06`、`9F41`）/ 跨交易 TSC 计数；`TerminalDol` 按 DOL 从二者与结果取值 |
| `Tvr` / `Tsi` | `kernel/data` | TVR（`95`）/ TSI（`9B`）位与位运算 |
| `EntryPoint` | `kernel/entry` | Entry Point Combination Selection（Book B §3.3.2）：ADF 匹配、`9F2A` 解码、优先级选择（纯函数） |
| `OfflineDataAuthentication` | `kernel/oda` | RSA ODA 编排：SDA/DDA/CDA 与 TVR/TSI 结果（Book 2 §5/§6.5/§6.6） |
| `TerminalActionAnalysis` | `kernel/analysis` | TAC/IAC（Denial/Online/Default）→ AAC/TC/ARQC（Book 3 §10.7；缺失 IAC-Online/Default 按全 1 默认） |
| `ProcessingRestrictions` | `kernel/analysis` | 版本/有效期/用途（`9F07`，含 goods/services、ATM、cashback 位）→ TVR byte 2（Book 3 §10.4） |
| `CvmList` | `kernel/analysis` | CVM List 解析与 CVM Results（Book 3 §10.5；奇数长度视为格式错误终止交易） |
| `TerminalRiskManagement` | `kernel/analysis` | floor limit、random selection（1..99 vs target %）、商户强制联机（Book 3 §10.6） |
| `IssuerScriptProcessor` | `kernel/script` | 终端侧发卡行脚本处理（Book 3 §10.10 / Book 4 Annex A5） |
| `ContactlessKernel` | `kernel` | 顶层：装配 `entry.PpseSelection`，然后委托 `TransactionFlow` |
| `TransactionFlow` | `kernel`（包私有） | 与接触内核共享的媒体中立流程（GPO 之后全部步骤） |
| `Selection` / `TransactionResult` | `kernel.core` | 应用选择接口与媒体中立交易结果（字段只读 + `Mutable` 写；`decision()` 统一决策；`PpseSelection`/`PseSelection` 在 `kernel.entry`） |
| `KernelListener` | `kernel.core` | 进度回调：Book 3 §10 步骤、候选表（`onCandidateList`）与 Final Outcome（`onOutcome`）；`NONE` 为 no-op |
| `CvmPerformer` | `kernel.analysis` | CVM 执行器接口（离线 PIN 实现在 `kernel.cvm.OfflinePinCvm`） |

传输（`Terminal` / `Terminals`）在 `host/common/transport/`；ODA 验证器在 `host/emv/oda/`。

> `ContactlessKernel` 与接触内核 `ContactKernel` 共享 `TransactionFlow`：GPO 之后的全部
> 流程只有一份实现，差异仅在应用选择（PPSE vs PSE/直接 ADF）与 CVM 执行（非接触无离线
> PIN）。接触内核见 [contact-kernel.md](contact-kernel.md)。

流程与关键点：

1. **Entry Point**：`SELECT PPSE` → 解析 `BF0C` 下的全部直接子 `61` → 按优先级排序候选 →
   `SELECT (ADF Name)`，失败则移除该候选并试下一候选（Book B §3.3.3.5）；ADF Name（5–16 B）与
   支持 AID 全等或前缀匹配；`9F2A` 按 Table 3-4/3-5 解码
   （b8b7=`00b`/`01b` 取字节 1 全值，故 2 字节 `00 xx` 仍解出 Requested Kernel ID `0`；仅
   b8b7=`10b`/`11b` 且长度 <3、或值域 >8 字节才跳过），缺省/单字节 `00` 按 Table 3-6
   品牌映射（Visa 3 / Mastercard 2 / Amex 4 / JCB 5 / Discover 6 / UnionPay 7 / 其它 0）。
2. **GPO / PDOL / TTQ**：从 SELECT 响应 `A5` 提取 `9F38` PDOL，按 `TerminalConfig`/`TransactionRequest` 逐标签
   填值（含 `9F66` TTQ、`9F33`、`9F40`、`9F35`），发 `80 A8 00 00 83 L …`。非接触响应为
   Format 2（`77 { 82, 94 }`）。DOL 填充按 §5.4：numeric 保留右端并左补 `00`，其它格式
   保留左端并右补 `00`。TTQ 默认 `31008000`（Table 5-4）：byte1 b6 EMV mode、b5 EMV
   contact chip、b1 ODA for online authorizations；byte3 b8 Issuer Update Processing——与内核
   实际执行 ODA、发卡行脚本与第二 AC 的行为一致。GPO `6985` 触发候选重选（§5）。
3. **READ RECORD**：按 AFL 读取全部记录，汇集 CDOL1/CDOL2、IAC、CVM List、有效期等。
4. **RSA ODA**（Book 2 §5/§6.5/§6.6）：
   - `SdaVerifier` 恢复并校验 issuer 公钥证书与 SSAD（`8F`/`90`/`92`/`9F32`/`93`）；
   - 由 issuer 公钥恢复 ICC 公钥证书（记录 5 的 `9F46`/`9F48`/`9F47`）；
   - DDA：按 ICC DDOL（`9F49`，CCD 要求仅含 `9F37`）填充终端 UN，发 `INTERNAL AUTHENTICATE`，
     `CamVerifier.verifyDda` 校验 SDAD；CCD 卡返回 Format 2 `77 { 9F4B }`；
   - CDA：`GENERATE AC` P1 b5-b4=`10`，`CamVerifier.verifyCda` 校验 SDAD、CID、AC 与
     Transaction Data Hash Code。
   - 失败映射 TVR byte 1：SDA 失败 `0x40`、DDA 失败 `0x08`、CDA 失败 `0x04`；SDA 被选为唯一
     ODA 方法时置 `SDA selected`（`0x02`）；完全不执行 ODA 置 `0x80`。ODA 一旦被选择并进入
     （无论成败）即置 TSI `ODA performed`（Book 3 §10.3）。
5. **Processing Restrictions**（Book 3 §10.4）：`9F08` 版本、`5F24`/`5F25` 日期、`9F07` AUC
   → TVR byte 2。domestic/international 由 `5F28` Issuer Country Code 与 `9F1A` Terminal
   Country Code 比较决定；purchase 需 goods（`0x20`/`0x10`）**和/或** services（`0x08`/
   `0x04`）位；ATM/非 ATM 需 byte1 b2/b1；带 cashback 时需 byte2 b8/b7（Table 36/42）。
6. **CVM**（Book 3 §10.5 / Book 4 §6.3.4.5 Table 2）：仅当 AIP b5=1 时解析 CVM List；写 CVM
   Results（`9F34`）与 TVR byte 3。CVM List 缺失时 TVR **byte 3** 不变、CVM Results `3F 00 00`、
   TSI=0，但 AIP b5=1 且 `8E` 缺失时另按 Book 3 §7.5 Table 35 置 TVR byte 1 b6「ICC data
   missing」；无 CV Rule 时同上（byte 3 不变）。条件均不满足/不支持/未识别时 CVM Results
   `3F 00 01`、TVR byte3 b8（未识别再加 b7）、TSI=1；Signature/Online PIN 的 byte3 为 `00`
   （Online PIN 另置 TVR b3）。
   X/Y 为 4 字节二进制；条件 05 看 cashback，06–09 要求交易币种=应用币种。奇数长度属格式
   错误，终止交易（§7.5）。
7. **TRM**（Book 3 §10.6）：floor limit → TVR byte 4 b8；random selection（生成 1..99 随机
   数，与 target percentage 0–99 比较，可选按金额偏置）→ b5；商户强制联机 → b4。
8. **TAA**（Book 3 §10.7）：先 Denial 对（TAC‖IAC），再 Online 对；命中 Denial → AAC，
   命中 Online → ARQC，否则 TC。缺失 IAC-Online/IAC-Default 按全 1 默认。联机不可用时用
   Default 对决定第二 AC 的 TC/AAC。
9. **GENERATE AC**：首 AC 请求 TAA 决定的类型（CDA 时置 `0x10`）；ARQC → `Issuer` 回调
   计算 ARPC（Method 2）与 CSU，填入 CDOL2 的 `8A`/`91`。第二 AC 的类型由 ARC 决定：
   ARC `00`（批准）→ TC，其它 ARC（拒绝）→ AAC（Book 4 §6.3.8）；无法联机时由 Default 对决定
   TC/AAC，ARC 取 `Y3`/`Z3`（Book 4 Annex A6 Table 35）。**CDA 失败**：首 AC 为 TC 时拒绝且
   不发第二 AC；首 AC 为 ARQC 时第二 AC 请求 AAC；第二 AC 的 CDA 失败同样拒绝（Book 4 §6.3.2.1）。
   离线结束时 ARC 取 `Y1`（批准）/`Z1`（拒绝）（Book 4 §6.3.6）。内核的 `TransactionResult.declined()` 汇总该决策。
10. **TSI**（`9B`）：**2 字节**（Book 3 Annex A / Annex C6 Table 47，byte 1 有效、byte 2 RFU）；
    ODA/TRM/Card risk management/发卡行认证/脚本处理执行位；CVM 位在 CVM List 处理运行且存在
    至少一条 CV Rule 时置位，含条件不满足/不支持/未识别（Book 4 Table 2）。
11. **ARC 处理**（Book 4 §6.5.2/§6.5.2.2、Annex A6）：ARC `00` 批准；`01` 为发卡行发起的
    voice referral，attended 终端经 `TerminalConfig.referralHandler` 让服务员接受（置
    `attendantForcedAcceptance`）或拒绝；`02` 请求 capture card（置 `cardCaptureRequested`）；
    其余拒绝。终端不修改 ARC。
12. **CID Advice / Service not allowed**（Book 3 Table 15、Book 4 §6.3.7 Table 3）：CID b4=1 置
    `adviceRequired`；reason `001b`（Service not allowed）置 `serviceNotAllowed` 并立即终止交易
    （第二 AC 记 AAC、拒绝），不再联机。
13. **Reversal**（Book 4 §6.3.8/§12.1.8）：ARC 为 online approved 而卡的最终决定拒绝（第二 AC
    为 AAC，或 CDA 失败）时置 `reversalRequired`（内核不发报文，只建模该要求）。
14. **Exception file**（Book 4 §6.3.5）：`TerminalConfig.exceptionFile` 中匹配的 PAN（及可选 PAN
    Sequence Number `5F34`）置 TVR byte1 b5 `Card appears in exception file`。
15. **重复数据对象**（Book 3 §7.5）：交易记录中「只应出现一次」的 ICC 对象出现多次时终止交易
    （`TransactionFlow.SINGLE_OCCURRENCE` 枚举内核消费的单次对象）。

卡侧行为：

- AIP 为非接触 RSA profile `0x6900`：按 **EMV v4.4 Book 3 Table 41** 解读——b8 XDA=0
  （无 ECC/XDA）、b7 SDA、b6 DDA、b1 CDA、b4 终端风险管理、b5 CVM=0（无离线 CVM）。
  本项目不声称 C-8 合规，故不采用 C-8 Table A.1 的位义（C-8 中该字节的 ECC 由 Card
  Qualifier/SC ASI 表达，而非 AIP）。
- 非接触 PDOL 请求 `9F66`/`9F33`/`9F40`/`9F35` 与金额/日期/币种/UN，由终端填充；卡只做
  长度校验（PDOL 数据对卡不透明）。
- 非接触 `GENERATE AC` 响应 Format 2（`77`）；CCD 口径接触实例同为 Format 2，通用接触为
  Format 1。CID/ATC 路径与接触侧共用
  `AcProcessor`/`EMVCrypto`/`DdaCrypto`；接触/非接触差异为响应格式（口径）与 CVM 策略。
- `9F2A`/`9F29`/`9F0A` 在流程中的读取：内核读 `9F2A` 做 Combination Selection；`9F29`/
  `9F0A` 不由目录生成，内核不解析。

### 6.1 Book 3 §7.5 / §5.4 终端处理

- **§7.5「shall ignore」**：内核读取交易/记录数据经 `TagPolicy.findIcc`，它按 Book 3 Annex A
  Table 37 丢弃 ICC 发来的 **terminal-sourced / issuer-sourced** 数据对象（卡伪造的
  `9F02` 金额、`91` 发卡行认证数据等一律忽略），并对 Table 34 列表（`5F20`/`9F0B`/`42`/
  `9F0C`/`5F50`/`9F4D`/`9F4F`/`9F1F`）的格式错误按「对象缺失」处理而不中止交易
  （`TagPolicy.isMalformed` 校验 IIN/IINE/Log Entry 长度与 Log Format 结构）。**例外**：ODA
  证书路径（`SdaVerifier`/`CamVerifier`）仍用普通 `Tags.find` 读取证书/静态数据，未做来源
  过滤（证书本身为 ICC 源，属已知范围）。同一 §7.5 的「单次出现对象重复出现即终止」由
  `TransactionFlow.checkSingleOccurrence` 对内核消费的单次 ICC 对象（`5A`/`5F24`/`8C`/`8D`/
  `8E`/`8F`/`90`/`92`/`93`/`9F07`/`9F0D`–`9F0F`/`9F42`/`9F46`–`9F4A` 等）实现。
- **Table 35 ATC / Last Online ATC 不适用声明**：内核从 GENERATE AC 响应取 ATC、不发
  `GET DATA`、不做卡侧频次检查，故 Table 35 的 `9F36`/`9F13`「ICC data missing」条件不成立，
  不置该位。**TVR 'Issuer authentication failed' 不适用声明**：本项目经 CDOL2 内联 `91` 完成
  发卡行认证（不发 `EXTERNAL AUTHENTICATE`），卡侧校验结果经 CVR 反映，终端无独立判据，故不置
  TVR byte5 b7；如发卡行在线响应明确返回认证失败（CID reason `011b`），内核仅置
  `adviceRequired`（见 §6 步骤 12）。
- **§5.4 DOL**：卡侧在个性化 `9F38`/`8C`/`8D` 时用 `DolReader.validate()` 拒绝 constructed
  tag（`6A80`）；terminal-sourced constructed 内的 primitive 不得被 DOL 请求（生物模板
  范围外，见 §1.2）。

## 7. 测试

- `test/emv/integration/card/DirectoryTest`：逐字段核对 Table 3-2（含 `9F2A` 嵌套在 `61` 内），并
  模拟 Entry Point Combination Selection（解析所有 `61`、解码 `9F2A`、按 `87` 选最高优先级、
  `SELECT (ADF Name)`）。PPSE 结构检查仅在 `TEST_CONTACTLESS=1` 构建执行。
- `test/emv/integration/host/kernel/contactless/ContactlessTest`：先直接调用内核 `EntryPoint.selectCandidate`/`selectCandidates` 覆盖多条 `61` 的优先级/
  tie-break/非法 `9F2A`/超长 ADF Name/候选排序；再用 `ContactlessKernel` 跑 9 个非接触场景——在线 CDA
  （ARQC→TC）、离线 CDA（TC）、终端经 TAC-Denial 拒绝（AAC）、发卡行拒绝（AAC）、无法联机拒绝
  （`Z3`）、无法联机批准（`Y3`）、CDA 失败拒绝、发卡行脚本 `72`（final AC 后）、发卡行脚本 `71`（final AC 前失败）；
  逐项核对 AIP `0x6900`、SDA/DDA/CDA 通过、CVM Results `3F 00 00`（AIP b5=0，不执行 CVM）、
  TVR、TSI、IAD CVR，并用 ICC 主密钥独立重算首/次 AC。默认构建 PPSE `6A82` 时报告跳过（不失败）。
- `test/emv/unit/host/kernel/PpseSelectionTest`：用脚本化 `CardChannel` 覆盖 Final Combination
  Selection——首候选 `SELECT (ADF Name)` 被拒后回退次候选、全部被拒抛 `EndApplicationException`
  （message `1C`）、DF Name 不匹配丢弃、Visa/Kernel 3 缺 `9F66` 丢弃、`reselect` 取次候选、
  2 字节 `9F2A` 按 bullet C 取字节 1、`dolContainsTag`（纯 JVM）。
- `test/emv/unit/host/kernel/contact/PseSelectionTest`：APDU 级 PSE 目录选择、List of AIDs 回退、
  `6A81` 终止、`reselect` 取次候选（纯 JVM）。
- `test/emv/unit/host/codec/ResponsesTest`：CID advice 位与 reason/advice code（纯 JVM）。
- `test/emv/unit/card/data/DirectoryBuilderTest`：`DirectoryBuilder` 的多条 `61`、`9F2A` 编码与
  `87` 掩码（纯 JVM，无需模拟器）。
- `test/emv/unit/host/kernel/{TerminalConfig,TerminalDol,TerminalActionAnalysis,CvmList,
  ProcessingRestrictions,TerminalRiskManagement}Test` 与 `test/emv/unit/host/util/BcdTest`：
  终端数据模型、DOL 填充（含不等长
  numeric/非 numeric）、BCD 往返、TAA 表驱动（含缺失 IAC 全 1 默认）、CVM（含奇数长度格式
  错误与 TSI 执行标志）、Processing Restrictions（含 services 位）、Terminal Risk Management
  （floor limit / random selection / 偏置 / 商户强制）的纯 JVM 单测。
- `test/emv/unit/host/codec/{Tags,TagPolicy}Test`：`Tags` 的 BER-TLV/DOL 读取；`TagPolicy.findIcc`
  的 §7.5 来源过滤与 Table 34 容错（terminal/issuer-sourced 忽略、IIN/IINE/Log Entry/Log
  Format 格式错误按缺失处理）。
- `test/emv/unit/card/data/StaticDataTest`：可选数据对象（`9F0C`/`9F0A`/`9F19`/`9F24`/`9F25`）
  的 FCI/记录 1 承载与缺省省略；DOL §5.4 constructed tag → `6A80`。
- 真卡 J3R180 冒烟：依赖 [toolchain.md](../common/toolchain.md) §5 的真卡 SCP02 个性化。J3R180 已接入并走通安装、个性化与非接触
  端到端交易（AIP `0x4800`、SDA、ARQC→TC；见 [toolchain.md](../common/toolchain.md) §5）。注意 `ContactlessTest` 断言
  AIP `0x6900` 与 DDA/CDA，对 SDA-only 的 J3R180 **不可移植**，真卡冒烟改由
  `terminal pay -iface=contactless` 手动执行。

## 8. Entry Point 状态机（Book A §5.8/§6、Book B §3.4/§3.5）

> 终端侧状态机由 `host/emv/kernel/entry/` 的下列类构成，`PpseSelection` 只做选择，
> `ContactlessKernel` 负责编排；Start A/B/C/D、Outcome/Restart、Try Again 与 Removal
> Timeout 均已实现。

### 8.1 配置与 Combination Table（Book A Table 5-1/5-2/5-6）

- `Combination`：读卡器支持的一个 `{AID, Kernel ID, EntryPointConfiguration?}` 组合；
  配置为空时回退到 Combination Table 的默认配置（`CombinationTable.configFor`）。
- `CombinationTable`：按交易类型（Purchase `00` / Cash `01` / Cashback `09` /
  Refund `20`，Table 5-6）维护 `Combination` 列表；`defaults(aids...)` 为每种类型都提供
  同一组组合，每个 Combination 携带本读卡器实现的 kernel（`EntryPoint.READER_KERNEL_ID`，
  即 kernel 0），而非 Table 3-6 的品牌默认（见 §5）。
- `EntryPointConfiguration`（Table 5-2）：Status Check Support、Zero Amount Allowed、
  Zero Amount for Offline Allowed、Reader Contactless Transaction/Floor Limit、Terminal
  Floor Limit（`9F1B`）、Reader CVM Required Limit、TTQ、Extended Selection Support；
  默认由 `TerminalConfig`（`floorLimit`/`cvmRequiredLimit`/`ttq`）派生，可覆盖。
  另含读卡器参数：**Autorun**（§8.1.1.6）、**Try Again on Decline**、**Field Off Request /
  Removal Timeout**（Table 6-2，秒，0 表示无；属设备参数而非 Table 5-2 数据）。

### 8.2 预处理指标（Start A/B，Book A Table 5-3）

`PreProcessingIndicators.startA(config, amount, contactlessApplicationNotAllowed)`
（Book B §3.1.1）：
- **Contactless Application Not Allowed**：交易类型在 Combination Table 中无组合；或
  Reader Contactless Transaction Limit 存在且金额 ≥ 该限值；或金额为 0、Zero Amount for
  Offline Allowed 未置 1 且 Zero Amount Allowed 为 0；或 Zero Amount 指示为 1 而 TTQ
  byte 1 b4 为离线终端。
- **Zero Amount**：金额为 0 且未按上一条被跳过/禁止。
- **Reader CVM Required Limit Exceeded**：Reader CVM Required Limit 存在且金额 ≥ 该限值。
- **Reader Contactless Floor Limit Exceeded**：Reader Contactless Floor Limit 存在且金额
  > 该限值；未提供时回退到 Terminal Floor Limit（`9F1B`）存在且金额 > 该限值。
- **Status Check Requested**：`statusCheckSupport` 置位**且** Amount, Authorised 为单一大单位
  货币（本项目按两位小数货币建模，即 100 个小单位，如 EUR 1.00；Book B §3.1.1.3）。
- **TTQ 副本**：从配置复制并复位 byte 2 b8/b7，再按 §3.1.1.9–.12 置位（floor/status →
  byte 2 b8；CVM → byte 2 b7）。

指标**按 Combination 逐个计算**：每个候选用其自身配置计算 Start A 指标，`Contactless
Application Not Allowed` 的候选被移出 Candidate List；全部候选被禁止时产出 Try Another
Interface（Book B §3.1.1.13）。若该 Combination 的 `autorun` 置位，则**不论是否请求 Status
Check**都改用 **Start B** 的固定指标（各指标清零，TTQ 复制并复位 byte 2 b8/b7），激活的
`KernelActivation.start` 记为 `START_B`（Book A §8.1.1.6：Autorun=Yes 时读卡器直接以
Start B 启动 Entry Point）。

### 8.3 选择与 SPI（Book B §3.3.2.5/§3.3.3、Annex C）

- `EntryPoint.selectCandidates(fci, CombinationTable, transactionType)`：按交易类型取
  Combination 集合，Directory Entry 的 ADF Name 与该集合的 AID 全等/前缀匹配，且
  Requested Kernel ID 为 0 或等于该 Combination 的 Kernel ID；按 `87` 优先级排序。
  集合为空即 Candidate List 为空（End Application Outcome `1C`）。
- **Extended Selection**：`EntryPointConfiguration.extendedSelectionSupported` 且
  Directory Entry 携带 `9F29` 时，`SELECT (ADF Name)` 追加 `9F29` 值（§3.3.3.3）。
- **SPI**（Annex C）：当终端类别在 PPSE FCI 的 `9F3E` 列表中、或卡返回 `9F3F` 时，
  `Spi.send` 先发 `80 1A 00 00 <83 ...>`（SDOL 值 + 两字节 ID 的 POI Information
  `0001` Terminal Category），用响应 FCI 做组合选择；响应非 `9000` 时按 §3.3.2.3b 不再加入
  候选并进入 End Application。响应 FCI 经 `Spi.stripAdvertisement` 剥离 `9F3E`/`9F3F`
  后再用于选择（Annex C.1.4；读卡器本已忽略这两个对象）。

### 8.4 Start 状态与 Outcome（Book A §6/§8.1.1、Table 6-2/6-3/6-4）

- **Start A/B/C/D**：`ContactlessKernel` 首次激活为 Start A（或按 §8.2 的 Start B）；
  Select Next 重启为 **Start C**；联机响应后重启为 **Start D**（`result.wentOnline` 为真时
  `start` 记 `START_D`，否则 `START_C`）。每次重启重抽 Unpredictable Number（§8.1.1.8）。
- **Final Outcome**：批准 → `APPROVE`，拒绝 → `DECLINE`，Service not allowed → `END_APPLICATION`
  （UI `1C`），全部候选 CANA → `TRY_ANOTHER_INTERFACE`（UI `18`）。配置 `restartOnDecline`
  时拒绝产出 `SELECT_NEXT`（Start C，取下一候选）；配置 `tryAgainOnDecline` 时拒绝产出
  **`TRY_AGAIN`**——按 EMV Contactless Book B v2.12 §3.5.1.3 / Book A v2.12 Table B.9 回到
  **Start B**（Protocol Activation）并以**同一 Combination** 重跑（`PpseSelection.restartStartB`，
  每次激活重抽 UN），UI Request on Restart 可选。
- **Outcome Table 6-2 字段**（`Outcome.from`）：`adfName`（Final Outcome ADF Name，Book B
  §3.5.1.5）、`dataRecordPresent`（读过 AFL 记录）、`discretionaryDataPresent`（所选 FCI
  含 `BF0C`）、`alternateInterfacePreference`（未建模，恒 false）、`receipt`（批准时为真）。
  `fieldOffRequest` / `removalTimeout` 在最终（非 restart）Outcome 上由配置填入，供读卡器
  关场并等待移除。
- **Restart 上界**：`MAX_RESTARTS = 4`；耗尽或 `activateNext` 无候选时产出 End Application
  （UI `1C`）。

## 9. 出处

- EMV Contactless Book B v2.12 §3.3.1（Table 3-2/3-3/3-4/3-5）、§3.3.2（Combination
  Selection）、§3.3.3（Final Combination Selection）、Table 3-6、Annex A（Table A-1/A-2）、
  Annex C（SPI）。
- EMV Contactless Book C-8 v1.2（`tools/specs-contactless-c8-1.2/`）：仅作**概念参照**——内核实际
  实现的是 **EMV v4.4 Book 3/4 通用终端流程**（PDOL/TTQ、§10.5 CVM、§10.7 TAA），不含 C-8
  的 ECC/Book E 安全通道、加密记录、卡选 CVM、IAD-MAC/EDA-MAC、Kernel Configuration 或 §6
  状态机；其 ECC/Book E/RRP/DE-DS 部分范围外。
- EMV v4.4 Book 2 §5（SDA）、§6.5（DDA）、§6.6（CDA）；Book 3 §5.4（DOL）、§10.4
  （Processing Restrictions）、§10.5（CVM）、§10.6（Terminal Risk Management）、§10.7
  （Terminal Action Analysis）、§9.3（AC 请求层级）。
