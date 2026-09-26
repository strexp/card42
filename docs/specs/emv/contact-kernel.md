# 接触终端内核（ContactKernel）规范

本文描述 Card42 参考主机栈的**接触模式终端内核** `ContactKernel` 及其接触应用选择。
依据 **EMV v4.4 Book 1–4**（`tools/specs-4.4/`）；非接触内核见
[contactless.md](contactless.md)，两者共享的流程见本文 §4。

> 命名说明：EMV 接触 Book 1–4 **没有 "kernel" 概念**（该词来自非接触 Book B/C 的
> Kernel 1–7）。`ContactKernel` 是本项目为「接触终端应用」起的名字，与
> `ContactlessKernel` 对位，便于两个内核共享同一套流程与测试结构。

## 1. 范围

### 1.1 做

- **接触应用选择**：SELECT PSE（`1PAY.SYS.DDF01`）→ 读目录记录 → 按 ADF Name / 优先级
  选候选；PSE 不可用或无候选时回退**直接 SELECT ADF Name**（Book 1 §12.3）。
- **接触编排** `ContactKernel`：GPO → READ RECORD → RSA ODA → Processing Restrictions →
  CVM（含离线 PIN）→ TRM → TAA → 首 AC → 联机 → 次 AC → 发卡行脚本。
- **离线 PIN 执行**：明文 `P2=80` / 加密 `P2=88`，PIN 输入用 `PinProvider` 回调。
- **共享结构**：与 `ContactlessKernel` 共享 `TransactionFlow` / `TransactionResult` /
  `Selection` / `CvmPerformer` / `Issuer` / `Authorization`（§4）。

### 1.2 明确范围外

与 [contactless.md](contactless.md) §1.2 相同：ECC/XDA/ODE、Book E 安全通道、
fDDA/dCVV/CVC3、Relay Resistance、Data Exchange / Data Storage、CDCVM、生物 CVM、
Level 1 通信（主机侧仅实现 EMV T=0 GET RESPONSE 检索，见
[architecture.md](../common/architecture.md)）、Torn transaction、云/分体内核。内核不持有 ICC 主密钥：联机授权由
`Issuer` 回调提供，ODA 由卡返回的证书链验证。

## 2. 接触应用选择（EMV v4.4 Book 1 §12.3）

`kernel/entry/ApplicationSelection`（纯函数）与 `ContactKernel` 的选择策略：

1. **PSE**：`SELECT 1PAY.SYS.DDF01`；成功则校验 PSE FCI 结构：

   ```
   6F L
     84 0E 315041592E5359532E4444463031   DF Name (1PAY.SYS.DDF01)
     A5 L
       88 01 <SFI>                         SFI of the Directory EF
   ```

   按该 FCI 宣告的 SFI（`88`，合法范围 1–10）逐条 `READ RECORD`，每条目录记录为：

   ```
   70 L
     61 L
       4F L <ADF Name>       (M)
       50 L <label>          (M)
       87 01 <priority>      (O)
   ```

2. **目录终止/跳过**（Book 1 §12.3.2 step 2）：仅当 `READ RECORD` 回 `6A83`（记录不存在）时
   结束读取。记录无 `70`、`70` 内无直接子 `61`、或某 `61` 无 `4F` 时**跳过该记录**并继续读取下一条。
3. **候选与优先级**：对每个 `61` 取 `4F`（长度须 5–16，Book 1 §12.2.1 Table 12）与
   `87` b4-b1（`0000` 视为 15），AID 匹配且优先级数值最小者胜出。AID 匹配按
   **Application Selection Indicator（ASI，Book 1 §12.3.1）**：本项目对所有受支持 AID
   均设 ASI=允许部分匹配，故接受全等或前缀（`EntryPoint.matchAid`）。`87` b8（持卡人确认）
   的条目按 Book 1 §12.4 处理：`ConfirmationProvider` 为空（默认，终端不提供持卡人确认）时，
   候选多于一个则跳过需确认者取次高优先级、仅此一个候选则终止会话；非空时按优先级顺序对
   需确认候选调用 `ConfirmationProvider.confirm(adfName, label)`，确认者按优先级加入候选、
   拒绝者跳过，全部无候选则终止。复用非接触
   `EntryPoint.matchAid`/`priority`/`confirmationRequired`（同为 `card42.host.emv.kernel.entry` 包）。
4. **回退（List of AIDs，Book 1 §12.3.3）**：PSE 不可选或无匹配候选时，按 `supportedAids`
   顺序直接 `SELECT`；`6A81` 终止会话（step 2）；成功（`9000`）时把 FCI `84` 与终端 AID 比对，
   全等或前缀（ASI 允许）时以 **FCI 的 DF Name** 作为选中值，并置终端 `9F06` 为该 DF Name
   （step 3/4，§12.4）。本项目卡不返回同一 AID 的多个 occurrence，且 Java Card JCRE 不支持
   `P2='02'`，故**不发 SELECT NEXT**（step 7），此差异已在 §1 范围声明。
5. 接触目录**不解析 `9F2A`**（Kernel Identifier 是非接触 Book B 概念）。

## 3. 接触内核流程（RSA profile）

`ContactKernel.run(terminal, data, issuer)` 先做接触应用选择，再调用共享
`TransactionFlow`（§4）。与非接触内核的差异仅两点：

- **应用选择**：PSE / 直接 ADF，而非 PPSE + Entry Point。
- **CVM**：接触 AIP 可声明 CVM（实例 01 AIP `0x7900`，b5=1），内核通过 `OfflinePinCvm`
  执行 CVM List 选中的离线 PIN；非接触内核的 `CvmPerformer` 为 null。

其余步骤（GPO/PDOL、READ RECORD、RSA ODA、Processing Restrictions、TRM、TAA、
首/次 GENERATE AC、发卡行脚本）完全一致；GPO 响应 Format 1/2 由 `Responses` 统一解析。
`9F66`（TTQ）只在非接触 PDOL 中出现，接触 PDOL 不请求即不填。

## 4. 与非接触内核的共享结构

| 类型 | 位置 | 职责 |
|------|------|------|
| `TerminalKernel` | `kernel` | 内核统一入口接口：`run(Terminal, TransactionRequest, Issuer) throws KernelException`；两个内核实现 |
| `TransactionResult` | `kernel.core` | 媒体中立的交易结果；字段只读，内核经 `Mutable` 写；`decision()` 给出统一决策 |
| `TerminalConfig` / `TransactionRequest` / `TerminalState` | `kernel.data` | 不可变终端常驻配置 / 每笔交易输入 / 跨交易 TSC 计数 |
| `TransactionFlow` | `kernel`（包私有） | GPO 之后的全部流程，参数化为 `Selection` + `CvmPerformer`；每步一个私有方法 |
| `Selection` | `kernel.core` | 应用选择策略接口 |
| `PpseSelection` / `PseSelection` | `kernel.entry` | 非接触 PPSE / 接触 PSE 的 APDU 级选择（`implements Selection`） |
| `CvmPerformer` | `kernel.analysis` | 执行 CVM List 选中的 CVM（离线 PIN）；null 表示不执行离线 CVM |
| `Issuer` / `Authorization` | `kernel.core` | 联机授权回调（ARC + 发卡行认证数据 + 可选脚本），回调可读 `TransactionResult` |
| `KernelListener` | `kernel.core` | 进度回调（Book 3 §10 步骤 / 候选表 / Outcome），默认 `NONE` |
| `KernelException`（+`TransactionException`/`TransportException`/`EndApplicationException`） | `kernel.core` | `run` 的受检异常层次 |
| `PinProvider` | `kernel.core` | 离线 PIN 输入回调（终端/UI 提供） |
| `OfflinePinCvm` | `kernel.cvm` | 离线 PIN `CvmPerformer`（明文/加密） |
| `EntryPoint` | `kernel.entry` | 非接触 Entry Point 组合选择（PPSE，纯函数） |
| `ApplicationSelection` | `kernel.entry` | 接触 PSE 目录选择（纯函数） |

`ContactlessKernel` / `ContactKernel` 都很薄：`run` 里构造 `TransactionFlow`，装配
`Selection`（+ 接触侧的 `OfflinePinCvm`）并委托 `TransactionFlow`。公共 API 只用
`kernel.core` 与 `kernel.data` 的类型（`TransactionResult` / `TerminalConfig` /
`TransactionRequest` / `Issuer` / `Authorization` / `PinProvider` / `KernelListener`）。

依赖方向：`core → data / host.oda`；`entry → core`；`oda → core`；`analysis → data`；
`cvm → analysis / core`；顶层 → 全部。`TransactionFlow` 包私有，仅两个内核使用。

## 5. 离线 PIN CVM（EMV v4.4 Book 2 §7.2，Book 3 §10.5）

`CvmList.process` 增加可选 `CvmPerformer` 重载：当 CVM List 选中离线 PIN
（CVM code `01` 明文 / `04` 加密）且 performer 支持时，由 performer 执行；执行结果映射到
CVM Results byte 3（`02` 成功 / `01` 失败）与 TVR byte 3（失败置 `CVM not successful`）。
默认（无 performer）路径行为不变：离线 PIN 视为不支持，置 `PIN pad not present`。

`OfflinePinCvm`：

- 明文（`01`）：`PinProvider.pin()` → `VERIFY P2=80`。
- 加密（`04`）：`SdaVerifier.recoverPinKey` 取 ICC PIN 公钥证书 → `GET CHALLENGE` 取
  ICC UN → `AcCrypto.emvEncipherPin(AcCrypto.iso9564Format2(pin), iccUn, n, e)`
  （Table 25 结构）→ `VERIFY P2=88`。
- `9000` → 成功；`63C0`（剩余 0）/`6983`/`6984` → 失败并置 TVR `PIN try limit exceeded`；
  `63Cx`（x>0）仅失败，不置该位（Book 3 §10.5.1 / Book 4 §6.3.4.1）。
- 组合 CVM（`03`/`05`，PIN + 签名）由 `CombinedPinSignatureCvm` 执行（EMV v4.4 Book 3 §10.5）。

接触终端配置用 `TerminalConfig.forContact()`：`9F33` byte 1 = `E0`（b8 Manual key entry、b7
Magnetic stripe、b6 IC with contacts），byte 2 = `98` 声明明文（b8）与加密（b5）离线 PIN 及
No CVM（b4），byte 3 = `C8` 声明 SDA（b8）/DDA（b7）/CDA（b4）（Book 4 Annex A2 Table 25/26/27；
Card capture 是 byte 3 b6，本内核不执行，故 `C8` 该位为 0），终端 AID 为接触实例。

## 6. 测试

- `test/emv/unit/host/kernel/contact/ApplicationSelectionTest`：PSE FCI 校验、目录终止、优先级、
  前缀匹配、持卡人确认（`87` b8）跳过、非 PSE FCI 拒绝（纯 JVM）。
- `test/emv/unit/host/kernel/contact/CvmListPerformerTest`：performer 重载的成功/失败/不支持分支，
  以及无 performer 的默认行为（纯 JVM）。
- `test/emv/unit/host/kernel/TerminalConfigTest`：`TerminalConfig.forContact()` 的能力与默认 AID。
- `test/emv/integration/host/kernel/contact/ContactKernelTest`：`ContactKernel` 端到端——离线 CDA + 离线 PIN
  成功（TC）、在线 CDA（ARQC→TC，校验 `9F13`）、TAC-Denial 拒绝（AAC）、发卡行 referral
  （ARC `01`，attendant 接受/拒绝）、capture card（ARC `02`）、exception file（TVR byte1 b5）、
  错误 PIN（CVM Results `01 00 01` / TVR）后正确 PIN 恢复；AC 密文用 ICC 主密钥独立重算。
  用例以一次 CSU 复位交易开始/结束，避免影响后续 suite 的脱机累加器。
- `test/emv/integration/card/EmvFlowTest`：末尾增加一段 `ContactKernel` 复跑，与手写流程互为对照。
- 真卡 J3R180 接触冒烟：PSE 选择（目录 rec2 `6A83` 终止）、接触 AIP `0x5800`、
  SDA、明文脱机 PIN（`VERIFY P2=80`，CVM Results `01 00 02`、TSI `F800`）与在线 ARQC→TC
  均走通。

## 7. UI / 凭条接口（占位，范围外）

POS/ATM 的完整 UI（显示、打印、持卡人交互）**不在本项目**，由独立项目实现；本项目只提供
稳定接口与 no-op 占位，供其接入：

| 接口 | 位置 | 职责 |
|------|------|------|
| `ConfirmationProvider` | `kernel.core` | 持卡人确认（Book 1 §12.4 step 5）；null = 不提供 |
| `Display` | `report`（`card42.host.emv.report`） | 面向持卡人的消息显示 SPI；`Display.NONE` 为 no-op（完整 UI 在独立项目） |
| `PinProvider` / `OnlinePinProvider` / `SignatureProvider` | `kernel.core` | CVM 输入回调 |
| `Receipt` | `report`（`card42.host.emv.report`） | 凭条数据模型（`Receipt.from(TransactionResult, TransactionRequest)`） |
| `ReceiptRenderer` | `report` | 凭条渲染接口；`text()`/`json()` 为参考实现 |
| `ReceiptPrinter` | `report` | 凭条呈现接口；`ReceiptPrinter.NONE` 为 no-op |

参考 CLI 的映射：`terminal pay -confirm=always|never` 构造 `ConfirmationProvider`；
`-receipt=<path>` 构造一个用 `ReceiptRenderer.text()` 写文件的 `ReceiptPrinter`，仅在
`Outcome.receipt`（非接触）或交易未拒绝（接触内核不建模 Outcome）时打印。

## 8. 出处

- EMV v4.4 Book 1 §12.3（应用选择）、Book 3 §10.4–§10.8（限制/CVM/TRM/TAA）、§10.10（脚本）、
  §9.3（AC 请求层级）。
- EMV v4.4 Book 2 §5/§6.5/§6.6（SDA/DDA/CDA）、§7.2（离线 PIN）、§8.2（发卡行认证）。
- EMV v4.4 Book 4 §6.3（终端处理）、Annex A2（终端能力）、Annex A6（ARC）。
- 共享结构与非接触侧：见 [contactless.md](contactless.md) §6。
