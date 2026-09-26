# 交易链路行为规范

本文描述卡侧在交易链路（GPO → READ RECORD → 认证 → GENERATE AC → 联机/后发卡）上的当前
行为与规范依据。

## 1. ATC 自增与封顶

- **ATC 每会话只自增一次，在 `GET PROCESSING OPTIONS` 成功处理时**（Book 2 Annex D3），
  不在 `SELECT` 自增。会话标志 `gpoDone` 保证幂等。
- `GENERATE AC` 返回的 `9F36` 与 AC 计算所用 ATC 一致。
- 达到 `0xFFFF` 不回绕：应用进入 invalidated（APPLICATION BLOCK）语义，`SELECT` 回 `6283`，
  `GENERATE AC` 只出 AAC。

## 2. GPO / PDOL / Format 2

- `P1=P2=00`，否则 `6A81`（Book 3 Table 18；错误 P1/P2 用 EMV Table 4 的 `6A81`，不用 ISO `6B00`）。
- 解析命令数据 `83` 模板：无 PDOL 时终端仍须发 `83 00`；命令数据域缺失回 `6700`；有 PDOL 时按
  `DolReader` 校验长度，值长度不符回 `6700`、模板畸形回 `6A80`，`83` 值后有多余字节回 `6A80`
  （Book 3 §6.5.8.3）。校验通过后才自增 ATC。
- PDOL 终端数据存入 `EMVProtocolState` 的 `CLEAR_ON_DESELECT` 会话 transient；展开长度
  超过缓冲（64 B）时回 `6985`。
- 响应格式由**应用 CCD 数据格式**决定（`PaymentData.isCcdFormat()`：个性化 CDOL2 含内联 `91`）：
  CCD 一律 Format 2（`77 {82 AIP, 94 AFL}`，Book 3 CCD §6.5.8.4 / Table CCD 4），接触与非接触
  皆然；通用 EMV 口径接触 Format 1（`80 || AIP(2) || AFL`，无 TLV 标签）、非接触 Format 2。
  AIP/AFL 由 DGI `9104` 提供；AIP byte1 bit3 只决定 `INS=82` 是否可用（§6），不决定格式。

## 3. DOL 字段定位

`card/emv/tlv/DolReader.java` 为零分配、可 `reset` 复用的游标：定义与数据域并行推进，提供
`totalDataLength`/`findValueOffset`。`EMVStaticData` 的 CDOL/PDOL 长度与 tag 偏移全部由它
实现；畸形/截断定义抛 `6A80`。记录 1（`0101`）的 CDOL/CVM/PAN/有效期在个性化时被解析进
结构化字段（EMV CPS v2.0 Annex A）。

**DOL 构造规则（Book 3 §5.4）**：`DolReader.validate()` 在个性化 `9F38`/`8C`/`8D` 时逐项
校验，只允许 **primitive** 数据对象；constructed tag（`70`/`A5`/`BF0C` 等）或畸形定义回
`6A80`。terminal-sourced constructed 内的 primitive（生物模板等，范围外）同样不得出现在
DOL 中（`Tlv.isConstructed`）。

## 4. Card Action Analysis / IAD / Format 2 AC

- `CardRiskManagement.decide` 按 Book 3 §10.8 顺序比较 TVR 与三档 IAC（长度取较短者逐字节
  AND）：命中 IAC-Denial → AAC；命中 IAC-Online → ARQC；命中 IAC-Default → AAC；否则 TC。
  默认 IAC 为 Denial 全 0、Online/Default 全 1。**注**：卡侧风险管理算法由发卡行定义、不在
  Book 3 §10.8 规范范围内；本项目把 IAC-Default 解释为「卡侧无法联机时的拒绝」，直接返回 AAC。
  标准里 IAC-Default 是**终端**在联机失败后（§10.7）使用的规则，两者口径不同，此处属发卡行选择。
- **请求/响应层级（Book 3 §9.3）**：终端可请求 TC/ARQC/AAC；卡**只可降级不可升级**。
  终端请求 AAC 必回 AAC；第二 AC 只回 TC/AAC；第三及以后回 `6985` 且响应体为空。
- `P2` 必须为 `00`（Book 3 Table 11/§6.5.5），否则 `6A81`；`P1` b5-b4=`01`（XDA，未实现）
  回 `6A81`；b5-b4=`11`（RFU ODA 类型）与 b6 等 RFU 位不校验（Book 3 §6.3.6），按「不请求
  CDA/XDA 签名」处理。命令数据长度须等于 CDOL 定义长度，不符 `6700`。CDOL1 数据须能容纳于卡的
  瞬态缓冲（按实际长度分配，上限 128 B），否则 `6A80`（不静默截断；Book 2 §6.6.1 要求第二次
  AC 的 CDA 哈希覆盖完整第一次 CDOL1 数据）。
- **CID**（`9F27`）按 Book 3 Table CCD 3 编码（含 Advice/Reason 位，默认全 0）。
- **IAD（`9F10`）**：固定 **32 B CCD Format Code 'A'**（EMV v4.4 Book 3 CCD §C9）；字节
  1/17 为 `0F`，字节 2 为 CCI `A5`（FC 'A'、CV '5'），字节 4-8 为 **CVR**，由卡在每次
  `GENERATE AC` 前聚合写入（见 [personalization.md](personalization.md) §5）。卡内 AC 输入
  尾部与响应 IAD 同字节/同长度（同源），日志 `9F10` 亦同源。
- AC 输入为 `CDOL 数据 ‖ AIP ‖ ATC ‖ IAD`；**AC 用 ISO/IEC 9797-1 Algorithm 3**（v4.4 CCD
  §8.1.2，CV '5'）。AC 输入由个性化 CDOL1 定义；**默认与示例 CDOL1 现为 Book 2 CCD Table CCD 3
  的元素集**（`9F02`/`9F03`/`9F1A`/`95`/`5F2A`/`9A`/`9C`/`9F37`，定义长度 `8C 15`），不追加
  `9F35`/`9F34`/`9F45`/`9F4C`；卡按 CDOL 逐字节计算，个性化仍可自行扩展。
- **响应格式**：非 CDA 的 `GENERATE AC` 与 GPO 一致——按**应用 CCD 数据格式**判定
  （`PaymentData.isCcdFormat()`：个性化 CDOL2 含内联 `91`，CCD §6.5.5.3）。CCD 一律 Format 2
  `77 {9F27, 9F36, 9F26, 9F10}`（Book 3 CCD §6.5.5.4 / Table CCD 2）；通用 EMV 口径接触 Format 1
  （`80 || CID(1) || ATC(2) || AC(8) || IAD`）、非接触 Format 2。**不用 AIP byte1 bit3**
  （那只是 CCD 合规的结果，CCD §6.5.4.1）。CDA 请求被降级为 AAC 时按普通密文格式返回；实际返回
  签名的 CDA 响应为 Format 2 `77 {9F27, 9F36, 9F4B, 9F10}`（Book 3 Table 14，签名字段为
  `9F4B`，不含 AC `9F26`）。

## 5. READ RECORD 与 AFL

- `isReadableSfi()` 只接受 GPO 所宣告 AFL 中的 SFI；未宣告 SFI → `6A82`（不泄露文件存在性）。
- P2 b3-b1 必须为 `100`（Book 3 Table 22），否则 `6A81`；SFI 合法但记录无数据 → `6A83`；可读 → `9000`（Book 3 §6.5.11）。
- 日志 SFI 显式放行（不在 AFL）。
- `DirectoryApplet`（PSE）同步：未知 SFI → `6A82`、目录文件无此记录 → `6A83`。
- `SW_RECORD_NOT_FOUND = 0x6A83` 由 Java Card 3.0.5 `ISO7816` 提供（卡侧类 `implements ISO7816`）。

## 6. 发卡行认证（ARPC）+ 联机 + `9F13`

两条路径，由 AIP byte1 bit3 选择（perso/构建开关）：

- **CCD（默认，bit3=0）**：认证数据 `91`（8 B = ARPC(4) ‖ CSU(4)）由**第二次 GENERATE AC**
  的 CDOL2 内联送达；`INS=82` 返回 `6985`。
- **通用 EMV（bit3=1）**：接受 `INS=82 EXTERNAL AUTHENTICATE`（CLA `00`、P1/P2=`00`、
  data=`91`，`Lc` 8–16）；成功 `9000`、失败 `6300`、每交易至多一次（重复 `6985`）、
  P1/P2 非 0 → `6A81`（Book 3 §6.5.4.5/§10.9，Table 4）。数据域为「前 8 B 密文 + 可选 1–8 B
  proprietary」（Book 3 §6.5.4.3）。**两种 ARPC 方法都接受**：先按 **Method 2** 校验
  （`Lc=8` 的标准 `ARPC(4)‖CSU(4)` 即可，成功时应用其 CSU），否则在 `Lc ≥ 10` 时按 **Method 1**
  校验；Method 1 需要 ARC 而标准数据域不含，故本项目把 ARC 放在 proprietary 前 2 B（项目约定，
  标准终端用 Method 1 必须同样携带）。`Lc=8/9` 且非 Method 2 时回 `6300`。

ARPC 校验复用第一次 AC 的 `SK_AC`（不重派生）：

- **Method 2**（CCD，Book 2 §8.2.2）：`ARPC = Annex A1.2 MAC(SK_AC)[ARQC ‖ CSU ‖ proprietary]`，
  取 4 B；CCD 的 proprietary=0 B。
- **Method 1**（通用，Book 2 §8.2.1）：`ARPC = DES3_ECB(SK_AC)[ARQC ⊕ (ARC‖00×6)]`，8 B。

失败（`6300` 或内联不匹配）使第二次 `GENERATE AC` 回 AAC。ARC `Y3`/`Z3`（无法联机）置
「Unable to go Online」风险输入（比较完整两字节 ARC）；此时**先解析 ARC、不执行内联 issuer
auth**（无发卡行响应，全零 `91` 不得判失败），CVR1 记「Issuer Authentication Not Performed」、
CVR4 记「Unable to go Online」，第二 AC 按终端请求在 Default 对下判 TC/AAC。**`9F13`（Last
Online ATC）**仅在交易实际联机（ARC 非 `Y3`/`Z3`）且首 AC 为 ARQC 时于第二 AC 写入，或 `INS=82`
成功时写入（Book 3 Annex A Table 37；Book 2 §8.2）。

**CSU 处理**（Book 3 Annex C §C10）：`Update PIN Try Counter`（byte2 b5）把持久 PTC 设为
byte1 b4-b1 的值，包括 0（锁 PIN）与任意中间值（`card/emv/command/OfflinePinState.java`，包裹
`OwnerPIN` 并另存持久 PTC/PTL，`9F17` 上报该值）；`CSU Created by Proxy for the Issuer`
（byte2 b3）为 1 时不驱动脱机计数（本卡采用 §10.11.1.1「shall not update the offline
counters」选项，`OfflineRisk.updateCountersApply`）。DGI `9010`（PTC‖PTL）个性化该计数器。

## 7. 安全报文 / 发卡行脚本 / 后发卡命令

- CCD 应用的 SM 命令一律 **Format 1**（CLA 低半字节 `C`）；数据对象 `81`（明文）/`87`（密文）/
  `8E`（MAC）；MAC 用 Book 2 Annex A1.2（ISO/IEC 9797-1 Alg 3），加密用 Annex A1.1（CBC/3DES，
  padding indicator `01`）。**不采用** Mastercard 专有 SMI/SMC 命名。Book 2 CCD §9.2.1 明确要求
  CCD 应用的所有 SM 命令使用 Format 1，因此 Book 3 Table 6/7/8 允许的 `84`/`94`（Format 2）本
  项目不实现（`84`/`94` → `6985`；`9C` 对 `PIN CHANGE/UNBLOCK` 为链式、对其余后发卡命令
  → `6884`）。
- **MAC 链**：首条脚本命令的 ICV 恒为**第一次 GENERATE AC** 的 AC（Book 2 §9.2.3.1），后续用
  前一条的完整 8 B MAC；链跨 `71`/`72` 连续（`scriptIcv` 8 B 暂存）。4 B 截断 `8E` 被接受，
  链仍以完整 8 B 推进。
- 明文请求回 `6985`，MAC 错回 `6A80`（本交易后续命令 `6985`）。
- **命令链**（EMV v4.4 Book 3 §6.5.13）：仅 `VERIFY` 与 `PIN CHANGE/UNBLOCK` 支持。非末块
  （CLA b5=1）回 `9000`：`VERIFY` 累积命令数据（末块校验 PIN），`PIN CHANGE/UNBLOCK` 校验并推进
  SM MAC 链但不改状态（末块执行）。其它 INS 的链式命令回 `6884`；链未以期望的末块结束（换命令）
  回 `6883`；链式 `VERIFY` 累积溢出回 `6800`（§6.5.12.5）。链状态为会话级，`SELECT` 复位；
  `GET CHALLENGE` 挑战仅对下一条命令有效（§6.5.6.1），非末块链式 `VERIFY` 分片即令其失效
  （加密 PIN 不能链式）。本卡只做非生物 PIN，链式主要用于长数据/结构一致性。
- 后发卡命令：`APPLICATION BLOCK(1E)` / `UNBLOCK(18)` / `CARD BLOCK(16)` /
  `PIN CHANGE/UNBLOCK(24)`，`CLA 8C`（**仅 Format 1**，低半字节 `C`；规范 Book 3 Table 6/7/8
  也允许 `84`，但本卡不实现 Format 2）、`P1=P2=00`、带 SM MAC。
  `84`/`94`（Format 2）→ `6985`；`9C`（含链位 b5）对 `PIN CHANGE/UNBLOCK` 为链式，对其余
  后发卡命令 → `6884`。
  - BLOCK → `SELECT` 回 `6283` 且 `GENERATE AC` 只出 AAC；UNBLOCK 恢复。
  - CARD BLOCK → 此后所有 `SELECT` 回 `6A81`（卡级标志）。
  - `PIN CHANGE/UNBLOCK P2=00` 仅解锁并把 PTC 复位到 PTL，**不含新 PIN**；`P2=01/02` 为支付
    系统专有，未实现（回 `6A81`）。
- **主机侧职责**（Book 3 §10.10、Book 4 Annex A5）：`71`/`72` 模板由发卡行→终端，终端逐条
  下发其中的 `86`（Issuer Script Command）；`9F5B`（Issuer Script Results）由**终端**汇总上报，
  不随卡响应返回。
- jcsl 不实现 `ALG_DES_MAC*_ISO9797_1_M2_ALG3`，卡侧 `RetailMac` 用单 DES CBC-MAC
  （`ALG_DES_MAC8_ISO9797_M2`）+ 两步单 DES ECB 终变换等价实现 ISO/IEC 9797-1 Alg 3
  （详见 [cryptography.md](../common/cryptography.md)）。

## 8. 交易日志（`9F4D` + `9F4F` + 环形记录）

- 入口为 **Log Entry `9F4D`**，放在支付 FCI 的 Issuer Discretionary Data（`BF0C`/`73`），
  值 `SFI ‖ 记录数`；**SFI 必须在 11–30**（采用 `0x0F`，容量 8）（Book 3 Annex D §D4）。
- `9F4F`（Log Format）经 `GET DATA 9F4F` 返回；可经 DGI `3000` 个性化，缺失用 `Defaults.LOG_FORMAT`。
- 日志记录为**纯值拼接、无 `70` 模板、不列入 AFL**（Book 3 Annex D §D4）；`READ RECORD` 读
  SFI 15，记录 #1 为最新（环形，Book 3 Annex D §D4）；**锁卡（APPLICATION BLOCK）后仍可读**
  （Book 3 Annex D §D4）。注：该行为依赖 SELECT 失败后 applet 仍保持选中；模拟器（jcsl）
  如此，真卡 J3R180 亦已实测保持选中（APPLICATION BLOCK 后 `6283`，随后 `READ RECORD`
  SFI15 回 `9000`，见 [architecture.md](../common/architecture.md) §3）。
- **写入时机**：仅在交易最终确立点写一条——首 AC 出 TC、首 AC 出 AAC、或第二 AC 结束；
  首 AC 出 ARQC 后未收到第二 AC（交易未完成）不写。
- **持久化**：index-free 环形（每槽自带 16 位序号 + 1 字节 XOR 校验和，无单一写指针热单元）；
  记录/序号/校验和在一个 `JCSystem` 微事务内提交。

## 9. 脱机风控累加器（`OfflineRisk`）

- 持久化连续脱机计数与累计脱机金额（BCD，6 B）。限值：`9F14`/`9F23`（LCOL/UCOL）与
  DGI `E002`（LCOTA/UCOTA；Card42 项目 DGI，非 CPS 保留段）。
- 达 LCOL/LCOTA 或 CSU「Set Go Online on Next Transaction」→ 首 AC 强制 ARQC（只降不升）。
  注：卡侧累加器阈值为发卡行自定义（Book 3 §10.8）；本实现把 LCOL/UCOL 当作**含端点**的阈值
  （计数等于限值即视为超限，0 视为禁用）。终端侧另按 Book 3 §10.6.3 实现独立的速度检查：
  仅当卡同时提供 `9F14`/`9F23` 时，用 GET DATA 读取 ATC（`9F36`）与 Last Online ATC（`9F13`），
  以 `ATC − Last Online ATC` 与 LCOL/UCOL 比较（**等于**限值视为未超限），Last Online ATC 为 0
  时置 TVR「New card」；任一寄存器缺失或 ATC ≤ Last Online ATC 时置 LCOL/UCOL 超限位
  （`TerminalRiskManagement.velocityChecking`）。
- 达 UCOL/UCOTA 且终端无法联机（ARC `Y3`/`Z3`）→ 第二 AC 降为 AAC（Book 3 CCD §9.2.3.3）。
- 第二 AC 离线批准（终端无法联机、ARC `Y3` 且第二 AC 为 TC）与首 AC 离线批准一样计入
  LCOL/UCOL 与累计脱机金额（Book 3 CCD §9.2.3.2「transactions approved offline」）。
- 联机成功后按 CSU 的 `Update Counters` 位复位/更新累加器；处理 CSU 的 Application/Card Block
  与 Set-Go-Online 位（Book 3 CCD Annex C §C10）。
- **口径**：CVR 写入 IAD（byte3 含脱机限值位，byte4 含 Go-Online/Unable 位，见
  [personalization.md](personalization.md) §5）；累加器状态同时经 Card Action Analysis 体现。
  byte4 b8-b5「成功经安全报文处理的命令数」（Book 3 §9.2.3.2）在本项目中**仅限本交易**：
  `SecureMessaging.startNewTransaction()` 每笔交易把计数归零（规范未限定交易范围，属项目口径）。

## 10. 锁卡语义分层

| 触发 | `SELECT` | `GENERATE AC` |
|------|----------|---------------|
| ATC 到 `0xFFFF` / APPLICATION BLOCK | `6283` | 只出 AAC |
| CARD BLOCK | `6A81` | — |
| 未个性化 | FCI（`9000`）；支付命令 `6985` | `6985` |

三者不得混用（Book 3 §6.5.1–6.5.3）。
