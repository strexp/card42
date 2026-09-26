# 个性化规范

个性化使用 `STORE DATA` 承载 **DGI 容器序列**，编号遵循 **EMV CPS v2.0（2021-08）**
。DGI 容器为 `DGI(2B) ‖ 长度 ‖ 值`，值内部为 BER-TLV；DGI 序列在
最后一块到达时原子应用。完成信号为 **末块 `P1.b8=1`**；可选 DGI `7FFF` 只作携带完成
数据之用，缺失不影响判定（CPS §3.3）。

## 1. 个性化路径

个性化只有一条路径：**GP 安全通道**（模拟器 SCP03；真卡 GPPro 可为 SCP02）。GPPro
`--personalize <AID> --store-data <hex>`（模拟器与真卡共用）向安全域打开会话，发
`INSTALL [for personalization]`（`80 E6 20 00`，数据域
`LV(实例AID) ‖ 00 00 00`），再逐块发 `STORE DATA`（`P1.bit8` 标最后一块）。SD
解密/验 MAC/校验块序后，把**每个 STORE DATA 命令原样**（含 `CLA/INS/P1/P2/Lc` + 数据域）
经 `org.globalplatform.Personalization.processData` **逐块转发**给 applet，applet 自行按
`P1/P2` 重组。机密性、完整性与抗重放由 SD 的会话承担。**DGI 应用的原子性由卡应用负责**
（GP Card API 1.6/1.7 `Personalization.processData` javadoc：应用自行管理其数据的原子修改），
CPS v2.0 未规定 SD 代为开事务。**当前实现**依赖 SD 在 `processData` 期间持有事务（GPPro/卡管理器
如此），applet 自身不 `beginTransaction`（嵌套事务会 `BUFFER_FULL`，见 [risks.md](../common/risks.md)）；GP 未强制该
语义，故这是实现约定而非规范保证。applet 侧不做额外认证。

### STORE DATA 语义

- `CLA=0x80`（GP），`INS=0xE2`。
- `P1.bit8`：`1`=最后一块，`0`=还有后续块。**这是个性化的完成信号**。
- `P1.b1`：CPS Table 4-9 定义为 "Response expected (R-MAC)"（`1` 期望响应 / `0` 不期望）。
  本项目约定：`1`=允许 applet 经 `outBuf` 回传数据，为 `0` 时 applet 返回 0 长度（不报告），
  兼容 GPPro `--store-dgi-file` 等置 `b1=0` 的工具；该 0 长度回传是项目/GP 约定，非 CPS 规定。
- `P2` = 块序号（从 0 递增）；**applet 校验块序**（`PersoHandler`，不匹配回 `6A86`）；CPS
  §4.3.4.6 note 10 说明 **ICC 应用可忽略 `P2`**（安全域可代为管理块序）。
- `Lc` 支持 1 字节或 3 字节（`00 || LcHi || LcLo`，EMV CPS v2.0 Table 4-8）；`PersoRules`
  解析后按实际宽度定位数据域，`Lc` 与命令长度不符回 `6A80`。
- 短 APDU；SCP 开销 24 B → 单块数据域 ≤ 231 B；单个 DGI 值建议 ≤ 200 B。
- 未实现 `Personalization` 且无 `0x80` 特权 → `6985`；未发 `INSTALL [for personalization]` →
  `6A88`。

### 长度编码（CPS §3.2）

- 数据长度 `00`–`FE`（0–254 B）：1 字节二进制长度。
- 数据长度 `0000`–`FFFE`（0–65534 B）：`FF` + 2 字节大端长度，如 `FF01AF` = 431 B。

> 注意：DGI 容器长度用 CPS 编码；**DGI 值内部**的 BER-TLV 长度仍为 BER（`81`/`82` 长形式）。

### `processData` 约束

applet 在 `processData` 期间**不是被选中的 applet**：不得依赖 `CLEAR_ON_DESELECT` transient
数组，`selectingApplet()` 不为真。原子性由应用负责（GP `Personalization.processData`），但
当前实现依赖 SD 的事务语义、**不自行 `beginTransaction`**（嵌套事务共享事务缓冲，长 DGI 序列
会 `BUFFER_FULL`）；`P2=0` 视为新序列起点，失败路径复位重组状态（EMV CPS v2.0 §4.3.4.5/§4.3.4.6）。
`inBuf` 是整个 STORE DATA 命令，`inOff` 指向 `CLA`。

## 2. 生命周期与命令准入

见 [architecture.md](../common/architecture.md) §3。个性化期间只接受 SELECT / STORE DATA / GET DATA；
完成后 `STORE DATA` 回 `6985`。

## 3. DGI 容器表（EMV CPS v2.0 + Card42 扩展）

| DGI | 含义 | 备注 |
|-----|------|------|
| `0101`/`01nn` | 文件记录（`70` 模板） | DGI = `(SFI<<8)｜record`，CPS §3.2 |
| `9102` | SELECT 响应（`A5` 模板） | FCI；PDOL 从其中提取 |
| `9104` | GPO 响应数据（`82` AIP、`94` AFL） | 卡按角色封装 format 1/2 |
| `3000` | 应用公共内部数据（`9F36` ATC、`9F4F` 日志格式） | |
| `3001` | 应用内部数据（IAC、`9F14`/`9F23`、`9F10` 等） | |
| `8000` | 块密码密钥：CAM（ICC 主密钥）‖ MAC UDK ‖ ENC UDK | CV '5' 3DES 每把 16 B；CV '6' AES 每把 16 B（CPS Table A-2 允许 16/32 B，但 jcsl 无 AES-256，卡侧仅 AES-128） |
| `9000` | 块密码 KCV | 接受但忽略（卡不计算/校验 KCV） |
| `8010` | Reference PIN Block（ISO 9564-1 format 1，8/16 B） | `VERIFY P2=80/88`；卡按明文处理，K_DEK 解密未实现（见 §7） |
| `9010` | PIN Try Counter ‖ PIN Try Limit（各 1 B，4 位值） | 配置持久 PTC/PTL（`OfflinePinState`，Book 3 Annex C §C10）；缺省 PTL=3 |
| `8101`/`8103` | ICC DDA/CDA 私钥指数 / 模数 | 两者齐备后建 `86 n 87 d` |
| `8102`/`8104` | ICC PIN 加密私钥指数 / 模数 | 两者齐备后建 `86 n 87 d` |
| `8105`/`8106` | ICC ECC 私钥（XDA/ODE） | 接受但忽略（XDA/ODE 范围外，见 contactless.md §1） |
| `7FFF` | 完成数据（可选） | 完成由 `P1.b8` 决定 |
| `E002` | **Card42 项目 DGI**：累计脱机金额限值 `LCOTA(6) ‖ UCOTA(6)`，BCD | |
| `E003` | **Card42 项目 DGI**：密文算法选择 `9F69`（CV，1 B）‖ `9F6A`（AES 密钥长度，1 B，可选，默认 16） | CV '5'=3DES / CV '6'=AES-128；**须先于 `8000`** |

**未支持 / 范围外**（已知限制）：

- CRT 常量 DGI `8201`–`8205`（DDA/PIN）与 `8301`–`8305`（PIN）：未支持；ICC 私钥只接受
  `8101`+`8103` / `8102`+`8104` 的模数/指数对（`RsaKey.parse` 本身支持 `81`–`85` CRT 容器）。
- 重复数据分组 `801n`/`901n`/`91nn`：未支持（多记录场景）。
- `9000` KCV：接受但忽略（卡不计算/校验 KCV）。
- `8105`/`8106` ECC 私钥：接受但忽略（XDA/ODE 范围外）。
- `8000` 每把密钥长度：CPS Table A-2 允许 CAM / MAC UDK / ENC UDK 各为 16 或 32 B，但
  DGI `8000` 不含逐把长度字段，卡按所选 profile 的统一下列长度解析（CV '5' 3DES 16 B、
  CV '6' AES-128 16 B）；CAM/MAC/ENC 混合长度不受支持。
- 未知 DGI（既非已处理 DGI 也非记录 DGI `01xx`–`1Exx`）：回 `6A88`（CPS §5.4.2.3）。
- **卡侧目录文件服务 `88` 宣告的 SFI（1–10）**：`PersoRules.validatePseTemplate` 要求 PSE 的
  `9102` A5 内 `88` 为单字节且取值 1–10（EMV v4.4 Book 1 §12.2.3 Table 12），否则回 `6A80`；
  `DirectoryApplet` 按该 SFI 服务目录记录（记录以 `(SFI<<8)|record` 为键保存），其余 SFI 回
  `6A82`。
- `9000` KCV（Table A-3）长度须为 3–9 B，否则 `6A80`；`3000` 的 `9F36`（Table A-17）须为
  2 B，否则 `6A80`（`PaymentPerso`）。
- `E003` 必须在 `8000` 之前；代码已强制（`PaymentPerso.applyAlgorithm` 在 `8000` 之后到达时回 `6A80`）。

- 记录 DGI（`01xx`–`1Exx`）由 `RecordStore` 保存，读回时归一化 `70` 长度；`70` 模板仅对
  `01xx`–`0Axx` 强制（CPS §3.2），`0Bxx`–`1Exx` 按原值保存。PSE 记录 DGI `0101` 在个性化时
  校验结构 `70 { 61 { 4F(5–16), 50(1–16) [, 9F12(1–16)] [, 87(1)] } }`，违规回 `6A80`。
  其中 Application Label `50` 强制依据 **EMV v4.4 Book 1 Table 12（M）**；CPS v2.0 Table A-20
  将 `50` 标为可选，二者冲突时本实现以 Book 1（PSE 的定义规范）为准。`EMVStaticData.setRecord`
  还校验内层 `70` 的**声明长度**：
  非零时必须等于实际值长度（CPS §3.2），`70 00` 占位约定除外（读回时按实际长度归一化）。单条记录含 tag/length ≤254 B（Book 3 §7），超限回 `6A80`
  （`EMVStaticData.setRecord`）；卡的服务缓冲
  `PaymentApplet.response` 为 **256 B**，覆盖 254 B 记录上限与 RSA-2048 CDA SDAD，记录可正常
  读回（见 [risks.md](../common/risks.md)）。
- **记录 1**（`0101`）承载 CDOL1/CDOL2/CVM/PAN/有效期以及可选的数据对象（`9F19`/`9F24`/`9F25`）；
  卡解析后供交易访问器使用。
- **可选数据对象**（Book 3 Annex A Table 37，见 §4）：`9F0C`/`9F0A` 个性化后由卡追加到
  FCI 的 `BF0C`；`9F19`/`9F24`/`9F25` 仅在默认记录 1 构造器中追加（记录 1 由原始
  `0101` DGI 个性化时随原文提供）。
- **DOL 规则**（Book 3 §5.4）：个性化 `9F38`/`8C`/`8D` 时，每一项必须是良构的
  `(tag, length)` 且 tag 为**primitive**；出现 constructed tag（如 `70`/`A5`/`BF0C`）即
  `6A80`。terminal-sourced constructed 内的 primitive（如生物模板，范围外，见 11.3）
  不得出现在 DOL 中。
- 记录 2–5 通常由 `@sda` 直接生成为完整 `70` 模板（SDA 链 / SSAD / PIN 证书 / ICC 证书）。
- 支付必需 DGI（本项目）：`9102`、`8000`、`8010`；其中 `8010` 在 CPS Table A-1/A-4 标为
  “C”（条件，仅离线 PIN）。此外记录 1（DGI `0101`）必须携带终端交易所需的强制字段
  PAN `5A`、有效期 `5F24` 与 CDOL1/CDOL2 `8C`/`8D`（EMV v4.4 Book 3 §7.2 Table 28）：
  `PaymentPerso.isComplete` 经 `EMVStaticData.hasMandatoryRecord1()`
  （`card/emv/data/EMVStaticData.java`）校验，缺任一项则个性化完成校验失败、回 `6A80`。
  目录必需 DGI：`9102`。
- 缺失必需 DGI 时本项目回 `6A80`。CPS §4.3.5.1 只要求「`6A86` **may** be returned …
  other status conditions may be used」，故 `6A80` 属允许的实现选择。
- **DGI 编号范围**：CPS §3.2 保留 `9F60`–`9F6F`（支付系统专有数据）、`7FF0`–`7FFE`、
  `8F01`、`7F01`、`00CF`、`0062`，EMV CPS 合规应用**不得**把它们用作 DGI **作其它用途**
  （"must not be used as a DGI … for other purposes"）。Card42 专有数据改用
  `E002`–`E003`（不在任何保留段），记录 DGI 用 `01xx`–`1Exx`（CPS §3.2 的 SFI 1–30）。

## 4. DGI 值内 TLV 标签表

| Tag | 名称 | 长度 | 说明 |
|-----|------|------|------|
| `5A` | PAN | 2–10 B | BCD |
| `5F24` | 有效期 | 3 B | YYMMDD |
| `5F34` | PAN Sequence Number | 1 B | 预留 |
| `5F28` | Issuer Country Code | 2 B | 预留 |
| `57` | Track 2 Equivalent Data | 1–19 B | 可选；记录 1；缺省由默认 PAN/有效期派生 |
| `9F07` | Application Usage Control (AUC) | 2 B | 可选；记录 1；终端 §10.4.2 消费 |
| `9F08` | Application Version Number | 2 B | 可选；记录 1；终端 §10.4.1 与 `9F09` 比较 |
| `9F0C` | Issuer Identification Number Extended (IINE) | 3/4 B | 可选；FCI `BF0C` |
| `9F0A` | Application Selection Registered Proprietary Data (ASRPD) | 可变 | 可选；FCI `BF0C` |
| `9F19` | Token Requestor ID | 6 B | 可选；记录 1 |
| `9F24` | Payment Account Reference (PAR) | 29 B | 可选；记录 1 |
| `9F25` | Last 4 Digits of PAN | 2 B | 可选；记录 1 |
| `50` | Application Label | 1–16 B | |
| `87` | Application Priority Indicator | 1 B | |
| `9F38` | PDOL | 可变 | 由 `9102` 的 A5 提供；GPO 校验 |
| `82` | AIP | 2 B | 接触 `7900` / 非接触 `6900` |
| `94` | AFL | 可变 | |
| `8E` | CVM List | 可变 | 接触 PIN / 非接触 No CVM |
| `8C` / `8D` | CDOL1 / CDOL2 | 可变 | 记录 1 内 |
| `9F4A` | SDA Tag List | 可变 | 可选 |
| `83` | Command Template | 可变 | GPO 命令数据域 |
| `95` | TVR | 5 B | Card Action Analysis 输入 |
| `9A` | Transaction Date | 3 B | 日志字段 |
| `9F02` / `9F03` | Amount, Authorised / Other | 6 B | BCD；CDOL1、日志、脱机累加 |
| `9F0D`/`9F0E`/`9F0F` | IAC Default/Denial/Online | 5 B | Card Action Analysis |
| `9F10` | IAD | 32 B | CCD Format Code 'A'；CVR 由卡动态写入（见 §5） |
| `9F69` | Cryptogram Version | 1 B | DGI `E003` 内：`05`=CV '5'（3DES）/ `06`=CV '6'（AES） |
| `9F6A` | AES Key Length | 1 B | DGI `E003` 内：AES 密钥长度字节数（卡侧仅 16） |
| `8F`/`90`/`92`/`9F32`/`93` | SDA 证书链 / SSAD | `90`≤248、`93`≤248 B | 记录 2/3（Book 2 Table 43） |
| `9F46`/`9F47`/`9F48` | ICC 公钥证书 / 指数 / 余数 | `9F46`≤247 B | 记录 5 |
| `9F2D`/`9F2E`/`9F2F` | ICC PIN 公钥证书 / 指数 / 余数 | `9F2D`≤247 B | 记录 4 |
| `9F4B` | SDAD | ≤247 B（Book 2 Table 43 ICC 模长） | DDA/CDA 响应 |
| `9F37` | Unpredictable Number | 4 B | CDOL |
| `9F13` | Last Online ATC Register | 2 B | GET DATA |
| `91` | Issuer Authentication Data | 8 B（CCD） | CDOL2 内联或 `INS=82` |
| `8A` | ARC | 2 B | CDOL2 |
| `9F4D` | Log Entry | 2 B | FCI `BF0C` |
| `9F4F` | Log Format | 可变 | GET DATA；纯值拼接 |
| `9F4E` / `9F21` | Merchant Name / Transaction Time | 可变 / 3 B | 预留日志字段 |
| `9F14` / `9F23` | LCOL / UCOL | 1 B | 脱机频次限值 |
| `70` | 记录模板 | 可变 | 记录内容 |

脚本层 `DFxx` 伪标签映射：`DF21→8000`（块密码密钥）。

## 5. CCD IAD / CVR（EMV v4.4 Book 3 Annex C §C9）

CCD 应用返回固定 **32 B** 的 IAD（EMV v4.4 Book 3 CCD §C9）：

```
字节 1      长度指示 '0F'
字节 2      CCI：Format Code 'A'（b8-b5）+ CV（b4-b1）= 'A5'（CV '5'）/ 'A6'（CV '6'）
字节 3      DKI
字节 4-8    CVR（卡在每次 GENERATE AC 前重写）
字节 9-16   Counters（发卡行/支付系统自定义）
字节 17     长度指示 '0F'
字节 18-32  Issuer Discretionary Data（15 B）
```

CVR 由卡聚合（EMV v4.4 Book 3 §9.2.3.2）：byte1 的两次 AC 类型 / CDA / DDA / 发卡行认证状态；
byte2 的 PIN Try Counter、离线 PIN 已执行/未成功；byte3 的脱机限值（`OfflineRisk`）；byte4 的
脚本计数、脚本失败、上次 ODA 失败、Go-Online-Next、Unable-to-go-Online。其中：

- **Number of Successfully Processed Issuer Script Commands Containing Secure Messaging**（byte4
  b8-b5，Book 3 §9.2.3.2）：规范只规定「成功经安全报文处理的命令数」，未把它限定在本交易；本项目
  口径为**仅统计本交易**——`SecureMessaging.startNewTransaction()` 在每笔交易开始时把
  `scriptCommands` 归零，因此每个 `GENERATE AC` 响应上报的计数不含上一交易的 SM 命令
  （`card/emv/crypto/SecureMessaging.java`）。
- **CDA Performed**：第二 AC 继承「第一或第二 AC 返回过 SDAD」；
- **Issuer Authentication Not Performed**：第二 AC 按本交易是否收到 `91`；第一 AC 沿用最近一次
  第二 AC 的值（跨交易持久）；
- **Issuer Authentication Failed**：跨交易持久，直到发卡行认证成功；
- **ODA Failed on Previous Transaction**：由上一交易 TVR 的 SDA/DDA/CDA 失败位置位，跨交易
  持久；成功联机或脱机批准后清除。

持久位的**逐项复位条件**（Book 3 §9.2.3.2 允许发卡行配置复位矩阵，本实现采用下表口径）：

| 持久位 | 置位 | 复位 |
|--------|------|------|
| Issuer Authentication Failed | 本交易收到 `91` 且 ARPC 校验失败 | 发卡行认证成功（收到合法 `91`/ARPC） |
| Issuer Authentication Not Performed | 第二 AC 时本交易未收到 `91`；由下一交易第一 AC 沿用 | 下一交易第二 AC 时收到 `91`（即该位为「最近一次第二 AC」的镜像） |
| Issuer Script Processing Failed | 脚本命令 MAC/结构失败，跨会话保留 | 成功联机（第二 AC 的 ARC 非 Y3/Z3） |
| ODA Failed on Previous Transaction | 本交易 TVR 的 SDA/DDA/CDA 失败位 | 本交易成功联机或脱机批准（同交易「复位优先」） |
| Last Online Transaction Not Completed | 第一 AC 为 ARQC 且本会话无第二 AC | 收到第二 AC 且 ARC 非 Y3/Z3，或发卡行认证成功 |

> 简化说明：`Issuer Script Processing Failed` 采用「联机成功即清」，未按 Book 3 §9.2.3.2
> 的发卡行可配置矩阵细分（如需细分属发卡行配置项，当前示例未启用）。

AC 输入、GENERATE AC 响应与交易日志的 `9F10` 同源。

## 6. 个性化脚本（`perso/emv/sample*.perso`）

UTF-8 扁平脚本：`#` 注释、空行忽略、指令行以 `@` 开头、数据行 `<TAG> <VALUE>`。

四个示例脚本，共用 `perso/emv/sample.perso.sda.keys`：

- `perso/emv/sample.perso`：仅生产实例（`CARD_EMV_PERSO_SCRIPT` 默认）。
- `perso/emv/sample-test.perso`：生产 + 测试实例 `04/06/08`（`SIM_EMV_PERSO_SCRIPT` 默认）。
- `perso/emv/sample-j3r180.perso`：J3R180 生产集，`@sda records pin`、AIP 去 DDA/CDA
  （接触 `0x5800`、非接触 `0x4800`）。
- `perso/emv/sample-j3r180-test.perso`：J3R180 安全测试集（生产 01/02/PSE/PPSE + `04` +
  `06` `@sda records pin` + `08`），用于真卡 `BoundaryTest`/`VelocityTest`/`AesFlowTest`。

```
@instance <AID-hex>         开始该实例的一段；段末置最后一块 P1.b8=1
@offline-pin <ascii-digits> DGI 8010（ISO 9564-1 format 1 Reference PIN Block）
@key icc|sm-mac|sm-enc <hex> DGI 8000（CAM ‖ MAC UDK ‖ ENC UDK）
@key <slot> derive <imk> <pan> <psn> [3des|aes]
                            由 IMK 派生后拼入 DGI 8000（EMV v4.4 Book 2 Annex A1.4）
@key kcv <hex>              DGI 9000（接受但忽略）
@sda [records|dda|pin]      生成记录 2-5 与/或 ICC DDA/CDA、PIN 密钥对
                            （8103/8101、8104/8102）；无参数=全部，否则只发命名部分
@dgi <hex>                  后续原始行构成该 DGI（如 9102/9104/3001/E002）
@record sfi=n rec=n         下一条 70 行归属记录 (SFI<<8 | record)（CPS §3.2）
@no-complete                本段不置末块 P1.b8（仅测试）
<tag> <value> ...           内部标签，归入 DGI 3001
```

- 数据行是空白分隔的十六进制字节和/或双引号 ASCII 字符串，如 `A5 0F 50 0D "Card42 CONTACT"`。
- `@key` 依脚本顺序把 16 B 键拼入 `8000`（CAM、MAC UDK、ENC UDK）。
- `@key <slot> derive` 在个性化时按 EMV v4.4 Book 2 Annex A1.4 从发行方主密钥派生 ICC 主密钥
  （`host/emv/crypto/EmvKeys.java`）：默认 `3des`（Option B，CV '5'），`aes` 为 Option C（CV '6'）。
  示例见 `perso/emv/sample.perso` / `perso/emv/sample-test.perso`（CV '5' 实例
  `@key icc/sm-mac/sm-enc derive ...`；CV '6' 实例 `@key icc derive ... aes`）。
- CV '6'（AES）实例在 `@key` 之前用 `@dgi E003` 下发 `9F69 01 06`（可选 `9F6A 01 10`）；
  这样 `8000` 的密钥长度按 AES 解释（`E003` 必须在前）。
- `@sda` 要求其前有 `@record sfi=1 rec=1`，且解析时须提供 SDA 密钥档案（CLI
  `perso export -keys=<path>`，由 `SdaKeyProfile` 加载；示例 `perso/emv/sample.perso.sda.keys`，
  真实部署自备档案，host 不内置密钥）；由该记录 1 的值生成 SSAD/证书。
- `@sda` 的 token 可选 `records`/`dda`/`pin`：只发命名的部分（无 token = 全部）。不含
  `dda` 的写法（如 `@sda records pin`）用于不支持 `ALG_RSA_SHA_ISO9796_MR` 的卡——它们无法
  导入 ICC DDA/CDA 私钥（个性化 `8103/8101` 会 `6A80`），但 SDA 与 ICC PIN 密钥对（加密脱机
  PIN `P2=88`）可用；示例 `perso/emv/sample-j3r180.perso`（同时把 AIP 的 DDA/CDA 位去掉）。注意
  该示例的 CVM List 仍为明文 `01 00`，真卡实测接触交易走 `P2=80`（CVM Results `01 00 02`）；
  加密 `P2=88` 需 CVM code `04` 的实例。
- 实例 01/02 的 DGI `3001` 与记录 1 均带 IAC-Denial/Online/Default（`9F0E`/`9F0F`/`9F0D`）。
  IAC 写入记录 1 是因为终端从 ICC 记录读取 IAC（`TagPolicy.findIcc`），卡自身副本放 `3001`。
  IAC-Online/Default 取 `40 00 00 80 00`：SDA 失败与 floor limit 时联机，但不对信息性的
  「SDA selected」TVR 位（byte 1 b2）置位，使 SDA-only 卡可离线批准（EMV v4.4 Book 3
  §10.7/§10.8）。
- PIN 一律 ASCII 数字 → ISO 9564-1 format 1 Reference PIN Block（`8010`，`0`‖N‖BCD‖`F` 补齐，
  8 B）；卡内 `OfflinePinState`（包裹 `OwnerPIN`）仍按压缩 BCD 存储。

## 7. 安全通道说明

- 保留 GP 安全域的 SCP03；模拟器仅支持 SCP03。
- applet 经 `Personalization.processData` 处理 DGI，与 SCP 无关；因此 SCP02 SD（真卡 /
  GPPro）下流程同样可用。
- 模拟器与真卡共用同一 GPPro 个性化命令：`--personalize <AID> --store-data <hex>`
  （DGI 序列由 `PersoExporter` 生成）。模拟器经 nextgen `--simulator`（SCP03），真卡经 classic
  PC/SC（SCP02/SCP03 自动协商）；见 [toolchain.md](../common/toolchain.md) §4/§5。
- CPS 把逐 DGI 的 `K_DEK`/`SKU_DEK` 解密归于**卡应用**（§4.3.4.12/§4.3.4.13，由 STORE DATA
  的 `P1.b7/b6` 指示），与安全通道无关；卡内未实现该解密（`PersoHandler` 只读 `P1.b1/b8`）。
  项目主机侧也不做逐 DGI 加密，故当前端到端路径是明文 DGI，不是 CPS 的 K_DEK 路径（已知限制）。
  未实现的直接原因是**部署工具链**：项目经 GPPro `--store-data` 下发 DGI，GPPro 自行管理
  `P1/P2`，不暴露 `P1.b7/b6`，因此无法在现有路径上指示逐 DGI 加密；实现需改走自定义 SD
  交互或 GPPro 脚本，而 SCP02/03 已提供端到端机密性，逐 DGI 加密的额外收益有限，故保留为
  已知限制。
