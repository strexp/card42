# 架构与命令规范

card42 是一套 **EMV + eMRTD** 工具链：EMV 与 eMRTD 并列，公共部分抽离为共享库。
交付物分卡侧与主机侧，各三个模块（EMV 业务详见 [../emv/](../emv/)，
eMRTD 详见 [../emrtd/emrtd.md](../emrtd/emrtd.md)）。

| 交付物 | 位置 | package | 产物 |
|--------|------|---------|------|
| 卡侧共享库（无 applet） | `card/common/` | `card42.common` | `card42common.cap` / `.exp` |
| EMV 卡侧 applet | `card/emv/` | `card42.emv` | `card42-emv.cap` |
| eMRTD 卡侧 applet | `card/emrtd/` | `card42.emrtd` | `card42-emrtd.cap` |
| 主机共享库 | `host/common/` | `card42.host.common` | `card42-common.jar` |
| EMV 主机栈 + 内核 + CLI | `host/emv/` | `card42.host.emv.<sub>` | `card42-emv.jar` |
| eMRTD 主机栈 + CLI | `host/emrtd/` | `card42.host.emrtd.<sub>` | `card42-emrtd.jar` |

业务 CAP 依赖 `card42common`；业务 jar 依赖 `card42-common.jar`（Manifest `Class-Path`）。
本文 §1–§8 以 EMV 卡侧（CAP）为主；内核流程见 [../emv/contactless.md](../emv/contactless.md) §6，
构建与打包见 [toolchain.md](toolchain.md) §2/§6，eMRTD 见 §9。

## 1. 拓扑与 AID

卡侧分三个 Java Card package（**三个 CAP**）：`card42.common`（库，无 applet）、
`card42.emv`、`card42.emrtd`。每个卡角色是某个 applet 类的一个**实例**，靠实例 AID 区分。
Java Card converter 要求 CAP *applet* AID 与 package RID 相同，但 **INSTALL 时选择的实例 AID
不受此限**（已在 jcsl 实测，见 [research-notes.md](research-notes.md)），因此 `1PAY`/`2PAY`
与 ICAO DF name 能作为对应 package 的实例安装。

统一私有 RID `CARD42_RID = 43 41 52 44 42`（"CARDB"，`config/ids.mk` 可配置；投产前替换为
ISO 注册 RID）。package AID 为 `RID:00`（common）、`RID:01`（emv）、`RID:02`（emrtd）。

| 类 | Class AID | 实例 AID | 角色 |
|----|-----------|----------|------|
| `card42.emv.PaymentApplet` | `43415244420101` | `43415244420101` | EMV contact |
| `card42.emv.PaymentApplet` | `43415244420101` | `43415244420102` | EMV contactless |
| `card42.emv.DirectoryApplet` | `43415244420103` | `315041592E5359532E4444463031`（`1PAY.SYS.DDF01`） | PSE |
| `card42.emv.DirectoryApplet` | `43415244420103` | `325041592E5359532E4444463031`（`2PAY.SYS.DDF01`） | PPSE |
| `card42.emrtd.EmrtdApplet` | `43415244420201` | `A0 00 00 02 47 10 01`（ICAO LDS1 DF name） | eMRTD LDS1 |
| `card42.emrtd.EmrtdApplet` | `43415244420201` | `A0 00 00 02 47 20 01/02/03`（LDS2 DF name） | eMRTD LDS2 Travel/Visa/Biometrics |

- package AID：common `434152444200`、emv `434152444201`、emrtd `434152444202`，version `1.0`。
- `deploy/deploy-emv-test.conf` 另装模拟器/测试专用支付实例：`43415244420104`（无 DDA/PIN 与 SM
  密钥）、`43415244420106`（CDA 无 `9F37`、5 位 PIN、通用 `EXTERNAL AUTHENTICATE` 路径，AIP
  byte1 bit3=1）、`43415244420108`（CV '6' / AES-128），由 `perso/emv/sample-test.perso`
  个性化（生产实例用 `perso/emv/sample.perso`）。
- 部署计划：`deploy.conf`（both）、`deploy-emv.conf`、`deploy-emv-test.conf`、`deploy-emrtd.conf`。
- 拓扑 B（多 package 再拆）作为回退方案保留，当前未使用。

## 2. 结构（卡侧 applet 与主机侧模块）

```
card/common/   card42.common 库：Tlv/TlvReader、RetailMac/AesCmac/MacAlgorithm/ConstantTime、
               ApduIo、AppletBase（SELECT/分派骨架）
card/emv/      card42.emv：
  applet/      EMVAppletBase / InstallParameters / PaymentApplet / DirectoryApplet
  command/     支付命令处理器：OfflinePin / OfflinePinState / DynamicAuth / AcProcessor /
               IssuerAuth / PostIssuance / PaymentPerso / CvrBuilder（CVR/IAD 组装）/
               TransactionFinalizer（交易收尾：累计器/日志/CVR 结转位）
  constants/   EMVCommands / EMVStatus / EMVRoles / EMVCodes / EMVAids
  data/        EMVStaticData(门面) / PaymentData / SdaCertificateData（ODA 证书数据）/
               FciBuilder / RecordBuilder / DirectoryBuilder / DirectoryRecords /
               RecordStore / Defaults / Iad
  state/       EMVProtocolState
  risk/        CardRiskManagement / OfflineRisk / TransactionLog
  crypto/      EMVCrypto / Arpc / AcResponseBuilder / SessionKey / CryptoProfile /
               SecureMessaging / DdaCrypto / PinCrypto / RsaKey
  perso/       PersoHandler / PersoRules（DGI/记录结构校验）/ PersoErrors
  tlv/         Dgi / DgiReader / DolReader / TlvTags
card/emrtd/    card42.emrtd：applet/（EmrtdApplet / EmrtdInstallParameters）、
               lds/（LdsFile / LdsFileSystem / LdsCatalog / LdsPerso；LDS2：
               Lds2TransparentFile / Lds2RecordFile / Lds2FileSystem / Lds2Perso）、
               command/（SelectFile / ReadBinary / GetChallenge / ExternalAuthenticate /
               InternalAuthenticate / Lds2Record / Mse）、access/（MrzKeySeed / BacCrypto /
               SecureMessaging / AbstractSecureMessaging /
               Iso7816Sm / Iso7816SmAes / ChipAuth / Pace / PaceSeedSink）、
               crypto/（AaCrypto）、tlv/（EmrtdTags）
```

卡侧 applet 骨架：

```
                    +---------------------+
   SELECT AID ----> | AppletBase          |  SELECT、命令分派骨架
                    +----------+----------+
                               |
                    +----------v----------+
                    | EMVAppletBase       |  EMV CLA/角色/媒体/FCI、
                    |  - lifecycle state  |  Personalization.processData
                    |  - protocol state   |
                    +----------+----------+
                               |
             +-----------------+-----------------+
             |                                   |
   +---------v---------+               +---------v----------+
   | PaymentApplet     |               | DirectoryApplet    |
   |  GPO / READ RECORD|               |  PSE FCI + records |
   |  VERIFY / GET DATA|               |  PPSE FCI          |
   |  GENERATE AC      |               |                    |
   +-------------------+               +--------------------+
```

`EmrtdApplet` 同样继承 `AppletBase`，自行处理 ICAO LDS1/LDS2 命令集（见 §9）。

- `AppletBase`：SELECT 入口 + 命令分派骨架；`rejectUnmatchedSelect()` 让 EMV 把未匹配的
  `INS=A4`（SELECT by name）回 `6A82`，而 eMRTD 用 `A4` 作 SELECT FILE 时可放行到分派。
- `EMVAppletBase`：从实例 AID 解析角色（优先 `JCSystem.getAID()`，回退 INSTALL 参数），
  强制生命周期状态机并把 INS 分派给具体类。**可变状态一律用实例字段**；唯一的静态可变状态
  是刻意的卡级 `cardBlocked`（CARD BLOCK 必须跨实例生效且无解锁）——同一 package 的所有实例
  共享一个 context，其余静态状态仅限不可变常量。两个 EMV applet 都
  `implements org.globalplatform.Personalization`。
- `PaymentApplet`：支付命令集；角色决定 CVM/AIP 策略（见 §4）。
- `DirectoryApplet`：从可个性化数据提供 PSE/PPSE 目录结构。

主机侧源码（**目录名不必等于 package 名**；`card42.host.*` 由 Makefile `find` 收集）：

```
host/common/    card42.host.common（无 EMV 依赖）：
  transport/    Terminal（通用 transmit/select）/ Terminals / TerminalSession / TracingChannel
  codec/        Tags / TlvWriter / TlvDump / Json / Responses / Der / DerWriter
  crypto/       AesCmac / Iso9797（ISO 9797-1 Alg3 + 3DES 原语）/ P256（自包含 P-256）
  util/         Hex / Bytes / Digests / Bcd / Args / Reporter / KeyValueFile
  report/       Display（UI/凭条 SPI，no-op 默认）
  cli/          CliSupport（退出码/usage 约定）
host/emv/       card42.host.emv：
  lib/          Apdus / TagPolicy（Book 3 §7.5 策略）/ Amounts / Terminal（EMV 便捷扩展）/
                IssuerKey（恢复出的 RSA 公钥）
  oda/          SdaVerifier / CamVerifier（SDA/DDA/CDA 验证）/ CaKey / CaKeyStore /
                CaKeyProfile（CA 公钥环）/ Sda / SdaKeys（离线 SDA 生成器与密钥档案）
  kernel/       TerminalKernel / ContactKernel / ContactlessKernel 共享 TransactionFlow
    core/       TransactionResult（只读，内核经 Mutable 写）/ Outcome / Decision / Selection /
                OdaVerifier（ODA 抽象，注入 TransactionFlow）/ Issuer / Authorization /
                KernelListener / KernelException +
                TransactionException + TransportException + EndApplicationException /
                PinProvider / OnlinePinProvider / SignatureProvider / ConfirmationProvider
    data/       TerminalConfig / TransactionRequest / TerminalState / TerminalDol / Tvr / Tsi /
                Cvm / ReferralHandler
    entry/      EntryPoint / ApplicationSelection / PpseSelection / PseSelection
    oda/        OfflineDataAuthentication（SDA/DDA/CDA 编排；实现 core/OdaVerifier）
    analysis/   TerminalActionAnalysis / CvmList / CvmPerformer / ProcessingRestrictions /
                TerminalRiskManagement
    cvm/        OfflinePinCvm / OnlinePinCvm / SignatureCvm / CombinedPinSignatureCvm /
                CompositeCvmPerformer
    script/     IssuerScriptProcessor（Book 3 §10.10）
  crypto/       EmvKeys / AcCrypto / SmCrypto / PersoMac
  report/       TransactionReport / Receipt / ReceiptRenderer / ReceiptPrinter
  app/issuer/   IssuerHost / IssuerCrypto / ClosedLoopIssuer / AuthFileIssuer / SubprocessIssuer
  app/perso/    PersoScript / SdaKeyProfile / PersoExporter
  cli/          Main（`card42.host.emv.cli.Main`）
    command/    PersoCommand / TerminalPayCommand / TerminalInspectCommand /
                TerminalApduCommand / TerminalEntryPointCommand / IssuerCommand / CardCommand
host/emrtd/     card42.host.emrtd：transport/EmrtdTerminal；lds/（LdsFileUtil / LdsReader /
                Dg1 / Dg2 / Dg15 / Dg / Com / Sod / CmsSignedData / LdsSecurityObject /
                AlgorithmIds / SecurityInfo / UnknownSecurityInfo / PaceInfo /
                ChipAuthenticationInfo /
                ChipAuthenticationPublicKeyInfo / ActiveAuthenticationInfo / CardAccess /
                CardSecurity）；access/（MrzKeySeed / Bac / Iso7816Sm / Iso7816SmAes /
                SecureMessaging / ChipAuth / Pace）；pa/（CscaKeyStore / DscVerifier /
                PassiveAuthentication）；aa/ActiveAuthentication；perso/（EmrtdPersoExporter /
                SodBuilder / Dg2Builder / CardSecurityBuilder / LdsScript）；
                report/PassportReport；cli/（Main / EmrtdCommand）
test/           测试（package card42.test，目录为功能分组而非包）
  common/       fixtures/TestKeys（示例 CA/SDA 密钥 + SdaKeys 档案 + CaKeyStore）；
                stubs/（javacard.framework / javacard.security / javacardx.crypto 极小桩）
  emv/unit/     UnitTests + support/Asserts；card/（{tlv,data,state,risk,perso,crypto}）、
                host/（{codec,crypto,perso,clearing,cli,util,oda,transport,kernel}）
  emv/integration/ card/（EmvFlow / Boundary / AesFlow / Directory / Log / Velocity /
                IssuerScript / CardBlock / OnlineClosedLoop）；host/kernel/{contact,contactless}、
                host/cli/TerminalCliTest；support/（Checks / TestTerminals）
  emrtd/unit/   card/（EmrtdCryptoTest / EmrtdLds2Test）、host/（EmrtdHostTest /
                EmrtdCardAccessTest）
  emrtd/integration/ EmrtdBacTest / EmrtdLds2IntegrationTest / EmrtdLds2AppsIntegrationTest /
                EmrtdPaceIntegrationTest / EmrtdChipAuthIntegrationTest
deploy/         deploy.conf（both）/ deploy-emv.conf / deploy-emv-test.conf / deploy-emrtd.conf
perso/emv/      sample.perso / sample-test.perso / sample-j3r180.perso（真卡示例）/
                sample-j3r180-test.perso / sample.perso.sda.keys / sample.ca.keys
perso/emrtd/    csca.crt / csca.key / dsc.crt / dsc.key / portrait.png / sample.perso
                （样例护照与 PA 夹具）
```

卡侧编成三个 CAP；主机侧只用 JDK 编译并打包为 `card42-common.jar` / `card42-emv.jar` /
`card42-emrtd.jar`，见 [toolchain.md](toolchain.md) §2。

主机侧传输层 `host/common/transport/` 基于 JDK `javax.smartcardio`。EMV v4.4 Book 1 删除了
Part II（传输协议），T=0/T=1、GET RESPONSE、状态字与 APDU case 属 *EMV Contact Interface
Specification*（本项目 Level 1 仍声明范围外）；但 `Terminals` 禁用了 JDK 对 T=0 的隐式
GET RESPONSE（SunPCSC 会沿用触发命令的 CLA，严格卡以 `6E00` 拒绝），改由 `Terminal.transmit`
按 EMV v4.1 Book 1 §9.3.1.2 step 4 / §9.3.1.3 Table 32 以 `CLA='00'` 检索（`61 xx` 取数据、
`6C xx` 用正确 Le 重发）。

**分层依赖方向**（由 `test/emv/unit/host/LayeringTest` 守卫）：

- `common` 不依赖任何其它 host 模块；
- `emv.lib → common`；`emv.kernel → {common, emv.lib}`；`emv.report → {…, kernel}`；
  `emv.app`；`emv.cli`（可依赖全部）；
- `emrtd → common`（业务模块之间互不依赖）。

### 2.1 内核对外 API

终端内核的公开契约收敛为四类对象，输入/输出与常驻/每笔严格分离：

- **入口**：`TerminalKernel.run(Terminal, TransactionRequest, Issuer) throws KernelException`。
  `ContactKernel`/`ContactlessKernel` 实现；内核配置（CVM provider、AID、Combination Table、
  `KernelListener`）经构造器/`listener(...)` 注入。
- **输入**：`TerminalConfig`（不可变，终端常驻：身份/能力/TAC/限额/CVM 支持/exception file，
  `forContact()`/`builder()` 构造）由 `TransactionRequest` 引用；`TransactionRequest` 承载每笔
  金额/币种/日期时间/类型/UN、选中的 `9F06` 与 `9F41`，是唯一被内核改写的输入对象。
- **输出**：`TransactionResult` 字段只读（getter），内核经包内 `TransactionResult.Mutable` 写入；
  提供 `decision()`（`Decision`：APPROVE/DECLINE/ONLINE/END_APPLICATION，综合接触 Book 4
  §6.3.2 终端决策与非接触 Book A Table 6-1 Outcome）与 `record()`/`firstValue(tag)`。交易态
  一律从结果读，不写回 `TransactionRequest`。
- **回调**：`Issuer.authorize(arqc, atc, TransactionResult)` 取联机授权（含发卡行脚本）；
  `KernelListener` 按 Book 3 §10.1–§10.11 步骤 + Book 1 §12 应用选择（`onStep`）、非接触
  候选表（`onCandidateList`）与 Final Outcome（`onOutcome`）上报进度，供独立 UI 项目接入。
- **异常**：`KernelException` 为 `run` 的受检基类；`EndApplicationException`（End Application
  Outcome）、`TransactionException`（EMV 处理失败）、`TransportException`（Level 1/传输失败）
  各司其职，取代原先的 `throws Exception`。

## 3. 生命周期状态机

```
install ──> PERSONALISATION ──(末块 P1.b8=1 且必需 DGI 校验通过)──> READY
                                                                      │
                                         (ATC 到 0xFFFF / APPLICATION BLOCK)
                                                                      v
                                                                   BLOCKED
                                         CARD BLOCK
                                             │
                                             v
                                       CARD_BLOCKED
```

| 状态 | 语义 | SELECT | 支付命令 |
|------|------|--------|----------|
| `PERSONALISATION` | 未完成个性化 | FCI | 仅 `GET DATA`；`VERIFY` 与其余支付命令 `6985` |
| `READY` | 可交易 | FCI | 全部；`STORE DATA` → `6985` |
| `BLOCKED` | 应用作废（APPLICATION BLOCK / ATC 溢出） | `6283` | `GENERATE AC` 只出 AAC |
| `CARD_BLOCKED` | 整卡锁定（CARD BLOCK） | `6A81` | — |

- 完成信号 = **末块 `P1.b8=1`**（可选 DGI `7FFF`，缺失不影响判定）；GPPro
  `--store-data` 在每段最后一块置位。
- **多实例不协调**：每个实例在各自末块独立切 `READY`；每实例状态用实例字段承载。
- 未匹配 SELECT（非 `selectingApplet()`）在 `EMVAppletBase` 统一回 `6A82`。
- **BLOCKED 的 SELECT `6283` 与日志可读**：卡在 SELECT 期间直接抛 `6283`；真实 Java Card 上
  applet 可能因此不被选中，而 Annex D4 要求 blocked 时日志仍可读。模拟器（jcsl）在 SELECT
  失败后仍保持选中，`LogTest` 依赖该行为；真卡 J3R180 实测同样保持选中（APPLICATION BLOCK
  后 `6283`，随后 `READ RECORD` SFI15 回 `9000`）。

## 4. 角色与 CVM 策略

角色由实例 AID 固定，决定 AIP/CVM/PIN 行为；`getProtocol()` 不参与角色/CVM/PIN 决策，
但**实例可选性**（PPSE/非接触实例在接触接口是否 `6A82`）依据它：`EMVAppletBase.isSelectableOnCurrentMedia()`
读 `protocolState.getMedia()`（由 `APDU.getProtocol()` 设置），故并非绝对「不作决策依据」：

| 角色 | AIP 默认 | CVM List | VERIFY |
|------|----------|----------|--------|
| CONTACT | `0x7900`（SDA+DDA+CDA+终端风险管理+CVM） | 明文离线 PIN | `P2=80` 明文 / `P2=88` 加密 |
| CONTACTLESS | `0x6900`（SDA+DDA+CDA+终端风险管理，无 CVM） | No CVM required | `6985` |

AIP byte1 bit3 是发卡行认证口径开关：CCD（bit3=0，默认）不支持 `INS=82`；通用 EMV
（bit3=1，如实例 `06`）接受 `INS=82`。响应格式按**应用 CCD 数据格式**决定：GPO 与非 CDA
`GENERATE AC` 依 `isCcdFormat()`（个性化 CDOL2 含内联 `91`）——CCD 为 **Format 2**
（Book 3 CCD §6.5.8.4/§6.5.5.4），通用接触口径为 Format 1。`INTERNAL AUTHENTICATE` 的
格式则依 AIP byte1 bit3（CCD 置 0 → Format 2 `77 { 9F4B }`；通用置 1 → Format 1 `80`）
（Book 3 CCD §6.5.9.4；样例中两判据同值）。AIP 的 RFU 位按 v4.4 置 0。

密码算法口径由 `CryptoProfile` 的 Cryptogram Version 决定（个性化 DGI `E003`，默认 CV '5'）：
CV '5' 用 3DES/Alg3，CV '6' 用 AES/CMAC（见 [cryptography.md](cryptography.md) §2–§4）。IAD 的
CCI 字节随之取 `A5`/`A6`（[../emv/personalization.md](../emv/personalization.md) §5）。

## 5. 命令矩阵

`SELECT` 所有角色都处理；其余 INS 取决于角色：

| INS | 命令 | Payment (contact) | Payment (contactless) | Directory (PSE) | Directory (PPSE) |
|-----|------|-------------------|-----------------------|-----------------|------------------|
| `A4` | SELECT | FCI | FCI | FCI（`88 01 <SFI>`，SFI 1–10） | FCI（`BF0C`+`61…`） |
| `B2` | READ RECORD | 支付记录 | 支付记录 | 目录记录（`88` 宣告的 SFI） | 不支持 |
| `1A` | SEND POI INFORMATION | — | — | — | SPI 响应 FCI（Book B Annex C） |
| `A8` | GET PROCESSING OPTIONS | AIP+AFL（校验 `83`/PDOL；CCD 数据格式 format 2 `77`，通用接触 format 1 `80`） | 同左（format 2） | — | — |
| `CA` | GET DATA | ATC / PIN counter / last online ATC / log format | 同左（无角色限制） | — | — |
| `84` | GET CHALLENGE | 8 B ICC UN（`P1=P2=00`） | 同左 | — | — |
| `20` | VERIFY | 离线 PIN（明文 `P2=80` / 加密 `P2=88`） | `6985` | — | — |
| `88` | INTERNAL AUTHENTICATE | DDA SDAD（CCD format 2 `77{9F4B}` / 通用 format 1 `80`） | 同左 | — | — |
| `AE` | GENERATE AC | TC/ARQC/AAC，可降级，`+CDA (P1 b5-b4=10)`，发卡行认证（CDOL2 内联 `91`） | 同左 | — | — |
| `82` | EXTERNAL AUTHENTICATE | 通用发卡行认证（AIP b3=1；否则 `6985`） | 同左 | — | — |
| `1E`/`18` | APPLICATION BLOCK / UNBLOCK | 仅 Format 1 SM（`6283` 直至解锁） | 同左 | — | — |
| `16` | CARD BLOCK | 仅 Format 1 SM（此后每次 SELECT `6A81`） | 同左 | — | — |
| `24` | PIN CHANGE/UNBLOCK | 仅 Format 1 SM（`P2=00` 复位 PIN try counter） | 同左 | — | — |
| `E2` | STORE DATA | 仅 `PERSONALISATION` | 同左 | 同左 | 同左 |

约束：

- **PPSE 在接触接口必须拒绝选择**（`6A82`）；PSE 仅在接触接口提供。`TEST_CONTACTLESS=1`
  测试构建放行非接触实例在接触接口被选中（§7）。
- `SELECT` 仅支持 `P1='04'`（select by name）、`P2='00'`（first or only occurrence）。
  Java Card JCRE 负责按 AID 选择 applet，applet 只在被选中后收到命令，故部分名选择
  （至少 5 B RID）与 Select Next（`P2='02'`）超出 applet 可控范围（EMV v4.4 Book 1
  §11.3.5 与 Table 7 定义了 ICC 能力，但经典 Java Card 的 JCRE 不暴露该选择语义）；
  未匹配的 P1/P2 由 JCRE 以 `6A82` 拒绝，applet 另在 `P1/P2` 异常时防御性回 `6A81`
  （EMV v4.4 Book 1 §11.3.2 Table 6/7）。此项为项目平台口径。
- `STORE DATA`：`P2`=块序号，`P1.bit8`=最后一块；由 SD 经
  `Personalization.processData` 转发（SCP03 安全通道）。
- `GET PROCESSING OPTIONS` 要求 `P1=P2=00`（否则 `6A81`）与 `83` 命令模板（缺失 `6700`）；值长度须等于
  个性化 PDOL（否则 `6700`；模板畸形/尾随字节 `6A80`）。校验通过后才自增 ATC。
- `GENERATE AC` 要求 `P2=00`（否则 `6A81`），接受终端 AAC 请求；卡只可**降级**不可升级。第三次及以后
  回 `6985`。响应格式：CCD 数据格式（CDOL2 含内联 `91`）一律 format 2（`77`）；通用接触 format 1、
  通用非接触 format 2；CDA 一律 format 2。`P1` b5-b4=`01`（XDA，未实现）回 `6A81`；b5-b4=`11`
  （RFU）按 EMV Book 3 §6.3.6「不得校验 RFU」处理，视为「不请求 CDA/XDA 签名」。
- `GET DATA`：未知 `9Fxx` 标签 → `6A88`（referenced data not found）；P1 非 `9F` → `6A81`。
  其余命令的错误 P1/P2 一律 `6A81`（EMV Book 3 Table 4，而非 ISO `6B00`）。
- **命令链**（EMV v4.4 Book 3 §6.5.13）：仅 `VERIFY` 与 `PIN CHANGE/UNBLOCK` 支持链式。非末块
  （CLA b5=1）把命令数据累积并回 `9000`，末块（b5=0）执行功能；其它 INS 的链式命令回 `6884`，
  链未以期望的末块结束回 `6883`，链式 `VERIFY` 累积失败回 `6800`（§6.5.12.5）。链状态为会话级，
  `SELECT` 复位；`GET CHALLENGE` 挑战仅对**下一条命令**有效（§6.5.6.1），因此非末块的链式
  `VERIFY` 分片即令其失效，加密 PIN 不能链式下发。
- `READ RECORD` 要求 P2 b3-b1=`100`（Book 3 Table 22），否则 `6A81`。
- `READ RECORD`：AFL 未列出的 SFI → `6A82`；文件存在但无此记录 → `6A83`；可读 → `9000`。
  日志 SFI 显式放行（不在 AFL）。

详细交易行为见 [../emv/transaction.md](../emv/transaction.md)。

## 6. 目录响应结构

目录数据由 CPS DGI 提供：PPSE 的 FCI 来自 `9102`（A5 模板）；PSE 的 FCI 来自 `9102`、
目录记录来自 `0101`（`70` 模板）。结构如下。

PPSE FCI：

```
6F L
  84 0E 325041592E5359532E4444463031
  A5 L
    BF0C L
      61 L  4F <payment AID>  50 <label>  87 01 <prio>  9F2A 01 00
      ...   (可多条)
```

> 本项目只做 Entry Point 的 PPSE 与终端侧内核（RSA profile）。内核实际实现的是 **EMV v4.4
> Book 3/4 的通用终端流程**，仅**概念上**参照 Book C-8；它**不是** C-8 流程的子集（C-8 使用
> ECC GPO、加密记录与卡选 CVM，见 [../emv/contactless.md](../emv/contactless.md) §1.2）。
> PPSE 的 `61` 携带 `9F2A = 00`（Kernel Identifier，EMV Contactless Book B v2.12 Table 3-4/3-5）：
> 语义为「内核由 ADF Name 决定」；本项目 AID 不在 Book B 品牌清单中，读卡器按
> Table 3-6 取默认内核 `0` 并接受该 Combination。`9F29`（Extended Selection）与 SPI
> （`9F3E`/`9F3F`）均已实现；`9F0A`（ASRPD）在 host 内核未解析，登记于 `TODO.emv.md` §D7
> （终端内核见 [../emv/contactless.md](../emv/contactless.md) §8）。

PSE FCI + 目录记录：

```
FCI: 6F L  84 0E 315041592E5359532E4444463031  A5 L  88 01 01
READ RECORD SFI=1 rec=1: 70 L  61 L  4F <AID> 50 <label> 87 01 <prio> ...
```

## 7. 测试构建开关

模拟器不模拟非接触媒体，非接触实例在接触接口默认应被拒绝。为在模拟器验证非接触流提供
编译期开关：

- `make TEST_CONTACTLESS=1` 生成 `build/gen/card42/emv/BuildConfig.java`：

  ```java
  package card42.emv;
  public final class BuildConfig {
      public static final boolean ALLOW_CONTACTLESS_ON_CONTACT = true;
  }
  ```

- 默认生成 `= false`。为 `false` 时 CONTACTLESS 实例在接触接口返回 `6A82`，为 `true` 时放行。
- 生成文件不入版本库，`make clean` 一并清理。

## 8. 个性化数据优先级

- SELECT 响应由 DGI `9102`（A5 模板）整块提供；缺失时由结构化字段（`50`/`87`/`5F2D`/`9F38`）
  构造为等价的 `A5` 模板。两条路径都把 Log Entry（`9F4D`）放入 `A5` 内的 `BF0C`
  （EMV v4.4 Book 1 Table 10，Book 3 Annex D4）。
- GPO 响应由 DGI `9104`（`82` AIP、`94` AFL）提供；卡按应用 CCD 数据格式（CDOL2 含内联 `91`）
  与非接触为 format 2，通用接触为 format 1。
- 记录由 `@record`（DGI `(SFI<<8)｜record`）直接下发；记录 1 的 CDOL/CVM/PAN/有效期被解析
  供交易访问器使用，记录 2–5 通常由 `@sda` 生成。
- 详见 [../emv/personalization.md](../emv/personalization.md)。

## 9. eMRTD（ICAO 9303）

eMRTD 与 EMV 并列，复用 `card42.common`（`AppletBase`、`Tlv`、`RetailMac` 等）。范围：
**LDS1 文件系统 + BAC + ISO/IEC 7816-4 安全报文 + Passive Authentication + Active
Authentication**，以及 **LDS2 应用 + EF.CardAccess/CardSecurity 解析 + Chip Authentication
（ECDH）+ PACE（ECDH 通用映射，3DES/AES-128，MRZ）**；EAC 1.11 仍为待办
（[../../TODO.emrtd.md](../../../TODO.emrtd.md)）。

- **实例 AID / 角色**：ICAO LDS1 DF name `A0 00 00 02 47 10 01`；LDS2 Travel/Visa/
  Biometrics DF name `A0 00 00 02 47 20 01/02/03`；`EmrtdInstallParameters` 按实例 AID
  决定角色。
- **LDS1 文件系统**：FID `0101`–`0110`（DG1–16）、`011D`（SOD）、`011E`（COM）、`011C`（CardAccess/CVCA）；
  `SELECT FILE`（P1=02/P2=0C）、`READ BINARY`（`B0`）；`LdsCatalog` 维护卡侧 COM 索引。
- **LDS2 文件系统**：记录式 EF（`Lds2RecordFile`）+ 透明 EF（`Lds2TransparentFile`），
  `READ/APPEND/SEARCH RECORD`、`FMM`、`UPDATE BINARY`/`ACTIVATE`；FID = `0x01 || SFI`。
- **MF 文件与访问控制**：EF.CardAccess/EF.CardSecurity 属主文件（`LdsMfStore`，跨实例共享），
  不在 LDS2 DF 内；EF.CardAccess 恒可读，EF.CardSecurity 与 LDS2 记录/透明 EF 需先完成 PACE，
  否则回 `6982`（Doc 9303-10 §3.11.4 Table 34、§5.4；Doc 9303-11 §1.2 Note 2）。
- **SM 会话**：PACE/BAC 成功后，收到明文 APDU 即中止会话并回 `6982`（Doc 9303-11 §9.8.3）。
- **BAC**：MRZ K_seed（SHA-1 + 7-3-1）→ K_enc/K_mac；三通道互认证 → 会话密钥 + SSC。
- **SM**：`[DO87][DO97]DO8E` 命令 / `[DO87]DO99DO8E` 响应，3DES-CBC + 零售 MAC；
  Chip Authentication 与 PACE 复用同一框架（SSC 归零 + 新密钥）。
- **PA**：EF.SOD（CMS SignedData）→ DSC→CSCA 链 + 签名 + 逐 DG SHA-256 比对。
- **AA**：DG15 公钥 + INTERNAL AUTHENTICATE 的 RSA ISO/IEC 9796-2 Digital Signature Scheme 1
  签名，消息 `M = RND.IC ‖ RND.IFD`（Doc 9303-11 §6.1.2.2）。
- **CA**：EF.CardSecurity 中的 P-256 公钥 + `MSE:SET KAT` 的临时 ECDH → `KDF(Z,1/2)`。
- **PACE**：EF.CardAccess 的 ECDH 通用映射 profile + MRZ 口令；`MSE:Set AT` + 四步
  `GENERAL AUTHENTICATE`；3DES 与 AES-128 两种 SM。
- 命令集、数据对象与主机模块详见 [../emrtd/emrtd.md](../emrtd/emrtd.md)。
