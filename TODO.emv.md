# card42 EMV 待办 (TODO.emv.md)

> 本文件保留**未完成的待办**与**当前状态快照**。
> - 系统当前设计与规范见 [`docs/specs/common/`](docs/specs/common/) 与 [`docs/specs/emv/`](docs/specs/emv/)。
> - 参考标准与工具链版本见 [`tools/README.md`](tools/README.md)。
>
> 图例：`[ ]` 待办 · `[~]` 进行中 · `[!]` 阻塞 · **范围外** = 不计划实现
>
> **维护约定（完成一项后）**：
> 1. 从本文件删除该项（或把索引项标为已完成）；
> 2. 若改变了系统行为、数据结构或命令语义，同步更新 `docs/specs/` 对应文档。

## 状态快照

- **代码基线**：EMV v4.4 Book 1–4（2022-10）+ EMV CPS v2.0（2021-08）；非接触参照
  EMV Contactless Book A/B v2.12，内核参照 Book C-8 v1.2（仅流程结构，RSA profile）。
  默认密文口径 CV '5'（3DES），可选 CV '6'（AES-128）。
- **已实现**：
  - **卡侧**：SDA/DDA/CDA 离线数据认证、明文与加密脱机 PIN、发卡行认证、EMV 安全报文、
    后发行命令（APPLICATION BLOCK/UNBLOCK、CARD BLOCK、PIN CHANGE/UNBLOCK）、交易日志、
    脱机风控累加器、CPS v2.0 个性化、多 SFI 目录、卡侧 SPI、持久中间密钥清零。
  - **非接触卡侧 Entry Point / PPSE**：候选列表、Combination Table / Entry Point
    Configuration / Pre-Processing Indicators、按交易类型选择 + Extended Selection + SPI。
  - **主机终端内核**：`ContactKernel`（PSE / 直接 ADF、离线 PIN）与 `ContactlessKernel`
    （PPSE Entry Point 状态机），共享 `TransactionFlow`；Entry Point 状态机（Start A/B/C/D、
    Outcome/Restart、Try Again、Removal Timeout）、Outcome 模型、发卡行脚本处理、
    ODA（SDA/DDA/CDA）、Processing Restrictions、CVM（离线/在线 PIN、签名、组合）、
    Terminal Risk Management、Terminal Action Analysis、velocity checking、清算主机。
  - **主机分层**：`host/` 只含产品栈，库层不依赖测试设施；依赖方向由 `LayeringTest` 守卫。
  - **真卡 J3R180（GP 2.3 / SCP02）**：安装、个性化与端到端交易（非接触 + 接触）走通；
    APPLICATION BLOCK 后 SELECT 回 `6283`、日志 SFI15 仍可读；加密脱机 PIN 全通过；
    DDA/CDA 不可个性化（卡不实现 `ALG_RSA_SHA_ISO9796_MR`），用 SDA + ICC PIN 密钥对；
    测试实例 `04/06/08` 真卡回归（含 `BoundaryTest`/`VelocityTest`/`AesFlowTest`）。
  - **生产实例真卡回归**：仅部署生产 4 实例 + J3R180 生产脚本时，卡侧最新规范修复全绿，
    全程无 `6F00`/`6883`。
- **未完成**：§A（A1/A3）、§B（B2）、§C（C.1–C.3）、§D、§E 可选、§G。
  范围外项（XDA/ODE、生物 CVM、Book C-8 专属、国别变体等）见
  [`docs/specs/`](docs/specs/) 的范围声明，不再单列。

**统一验收门**（每个行为变更步骤）：`make`/`make verify` 0 错 0 警告；`make test`、
`make TEST_CONTACTLESS=1 test`、`make test-unit` 全绿；每条行为变更同步 `docs/specs/`；
新增报文使用标准 EMV/GP 数据对象与状态字。

## 待办总览

| 章节 | 主题 | 门控 | 条目 |
|------|------|------|------|
| [A](#a-真卡验收硬件门控) | 真卡验收 | 需 J3R180 | A1, A3 |
| [B](#b-卡侧实现与健壮性) | 卡侧实现与健壮性 | — | B1–B3 |
| [C](#c-规范符合性遗留) | 规范符合性遗留 | — | C.1–C.3 遗留 |
| [D](#d-测试覆盖缺口) | 测试覆盖缺口 | 部分需夹具/真卡 | D1, D3, D4, D6–D9 |
| [E](#e-范围内可选) | 范围内可选 | — | E1, E3, E5–E7 |
| [G](#g-结构重构solid遗留) | 结构重构（SOLID）遗留 | — | G3–G4 |

---

## A. 真卡验收（硬件门控）

> 实现已就绪；J3R180 真卡已接入（GP 2.3 / SCP02，见 `docs/specs/common/toolchain.md` §5），安装、
> 个性化与端到端交易（非接触 + 接触）均已在真卡走通；其余验收项待跑。模拟器（jcsl）无法覆盖。

- [ ] **A1 换钥（SCP03 待重新界定）**：`make card-keychange`（真卡 classic，GPPro
      `--lock-enc/mac/dek --new-keyver`）已就绪但未验收。真卡实测该 J3R180 为 **SCP02-only**、
      keyset 为 DES3、**无 SCP03/AES keyset**，故 SCP03 换钥当前不可验；真卡只能验 SCP02
      PUT KEY 路径（或先经 SCP02 注入 AES keyset 再切 SCP03，需评估）。模拟器 NG 换钥需卡
      KDD/发现上下文，jcsl 下不可达。
- [ ] **A3 瞬态余量实测**：J3R180 上实测
      `JCSystem.getAvailableMemory(MEMORY_TRANSIENT_DESELECT)` 余量。真卡已确认多实例惰性
      缓冲（`workScratch` 256、`chainData` 255、PIN 恢复 256）耗尽后 `6F00`（见 §B3）；
      §B1 的包级共享 `EmvScratch` 已把 per-instance 瞬态归零（共 1408 B，一次分配），本项
      现只需**实测安装后的余量**并复跑 §B3 的 `BoundaryTest`/`AesFlowTest`/非接触第二 AC
      确认不再复现。实现建议：加只读诊断（`PersoHandler` 的 `3000` 报告
      已带 persistent 余量，可并列 transient；或项目私有 GET DATA/DGI），用
      `terminal apdu`/`card get-data` 在交易前后取值。硬件已具备，待执行。

## B. 卡侧实现与健壮性

- [ ] **B1 瞬态预算压缩（§B3 的修复）——已完成，保留真卡验收**：P2 批次把 EMV 的全部
      per-instance 瞬态缓冲收拢为包级共享的 `card/emv/EmvScratch`
      （response/work/chain/pdol/firstCdol/cda*/SM/会话/CVR/protocol，共 **1184 B**），在
      `EMVProtocolState` 构造（即安装期）分配一次；`work` 288 B 覆盖 2048-bit DDA/CDA 消息
      （prefix 234 + 实际 DDOL）、`chain` 255 B、`firstCdol` 128 B、`pdol` 64 B 亦共享。命令
      路径已无任何 `makeTransient*`（单元测试逐步断言）。**真卡实测教训**：把全部缓冲在安装期
      直接 `makeTransient` 会在创建第 4 个 eMRTD 实例时耗尽预算抛 `SystemException` → `6F00`；
      故所有分配改走共享的 `card42.common.TransientBuffers.makeByteArray/makeShortArray`
      （`RetailMac`/`AesCmac` 小块同）——优先 `CLEAR_ON_DESELECT`，**耗尽时回退持久数组**而非
      失败。同理 eMRTD 侧 `SmScratch` 由 1 KB 收到 800 B、`LdsCatalog` 的 COM 构造 scratch 改
      包级 static、LDS2 实例不再分配只有 LDS1 用的 `LdsCatalog`/`LdsPerso`/`BacCrypto`/`AaCrypto`
      （每例省约 1.5–1.8 KB 持久堆）。**剩余仅真卡验收**：见 §A3，用生产+测试实例
      重跑 `BoundaryTest`/`AesFlowTest`/非接触第二 AC；模拟器矩阵 `make test`/`make test-emv`/
      `make TEST_CONTACTLESS=1 test-emv` 已全绿，真卡只读套件（Directory/ContactKernel/EmvFlow/
      OnlineClosedLoop/BAC/PACE/ChipAuth）亦已通过。回退到持久只影响 EEPROM 写量，不影响功能；
      真卡余量实测后再决定是否收紧。
- [ ] **B2 健壮性与资源**：EEPROM 预算与事务原子性、模糊测试、日志格式可配置与审计。
- [~] **B3 瞬态内存耗尽（J3R180 真卡已确认；由 §B1 的包级共享修复，待真卡复测）**：JCOP 的
      `MEMORY_TRANSIENT_DESELECT` 预算在多个实例各自惰性分配大缓冲后耗尽，此后**任何**惰性
      `JCSystem.makeTransientByteArray` 抛 `SystemException` → `6F00`；真卡实测路径见下（历史）：
      1. 实例 02（非接触）第二 `GENERATE AC`：`Arpc.verifyMethod2` `getWorkScratch(40)`；
      2. 实例 08（CV '6'/AES）第二 AC：同上；
      3. 实例 01 链式 VERIFY：`chainData` 255 B；
      4. 实例 06 加密脱机 PIN：`OfflinePin` 恢复缓冲 256 B。
      共性：缓冲**每实例一份**且安装期 `response` 256 B × N 已占约 1.8 KB。`EmvScratch`
      把上述四块及 `response` 全部改为包级共享、安装期一次分配，per-instance 瞬态归零，
      故真卡上应不再复现；待 §A3/真卡回归确认。
      **真卡复现（P2 后）**：安装第 2 个 eMRTD 实例时 `6F00`——安装期直接 `makeTransient`
      仍会在总预算不足时抛 `SystemException`。已改为 `transientBytes()` 瞬态优先、**耗尽回退
      持久**（EMV/eMRTD/SM/MAC 全部），安装不再因瞬态失败；代价是回退缓冲的 EEPROM 写。
      另注意卡上残留同名实例（日志 `Applet ... already present`）会叠加占用，复测前应
      `gp --delete 434152444201`/`434152444202` 干净重装。

## C. 规范符合性遗留

> 多轮「规范 vs 实现 vs 文档 vs 测试」审计（EMV v4.4 Book 1–4、EMV CPS v2.0、
> EMV Contactless Book A/B v2.12）已修正大部分实现/文档/测试；以下为**尚未满足规范**
> 的项，不计入「已实现」。测试盲区见 §D，范围外项见 [docs/specs/](docs/specs/)。

### C.1 ODA（Book 2）

- [ ] **CRL 未检查**（Book 2 §5.3/§6.3 step 10，**可选**：RID/CA 索引/证书序列号对照 CRL）。
- [ ] **CA 公钥选择忽略 RID（Book 2 §5.2/§11.2.2）**：`CaKeyStore` 仅以 1 字节 `8F` 为键，
      无 RID 维度；两个 RID 共用同一索引会冲突。当前为单 RID 简化，需在密钥环/配置文件与
      `SdaVerifier` 查找中引入 RID。

### C.2 主机侧非接触遗留（Book B / Book A）

- [ ] **SELECT(ADF) 失败的 End Application 分支缺失**（EMV Contactless Book B v2.12 §3.3.3.5）：
      规范要求 `SELECT (AID)` 返回非 `9000`/格式错误时，若存在待发送的 Issuer Authentication
      Data 和/或 Issuer Script，Entry Point 应产生 **End Application Outcome**（UI Request `1C`）
      而非继续重选。当前 `PpseSelection.selectNext`（`host/emv/kernel/entry/PpseSelection.java`）
      只做「移除该 Combination 并试下一个」；本实现的联机响应数据由 `TransactionFlow` 持有，
      Entry Point 层不感知，故该分支不可达。实现前须先确定 Entry Point 与联机响应数据的接口
      （Book B §3.3.2.1 的 Start B 携带 issuer 响应数据路径）。
- [ ] **Start B 携带 issuer 响应数据的重启语义**（Book B §3.3.2.1）：规范在 Start B 且存在
      Issuer Authentication Data/Script 时要求回到 §3.3.3.3 用上次选中的 Combination 继续；
      当前实现用 Start D（`wentOnline`）代替，未单独建模该路径。

### C.3 卡侧遗留（CPS v2.0 / Book 1）

- [ ] **STORE DATA 逐 DGI K_DEK / SKU_DEK 解密**（EMV CPS v2.0 §4.3.4.13）：`P1.b7`/`b6`
      指示逐 DGI 加密时，卡应用须用 K_DEK（或按需 SKU_DEK）解密每个 DGI。当前
      `card/emv/perso/PersoHandler.java` 只读 `P1.b1`/`b8`，无解密路径；`TODO` §D4 亦列其负例。
- [ ] **CRT 常量 DGI `8201`–`8205` / `8301`–`8305`**（EMV CPS v2.0 §A.2）：当前落入未知 DGI
      `6A88`（`card/emv/command/PaymentPerso.java`）。实现或保持 `docs/specs/emv/personalization.md`
      的范围外声明。
- [ ] **部分名选择 / Select Next**（EMV v4.4 Book 1 CCD §11.3.5）：CCD 应用应支持部分名选择；
      当前 `card/emv/applet/EMVAppletBase.java` 对 `SELECT` 的 `P2!='00'` 回 `6A81`，Java Card
      JCRE 不向 applet 暴露 `P2='02'`。已在 `docs/specs/common/architecture.md` 记项目平台口径。
- [ ] **XDA/ODE `8105`/`8106`、生物识别 CVM、Book C-8 专属项**：范围外（见
      `docs/specs/emv/contactless.md` §1.2 与 `docs/specs/emv/personalization.md` 的范围声明）。

## D. 测试覆盖缺口

> 以下项不违反规范，属项目范围内的质量缺口。真卡已接入，**7 实例上限是 jcsl 独有**，
> 受此限制的项（D1/D3/D6）可改由真卡部署额外实例覆盖；真卡测试夹具
> `perso/emv/sample-j3r180-test.perso`（`04/06/08`）已就绪，可跑
> `BoundaryTest`/`VelocityTest`/`AesFlowTest`，但 D1/D3/D6 的**专用变体**（变长 `91`、
> 长 PDOL、AES SM）仍需新增实例/脚本。

- [ ] **D1 CCD 内联 `91` 变长用例**：CCD 内联 `91` 长度 <8 / >8 未单独用例。卡内
      `performInlineIssuerAuth` 对 `length < 8` 视为未执行、对 `length > 8` 按
      `ARQC‖CSU‖proprietary` 处理；现有实例 CDOL2 `91` 固定 8 B，构造变长需再增实例
      （jcsl 上限 7 个 applet 实例；真卡无此上限），暂以代码注释与逻辑评审代替。
- [ ] **D3 GPO 展开 PDOL >64 B → `6985` 端到端用例**：`PaymentApplet` 已实现该分支，但样例
      实例展开后 PDOL ≤42 B，且 jcsl applet 实例上限为 7，无法新增长 PDOL 实例。需专用测试
      构建（放宽实例上限或提供长 PDOL 变体；真卡无 7 实例上限），当前由
      `EMVProtocolState.pdolFits()` 单测 + `StaticDataTest` 的 66 B 度量覆盖决策层。
- [ ] **D4 其余测试盲区（受夹具/jcsl 限制）**：
  - **卡侧命令负例**：`PersoHandler.processData` 负例（`P2` 错、`P1.b1=0`、多块/不完整）；
    ATC 达 `0xFFFF` 的 §6.5.1 契约；STORE DATA 路径直接单测（`PersoHandler`/`PaymentPerso`，
    含 `9000` KCV / `3000` `9F36` 长度负例，实现已加校验）；记录 1 强制字段
    （`hasMandatoryRecord1`/`isComplete`，Book 3 §7.2 Table 28）缺失 → `6A80` 用例。
  - **密钥与验证器**：卡侧密钥路径 `DF22/DF30` 与 `E003` 非法 CV/AES-256 拒绝；`RsaKey`
    CRT/模数边界与 SDA-only 248 B issuer 上限无产生路径；CVR byte3「ODA Failed on
    Previous」端到端（Book 3 §9.2.3.2）。
  - **安装与数据构建**：`FciBuilder` 覆盖 A5 且长长度字段右移；通用口径 Format 1
    `GENERATE AC`/`INTERNAL AUTHENTICATE` 响应。（`InstallParameters` 角色回退、
    `RecordBuilder.directView`、默认记录 2–5 与记录过大 `6700`、默认构建非接触实例 `6A82`
    已覆盖。）
  - **内核**：Entry Point `9F0A` 解析（Book B §3.3）。（脚本 warning SW 应继续、`VERIFY`
    `6984` 置位已由 `IssuerScriptProcessorTest`/`OfflinePinCvmTest` 覆盖。）
  - **规范-测试盲区**：`72` 脚本失败 → 下一交易首 AC 的 CVR byte4 b4 跨会话
    置位；第二 AC 的 CVR byte1「Offline DDA Performed」继承本交易 INTERNAL AUTHENTICATE
    （Book 3 §9.2.3.2）；`PERSONALISATION` 状态下 `GET DATA` → `9000`。
  - **真卡缺口**：生产实例真卡回归全绿；通用 `EXTERNAL AUTHENTICATE` Method 2
    正例已由定向命令在实例 06 真卡通过（`SW=9000`）。`87` 加密对象拒绝仍未在真卡验证
    （`IssuerScriptTest` 末段会 CARD BLOCK 整卡，按约束未跑）；需非封锁夹具。
  - 多数需专用夹具或放宽 jcsl 实例上限，暂以单测/评审覆盖决策层。
- [ ] **D6 AES ARPC Method 1 / AES secure messaging 端到端不可达**：
      `Arpc.verifyMethod1` 的 AES 分支与 `SecureMessaging.isAes` 分支在当前夹具下无端到端
      用例（通用 AES 实例是 CCD 口径不触发 `INS=82`，AES 实例未注入 `sm-mac`/`sm-enc`）。
      `AesFlowTest` 在 J3R180 上通过 AES 首/次 AC 与错误 ARPC→AAC，**AES ARPC Method 2 已真卡
      验证**；Method 1 与 AES SM 仍缺端到端用例。需新增 AIP b3=1 的 AES 通用实例并补发卡行
      脚本/ARPC 用例（真卡无 7 实例上限），或登记为夹具限制。
- [ ] **D7 应用选择 / ODA / 终端 / 非接触单测缺口**（`SdaVerifier`/`CamVerifier`、
  Entry Point bullet E/品牌默认/ADF 前缀/`87`/`9F29`/BF0C 嵌套、CPS 模板校验、GENERATE AC
  长度 `6700` 已补齐；CVM 条件 07/08/未知/生物识别、AUC 现金正例/缺版本/日期相等已补）：
  - Book 3 终端 §7.5/§10.3/§10.4.2/§10.8/§10.9/§10.10 负例。
  - Book 3 强制 ICC 对象（`5A`/`5F24`/`8C`/`8D`）缺失 → 终止交易的负例（`TransactionFlow`
    `checkMandatoryObjects`，需脚本化通道）。
  - Book 3 速度检查（§10.6.3）经 `TransactionFlow` 的 GET DATA `9F36`/`9F13` 端到端用例。
  - ODA issuer/ICC 公钥算法指示符负例（`Sda` 生成器不产生非 RSA 指示符，需测试挂钩）。
  - Book 4 CID advice reason `001b`（Service not allowed）内核分支用例（`TransactionFlow`）。
  - Book 4 偏差项负例；清算确认报文（Table 15/16）未建模、未由交易结果驱动
    （§12.1.4；`9F5B` 未接清算模型）。
  - CPS STORE DATA 路径负例（保留 DGI、`7FFF`、`P2` 块序、`P1.b8`、3 字节 `Lc`、未知/缺
    必需 DGI、`9F36` 长度、KCV 3–9、`applyBlockKeys`/`applyReferencePinBlock`/`9010`/
    `buildDdaKey`/`RsaKey.parse`/`E003` 负例）。
- [ ] **D8 测试基础设施**：
  - 端到端 AC 用主机代码重算，卡机同错则通过。
  - 非接触内核场景在默认构建被整体跳过（`TEST_CONTACTLESS=0`）。
  - Entry Point 组合选择用测试自建 FCI，绕开真实卡（无法发现卡侧 PPSE 与内核漂移）。
  - jcsl 独有行为（`LogTest` SELECT 失败后仍选中；`CardBlockTest` 需全新模拟器；实例上限 7）。
  - `LogTest` 不归零持久 CVR「Last Online Transaction Not Completed」位：若前一交易（如
    `-online=never`）未完成联机，后续 `tcTransaction` 请求的 TC 被卡按规范升级为 ARQC，造成
    13 项误报；需在套件开头先完成一笔联机交易归零该位。
  - 单元测试用最小 stub 链接卡侧类（瞬态内存、真实 `ISOException` 语义不覆盖）。
  - `Checks` 进程级计数、每套件独立 JVM（提前抛异常则后续 check 静默缺失）。
- [ ] **D9 非接触 Entry Point / 内核集成测试缺口（需脚本化完整 GPO/AC 流程）**：
  - **Select Next / Try Again 刷新 UN**（EMV Contactless Book A v2.12 §8.1.1.8）：每次内核
    激活（含 Select Next / Try Again）应重新生成 Unpredictable Number；`ContactlessKernel`
    已实现 `flow.newUnpredictableNumber`，但无断言 UN 新鲜度的用例。
  - **Restart 循环（参数保留、Start C/D）**（Book A §8.1.1.19–§8.1.1.24）：`ContactlessKernel`
    的 `MAX_RESTARTS` 与 `activateNext`/`restartStartB` 分支无端到端用例。
  - **`reversalRequired` 由内核结果驱动**（EMV v4.4 Book 4 §6.3.8）：`TransactionFlow` 的
    冲正标志无由真实内核交易结果驱动的用例（现 `ClearingHostTest` 仅合成数据）。
  - **`fieldOffRequest`/`removalTimeout` 落入最终 Outcome**（Book A Table 6-2）：无断言用例。

## E. 范围内可选

> 属于项目范围内，但非规范要求、非必须完成；按需或将来有需求时再处理。

- [ ] **E1 4.X.8 P2（需权衡）**：`PaymentData` 的 15+ 组 `byte[] + short` 平行字段 → 值对象
      `ByteField { byte[] data; short length; }`；先评估 Java Card 对象/EEPROM 开销（每字段多
      一个对象头 + 引用），必要时与记录区重构一并做。（主机侧 TLV 解析已合并为
      `Tags.find`，无需再做。）
- [ ] **E3 死代码 / 仅测试访问器清理**：`TransactionLog.getSfi/getCapacity/getRecordLength`、
      `OfflineRisk.isEnabled`、`EMVStaticData.getPdolValueOffset`、`Sda.ssad`、
      `Sda.MAX_ISSUER_MODULUS_SDA`、`TlvWriter.dgi`、`AcCrypto` 的测试 oracle 方法、
      `Tvr`/`Tsi`/`CvmList` 未用掩码常量。删除需同步改测试，纯清理。
      （`TerminalConfig` 的 `9F1D` 未建模已在 Javadoc 声明，PDOL 请求 `9F1D` 只补零。）
- [ ] **E5 CPS `0062`：动态创建 EF**（FCP：`62`/`80`/`82`/`88`/`8C`）。当前记录区为静态池，
      暂不实现；若将来支持动态文件结构再启用。
- [ ] **E6 扩展 APDU（ISO 7816-4；EMV v4.4 Book 1 §11.3.4）**：当前仅短 APDU。如 J3R180/jcsl
      支持，可评估扩展 APDU 收发，用于 >255 B 记录/响应（当前靠 256 B 服务缓冲与分块规避）。
- [ ] **E7 `terminal inspect` Entry Point 候选补全**：`terminal entrypoint` 已带 `-spi` 并展示
      `appNotAllowed`；`terminal inspect` 的候选列表仍只输出 AID/label/priority/kernel，可补
      `priorityPresent`/`9F29`/`Contactless Application Not Allowed` 并加 `-spi`；纯诊断可读性，非规范要求。

## G. 结构重构（SOLID）遗留

> 第一批重构已完成 APDU 接收去重、`AcProcessor`/`PaymentData` 拆分、主机
> Alg3 MAC / `TracingChannel` / `SdaVerifier` 清理；第二批已完成
> `TagPolicy` 分离、`TerminalDol`/`Bcd` 分离与 Issuer 策略顶层化；其后完成主机分层重构
> （`host/emv/cli` 入口与功能库分离）。以下为审计出但**暂缓**的项，均为**无行为变更**
> 重构，不违反规范。

- [ ] **G3 主机 `AcCrypto` 拆分（剩余）**：`AcCrypto` 的会话密钥、RSA/PIN block、ARPC、AES
      派生可各自成类；三个 Issuer 策略已提为顶层类并上移到 `card42.host.emv.app.issuer`
      （G3a 已完成）。纯可读性收益，改动面大（26 文件/190 引用，多为测试），暂缓或仅做与
      `TerminalDol` 共用的 DOL 助手去重。
- [ ] **G4 卡侧 `SecureMessaging` 抽取 `Format1Codec`**：把 `format1MacInput`（纯解析/padding）
      移出。（`EMVConstants` 常量接口已拆为 `EMVCommands`/`EMVStatus`/`EMVRoles`/`EMVCodes`
      四个常量持有类，各卡侧类只依赖所用的一组并直接 `implements ISO7816`。）
