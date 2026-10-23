# card42 eMRTD 待办 (TODO.emrtd.md)

> 本文件保留**未完成的待办**与**当前状态快照**（eMRTD / ICAO 9303 部分）。
> - 系统当前设计与规范见 [`docs/specs/emrtd/`](docs/specs/emrtd/) 与 [`docs/specs/common/`](docs/specs/common/)。
> - 参考标准与工具链版本见 [`tools/README.md`](tools/README.md)。
> - EMV 部分见 [`TODO.emv.md`](TODO.emv.md)。
>
> 图例：`[ ]` 待办 · `[~]` 进行中 · `[!]` 阻塞/延后 · **范围外** = 不计划实现
>
> **维护约定（完成一项后）**：
> 1. 从本文件删除该项；
> 2. 若改变了系统行为、数据结构或命令语义，同步更新 `docs/specs/` 对应文档。

## 状态快照

- **基线**：ICAO Doc 9303 Part 3/9/10/11/12（`tools/icao9303/`），BSI TR-03110 Part 1–4
  （`tools/bsi-tr-03110/`）。
- **已落地并验证**：
  - **卡侧 `card42-emrtd`**：LDS1 文件系统（`LdsCatalog`/`LdsPerso` 含卡侧 COM 索引）、
    `command/*`、BAC、ISO/IEC 7816-4 SM、AA、GP 个性化；LDS2（Travel/Visa/Additional
    Biometrics、记录/透明 EF、READ/APPEND/SEARCH RECORD、FMM、UPDATE BINARY/ACTIVATE）；
    EF.CardAccess/CardSecurity（主文件 `011C`/`011D`）；MF EF.ATR/INFO（2F01）与 EF.DIR（2F00）；
    LDS2 EF.Certificates 254/64 记录上限；Chip Authentication（FF03 + EF.CardSecurity；LDS1
    主文件 EF.CardSecurity DGI FF05、读访问 PACE，SELECT MF 后 `011D` 解析）；DG3–DG16；
    PACE 卡侧（ECDH 通用映射 3DES 与 AES-128 宣告、MRZ/CAN 口令）。
  - **PACE 口令卡级共享（2026-10-23）**：`Pace` 的 f(MRZ)/f(CAN) 改为包级 static，LDS1 段
    个性化一次即被三个 LDS2 DF 继承；样例脚本的 LDS2 段不再重复 `@doc/@dob/@doe`、`@can`
    （仍可写入以覆盖全卡值）。sim 由 `EmrtdLds2AppsIntegrationTest`（Visa/Bio MRZ）与
    `EmrtdLds2AlgorithmsIntegrationTest`（Travel CAN）覆盖继承路径，`Lds2SampleTest`
    锁定 LDS2 段不携带 PACE 凭据。
  - **CA 对端点校验修复**：`P256.isLessThanP` 改为显式无符号逐字节比较（不再依赖
    `Util.arrayCompare` 的平台相关符号性）；修复前某平台会间歇性把合法坐标判为 `>= p` 回
    `6A80`，导致 LDS2 CA 集成测试随机失败。
  - **主机 `card42.host.emrtd`**：`EmrtdTerminal`/`LdsReader`、DG1/DG2/DG15/COM/SOD、
    `Bac`/`Iso7816Sm`/`Iso7816SmAes`/`ChipAuth`/`Pace`、`CscaKeyStore`/`DscVerifier`/
    `PassiveAuthentication`、AA、`EmrtdPersoExporter`/`SodBuilder`/`Dg2Builder`/
    `CardSecurityBuilder`/`LdsScript`、CLI（`-pace`、`-ca`、`lds2`）。
  - **真卡 / 互操作**：J3R180 安装、个性化与读取（接触、非接触）；项目工具与第三方独立
    主机库（BAC、LDS1 读取、PA、AA、PACE 两 profile、LDS2 CardAccess/CardSecurity）均通过。
  - **真卡堆耗尽修复**：`LdsFile`/`Lds2TransparentFile` 改为惰性按实际长度分配、`persoBuffer`
    包内 `static` 共享，释放约 11 KB，真卡 PACE/BAC/ChipAuth/LDS2 与 EMV 全部恢复。
  - **PACE 持久堆泄漏修复**：`Pace` 的 EC 密钥/KeyPair 改为跨会话复用（避免 J3R180 不回收
    导致的 `6F00`）；真卡连续 50 次 PACE 通过。
  - **MF-level EF.CardAccess**：LDS1 实例以 GP `CardReset` 默认选中 + 卡侧 `SELECT MF`
    分支，reader 可在选应用前于 MF 读 `011C`（PACE）；接触/非接触均验证。
  - **响应缓冲转瞬态 / EEPROM 写入削减**：`EmrtdApplet` 的 `plain`/`response`（各 256 B 实例
    持久）与静态 `smOut`（512 B）改为包级共享的瞬态 `EmrtdScratch`（`io` 320 B 兼作解包命令与
    SM 封装响应、`response` 256 B，均 `CLEAR_ON_DESELECT`，安装期一次分配，命令路径不再
    `makeTransient*`）；`SmScratch` 亦改为安装期 `init()`。纯 JVM 基线里 BAC 读五组 DG 的持久
    写由 4330 B 降到 498 B，AA 由 ~1100 B 降到 ~555 B；EMV 的包级共享 `EmvScratch` 见
    `TODO.emv.md` §B1。`LdsCatalog` 的 COM 构造 scratch 由运行期局部数组改为包级 `static`（LDS2
    实例不再各占 160 B）；`DdaCrypto` 重灌密钥后显式 `JCSystem.requestObjectDeletion()`。
    **（2026-10-11）** `SmScratch` 800→**352 B**（`wrap` 密文直写调用方输出缓冲，加密区与
    MAC 输入区合并复用）、`RetailMac`/`AesCmac` 收为包级共享 `MacEngines`；eMRTD 共享瞬态
    1664→**1218 B**，余量回到约 540 B（含 `AesCmac` 256 B CBC 暂存；原仅 ~32 B）。BAC 基线 state 96→167 B 系共享引擎在
    会话边界的 `AesCmac` 清零（非逐命令），`Util` 批量写 199→135 B。个性化路径的 `TlvReader`/
    `DgiReader` 改为可复用游标，不再每次 `new`（Java Card `new` 落持久堆）。
  - **真卡持久堆修复（第 4 个实例 6F00）**：LDS2（Travel/Visa/Biometrics）实例按角色门控，
    不再创建只有 LDS1 用得到的 `LdsCatalog`（19 个 `LdsFile` + 数组）、`LdsPerso`
    （seed + 520 B scratch）、`BacCrypto` 与 2048-bit `AaCrypto`，每例省约 1.5–1.8 KB 持久堆。
    Java Card 不自动回收已删对象，反复失败的 INSTALL 会泄漏，故真卡复测前应
    `make card-uninstall` 再 `make card-both-install`（新增卸载目标）。
  - **读路径性能优化**：BAC/PACE 的 Alg-3 MAC 优先用平台 `Signature`（
    `ALG_DES_MAC8_ISO9797_M2`/`ALG_DES_MAC8_NOPAD` + 两次单 DES 终变换），平台不支持时自动回退
    到逐块手工构造，单测两条路径同向量；SM 的 1 KB scratch 改为包级共享 `SmScratch`（**2026-10-11
    再收到 352 B**，瞬态优先、持久回退）、每实例省 ~1 KB 且不再随实例数倍增瞬态需求；会话密钥仅在变化时 `setKey`；
    单次 `READ BINARY`/`READ RECORD` 明文上限按活动 SM profile 的块大小计算
    （`SecureMessaging.maxResponseData()`：3DES `0xE7`、AES `0xDF`），超限回车侧 `6700`；主机
    `LdsReader` 请求 `0xE7` 但以位移越过 EF 末尾判 EOF（不能以「短块」判，AES 会合法回 223）；PACE/CA/AA/BAC
    等慢命令前调用 `APDU.waitExtension()`（`READ BINARY` 不调用，避免每包多一次 WTX）。
    纯 JVM 单测与 jcsl 集成矩阵（BAC/LDS2/PACE/CA）全绿。
  - **AES 安全报文提速 / 重新宣告 AES-128（原 T5.4）**：平台无 AES-CMAC `Signature`
    （`ALG_AES_CMAC_128`/`AES_MAC_128_NOPAD` 实测不可用），`AesCmac` 一次性 MAC 改为用
    `Cipher.ALG_AES_BLOCK_128_CBC_NOPAD` 批量链式（256 B 分块，只留末块作链值，末块再一次 ECB），
    352 B 的 SM 消息由 ~22 次 ECB 调用降到 2 次 CBC + 1 次 ECB。**真卡 J3R180 实测**（接触，
    ACR1581 PICC，DG2 8309 B）：AES-128 每 `READ BINARY` **81 ms**（min 76.9 / max 84.0，3 遍）、
    3DES 93 ms；~8 KB DG2 全读 AES ~3.1 s / 3DES ~3.3 s（旧实现 AES ~1.4 s/包，约 17× 慢）。
    `ALG_AES_BLOCK_128_CBC_NOPAD` 在 jcsl 与 J3R180 均确认可用（AES-128 PACE 两侧通过）；
    因此 `EmrtdPersoExporter.cardAccessInfos` **重新宣告 3DES + AES-128**（`perso/emrtd/sample-sha256.perso`
    的 `@cardaccess` 同步重新生成）。单测（含 >256 B 跨块向量）与 `make test-both-sim`/`make test-emv-sim` 全绿。
  - **大照片（DG2）支持**：个性化改为**逐 DGI 流式落盘**（`DgiStream` + `LdsPerso`/`Lds2Perso`，
    不再有 4096 B 整段重组缓冲），LDS1/LDS2 透明 EF 与记录分别改为 **256 B 分页**与
    `beginRecord/appendChunk/endRecord` 流式记录（不复制增长、不需连续大数组）；DG2 预算
    16384，演示样例 DG2 提升到 ~7 KB。模拟器 `make test-emrtd-sim` / `make test-both-sim` 全绿，新单测
    `EmrtdPersoStreamTest`（分页边界、DGI 跨块/截断/超长、5000 B DG2、1 B 分块）。
  - **LDS2 命令级纯 JVM 单测**：`test/emrtd/unit/card/EmrtdCommandTest.java` 直接驱动
    `card/emrtd/command/Lds2Record.java`（SEARCH RECORD A2 含 P2、FMM 5F、UPDATE BINARY D7、
    ACTIVATE 44 的往返与错误状态字）；`test/emrtd/unit/host/EmrtdCliTest.java` 覆盖主机 CLI
    dispatcher 与 `-json`/`-pace` 参数（`docs/specs/common/toolchain.md §7.1`）。
  - **SEARCH RECORD DO 解析修复（2026-10-22）**：窗口 `DO'02'` 改为按实际 BER 长度解 1/2 字节
    （Appendix I.1/J.1 的 `02 01 03`），短 EF 标识符先按原始 SFI 解析、失败再回退 `SFI<<3`，
    同时接受 `01`/`1A` 与 `08`/`D0` 两种写法；`EmrtdCommandTest` 覆盖原始/移位/窗口最小编码。
  - **LDS2 CLI PACE/CA/TA + 多记录 EF（2026-10-22）**：`terminal emrtd lds2` 增加 `-pace/-can`、
    `-ca`、`-ta -ta-chain -ta-key` 与 `-record=entry|exit|visa|cert|all`，可在 PACE/TA 授权后读
    Travel/Visa 的全部记录 EF；`EmrtdLds2CliIntegrationTest` 端到端覆盖（模拟器）。
  - **LDS2 结构化写入 + 记录容量（2026-10-22）**：新增 `TravelRecordBuilder`/`VisaRecordBuilder`/
    `BiometricsRecordBuilder`/`CertificateRecordBuilder`，按 Table 86/90/93/83 编码并由 LDS2-TS
    私钥签名（RSA SHA256withRSA / EC SHA256withECDSA），`Lds2RecordWriter` 负责 APPEND 或
    UPDATE BINARY+ACTIVATE + SW 检查，`Lds2CertificateStore` 负责 EF.Certificates 的复用/追加与
    `5F38` 引用，`Lds2Signature` 提供验签；CLI `-append=<json>` 支持 entry/exit/visa/biometrics/
    certificate。样例 `perso/emrtd/sample-*.perso` 已改为 Table 86/90/93/83 的多条记录
    （Travel 3 Entry + 1 Exit、Visa 2、Biometrics 1、每个 LDS2 应用 1 个包装证书），
    `Lds2SampleTest` 解析并验签。Travel/Visa 记录上限 256→**640 B**、Entry/Exit/Visa 池
    1→**2 KB**（每包约 +5 KB 持久，含 Travel/Visa 的 EF.Certificates 2 KB；真卡需复测余量）。
  - **LDS2 全命令集成测试（2026-10-23）**：新增 `EmrtdLds2OpsIntegrationTest` 端到端覆盖
    FMM（P1=00/01、DO'51' 短 EF 标识、current-EF 规则）、SEARCH RECORD（Appendix I.1/J.1 的
    FID/raw SFI、窗口、stop-after-first、6282）、READ RECORD P2=05 全序列与 P1=00、SFI READ BINARY、
    UPDATE BINARY + ACTIVATE（DO'54'/DO'53'/DO'C0'、激活后 6982、多 chunk 读回）、Travel Exit /
    Visa / 新 EF.Certificates 记录的实际 APPEND 与 `5F38`/b4 路径、641 B 超长记录 6700、以及
    Travel b1-only 终端链对 b2/b3/b4 的拒绝。新增 `EmrtdLds2AlgorithmsIntegrationTest` 覆盖 LDS2 上
    的 PACE/CA AES-128、PACE-CAN 与 TA RSA-PSS。扩展 `EmrtdLds2CliIntegrationTest`：`-csca`
    报告必须 `signatureValid/trusted`，并实际跑 entry/visa/certificate `-append`。宿主新增
    `Lds2Search`/`Lds2Fmm`/`LdsReader.readRecordSequence`。期间修复：READ RECORD all 模式只按首条
    长度截断；CA v1 AES 的 GENERAL AUTHENTICATE 未记录 `Comp(PKDH,IFD)` 导致 TA 6300；
    APPEND 证书（~650 B）在 SM 解包时超过 512 B `raw`/`SmScratch`；UPDATE BINARY 的 CLA `8C`
    被 SM 层丢掉；Travel/Visa EF.Certificates 池 1→2 KB。模拟器 15 suite 全绿；真卡需复测
    新增 +2 KB 证书池与近 900 B APPEND 后的持久/瞬态余量。
  - **LDS2 签名 PKI / P0 修复（2026-10-23）**：`EmrtdPersoExporter.loadPrivateKey` 同时支持
    EC/RSA PKCS#8；`SodBuilder`/`CardSecurityBuilder` 支持 ECDSA-SHA-256 DSC。新增
    `Lds2Verifier`：`5F38`→EF.Certificates→X.509→CSCA 链→LDS2 Signer EKU/profile→`5F37` 验签；
    CLI `lds2 -csca` 与报告输出 `valid/signatureValid/profileValid/trusted`。`Lds2CertificateStore`
    校验 Doc 9303-12 §7.1.2 profile，`5F3A` country/serial 从证书推导；`-ts-key` 必须在
    APPEND 前证明与 `5F38` 证书公钥匹配，并在写入后读回验签；证书 append 必须带 `-csca`。
    `TravelRecord`/`VisaRecord`/`BiometricsRecord` 保留原始 `73`/`71`/`5F2E` 编码，`Lds2Signature`
    兼容 SHA-256/384/512（及 RSA SHA-1）。
  - **示例证书与 TA 授权（2026-10-23）**：样例 LDS2 Signer 改为独立
    `perso/emrtd/lds2.crt/key`（仅 AKI + critical `.8.1/.8.2/.8.3` EKU），不再用 DSC 冒充；
    sample DSC 重新签发为带 KU/DocumentType/SAN/IAN/CRLDP 的合规 DS 证书；Additional
    Biometrics sample 改为 `7F2E { 5F2E, 5F37, 5F38 }` 签名结构。卡侧 `TaTrustStore` 在
    CVCA tail 的三个 LDS2 字节全为 0 时默认 `0x0F`（legacy ePassport-only perso），避免
    “TA OK 但所有 LDS2 访问 6982”；单个应用为 0 而其他字节非 0 仍是显式拒绝。PA/CA 增加
    DSC 有效期/DocumentType 校验与 EF.CardSecurity CMS 签名校验（有 `-csca` 时）。
  - **主机 LDS2 结构化读取（2026-10-22）**：`host/emrtd/lds/Lds2Record` + `TravelRecord`/
    `VisaRecord`/`CertificateRecord` 按 Table 86/90/83 解析命名字段（容错 demo 记录，`wellFormed`
    标明完整性）；`PassportReport.lds2Text/Json` 同时输出 tag/hex 与结构化字段。
  - **LDS2 READ RECORD 扩展 Le / 大记录（2026-10-22）**：卡侧识别扩展 Le（`00 00 00`），超过
    231/223 B 的记录改走 `EmrtdScratch.record`/`recordEnvelope`（各 1 KB，仅 LDS2 角色持久分配）
    与 `wrapLarge()`，一次返回最大 900 B 的 EF.Certificates；主机 `LdsReader.RECORD_LE=65536`，
    SM DO'97' 支持 1/2 字节 Le。`EmrtdLds2IntegrationTest` 断言 837 B 证书完整读回；`EmrtdCryptoTest` 覆盖 3DES/AES
    900 B `wrapLarge`。规范见
    [`docs/specs/emrtd/emrtd.md`](docs/specs/emrtd/emrtd.md) §2/§11 与
    [`docs/specs/common/risks.md`](docs/specs/common/risks.md) §2。

## 待办

- [ ] **算法支持增量（可选，按 matrix §4）**：**第一期（PA PSS、AA SHA-256、CA AES-128）与第二期
  AA ECDSA-SHA-256 已完成（2026-10-13）**，jcsl 与 J3R180 实测通过。样例改为按 AA 算法分档的
  `perso/emrtd/sample-<aa>.perso`（`-emit -aa=`，`make perso-emrtd-emit`；默认
  `sample-sha256.perso`），每个 sample 同时含
  PACE/CA 3DES+AES 与 ECDSA+RSA-PSS 两个 TA 信任点；`EmrtdPerfTest` 计时各算法。剩余：多 CA
  密钥/keyId 选择（第二期）；PACE ECDH-CAM、DH 版 CA、TA 非 SHA-1 变体、非标域参数/Brainpool
  （第三期，须先探针）。平台不可能项（AES-192/256、PACE DH-GM/IM）见 matrix §3；附加生物识别加密
  见「延后 / 范围外」。判据与复杂度/瞬态评估见
  [`docs/specs/emrtd/algorithm-support.md`](docs/specs/emrtd/algorithm-support.md) §4。
- [ ] **T5.1 PACE 官方 BSI 测试向量**：BSI TR-03110 Test-Vector 文档未提供；现以 BSI KDF
  定义独立计算的 KAT + 第三方独立主机库互操作验证。
  （`test/emrtd/unit/host/EmrtdHostTest.java` 的 `paceKdf` 注释已改为“按定义计算、非 BSI
  已知答案”。）
- [ ] **T5.2 真卡读性能复测**：在 J3R180（接触/非接触）上实测优化后的读取耗时——
  `JCSystem.getAvailableMemory(MEMORY_TRANSIENT_DESELECT)` 余量、原生 `Signature` MAC 是否命中、
  单包 `READ BINARY` 是否仍触发 WTX，并与优化前对比记录。并复测**大 DG2 个性化**：确认 SD 的
  `processData` 事务粒度（逐命令 vs 整段）、约 10 KB 序列在真卡事务缓冲下不 `BUFFER_FULL`、
  以及 `MEMORY_TYPE_PERSISTENT` 余量（J3R180 ~180 KB NVM，DG2 预算 16384）。
- [x] **T5.3 真卡 `test-emrtd-card` 间歇 6F00（已消除）**：ACR1581 非接触口上，
  `EmrtdLds2AppsIntegrationTest` 的 Additional Biometrics PACE step 4 曾在**多个 suite 连跑**时
  间歇回 `6F00`（特征更像读卡器/卡复位或持久堆余量，而非确定性逻辑）。在共享引擎/KDF/瞬态归并
  （`EmvEngines`/`MacEngines`/`KdfEngines`、`SmScratch` 收窄）之后不再复现；`test-emrtd-card`
  已移除每 suite 重试，改为每个 suite 只运行一次（见 `mk/test.mk`）。若复发，失败时读
  `JCSystem.getAvailableMemory(MEMORY_TYPE_PERSISTENT)`，并核对前置 suite 的持久写
  （LDS2 APPEND RECORD）与 PACE 会话次数。
- [x] **T5.4 PACE-AES 读性能 / 重新宣告 AES（已完成）**：见状态快照「AES 安全报文提速 / 重新
  宣告 AES-128」。根因为 `AesCmac` 逐块 ECB（平台无 AES-CMAC `Signature`），已改为
  `ALG_AES_BLOCK_128_CBC_NOPAD` 批量链式；真卡实测 AES-128 每 `READ BINARY` 81 ms（3DES 93 ms），
  `EF.CardAccess` 已重新宣告 3DES + AES-128。
  （`card/emrtd/command/Lds2Record.java`；测试 `test/emrtd/unit/card/EmrtdCommandTest.java`。）
- [ ] **C2 主机纯 JVM 卡仿真**：用第三方纯 JVM 卡仿真库跑主机 PA/读流程（无 jcsl）。
- [x] **LDS2 Terminal Authentication 授权位（已实现 2026-10-12）**：TA v1 + ECDSA-SHA-256 已落地
  （卡侧 `card/emrtd/ta/TaContext` + `MSE:Set DST`/`PSO:Verify Certificate`/`MSE:Set AT`/
  `EXTERNAL AUTHENTICATE`，主机 `host/emrtd/ta/`，个性化 DGI `FF07`/`FF08`）。LDS2 各 EF 的
  访问条件为 PACE+TA：`requireLds2Access(bit)` 按 `effectiveAuth`（信任点 ∧ 各证书 CHAT/应用
  扩展逐位 AND，Doc 9303-10 §5.4 Table 96/97/98）门控选择/读/写/追加；授权位按文件选
  （Travel/Visa 的 EF.Certificates 用 **b3/b4**，其余用 b1/b2）；`EmrtdTerminalAuthIntegrationTest`
  端到端。设计见 [`docs/specs/emrtd/terminal-authentication.md`](docs/specs/emrtd/terminal-authentication.md)。
  **真卡复测已通过（2026-10-12，J3R180 / ACR1581 PICC）**：全部 7 个 eMRTD suite（含
  `EmrtdTerminalAuthIntegrationTest` 的 PACE→CA→TA 与扩展长度 PSO）全绿。**教训**：TA 的 ECDSA
  验签引擎须在**安装期**构建，不得在 SD 个性化事务内（DGI `FF07`）构建——J3R180 会 `6F00`。
  RsaPss/双信任点/DG3-DG4 门控由单测覆盖；示例个性化仍用 ECDSA。附加生物识别加密
  （Doc 9303-11 §7.2，旧称 EAC 1.11）属范围外，见「延后 / 范围外」。

## 延后 / 范围外

- [!] **AES-192/256 PACE / CA / SM（平台不可能，已排除）**：jcsl 的 AES 仅 128-bit
  （`LENGTH_AES_256`/`ALG_AES_BLOCK_256_*` 抛 `NO_SUCH_ALGORITHM`），卡侧 `AesCmac` 亦按
  16 B 密钥写死，CI 门禁无法验证，故不再计划（J3R180 是否支持 AES-256 未做探针实测）。
  当前 PACE/CA/SM 支持 3DES 与 AES-128。判据见
  [`docs/specs/emrtd/algorithm-support.md`](docs/specs/emrtd/algorithm-support.md) §3。
- [!] **PACE DH generic mapping（平台不可能，已排除）**：卡侧通用映射需算 `G' = G^s · H`
  （MODP 模乘），Java Card classic 无公开大整数/模乘原语，也无 `ALG_DH_PACE_GM`，故无法实现
  （主机虽可用 `BigInteger` 写，但无卡可测）。注意 **DH 版 Chip Authentication 是可做的**
  （`KeyAgreement.ALG_DH_PLAIN` 够用），与 DH-GM 不同。判据见
  [`docs/specs/emrtd/algorithm-support.md`](docs/specs/emrtd/algorithm-support.md) §3。
- [!] **PACE 非标准化域参数（`PACEDomainParameterInfo`）**：主机仅支持标准化 P-256
  （`SecurityInfo.parse` 对未知 PACE OID 静默丢弃，Doc 9303-11 §9.2.2）；影响有限。
- **附加生物识别加密（Doc 9303-11 §7.2，范围外）**：ICAO 明确加密算法与密钥由各州自定、
  **不在规范范围**（*"up to the implementing State and is outside the scope of this document"*），
  没有可互操作的线上格式；旧 BSI EAC v1.11 的私有约定已被取代。故不作为算法缺口实现，仅在出现
  明确对手方需求时按该私有约定另议。判据见
  [`docs/specs/emrtd/algorithm-support.md`](docs/specs/emrtd/algorithm-support.md) §5。
- **范围外**：国别 profile、生物 CVM、LDS2 之外的附加应用；代码内自签证书（`SodBuilder`
  沿用 openssl 夹具 `perso/emrtd/{csca,dsc}.crt`，LDS2 用 `perso/emrtd/lds2.crt`；生产需
  替换真实 CSCA/DSC/LDS2 Signer 并补 CRL/OCSP，见 `risks.md`）。

## 统一验收门

`make`/`make verify` 0 错 0 警告；`make test-unit`、`make test-both-sim`（EMV+eMRTD 共存矩阵）、
`make test-emrtd-sim` 全绿；每条行为变更同步 `docs/specs/`；新增报文使用标准 BSI/ICAO
数据对象与状态字。
