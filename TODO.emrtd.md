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
    EF.CardAccess/CardSecurity（应用级 `011C`）；MF EF.ATR/INFO（2F01）与 EF.DIR（2F00）；
    LDS2 EF.Certificates 254/64 记录上限；Chip Authentication（FF03 +
    EF.CardSecurity）；DG3–DG16；PACE 卡侧（ECDH 通用映射 3DES/AES-128、MRZ）。
  - **主机 `card42.host.emrtd`**：`EmrtdTerminal`/`LdsReader`、DG1/DG2/DG15/COM/SOD、
    `Bac`/`Iso7816Sm`/`Iso7816SmAes`/`ChipAuth`/`Pace`、`CscaKeyStore`/`DscVerifier`/
    `PassiveAuthentication`、AA、`EmrtdPersoExporter`/`SodBuilder`/`Dg2Builder`/
    `CardSecurityBuilder`/`LdsScript`、CLI（`-pace`、`lds2`）。
  - **真卡 / 互操作**：J3R180 安装、个性化与读取（接触、非接触）；项目工具与第三方独立
    主机库（BAC、LDS1 读取、PA、AA、PACE 两 profile、LDS2 CardAccess/CardSecurity）均通过。
  - **真卡堆耗尽修复**：`LdsFile`/`Lds2TransparentFile` 改为惰性按实际长度分配、`persoBuffer`
    包内 `static` 共享，释放约 11 KB，真卡 PACE/BAC/ChipAuth/LDS2 与 EMV 全部恢复。
  - **PACE 持久堆泄漏修复**：`Pace` 的 EC 密钥/KeyPair 改为跨会话复用（避免 J3R180 不回收
    导致的 `6F00`）；真卡连续 50 次 PACE 通过。
  - **MF-level EF.CardAccess**：LDS1 实例以 GP `CardReset` 默认选中 + 卡侧 `SELECT MF`
    分支，reader 可在选应用前于 MF 读 `011C`（PACE）；接触/非接触均验证。
  - **读路径性能优化**：BAC/PACE 的 Alg-3 MAC 优先用平台 `Signature`（
    `ALG_DES_MAC8_ISO9797_M2`/`ALG_DES_MAC8_NOPAD` + 两次单 DES 终变换），平台不支持时自动回退
    到逐块手工构造，单测两条路径同向量；SM 的 1 KB scratch 改为包级共享 `SmScratch`（瞬态优先、
    持久回退）、每实例省 ~1 KB 且不再随实例数倍增瞬态需求；会话密钥仅在变化时 `setKey`；
    单次 `READ BINARY` 明文上限 `0xE0`→`0xE7`（主机 `LdsReader.CHUNK` 同步）；PACE/CA/AA/BAC
    等慢命令前调用 `APDU.waitExtension()`（`READ BINARY` 不调用，避免每包多一次 WTX）。
    纯 JVM 单测与 jcsl 集成矩阵（BAC/LDS2/PACE/CA）全绿。
  - **大照片（DG2）支持**：个性化改为**逐 DGI 流式落盘**（`DgiStream` + `LdsPerso`/`Lds2Perso`，
    不再有 4096 B 整段重组缓冲），LDS1/LDS2 透明 EF 与记录分别改为 **256 B 分页**与
    `beginRecord/appendChunk/endRecord` 流式记录（不复制增长、不需连续大数组）；DG2 预算
    16384，演示样例 DG2 提升到 ~7 KB。模拟器 `make test-emrtd` / `make test` 全绿，新单测
    `EmrtdPersoStreamTest`（分页边界、DGI 跨块/截断/超长、5000 B DG2、1 B 分块）。
  - **LDS2 命令级纯 JVM 单测**：`test/emrtd/unit/card/EmrtdCommandTest.java` 直接驱动
    `card/emrtd/command/Lds2Record.java`（SEARCH RECORD A2 含 P2、FMM 5F、UPDATE BINARY D7、
    ACTIVATE 44 的往返与错误状态字）；`test/emrtd/unit/host/EmrtdCliTest.java` 覆盖主机 CLI
    dispatcher 与 `-json`/`-pace` 参数（`docs/specs/common/toolchain.md §7.1`）。

## 待办

- [ ] **E5.8 EAC 1.11（可选，低优先）**：EAC 1.11 变体，仅在有真卡需求时做
  （`card/emrtd/access/*`）。
- [ ] **T5.1 PACE 官方 BSI 测试向量**：BSI TR-03110 Test-Vector 文档未提供；现以 BSI KDF
  定义独立计算的 KAT + 第三方独立主机库互操作验证。
  （`test/emrtd/unit/host/EmrtdHostTest.java` 的 `paceKdf` 注释已改为“按定义计算、非 BSI
  已知答案”。）
- [ ] **T5.2 真卡读性能复测**：在 J3R180（接触/非接触）上实测优化后的读取耗时——
  `JCSystem.getAvailableMemory(MEMORY_TRANSIENT_DESELECT)` 余量、原生 `Signature` MAC 是否命中、
  单包 `READ BINARY` 是否仍触发 WTX，并与优化前对比记录。并复测**大 DG2 个性化**：确认 SD 的
  `processData` 事务粒度（逐命令 vs 整段）、约 10 KB 序列在真卡事务缓冲下不 `BUFFER_FULL`、
  以及 `MEMORY_TYPE_PERSISTENT` 余量（J3R180 ~180 KB NVM，DG2 预算 16384）。
- [ ] **SEARCH RECORD 命令 DO 解析复核（命令级单测发现，待正文复核）**：
  ① 搜索窗口的两个 `DO'02'`（偏移/字节数）由 `Lds2Record.searchRecord` 固定按 2 字节
  `Util.getShort` 读取，未按 BER 长度字段解码；ICAO Doc 9303-10 §3.7.3 Table 17 与
  Appendix I.1/J.1 的示例使用最小编码（如 `02 01 03`），按示例编码时窗口偏移被误读、
  匹配丢失（返回 `6282`）。当前命令级单测以 2 字节 BER 形式覆盖正路径。
  ② 1 字节 `DO'51'` 短 EF 标识符按位 b8–b4（`SFI<<3`，与 §3.8.3 Table 25 及 READ/APPEND
  RECORD P2 的 §3.7.1/§3.7.2 Table 10/13 一致）解码；信息性 Appendix I.1/J.1 直接写原始
  SFI（EF.Certificates 的 `1A`），两者不一致，需按正文复核。
  （`card/emrtd/command/Lds2Record.java`；测试 `test/emrtd/unit/card/EmrtdCommandTest.java`。）
- [ ] **C2 主机纯 JVM 卡仿真**：用第三方纯 JVM 卡仿真库跑主机 PA/读流程（无 jcsl）。
- [ ] **LDS2 Terminal Authentication 授权位**：LDS2 各 EF 的访问条件为 PACE+TA，授权位来自
  IS/DV/CVCA 证书的 CHAT 扩展（Doc 9303-10 §5.4 Table 96/97/98）。TA 未实现，当前仅强制
  PACE；需要时实现 TA（CV 证书链 + CHAT）后按授权位限制选择/读写。
- [ ] **Chip Authentication AES profile（`id-CA-*-AES-CBC-CMAC-*`）**：主机 `ChipAuth` 仅
  ECDH+3DES；AES CA 需 MSE:Set AT + GENERAL AUTHENTICATE 流程（Doc 9303-11 §6.2.4.2），
  卡侧亦仅 3DES CA。

## 延后 / 范围外

- [!] **AES-192/256 PACE**：卡侧 `AesCmac` 仅 AES-128；当前支持 3DES 与 AES-128。
- [!] **PACE DH generic mapping**：主机仅实现 ECDH 通用映射；DH-GM OID 被显式拒绝
  （`Pace.authenticate`），当前无 DH 卡需求。
- [!] **PACE 非标准化域参数（`PACEDomainParameterInfo`）**：主机仅支持标准化 P-256
  （`SecurityInfo.parse` 对未知 PACE OID 静默丢弃，Doc 9303-11 §9.2.2）；影响有限。
- **范围外**：国别 profile、生物 CVM、LDS2 之外的附加应用；代码内自签证书（`SodBuilder`
  沿用 openssl 夹具 `perso/emrtd/{csca,dsc}.crt`，生产需替换真实 CSCA/DSC 并补有效期/
  策略/吊销，见 `risks.md`）。

## 统一验收门

`make`/`make verify` 0 错 0 警告；`make test-unit`、`make test`（EMV+eMRTD 共存矩阵）、
`make test-emrtd` 全绿；每条行为变更同步 `docs/specs/`；新增报文使用标准 BSI/ICAO
数据对象与状态字。
