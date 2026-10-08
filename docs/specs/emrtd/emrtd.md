# eMRTD (ICAO 9303) — card42-emrtd

> eMRTD 实现的当前设计：LDS1 + BAC + ISO/IEC 7816-4 安全报文 + Passive Authentication +
> Active Authentication，以及 LDS2 应用、EF.CardAccess/SecurityInfo 解析、Chip
> Authentication（ECDH）与 PACE（ECDH 通用映射，3DES/AES-128）。EAC 1.11 仍为可选待办
> （[`TODO.emrtd.md`](../../../TODO.emrtd.md)）。

## 1. 范围与 AID

| 角色 | 实例 AID | Class AID |
|------|----------|-----------|
| LDS1（issuer stored data） | `A0 00 00 02 47 10 01`（ICAO DF name） | `43 41 52 44 42 02 01`（`card42.emrtd.EmrtdApplet`） |
| LDS2 Travel Records | `A0 00 00 02 47 20 01` | 同上 |
| LDS2 Visa Records | `A0 00 00 02 47 20 02` | 同上 |
| LDS2 Additional Biometrics | `A0 00 00 02 47 20 03` | 同上 |

applet 位于 `card42.emrtd` package / `card42-emrtd` CAP，依赖库 CAP `card42common`
（`card42.common`）。实例 AID 是标准 ICAO DF name（别名：其 RID 与 package RID 不同，
对 INSTALL 时选择的**实例** AID 是允许的）。

## 2. LDS1 文件系统

LDS1 应用是一组以 2 字节 FID 寻址的透明基本文件（ICAO Doc 9303-10 §4.6）：

| 文件 | FID | 容量 |
|------|-----|------|
| DG1 | `0101` | 128 |
| DG2 | `0102` | 16384 |
| DG3–DG14 | `0103`–`010E` | 256 |
| DG15 | `010F` | 512 |
| DG16 | `0110` | 256 |
| EF.CardAccess | `011C` | 256 |
| EF.SOD | `011D` | 2048 |
| EF.COM | `011E` | 64 |

EF.CardSecurity 也是主文件 EF（`011D`，Doc 9303-10 §3.11.4），与 DF 内的 EF.SOD 同 FID：
LDS1 实例在 `SELECT MF` 后用 `SELECT FILE 011D` 选主文件 EF.CardSecurity（`LdsMfStore`），
普通 `SELECT 011D` 仍指向本 DF 的 EF.SOD；读访问为 PACE（Table 34）。它由 DGI `FF05`
个性化（§8），与 LDS2 应用共享同一主文件文件（每张卡一个 EF.CardSecurity）。

`SELECT FILE`（P1=02，P2=0C）按 FID 选 EF；`READ BINARY`（`B0`）读窗口。READ BINARY 接受
ISO/IEC 7816-4 §6.1.1 的两种寻址形式：P1 b8=0 时 P1P2 为所选 EF 的 15 位偏移
（Doc 9303-10 §3.6.3.1 Table 4）；P1 b8=1 时 P1 的 b5..b1 为短 EF 标识、P2 为 8 位偏移，
无需 SELECT（Doc 9303-10 §3.6.3.2 Table 5）。合法 SFI 同时把该 EF 设为当前 EF
（ISO/IEC 7816-4 §6.1.2），故大 EF 在 SFI 前缀读取后可直接按偏移续读、无需再 SELECT——
这正是读卡器读取大于 256 B 的 EF 的方式。SFI 形式对 eMRTD 是**强制**的；SFI 为 FID 的低
5 位。FID 或 SFI 缺失回 `6A82`；无当前 EF 的偏移读取回 `6986`。容量是受限卡持久内存的
个性化预算（上限）；每个 EF 的后备存储是 **256 B 分页**（`LdsFile`，页在首次写入时按需分配、
跨写复用），所以未用或很小的 EF 几乎不占空间，而一个多 KB 的 DG2 只花它实际写入的字节，
不需要一整块连续 EEPROM，也不会在增大时复制旧内容（见 §8；J3R180 内存预算见
[../common/research-notes.md](../common/research-notes.md) §14）。

EF.CardAccess（`011C`，与 EAC 的 EF.CVCA 同 FID）作为透明 EF 提供，使 LDS1 实例宣告 PACE
（Doc 9303-10 §3.11.3）。该文件属于主文件，故 applet 也服务 SELECT FILE 的 MF 形式
（无数据 `P1=00`，或带 FID `3F00` 的 `P1=00/02`）：读卡器可在选择 eMRTD 应用**之前**
（SELECT MF、SELECT `011C`、READ BINARY）或之后于 MF 层读 EF.CardAccess。MF 预读要求
LDS1 实例在复位后被 Default Selected；这是 GP `CardReset` 权限（create 时 `--privs CardReset`；
GPPro 已退役的 `--default` 旗标对 `--create` 不编码，而 `--make-default` 在 J3R180 上回
`6A80`）。真卡与模拟器安装目标（`card-emrtd-install` / `card-install`、
`sim-emrtd-install` / `sim-install`）都以该权限安装 LDS1 AID；jcsl 同样遵守。

EF.COM 由卡侧根据数据组索引（E1.6）按规范形式
`60 { 5F01 LDS version (4 bytes), 5F36 Unicode version (6 bytes), 5C tag list }`
生成（Doc 9303-10 §4.6.1 Table 35）；EF.COM 内没有 `5F37`。

applet 实现 `javacardx.apdu.ExtendedLength`，故扩展长度 APDU 能到达 applet（符合规范的
读卡器做 RSA-2048 Active Authentication 时需要）。

## 3. 命令

| INS | 命令 | 说明 |
|-----|------|------|
| `A4` | SELECT (by name / SELECT FILE) | SELECT by name 回 `6F 09 84 07 <DF name>`（明文由 JCRE 匹配；SM 内到达时由 applet `selectByName` 匹配，见下） |
| `B0` | READ BINARY | 所选 EF 偏移（P1 b8=0）或短 EF 标识（P1 b8=1，P2 偏移）；不用 `READ BINARY2`（`B1`） |
| `84` | GET CHALLENGE | 8 字节 RND.ICC |
| `82` | EXTERNAL AUTHENTICATE | BAC 互认证（40 字节数据） |
| `88` | INTERNAL AUTHENTICATE | Active Authentication（8 字节挑战） |
| `22` | MSE | Chip Authentication `MSE:SET KAT`（§13）、PACE `MSE:Set AT`（§16） |
| `86` | GENERAL AUTHENTICATE | AES Chip Authentication 变体、PACE 四步（§16） |

LDS2 应用另加 `B2`/`E2`/`A2`/`5F`/`D7`/`44`（§11）。`EmrtdApplet` 按角色分派：LDS1 服务
上表，LDS2 角色服务 LDS2 记录/透明命令以及公共安全命令。

`AppletBase.rejectUnmatchedSelect()` 覆写为 `false`，使 `INS=A4` 进入命令分派器（eMRTD 用
A4 作 SELECT FILE，不同于 EMV 中非选中的 A4 表示「SELECT by name 未匹配」）。

**SM 内的 SELECT by name**：标准读卡器先做 PACE、再以 SM 包裹 `SELECT <DF name>` 选择应用
（JMRTD `sendSelectApplet(true)`）。SM 数据域是加密信封，JCRE 无法按 AID 匹配，命令会落到
applet 分派器；`EmrtdApplet.selectByName()` 在解包后按本实例 DF name 匹配：匹配则回 FCI
（`6F 09 84 07 <DF name>`）并**保持已建立的 SM 会话**，不匹配回 `6A82`。LDS1 与 LDS2 角色
共用同一逻辑。

## 4. Basic Access Control (Doc 9303-11 §4.3)

- **K_seed** = SHA-1(MRZ_information) 的前 16 字节，MRZ_information = 证件号（9 位，`'<'`
  补齐）+ 校验位 + 出生日期 + 校验位 + 有效期 + 校验位。校验位 = 7-3-1 加权和
  （Doc 9303-3 §4.9）。
- **K_enc / K_mac** = SHA-1(K_seed ‖ `00 00 00 01` / `…02`) 的前 16 字节，奇 DES 奇偶校验。
- **互认证**：GET CHALLENGE（RND.ICC）→ 终端发 `E_IFD ‖ M_IFD`，其中
  `S = RND.IFD ‖ RND.ICC ‖ K_IFD`、`E_IFD = 3DES-CBC(K_enc, S)`（零 IV）、
  `M_IFD = MAC(K_mac, E_IFD)`；卡校验 M_IFD 与 RND.ICC 后回由新的 `K_IC` 构造的
  `E_IC ‖ M_IC`。
- **会话密钥**：先 `Kseed = K_IFD ⊕ K_IC`，再 `Ks_enc = KDF(Kseed, 1)`、`Ks_mac = KDF(Kseed, 2)`
  （Doc 9303-11 §4.3.1 step 5 / §9.7.4、Appendix D.3）；
  **SSC** = RND.ICC 最右 4 字节 ‖ RND.IFD 最右 4 字节。

## 5. 安全报文 (Doc 9303-11 §9.8)

BAC 之后终端置 `CLA | 0x0C` 并封装每条命令：

```
command data = [DO85|DO87] [DO97] DO8E
response data = [DO85|DO87] DO99 DO8E
```

- **DO87**（加密数据，even INS）= `87 <len> 01 <3DES-CBC(Ks_enc, M2-pad(data))>`（零 IV）；
- **DO85**（明文数据，odd INS）= `85 <len> <data>`；even INS 用 DO`87`、odd INS 用 DO`85`
  （Doc 9303-11 §9.8.4）；
- **DO97** = `97 01 <Le>`；
- **DO99** = `99 02 <SW1 SW2>`；
- **DO8E** = `8E 08 <retail MAC>`。

MAC 输入（ISO/IEC 9797-1 algorithm 3，密钥 Ks_mac）：

```
command:  pad(SSC ‖ pad(CLA' INS P1 P2) ‖ [DO87|DO85] ‖ DO97)
response: pad(SSC ‖ [DO87|DO85] ‖ DO99)
```

SSC 是 64 位大端计数器，每次 MAC 前自增。DO87 用 BER 短/长形式长度；会超过 256 字节短
APDU 缓冲的响应由终端分块。单次 `READ BINARY` 的明文窗口上限是
`ReadBinary.SM_RESPONSE_MAX = 0xE7`（231 B：DO87 的 `0x81` 长度 + 232 B M2 填充 + DO99/DO8E
共 250 B，刚好装进 256 B 短响应；232 B 明文会到 258 B 超限）；主机 `LdsReader.CHUNK = 0xE7`
与之一致。AES-128 的 PACE SM 用 `Iso7816SmAes`（§16）。

**MAC 实现**：ISO/IEC 9797-1 Algorithm 3 的 CBC 段优先用平台 MAC 引擎
（`Signature.ALG_DES_MAC8_ISO9797_M2` 处理需 M2 填充的消息，`ALG_DES_MAC8_NOPAD` 处理
已对齐的消息），再做两次单 DES ECB 终变换 `DES_dec(K2)` / `DES_enc(K1)`（与
`tools/passportapplet` 的 JCOP 实现同构）。平台不支持这些 MAC 签名而报
`NO_SUCH_ALGORITHM` 时自动回退到逐块 `Cipher.ALG_DES_ECB_NOPAD` 的手工构造；两条路径源码同一份，
单测用开关同时验证。这样真卡一次调用即可完成整段 CBC-MAC，避免每个 SM 包在字节码里逐块调用
密码机的开销。

**缓冲与密钥**：两个 SM 包装器共享包级 `SmScratch`（`CLEAR_ON_DESELECT` 瞬态数组，无瞬态余量时
回退持久数组），仅在选中时首次分配、整个 package 一份，因此每个实例不再各占 1 KB 持久内存，
也避免多实例各自惰性分配耗尽瞬态预算（[../common/risks.md](../common/risks.md) §2）。3DES 包装器的
K_enc 与 MAC 的 K1/K2 只在会话密钥变化时装载一次（`Iso7816Sm.reset()` / `Iso7816SmAes.reset()`
在应用重选时清零缓存）。

**等待时间**：PACE/Chip Authentication 的 EC 运算、Active Authentication 的 RSA 签名和
BAC 握手这类可能超过非接触块等待时间的命令，在处理前调用 `APDU.waitExtension()` 申请额外时间
（`EmrtdApplet.requestMoreTime`）。`READ BINARY` 刻意不申请：原生 MAC + 瞬态缓冲后单包远低于超时，
无条件 WTX 反而会给每次读增加一次射频往返。

## 6. Active Authentication (Doc 9303-11 §6.1)

DG15 以 RFC 5280 `SubjectPublicKeyInfo` 存放 AA 公钥
（`6F { SEQUENCE { AlgorithmIdentifier(rsaEncryption), BIT STRING } }`，Doc 9303-11 §6.1.5）。
卡用个性化注入的 AA 私钥对消息 `M = RND.IC ‖ RND.IFD` 做 **ISO/IEC 9796-2 Digital
Signature Scheme 1** 签名（消息恢复）：`RND.IC` 由卡生成（可恢复部分 M1），`RND.IFD` 为
8 字节 INTERNAL AUTHENTICATE 挑战；SHA-1 用 trailer 选项 1（`0xBC`），SHA-256 用选项 2
（`0x34CC`）。终端用 DG15 公钥做消息恢复并校验 `H(M)`（Doc 9303-11 §6.1.2.2）。256 字节
RSA 签名装不进 SM 封装的短 APDU，故 AA 在明文下执行（DG15 为公钥，可无 BAC 读取）。

## 7. Passive Authentication (Doc 9303-10 §4.6.2, Doc 9303-11 §5.1)

EF.SOD 是外层 `77` 标签内的 CMS SignedData（RFC 5652）（Doc 9303-10 §4.6.2 Table 36）：

- `CmsSignedData` 提取封装的 LDS Security Object（`eContent`）、首个签名者证书、signed
  attributes、摘要/签名 OID 与签名。
- `LdsSecurityObject` 解析 `SEQUENCE { version, hashAlgorithm, dataGroupHashValues }`。
- `DscVerifier` 用受信任的 CSCA 库校验 Document Signer Certificate；`PassiveAuthentication`
  校验 `messageDigest` signed attribute、验证对 signed attributes（重编码为 SET OF）的签名，
  并把每个读到的 DG 与其哈希比对。

## 8. 个性化

applet 实现 GP `Personalization.processData`。SD 把**每条** STORE DATA 命令（短 APDU，数据域
≤231 B）原样转发，applet **逐块增量应用**：`DgiStream` 解析 DGI 头（`dgi(2) ‖ len(1 | 0xFF len(2))`，
CPS §3.2；头最多 5 B 可跨块）并把值字节直接交给目标（文件/记录/密钥 sink），DGI 值可任意跨块
（上限 32767，受 15 位 READ BINARY 偏移与有符号 short 约束）。因此**不再有整段重组缓冲**
（此前的 4096 B `persoBuffer` 已移除）：峰值 RAM 只与一条 STORE DATA 命令有关，与照片大小无关；
文件值经分页 EF 落盘（§2），记录值直接写入记录池（`Lds2RecordFile.beginRecord/appendChunk/endRecord`）。
只有小密钥 DGI（AA 私钥 ≤516 B、CA 标量 32 B、PACE 种子 20 B、BAC 种子 16 B）暂存于固定
scratch。`P2=0` 复位序列，末块（`P1.b8=1`）触发完成校验：LDS1 `LdsCatalog.finalizeCatalog()` +
必填 DGI 校验（FF01 与 DG1），LDS2 无 COM 索引。序列中途截断（`DgiStream.finish` 时仍处于值
状态）回 `6700`，由 SD 事务回滚。

DGI 编号即目标 FID；两个项目 DGI 承载 BAC 与 AA 密钥材料：

| DGI | 值 |
|-----|-----|
| `FF01` | BAC K_seed（16 字节） |
| `FF02` | AA 私钥：`modLen(2) ‖ modulus ‖ expLen(2) ‖ exponent` |
| `FF03` | Chip Authentication 静态私钥标量（P-256，32 字节） |
| `FF04` | PACE 密钥种子 SHA-1(MRZ_information)（20 字节） |
| `FF05` | LDS1 主文件 EF.CardSecurity CMS SignedData（DGI 专用：DF 的 `011D` 已是 EF.SOD） |
| `<FID>` | EF 内容（DG1 `0101`、DG2 `0102`、DG15 `010F`、COM `011E`、SOD `011D`、EF.CardAccess `011C` 等） |

对 LDS2 角色，DGI 编号是透明 EF 的 FID；EF.CardAccess `011C` 与 EF.CardSecurity `011D`
写入主文件存储 `LdsMfStore`（不在 DF 内），`0x7000 | FID` 则向记录 EF（EF.Certificates
`011A`、Entry/Visa `0101`/`0103`、Exit `0102`）追加一条记录。`Lds2Perso` 同样消费
`FF03`/`FF04`，故 LDS2 EF.CardAccess 宣告的 Chip Authentication 与 PACE 实际可用。`CardSecurityBuilder` 围绕匹配密钥的 `ChipAuthenticationPublicKeyInfo`
构造 EF.CardSecurity CMS SignedData（`id-SecurityObject` `0.4.0.127.0.7.3.2.1`）。

`EmrtdPersoExporter` 用新的 RSA-2048 AA 密钥和由 DSC 夹具
（`perso/emrtd/{csca,dsc}.crt`、`perso/emrtd/dsc.key`）签名的 EF.SOD 构造 ICAO 样例护照的
DGI 序列。DG1 与 DG15 内联构造；DG2 由 `Dg2Builder` 构造成 CBEFF/ISO 7816-11 包装
（`75 { 7F61 { 7F60 { A1 SBH, 5F2E } } }`），内含一个 ISO/IEC 19794-5 Basic Facial
Image Record。头像来自输入图片（默认 `perso/emrtd/portrait.png`，可用 `-face=<path>` 覆盖），
按 4:5 居中裁切并把最长边缩到 512 px（`Dg2Builder.MAX_SIDE`）后编码为 JPEG（DG2 约 8 KB）；
图片缺失或不可读即报错，host 不再合成占位图。SOD 覆盖 DG1、DG2、DG15 的 SHA-256 哈希（A3）。
`LdsScript` 是人类可读输入格式；`perso/emrtd/sample.perso` 是演示集，
`EmrtdPersoExporter -script=<path>` 个性化每个 `@instance` 段（`-emit` 打印内置样例脚本；
无 `-script` 时用内置样例，头像取自 `-face=<path>`，默认 `perso/emrtd/portrait.png`）。
LDS2 指令为 `@lds2 <role>`、`@cardaccess`、`@cardsecurity`、`@record <fid> <hex>`。

## 9. 主机模块

```
host/emrtd/
├── transport/ EmrtdTerminal
├── lds/       LdsFileUtil, LdsReader, Dg1, Dg2, Dg15, Dg, Com, Sod,
│              CmsSignedData, LdsSecurityObject, AlgorithmIds,
│              SecurityInfo, PaceInfo, ChipAuthenticationInfo,
│              ChipAuthenticationPublicKeyInfo, ActiveAuthenticationInfo,
│              CardAccess, CardSecurity
├── access/    MrzKeySeed, Bac, Iso7816Sm, Iso7816SmAes, SecureMessaging, ChipAuth, Pace
├── pa/        CscaKeyStore, DscVerifier, PassiveAuthentication
├── aa/        ActiveAuthentication
├── perso/     EmrtdPersoExporter, SodBuilder, Dg2Builder, CardSecurityBuilder, LdsScript
├── report/    PassportReport
└── cli/       Main, command/EmrtdCommand
```

## 10. 验证

- `make test-unit` — 卡侧密码学（ICAO BAC 向量）、主机 DG 解析器、卡↔主机 SM 交叉校验、
  LDS2 文件系统/记录命令、CardAccess/SecurityInfo、DG3–DG16、Chip Authentication ECDH
  往返与 PA 篡改拒绝、PACE KDF（`test/emrtd/unit`）；`EmrtdPersoStreamTest` 另覆盖分页 EF
  （跨页读写、更新 gap、容量/激活拒绝）、DGI 流式帧解析（头/值跨块、空值、截断、超长）与
  LDS1/LDS2 逐块（1–13 B）个性化，含 5000 B DG2。
- `make test-emrtd` — 模拟器端到端：SELECT LDS1、AA、BAC、SM 读 DG1/DG2/COM/DG15/SOD、
  PA（DSC 链 + 签名 + DG 哈希）、LDS2 Travel Records DF（CardAccess + READ/APPEND RECORD）、
  PACE（3DES/AES-128）、LDS1 Chip Authentication（PACE → 主文件 EF.CardSecurity → CA →
  新 SM 下读 DG1）；样例 DG2 约 8 KB（>4096），覆盖流式个性化 + 分页 EF + 大 DG 读回。
- `make test` — both 矩阵（EMV 生产 + eMRTD LDS1/LDS2 共存）。

## 11. LDS2 应用 (Doc 9303-10 §5)

LDS2 是 LDS1 eMRTD 的可选、向后兼容扩展。同一个 `EmrtdApplet` 类服务所有角色；角色在
INSTALL 时由实例 AID 决定（`EmrtdInstallParameters.role()`）：

| 角色 | 实例 AID | 记录 EF（FID / SFI） | 透明 EF（DF 内） |
|------|----------|----------------------|---------|
| Travel Records | `A0 00 00 02 47 20 01` | EF.Certificates `011A`/`1A`、EF.EntryRecords `0101`/`01`、EF.ExitRecords `0102`/`02` | — |
| Visa Records | `A0 00 00 02 47 20 02` | EF.Certificates `011A`/`1A`、EF.VisaRecords `0103`/`03` | — |
| Additional Biometrics | `A0 00 00 02 47 20 03` | EF.Certificates `011A`/`1A` | EF.Biometrics1 `0201`（SFI N/A） |

每个 LDS2 DF 拥有一个 `Lds2FileSystem`：少量 `Lds2TransparentFile`（容量为上限；内容为
256 B 分页，按需分配、跨写复用，可选 ACTIVATE 锁）与 `Lds2RecordFile`（扁平池中的线性变长
记录，带并行偏移/长度数组；记录可由 `beginRecord/appendChunk/endRecord` 逐块写入，池字节先写、
`used`/`count` 到 `endRecord` 才提交）。LDS2 文件的短 EF 标识为其 FID 的低字节（`0x01 || SFI`，
Doc 9303-10 §5.1）。

EF.CardAccess `011C` 与 EF.CardSecurity `011D` 属**主文件**（`LdsMfStore`，包内静态、跨
实例共享），不在任何 LDS2 DF 内（Doc 9303-10 §3.11.3/§3.11.4）。EF.CardAccess 恒可
选择/读取；EF.CardSecurity 与所有 LDS2 记录/透明 EF 的访问 **MUST** 先完成 PACE，否则
回 `6982`（Doc 9303-11 §1.2 Note 2 / §4.2 step 3；Doc 9303-10 §3.11.4 Table 34、§5.4）。
SM 建立（BAC/PACE/CA）后收到明文 APDU 即中止会话并回 `6982`（Doc 9303-11 §9.8.3）。

命令：

| INS | 命令 | 说明 |
|-----|------|------|
| `A4` | SELECT FILE | P1=02 按 FID；P1=04 按名：明文由 JCRE 匹配，SM 内到达时由 `EmrtdApplet.selectByName` 匹配并回 FCI（保持会话） |
| `B0` | READ BINARY | 所选透明 EF，或按短 EF 标识寻址（P1 b8=1，P2 偏移） |
| `B2` | READ RECORD | P2 b8-b4 = SFI，b3=1，b2b1 = 单条（00）/ 全部（01）；P1 = 记录号（00 = 当前） |
| `E2` | APPEND RECORD | P2 b8-b4 = SFI；满时 `6A84`，记录超 EF 上限时 `6700` |
| `A2` | SEARCH RECORD | 记录处理 DO `7F76`；响应 `7F76 { 51, 02… }`；无匹配时 `6282` |
| `5F` | FILE AND MEMORY MANAGEMENT | P2 选总字节/剩余/已有记录数，在 `7F78` 返回 |
| `D7` | UPDATE BINARY（奇数 INS） | 偏移 DO `54` + 数据 DO `53`；激活后 `6982` |
| `44` | ACTIVATE | 冻结所选的 Additional Biometrics 透明 EF |
| `22`/`86` | MSE:SET KAT / GENERAL AUTHENTICATE | Chip Authentication（§13）、PACE（§16） |

## 12. EF.CardAccess / EF.CardSecurity (Doc 9303-10 §3.11, Doc 9303-11 §9.2)

EF.CardAccess 是公开 DER `SET OF SecurityInfo`；EF.CardSecurity 是 CMS SignedData，其
eContent 为同一 `SET OF SecurityInfo` 加芯片静态 Chip Authentication 公钥。与 EF.SOD 不同，
EF.CardSecurity 存为纯 RFC 3369 SignedData ContentInfo（无外层 `77` 标签，Doc 9303-10
§3.11.4）。EF.CardAccess 属于主文件（Doc 9303-10 §3.11.3）；LDS1 实例在 `011C` 提供它，
LDS2 实例读同一主文件 `LdsMfStore`（见下）。

主机 `SecurityInfo` 层次解析基础 OID 及 profile 字段：`PaceInfo`（version、parameter id）、
`ChipAuthenticationInfo`（version、key id）、`ChipAuthenticationPublicKeyInfo`
（SubjectPublicKeyInfo、key id）、`ActiveAuthenticationInfo`。`CardAccess.selectPace()`
优先 ECDH 通用映射，其次 DH 通用映射；`CardSecurity` 暴露 CMS 签名者证书与 CA 公钥，
`ChipAuthenticationPublicKeyInfo.rawPoint()` 给出用于自包含 ECDH 的未压缩 P-256 点。
EF.CardAccess 与 EF.CardSecurity 由个性化作为透明 EF 存储（DGI = FID）并原样提供；
卡侧无需解析。

EF.CardAccess/EF.CardSecurity 均属主文件（Doc 9303-10 §3.11.3/§3.11.4）。LDS1 把
EF.CardAccess `011C` 放在其 DF catalog（无同 FID 冲突），EF.CardSecurity 用 DGI `FF05`
写入主文件 `LdsMfStore`（`011D`，读访问 PACE）；LDS2 用 DGI `011C`/`011D` 写同一主文件
store，所有实例共享一份 EF.CardAccess/EF.CardSecurity。EF.CardSecurity 必须包含
EF.CardAccess 的 SecurityInfos 与 CA 公钥，故示例中 LDS1 与 LDS2 使用同一 CA 密钥对与
同一份 EF.CardSecurity。

## 13. Chip Authentication (Doc 9303-11 §6.2, BSI TR-03110-3 A.4/B.2)

芯片持有静态 P-256 密钥对，其公钥公布在 EF.CardSecurity。终端生成临时 P-256 密钥对，用
`MSE:SET KAT`（P1=41，P2=A6，DO`91`）发送其公钥，双方计算 `Z = ECDH(static_priv,
ephemeral_pub)`。新的安全报文密钥为 `Ks_enc = KDF(Z, 1)`、`Ks_mac = KDF(Z, 2)`，其中
`KDF(Z, c) = SHA-1(Z ‖ 00 00 00 c)`，截断到 16 字节并加奇 DES 奇偶校验（3DES profile）；
发送序列计数器归零，复用现有 `Iso7816Sm`。

卡只有在 `MSE:SET KAT` 的响应用旧密钥封装后才应用新密钥，故终端可在下一条命令切换 SM。
卡在处理前对终端的临时公钥做结构校验（长度、`0x04` 前缀、两坐标 `< p`，BSI TR-03110-3
A.3.4.1）：`P256.isLessThanP` 用**显式无符号逐字节比较**，不使用 `Util.arrayCompare`——部分
Java Card 平台（含 J3R180/nextgen）按有符号字节比较，会间歇性把合法坐标判为 `>= p` 而回
`6A80`（回归由 `EmrtdChipAuthIntegrationTest`/`EmrtdLds1ChipAuthIntegrationTest` 覆盖）。
CA 私钥标量用 DGI `FF03` 个性化；LDS1 的 EF.CardSecurity 用 DGI `FF05` 写入主文件（§8）。
LDS1 与 LDS2 角色共用同一 CA 实现：LDS1 在 `SELECT MF` 后于主文件 `011D` 读
EF.CardSecurity（读访问 PACE，Doc 9303-10 §3.11.4 Table 34），LDS2 读共享的 MF `011D`。
ECDH + KDF + SM 往返在纯 JVM 中用独立 JCE 密钥对验证（`EmrtdLds2Test`、
`EmrtdPersoStreamTest`），端到端由 `EmrtdChipAuthIntegrationTest`（LDS2）与
`EmrtdLds1ChipAuthIntegrationTest`（LDS1）覆盖；真卡部署依赖其 ECC/`KeyAgreement` 支持
（与 PACE 同一门控，见 [risks.md](../common/risks.md)）。

## 14. DG3–DG16 (Doc 9303-10 §4.7.3–4.7.16)

`LdsFileUtil` 把每个数据组编号映射到 FID 与外层标签（`63`、`76`、`65`–`6E`、`6F`、`70`）。
`Dg` 是通用解析器/生成器：识别外层标签，保留 EF 原始字节，并按标签暴露嵌套值
（`value`/`values`），`Dg.wrap` 从内层 TLV 列表构造数据组。报告消费的组（DG1/DG2/DG15）
保留专用解析器。

## 15. 主机 CLI

`card42.host.emrtd.cli.Main`（`card42-emrtd.jar` 入口）：

```
Main terminal emrtd read    -host=<spec> -doc=<no> -dob=YYMMDD -doe=YYMMDD [-pace] [-ca] [-json=1]
Main terminal emrtd inspect -host=<spec> [-json=1]
Main terminal emrtd lds2    -host=<spec> [-app=travel|visa|biometrics] [-json=1]
Main terminal emrtd apdu    -host=<spec> -apdu=<hex>
Main version | help
```

- `<spec>` 为 `pcsc[:<reader-index>]` 或 `socket:<host>:<port>`。
- `read` 跑 AA（明文）、BAC（或 `-pace` 时的 PACE）与 SM，读 DG1/DG2/COM/DG15/SOD，并对照
  `perso/emrtd/` 下的 CSCA 文件验证 PA；`-ca` 时在 SM 建立后读 EF.CardAccess/EF.CardSecurity
  执行 Chip Authentication 再读数据组；输出文本报告，`-json=1` 时输出 JSON 对象（证件号、
  姓名、日期、LDS/Unicode 版本、AA 模长位数）。
- `inspect` 无 BAC 读 COM/DG15，报告公开数据。
- `lds2` SELECT 一个 LDS2 DF，读 EF.CardAccess 与记录 EF 的每条记录，打印 SecurityInfo 与
  记录（文本或 JSON）。
- `apdu` 发一条原始 APDU，打印 `SW=` 与响应数据。
- 退出码：`0` 成功，失败非零并输出 `error: <message>`。

## 16. PACE (BSI TR-03110-3 A.3/B.1, Doc 9303-11 §4.4)

PACE（Password Authenticated Connection Establishment）为在 EF.CardAccess 中宣告它的应用
替代 BAC。卡实现 **ECDH 通用映射（generic mapping）** profile，支持 **3DES** 或 **AES-128**
安全报文与 **MRZ** 口令：`id-PACE-ECDH-GM-3DES-CBC-CBC`
（`0.4.0.127.0.7.2.2.4.2.1`）与 `id-PACE-ECDH-GM-AES-CBC-CMAC-128`
（`0.4.0.127.0.7.2.2.4.2.2`），P-256（标准化域参数 id 12）。MSE:Set AT 的 OID 末字节选择
profile。

LDS1 EF.CardAccess 在 `011C` 提供；LDS1 实例带 GP `CardReset`（Default Selected）时可在选
应用前于 MF 层读，选择后始终可读。LDS2 DF 在自己的 EF.CardAccess 中宣告 PACE/CA，并以
PACE 密钥种子（FF04）个性化，CA 另有静态 P-256 标量（FF03）与 EF.CardSecurity。

- 20 字节 PACE 密钥种子 `SHA-1(MRZ_information)` 用 DGI `FF04` 个性化；卡派生
  `K_pi = KDF(seed, 3)`（基于 SHA-1；仅 3DES 调整 DES 奇偶校验，BSI TR-03110-3 §A.2.3）。
- `MSE:Set AT`（P1=41 或 C1，P2=A4）携带 `DO'80'`（PACE OID）与 `DO'83'`（口令引用
  `01` = MRZ）。
- 四步 `GENERAL AUTHENTICATE`（BSI TR-03110-3 B.1）：`DO'80'` 加密 nonce `E(K_pi, s)`、
  `DO'81'`/`DO'82'` 映射公钥、`DO'83'`/`DO'84'` 临时公钥、`DO'85'`/`DO'86'` 认证令牌。
  第 1–3 步用命令链（`CLA=0x10`），第 4 步明文。
- 通用映射用平台 `KeyAgreement.ALG_EC_PACE_GM`（`G' = [s]G + H`）；
  `ALG_EC_SVDP_DH_PLAIN_XY` 给出映射共享点，`ALG_EC_SVDP_DH_PLAIN` 给出会话共享密钥。
  `K_enc = KDF(Z, 1)`、`K_mac = KDF(Z, 2)`；第 3 步后替换会话密钥、SSC 归零。3DES 复用
  `Iso7816Sm`（retail MAC）；AES-128 用 `Iso7816SmAes`（AES-CBC，IV = AES-ECB(K_enc, SSC16)，
  加 AES-CMAC，BSI §F.4.2）。
- J3R180 支持完整 ECC 栈（`ALG_EC_PACE_GM`、`ALG_EC_SVDP_DH_PLAIN_XY`、`ALG_EC_FP` P-256
  密钥生成）；实现前用一次性探针 applet 确认。第三方独立主机库的 `doPACE` 对两种 profile
  均互操作。

- 主机终端实现同一 profile（`host/emrtd/access/Pace.java`）；其通用映射 `G' = [s]G + H`
  使用 `host/common/crypto/P256.java` 的自包含 P-256 运算（仿射点加 + double-and-add 标量乘），
  无需外部 EC provider。CLI 用 `terminal emrtd read -pace` 运行。
