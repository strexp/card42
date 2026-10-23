# eMRTD Terminal Authentication（TA）— 设计决策与可行性

> 状态：**已实现（2026-10-12，`ta` 分支摘取并适配当前 master）**。可行性在模拟器（jcsl）与
> 真卡（NXP J3R180）上实测确认；本文件冻结算法/版本/信任点四个关键决策，并作为 P1–P7 实现的
> 设计基线。P1–P7 已落到 `card/emrtd/`、`host/emrtd/ta/` 与集成套件
> `EmrtdTerminalAuthIntegrationTest`（模拟器矩阵全绿）；残余见 §1.1。
>
> 参考标准（`tools/`）：ICAO Doc 9303-10 §3.11/§5.4、Doc 9303-11 §7.1；BSI TR-03110-2
> §3.3、TR-03110-3 A.1.1.3/A.7/C.1、TR-03110-4。命令与 DO 一律用标准编号
> （[`../../common/toolchain.md`](../common/toolchain.md) 的工具链约定）。

## 1. 结论摘要

- **TA 已实现**（卡侧与主机侧；见本文与 [`emrtd.md`](emrtd.md) §17）。
- **可行性来源（TA v1 + ECDSA-SHA-256）**：真实 J3R180 上 `Signature.ALG_ECDSA_SHA_256`
  验签通过；`RSA-PSS-SHA-256` 亦通过，作为备选。
- **plain（r‖s）可直接验签，无需转换**：Java Card 两参 `getInstance(ALG_ECDSA_SHA_256)`
  的签名编码是 ANSI X9.62 **DER**（API 规范如此），但四参
  `getInstance(MessageDigest.ALG_SHA_256, Signature.SIG_CIPHER_ECDSA_PLAIN, Cipher.PAD_NULL, false)`
  在 jcsl 与 J3R180 上都直接接受 TA 的 TR-03111 **plain（r‖s）**签名。因此**不需要
  plain→DER 转换，也不需要自实现 P-256**（`ALG_NULL` + `verifyPreComputedHash` 组合两平台
  均不支持，无需）。
- **内存可行**：清理探针后真卡持久余量约 **13–15 KB**，瞬态 `CLEAR_ON_DESELECT` 约
  2.4–4 KB；TA 的持久足迹（信任点 + 元数据）预计 <1 KB，余量充足。

## 1.1 实现状态

- **P0（平台可行性）已完成**：见 §2。
- **P1（主机侧 CV 证书）已完成**：`host/emrtd/ta/` 的 `CvcPrincipal`/`Chat`/`CvCertificate`/
  `CvCertificateCodec`/`CvCertificateBuilder`/`CvChainVerifier`/`TaChain`，ECDSA 用自包含
  `host/common/crypto/Ecdsa`（plain r‖s，无 JDK EC 依赖）；纯 JVM 单测
  `EmrtdTaTest`（编解码往返、DER↔plain 与 JDK 交叉验证、链验证正/负、有效授权 AND）。
  另在 `host/emrtd/lds/` 增 `TerminalAuthenticationInfo` 并接入 `SecurityInfo` 解析。
- **P2（主机侧 TA 驱动 + CLI）已完成**：`TerminalAuth`（`ID_IC‖rIC‖Comp(PKDH,IFD)` 签名）、
  `EmrtdTerminal` 的 `MSE:Set DST`(`81B6`)/`PSO:Verify Certificate`(`2A/00BE`)/`MSE:Set AT`(`81A4`)；
  `Pace.Session.piccPublicKey` 与 `ChipAuth` 的终端 CA 公钥暴露给 `ID_IC`/`Comp`；CLI
  `read -ta -ta-chain=<file> -ta-key=<hex>` 与 `ta-export`（生成演示链）。
- **P3（卡侧 CV 证书校验 + 信任点）已完成**：`card/emrtd/ta/TaContext`（CVCA 信任点、
  `MSE:Set DST`(`81B6`)、`PSO:Verify Certificate`(`2A/00BE`)、ECDSA plain 验签、
  公钥导入）、`Mse`/新 `PsoVerifyCertificate` 命令、`LdsPerso` DGI `FF07` 注入信任点；
  卡侧单测 `EmrtdTaCardTest`（链导入、篡改→`6A80`、未知引用→`6A88`、无信任点→`6985`）。
  签名覆盖**含 tag/len 的 body**（被单测发现并修正）。
- **P4（卡侧 TA 协议）已完成**：`MSE:Set AT`(`81A4`) 选终端密钥、`EXTERNAL AUTHENTICATE`
  验 `ID_IC‖rIC‖Comp(PKDH,IFD)`（坏签名→`6300`）；`ID_IC` 取自 PACE 卡侧 step-3 临时公钥
  x 坐标、`Comp(PKDH,IFD)` 取自 CA 终端临时公钥 x 坐标；`GET CHALLENGE` 兼填 TA rIC；
  `ExternalAuthenticate` 在已选终端密钥时路由到 TA，否则 BAC；同一会话只允许一次 TA
  （第二次 `MSE:Set DST/AT`→`6982`）。卡侧单测覆盖全流程。
- **P5（授权 + 个性化）已完成**：卡侧 `TaContext.effectiveAuth`（CVCA 信任点与每张证书的
  CHAT/应用扩展逐位 AND，App 序号 Travel/Visa/Bio = 1/2/3）；DGI `FF07` 扩展为
  `W(65)‖refLen(1)‖CAR‖[CHAT,Travel,Visa,Bio]`；`EmrtdApplet.requireLds2Access` 按有效授权
  门控 LDS2 EF/记录（read=b1、append=b2），`ta` 在所有 eMRTD 实例上启用，LDS2 分派加入
  `GET CHALLENGE`/`EXTERNAL AUTHENTICATE`/`PSO`；EF.CardAccess/DG14 宣告
  `TerminalAuthenticationInfo`；个性化对 LDS1 注入 FF07（demo CVCA `TaChain.demo`）。
- **P6（测试/文档）**：卡侧单测覆盖授权正/负路径（有授权读达记录 EF `6A83`、无授权 `6982`）。
  **E6 已落地**（卡侧扩展长度命令接收：`EmrtdApplet.receiveCommand` 用 `getIncomingLength`/
  `receiveBytes` 把命令装配进 `EmrtdScratch.raw`，保留 4 字节头给 SM 解包；主机 `CommandAPDU`
  按需扩展）。**TA 端到端在 jcsl 通过**：`EmrtdTerminalAuthIntegrationTest` 演示
  PACE→CA→TA 后 LDS2 Travel 记录的读/追加放行、TA 前 `6982`；LDS2 套件均加入 CA+TA。
- **时间递进机制已实现（BSI TR-03110-3 §2.5/§2.6）**：`TaContext.currentDate`（6 octet 未打包
  BCD YYMMDD）由个性化 DGI `FF08` 注入；`PSO:Verify Certificate` 对**非 CVCA Link** 证书做
  过期判断（`Expiration < current` → `6A80`），并把 `Effective Date` 前移当前日期（CVCA/DV，
  以及由**本国 DV** 签发的 Accurate Terminal 证书）；卡侧单测覆盖"日期前移"与"过期拒绝"。
- **附加生物识别加密（Doc 9303-11 §7.2）**：ICAO 未定义算法/密钥（State-specific），属范围外；
  见 [algorithm-support.md](algorithm-support.md) §5。
- **（2026-10-12 增强 + 真卡复测）** 原残余 ②/③/④ 已落地：LDS1 的 DG3/DG4 按 ePassport CHAT 位
  门控（`EmrtdApplet.requireLds1ChatAccess`，无信任点时为 PACE-only）；信任点改为**最多两个**并支持
  运行期 **CVCA Link Certificate** 导入与**按 Effective Date 启用**（未到期不可作 DST 校验键、最新
  到期者播种会话授权，`TaContext.activeTrustPoint`/`slotEffective`）；**RSA-PSS-SHA-256** 备选
  profile 按证书 `7F49` 公钥 OID 选择（卡侧 `Signature.ALG_RSA_SHA_256_PKCS1_PSS`，主机
  `host/common/crypto/RsaPss` + `CvCertificateCodec.encodeBodyRsa` + `TerminalAuth` RSA 分支）。
  **真卡 J3R180（ACR1581 PICC）复测通过**：全部 7 个 eMRTD suite（含
  `EmrtdTerminalAuthIntegrationTest` 的 PACE→CA→TA 与扩展长度 PSO）全绿。
  **关键教训**：ECDSA 验签引擎（`ECPublicKey` + `Signature(SIG_CIPHER_ECDSA_PLAIN)`）**不得在 SD
  的个性化事务内构建**——J3R180 实测在 `FF07` 处理中构建会 `6F00`（事务/系统限制）；改为在
  **安装期**（`EmrtdApplet` 构造器调用 `TaContext.ensureKeys()`）构建，个性化只存密钥字节。

## 2. 平台实测（一次性探针，探针已移除）

方法沿用 [`../../common/research-notes.md`](../common/research-notes.md) §10 的约定：一个
实现 `Personalization`/命令接口的一次性 applet（`card42.probe`）由主机驱动，在 jcsl 与
真卡 J3R180（经 ACR1581 PICC 非接触口）上各跑一遍；探针已从卡上删除。

| 探测项 | jcsl v26.0 | J3R180 |
|--------|-----------|--------|
| `Signature.ALG_ECDSA_SHA` (SHA-1) | ✓（DER） | ✓（DER） |
| `ALG_ECDSA_SHA_224/256/384/512`（两参 `getInstance`） | ✓（DER） | ✓（DER） |
| `getInstance(ALG_SHA_256, SIG_CIPHER_ECDSA_PLAIN, PAD_NULL)` → plain r‖s | ✓ | ✓ |
| `getInstance(ALG_NULL, SIG_CIPHER_ECDSA_PLAIN, PAD_NULL)` + `verifyPreComputedHash` | ✗ | ✗ |
| `ALG_RSA_SHA_PKCS1` / `ALG_RSA_SHA_256_PKCS1` / `ALG_RSA_SHA_512_PKCS1` | ✓ | ✓ |
| `ALG_RSA_SHA_256_PKCS1_PSS`（ICAO Table 7） | ✓ | ✓ |
| `MessageDigest.ALG_SHA/224/256/384/512` | ✓ | ✓ |
| `KeyBuilder.TYPE_EC_FP_PUBLIC` + 显式 P-256 域参数 + `setW` | ✓ | ✓ |
| 持久余量 | 32767（封顶） | ≈13.6–14.9 KB |
| 瞬态 `RESET` / `DESELECT` 余量 | 5.3 KB | 256 B / ≈2.4–4 KB |

注：主机用 JCE 生成 P-256 向量（`SHA{1,224,256,384,512}withECDSA`，DER）；两参
`getInstance(ALG_ECDSA_*)` 的 DER 编码是 Java Card API 规范（“签名编码为 r、s 两个 INTEGER
的 ASN.1 SEQUENCE”），而 TA 线上是 TR-03111 plain，故卡侧用 `SIG_CIPHER_ECDSA_PLAIN`
直接验 plain（见上表）。「JDK 同时需要 `jdk.crypto.ec`」与「ACR1581 非接触在连续 ECC 下
偶发掉卡（`SCARD_E_NO_SMARTCARD`，同 [`TODO.emrtd.md`](../../../TODO.emrtd.md) T5.3）」
是运维注记，不影响结论。

## 3. 决策

| 编号 | 决策 | 依据 |
|------|------|------|
| **A** | **Terminal Authentication v1**（ICAO Doc 9303-11 §9.2.8 `version MUST be 1`），终结签名算法 **ECDSA-SHA-256**（`id-TA-ECDSA-SHA-256`）；`RSA-PSS-SHA-256`（`id-TA-RSA-PSS-SHA-256`）为已备选 | Doc 9303-11 §7.1.4 Table 7/8；实测两者在 J3R180 均可用；ECDSA 与既有 P-256/CA 栈同族 |
| **B** | TA 必须**跟在 Chip Authentication 之后**（本项目 PACE 是通用映射而非 CAM），授权绑定到 CA 会话的终端临时公钥 | Doc 9303-11 §7.1.2/§7.1.3 |
| **C** | 使用 **EF.CVCA**（LDS1 DF，默认 FID `011C`/SFI `1C`，36 B，≤2 CAR，PACE 读，Doc 9303-11 Annex K.2）；EF.CardAccess 归 MF（同 FID 不同 DF）。卡侧按上下文解析 `011C`：未建立安全报文（PACE 前）为 MF `EF.CardAccess`（明文可读，真实读卡器如 ReadID 在选应用后直接读 `011C` 取 PACE 参数），建立安全报文后为 DF `EF.CVCA`；`SELECT MF` 亦强制取 MF `EF.CardAccess`。信任点（CVCA 公钥/引用/Effective Date/相对授权）由个性化注入，`TerminalAuthenticationInfo` 宣告 version 1（默认 FID，`efCVCA` 省略） | Doc 9303-11 §7.1.4.3.1 + Annex K.2；Doc 9303-10 §3.11.3/§3.11.4 |
| **D** | LDS2 访问 = `PACE`（或 CA）+ **有效授权**：对 IS/DV/CVCA 的 CHAT/扩展逐位 AND，按 Doc 9303-10 §5.4 Table 96/97/98 门控读/写/追加 | Doc 9303-10 §5.4.1/§5.4.2 |
| **E** | **Chip Authentication 仅 `id-CA-ECDH-3DES-CBC-CBC`**（CA v1，CA 后 SM 为 3DES+SHA-1）；`id-CA-ECDH-AES-CBC-CMAC-128` 等 AES 变体**未宣告、未实现**（ICAO 可选）。影响：拒绝 3DES 的终端无法完成 CA；未使用 AES-CMAC CA。 | Doc 9303-11 §9.2.5；延后见 [`TODO.emrtd.md`](../../../TODO.emrtd.md) |

## 4. 协议与 APDU（Doc 9303-11 §7.1.5）

TA 的两动挑战-响应（§7.1.2），全程在已建立的 SM 内，命令序列：

| 步 | 命令 | CLA/INS/P1P2 | 数据 |
|----|------|--------------|------|
| 1 | `MSE:Set DST` | `22 / 81 B6` | DO`83` = 待验/待导入公钥的 ISO 8859-1 引用 |
| 2 | `PSO:Verify Certificate` | `2A / 00 BE` | DO`7F4E`（证书体）+ DO`5F37`（签名） |
| 3 | `MSE:Set AT` | `22 / 81 A4` | DO`83` = 终端公钥引用 |
| 4 | `GET CHALLENGE` | `84 / 00 00`, Le=08 | → `rIC`（8 B） |
| 5 | `EXTERNAL AUTHENTICATE` | `82 / 00 00` | 终端签名 `sIFD` |

- 步 1–2 对**链中每个** CV 证书重复（CVCA Link → DV → Terminal）。
- `sIFD = Sign(SK_IFD, ID_IC ‖ rIC ‖ Comp(PKDH,IFD))`；ECDSA profile
  `Comp(PK) = x 坐标`（32 B，Doc 9303-11 §7.1.4.2.3），RSA profile 为 `SHA-1(DH 值)`
  （§7.1.4.1.3）。
- `ID_IC`：用 BAC 时为 MRZ 证件号；**用 PACE 时为 `Comp(PKDH,IC)`（卡侧 PACE 临时公钥）**。
  因本项目流程是 PACE(GM) → CA，具体取 PACE 还是 CA 的卡侧临时/静态公钥需在 P4 以
  JMRTD 互操作定案（见 §5 开放点）。
- 状态字：`9000` 正常；`6A88`（引用不存在）、`6A80`、`6300`（签名校验失败）、`6982`
  （当前认证级别不允许 TA，如同一会话内重复 TA）见 §7.1.5。
- `sIFD` 线上为 **TR-03111 plain（r‖s）**；平台 `Signature.verify` 要 **DER**，卡侧需转换。

## 5. 卡侧设计要点（`card/emrtd/`）

- **新命令**：`MseSetDst`（复用 `command/Mse.java` 增 `0x81B6` 分支）、
  `PsoVerifyCertificate`（新 `command/Pso.java`，`INS=0x2A` 常量已存在）、
  TA 版 `MseSetAt`（`0x81A4`，与 PACE 的 `MSE_Set AT` 区分）、TA challenge/`ExternalAuthenticate`
  分支（与 BAC 的 `challenge` 字段解耦）。
- **CV 证书解析**（`card/emrtd/ta/CvCertificate.java`）：`7F21 { 7F4E body, 5F37 sig }`，
  body 内 PID/CAR/公钥/CHR/CHAT(tag `7F21`… 实为 `7F4E` 内)/有效期/扩展 `73`；DER 长度必须
  按 BER 解码（吸取 `Lds2Record` SEARCH RECORD 的教训，见 `TODO.emrtd.md`）。
- **验签**（`ta/CvVerifier.java`）：ECDSA 用
  `Signature.getInstance(MessageDigest.ALG_SHA_256, Signature.SIG_CIPHER_ECDSA_PLAIN, Cipher.PAD_NULL, false)`
  **直接校验 TR-03111 plain（r‖s）签名**（无需 DER 转换）；备选 RSA-PSS。签名覆盖
  **带 tag/len 的 body**（TR-03110-3 C.1.8）。证书签名（`5F37`）与终端签名 `sIFD`
  共用同一验签路径。
- **信任点**（`ta/TrustPointStore.java`）：CVCA 引用 + 公钥（永久导入语义），个性化注入；
  临时导入 DV/IS 公钥（掉电失效，§A.7.2.2）。
- **会话绑定**：保存 `PKDH,IFD`（CA 终端临时公钥）与 `PKDH,IC`（PACE 卡侧临时公钥），
  计算 `Comp`；会话内**只允许一次** TA（重复 → `6982`）；TA 失败不破坏 SM（§7.1.3）。
- **授权**（`ta/Authorization.java`）：CHAT（角色 OID `0.4.0.127.0.7.3.1.2` + `id-IS`…）
  与应用扩展（`id-icao-lds2-*-access` = `2.23.136.1.1.9.1.3` / `…9.2.3` / `…9.3.3`，
  Doc 9303-10 Table 99）逐位 AND 求有效授权；`EmrtdApplet.requirePace()` 升级为
  `requireAccess(bits)`，按 Table 96/97/98 门控 LDS2 EF 选择/读/写/追加。
- **个性化 tail**：`FF07/FF09` 的 4 字节授权为
  `[ePassport, Travel, Visa, Bio]`。三个 LDS2 字节**全为 0** 视为 legacy
  ePassport-only 脚本（如 `03 00 00 00`），卡侧默认 `0x0F`；若只有一个 LDS2 应用为 0
  而其他字节非 0，则该应用仍是显式拒绝。这样旧 perso 不会出现“TA 成功但所有 LDS2
  访问 6982”，而合法的单应用拒绝仍可表达。
- **缓冲**：复用包级 `EmrtdScratch`/`SmScratch`，命令路径不 `new` 大数组（真卡余量实测见 §2）。
- **SecurityInfo**：`TerminalAuthenticationInfo`（protocol `id-TA = 0.4.0.127.0.7.2.2.2`，
  **version 1**，默认 EF.CVCA FID 因此 `efCVCA` 省略）；`ChipAuthenticationInfo` version 1。

## 6. 主机侧设计要点（`host/emrtd/`）

- `ta/CvCertificate`、`ta/Chat`、`ta/CvcPrincipal`、`ta/CvCertificateCodec`、
  `ta/CvCertificateBuilder`、`ta/CvChainVerifier`（签名用 JCE `SHA256withECDSA`，
  线上 plain 编码）。
- `ta/TerminalAuth`：读 CardAccess/CardSecurity → 逐证书 `MSE:Set DST` +
  `PSO:Verify Certificate` → `MSE:Set AT` → `GET CHALLENGE` → 组
  `ID_IC‖rIC‖Comp(PKDH,IFD)` → `EXTERNAL AUTHENTICATE`。
- `EmrtdTerminal` 增对应命令；`EmrtdCommand` 的 `read`/`lds2` 增 `-ta` 选项。
- 个性化工件：CVCA/DV/IS 链与终端密钥（离线生成，样例如 `perso/emrtd/`）、信任点注入、
  `TerminalAuthenticationInfo`。

## 7. 开放点（P1–P4 解决）

1. `ID_IC` 在「PACE(GM) → CA」流程下取 PACE 还是 CA 的卡侧公钥——以 JMRTD
   （`tools/jmrtd-hostapi`，仅测试期引用）互操作定案。
2. `Comp` 的口径（ECDSA = x 坐标）与卡侧保留位置。
3. EF.CVCA（LDS1 DF `011C`）与 MF EF.CardAccess（同 `011C`）已按 DF/MF 分离实现；PACE
   数据对象下发 CAR（`0x87`/`0x88`）为 EF.CVCA 之外的补充。

## 8. 分阶段计划（P1–P7）

沿用初评计划（主机 CV 编解码 → 卡侧证书校验/信任点 → 卡侧协议与授权 → LDS2 接线与个性化
→ 测试/互操作 → 文档），每阶段独立提交、可 revert，行为/结构变更同步 `docs/specs/`。
P0 的产出即本文件 + [`../../common/research-notes.md`](../common/research-notes.md)
§15 与 [`../../common/risks.md`](../common/risks.md) 的更新。

## 9. 风险（P0 后更新，见 [`../../common/risks.md`](../common/risks.md)）

| 风险 | 级别 | 状态/缓解 |
|------|------|-----------|
| 卡侧无可用 ECDSA / EC 公钥导入 | 曾高 | **已消除**：J3R180 与 jcsl 实测通过 |
| ICAO Table 7 要求 RSA-**PSS**，Java Card 无 PSS | 曾高 | **已缓解**：J3R180 `ALG_RSA_SHA_256_PKCS1_PSS` 实测通过；主选 ECDSA |
| ECDSA 签名编码（plain vs DER） | 低 | **已消除**：`SIG_CIPHER_ECDSA_PLAIN` 直接验 plain，无需转换 |
| TA 持久/瞬态内存 | 中 | 真卡余量 ≥13 KB 持久、≥2.4 KB 瞬态；TA 足迹 <1 KB，复用共享 scratch |
| `ID_IC`/`Comp` 口径与互操作 | 中 | P4 以 JMRTD 互操作定案（§7） |
| ACR1581 非接触连续 ECC 偶发掉卡 | 低 | 与 T5.3 同类，测试加重试；不影响真卡逻辑 |
