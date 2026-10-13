# eMRTD 算法支持矩阵（ePassport）

> 本文件冻结 **card42-emrtd** 对 ICAO Doc 9303（ePassport / LDS1+LDS2）所定义的访问控制与
> 认证机制的算法支持度，并明确区分**「平台不可能」**（Java Card classic API 或 jcsl/J3R180
> 缺失的能力，排除、不再计划）与**「可实现但未做」**（保留为潜在待办）。机制与协议的完整设计
> 见 [`emrtd.md`](emrtd.md) 与 [`terminal-authentication.md`](terminal-authentication.md)；
> 平台实测依据见 [`../common/research-notes.md`](../common/research-notes.md) §10–§12 与
> [`../common/cryptography.md`](../common/cryptography.md) §1/§4.1；待办的落地顺序见
> [`../../../TODO.emrtd.md`](../../../TODO.emrtd.md)。

## 0. 图例

| 标记 | 含义 |
|------|------|
| ✅ | 已实现并在 jcsl（模拟器）+ J3R180（真卡）上验证 |
| ⚠️ | 部分实现（有明确限制） |
| ○ | 可实现、尚未做（保留为潜在待办） |
| ⛔ | 目标平台不可能（排除，不再计划） |
| ▢ | 范围外（eID/eIDAS 等非护照能力，不计划） |

## 1. 范围：本项目做的是 ePassport，不是 eID

两者共享 CV 证书体系与 EAC 的 PACE/CA/TA 构造，但属于两套 profile，关键差异如下：

| 维度 | **ePassport（ICAO Doc 9303 / MRTD）** | **eID / eIDAS token（BSI TR-03110-2/-4）** |
|------|----------------------------------------|--------------------------------------------|
| 协议集 | BAC / PACE、PA、AA、**CA v1**、**TA v1** | PACE v2、**CA v2**、**TA v2**、Restricted Identification、假名签名、PIN 管理、eSign |
| 应用/数据 | LDS1（DG1–DG16）+ LDS2（Doc 9303-10 Part 10） | eID application（BSI TR-03110-4 App E，含 DG1–DG21 公民数据）、eSign application |
| 访问模型 | 只需 Inspection System 身份；TA 保护 DG3/DG4 与 LDS2 | General Authentication Procedure；区分 inspection / authentication / signature / attribute terminal，按位读/写授权 |
| 协议版本 | PACE（ICAO）、CA v1、TA **v1** | PACE v2、CA v2、TA **v2** |

### 1.1 TA 版本恒为 v1（针对护照应用）

`TerminalAuthenticationInfo ::= SEQUENCE { protocol id-TA, version INTEGER, -- MUST be 1 for
TAv1 or 2 for TAv2, efCVCA FileID OPTIONAL -- MUST NOT be used for version 2 }`

- **TAv1**：ICAO Doc 9303-11 §9.2.8（`version MUST be 1`）、BSI TR-03110-1；JMRTD
  `TerminalAuthenticationInfo.VERSION_NUM = 1`（注释即 “see EAC 1.11 specification”）。
- **TAv2**：BSI TR-03110-2，仅用于 **eID / eIDAS token**；且 `efCVCA` 必须缺省、TA 先于 CA、
  终端签名覆盖 `IDICC‖rICC‖Comp(PK_PCD_CA)‖APCD`，并把授权绑定到 CA v2 会话。
- BSI TR-03110-2 明确：若要求符合 ICAO Doc 9303，则 **MUST** 使用 BAC/PACE 与 **EAC v1
  （CA v1 + TA v1）**；TR-03110-4 的 ePassport 应用写 **TA v1（REQUIRED）**，eIDAS token
  应用才写 **TA v2（REQUIRED）**。

**结论**：本项目是 ICAO LDS1/LDS2 护照实现，**TA 版本恒为 1**。卡侧 `TerminalAuthenticationInfo`
写 version 1、使用 `efCVCA`、CA 先于 TA、签 `ID_IC‖rIC‖Comp(PKDH,IFD)` 均正确；LDS2 的访问控制
同样走 ICAO EAC v1，即 TAv1。**TA v2 不是本项目的缺口，而是 eID/eIDAS 能力**（见 §5 范围外）。

## 2. 逐机制支持矩阵

### 2.1 BAC 与安全报文（SM）

| 机制/组合 | 状态 | 说明 |
|-----------|------|------|
| BAC：`SHA-1(MRZ)` K_seed + 3DES-CBC + ISO 9797-1 Alg3 retail MAC | ✅ | ICAO 9303-11 §4.3 只定义这一套，无变体 |
| SM：3DES（retail MAC，SSC 8 B） | ✅ | `Iso7816Sm`；BAC 与 PACE-3DES 共用 |
| SM：AES-128（AES-CBC + AES-CMAC，SSC 16 B，IV=AES-ECB(K_enc,SSC16)） | ✅ | `Iso7816SmAes`；PACE-AES-128 使用 |
| SM：AES-192/256 | ⛔ | jcsl 无 AES-192/256；卡侧 `AesCmac` 按 16 B 写死（见 §3） |

### 2.2 PACE

| 维度 | 状态 | 说明 |
|------|------|------|
| ECDH 通用映射（GM）+ 3DES-CBC-CBC（`…4.2.1`） | ✅ | EF.CardAccess 宣告并实测 |
| ECDH 通用映射（GM）+ AES-CBC-CMAC-128（`…4.2.2`） | ✅ | EF.CardAccess 宣告并实测 |
| ECDH 通用映射实现（映射/会话） | ✅ | 卡侧 `ALG_EC_PACE_GM`/`ALG_EC_SVDP_DH_PLAIN*`；主机自包含 P-256 |
| 口令 MRZ（`DO'83'=01`）、CAN（`=02`） | ✅ | |
| 标准化域参数 P-256（param id 12） | ✅ | 卡侧 `Pace.mseSetAt` **忽略** `DO'84'`，始终用固定 P-256（§6 备注） |
| KDF：`KDF(x,c)=SHA-1(x‖000000c)` | ✅ | PACE 规范固定 SHA-1，**不存在 SHA-256 KDF 变体** |
| ECDH Chip Authentication Mapping（CAM） | ○ | 复用通用映射原语，属 PACE v2 可选件，未做 |
| DH 通用映射（`…4.1.x`） | ⛔ | 卡侧缺 MODP 模乘原语（见 §3） |
| 集成映射 IM（DH/ECDH，`…4.4`/`…4.5`） | ⛔ | Java Card classic 无 IM/MAP2 原语（见 §3） |
| AES-192/256 PACE（`…4.2.3`/`…4.2.4`） | ⛔ | 同 2.1（jcsl 无 AES-192/256） |
| 非标准化域参数 `PACEDomainParameterInfo` / Brainpool | ○ | 软件可做；J3R180 的 P-256 以外曲线支持**未验证** |

### 2.3 Chip Authentication（CA）

| 组合 | 卡侧 | 主机侧 | 说明 |
|------|------|--------|------|
| ECDH + 3DES（`id-CA-ECDH-3DES-CBC-CBC`，v1） | ✅ | ✅ | 唯一已宣告/实现；P-256 静态密钥，KDF SHA-1，CA 后 SM=3DES |
| ECDH + AES-128（`…3.2.2`） | ○ | ○ | ECDH 与 AES-128 SM 均具备；需 AES-CMAC 形式 KDF 与 keyId 绑定 |
| ECDH/DH + AES-192/256（`…3.2.3`/`…3.2.4`、`…3.1.3`/`…3.1.4`） | ⛔ | ⛔ | jcsl 无 AES-192/256 |
| DH + 3DES（`id-CA-DH-3DES-CBC-CBC`） | ○ | ○ | `KeyAgreement.ALG_DH_PLAIN` 可算 CA 的 `Z = PK^SK mod p`（不需要 PACE-GM 的模乘） |
| 多 CA 密钥 / keyId 选择语义 | ⚠️ | ⚠️ | 卡侧仅存一个 CA 私钥（DGI `FF03`）；主机取 `publicKeyInfos().get(0)` |

### 2.4 Active Authentication（AA）

| 方向/组合 | 状态 | 说明 |
|-----------|------|------|
| 卡侧签发：RSA-2048 + ISO/IEC 9796-2 DS1 + SHA-1 | ✅ | `EmrtdApplet` 固定 `new AaCrypto(2048, AA_SHA1)`；编码用 `Cipher.ALG_RSA_NOPAD` 手工完成 |
| 卡侧签发：RSA ISO 9796-2 + SHA-256（option 2 trailer `0x34CC`） | ○ | `AaCrypto.AA_SHA256` 分支已实现，仅未接线 |
| 卡侧签发：ECDSA-SHA-256（Doc 9303-11 §6.1.2.3） | ○ | 平台探针显示 `getInstance(ALG_SHA_256, SIG_CIPHER_ECDSA_PLAIN, PAD_NULL)` 可用 |
| 主机校验：RSA ISO 9796-2 DS1，SHA-1 / SHA-256 / SHA-384 / SHA-512 | ✅ | `ActiveAuthentication.verifySignature`（trailer 选项 1/2） |
| 主机校验：ECDSA-SHA-256（plain `r‖s` → DER） | ✅ | `verifyEcdsa` |
| EF.CardAccess 宣告 `ActiveAuthenticationInfo` | ○ | 可选（ICAO §9.2.4）；解析器已支持，样例未写 |

### 2.5 Terminal Authentication / CVCA

| 维度 | 状态 | 说明 |
|------|------|------|
| 协议版本 TAv1 | ✅ | ICAO 要求；`MSE:Set DST`/`PSO:Verify Certificate`/`MSE:Set AT`/`EXTERNAL AUTHENTICATE` |
| 签名 ECDSA-SHA-256（`id-TA-ECDSA-SHA-256`） | ✅ | 主选；卡侧 `SIG_CIPHER_ECDSA_PLAIN` 直接验 TR-03111 plain `r‖s` |
| 签名 RSA-PSS-SHA-256（`id-TA-RSA-PSS-SHA-256`） | ✅ | 备选；按证书 `7F49` 公钥 OID 选择；RSA-1024/2048 |
| 其余签名 OID（ECDSA-SHA-1/224/384/512、RSA-PSS-SHA-1/512、RSA v1.5） | ○ | 平台 `Signature` 可用，但 SHA-1 系列已弃用，安全上不建议补 |
| CVCA 信任点（≤2）、CVCA Link Certificate、按 Effective Date 启用 | ✅ | `TaContext` |
| CHAT 角色与授权位（ePassport b1/b2；LDS2 应用扩展 b1..b4） | ✅ | `requireLds1ChatAccess`/`requireLds2Access` |
| EF.CVCA（LDS1 DF `011C`）与 PACE 下发 CAR（`7F4C`→`87`/`88`） | ✅ | |
| TA v2 | ▢ | eID/eIDAS 能力，非护照（见 §5） |

### 2.6 Passive Authentication（PA）

| 组合 | 状态 | 说明 |
|------|------|------|
| 摘要 SHA-1 / SHA-256 / SHA-384 / SHA-512 | ✅ | `AlgorithmIds.digest` |
| 签名 RSA v1.5（SHA-1/256/384/512）、ECDSA（SHA-256/384） | ✅ | `AlgorithmIds.signature` |
| RSASSA-PSS OID（`1.2.840.113549.1.1.10`）、SHA-224 等映射 | ○ | 纯主机 JDK 可补 |
| 证书链/策略/有效期/吊销检查 | ⚠️ | 仅校验 DSC 由 CSCA 签名（`DscVerifier`）；生产需补策略/有效期/吊销 |
| LDS2 的语义（附加生物识别加密，Doc 9303-11 §7.2） | ○ | 见 §4「EAC 残余」 |

## 3. 平台不可能项（⛔ 的依据）

| 项 | 平台缺失 |
|----|----------|
| **PACE DH 通用映射** | 卡侧通用映射要算 `G' = G^s · H`（MODP 群上的模乘 + 映射）。Java Card classic 只暴露 `KeyAgreement.ALG_DH_PLAIN`（算 `y^x mod p`），**没有公开大整数/模乘原语**，也没有 `ALG_DH_PACE_GM`。卡侧无法实现；主机侧虽可用 `BigInteger` 实现，但无卡可测。 |
| **PACE 集成映射 IM（DH/ECDH）** | classic API 只有 `ALG_EC_PACE_GM`（通用映射），无 IM 所需的 MAP2 原语，且不暴露裸 EC 点运算。卡侧无法实现。 |
| **AES-192/256（PACE / CA / SM 的一切用途）** | jcsl 明确 `LENGTH_AES_256`/`ALG_AES_BLOCK_256_*` 抛 `NO_SUCH_ALGORITHM`；卡侧 `AesCmac` 亦按 16 B 密钥写死。CI 门禁在 jcsl 上**无法验证**（J3R180 是否有 AES-256 未做探针实测）。 |

> 平台缺失但**已用替代路径绕开、不构成功能缺口**：`Signature.ALG_AES_CMAC_128`（改用
> `Cipher.ALG_AES_BLOCK_128_CBC_NOPAD` 批量链式）、`ALG_DES_MAC*_ISO9797_1_M2_ALG3`（jcsl 缺，
> 改用 `ALG_DES_MAC8_ISO9797_M2`/`NOPAD` 或手工构造）、`ALG_RSA_SHA_ISO9796_MR`（J3R180 缺，
> 项目本就用 `ALG_RSA_NOPAD` 手工做 ISO 9796-2 编码）。详见
> [`../common/cryptography.md`](../common/cryptography.md) §1/§4.1。

## 4. 可实现但未做项（○ 的清单）

按优先级（性价比）排序：

1. **附加生物识别加密（Doc 9303-11 §7.2，即仓库旧称 “EAC 1.11” 的残余）**——唯一的 EAC 真实缺口，
   用现有 ECDH/CA 密钥派生加密密钥即可，平台能力足够。
2. **CA ECDH + AES-128**——ECDH 与 AES-128 SM 均已具备，需补 AES-CMAC 形式的 `KDF(Z,c)` 与
   `MSE:Set KAT` 的 keyId→静态密钥绑定。
3. **AA 卡侧接线**：SHA-256（`AaCrypto.AA_SHA256` 已存在）与 ECDSA-SHA-256（平台已验证），
   并在 EF.CardAccess 增加 `ActiveAuthenticationInfo`。
4. **PA 映射补全**（纯主机 JDK）：RSASSA-PSS OID、SHA-224 等；生产环境另需证书策略/有效期/吊销检查。
5. **PACE ECDH-CAM**；**DH 版 CA**（`ALG_DH_PLAIN` 够用）；**多 CA 密钥 / keyId 选择语义**。
6. **TA 其它签名变体**（ECDSA/RSA-PSS 的 SHA-384/512、RSA v1.5）——安全上仅在非 SHA-1 时考虑。
7. **非标准域参数 / Brainpool**（软件可做，需先对 J3R180 做曲线支持探针）。

## 5. 范围外（▢）

- **eID / eIDAS token**：TA v2、CA v2（General Authentication Procedure）、Restricted
  Identification、假名签名、eSign、PIN 管理、eID 应用数据组（BSI TR-03110-4 App E）。
- 国别 profile 的额外扩展、生物 CVM、LDS2 之外的附加应用；生产证书体系（真实 CSCA/DSC、
  有效期/策略/吊销）见 [`../common/risks.md`](../common/risks.md)。

## 6. 备注与已知小项

- 卡侧 `Pace.mseSetAt` 只校验 `DO'80'`（PACE OID）与 `DO'83'`（口令引用），**不校验 `DO'84'`
  （域参数 id）**，且始终使用固定 P-256。即“仅支持标准化 P-256”在卡侧是**忽略而非校验**；
  建议后续补校验或明确记录（与“非标准化域参数”一项相关）。
- 安全报文对**未建立 SM 时的明文 APDU**当前临时放行以排障（`EmrtdApplet.processCommand`
  的实验注释）；这不改变逐命令的访问控制，但正式发布前应恢复“收到明文即 `6982`”的严格行为。

## 7. 维护约定

- 本文件随**算法/协议行为变更**同步更新；新增或改变组合时，须注明状态标记（✅/⚠️/○/⛔/▢）与依据。
- 涉及 ⛔ 的项如需重启，必须先以一次性探针 applet（见
  [`../common/research-notes.md`](../common/research-notes.md) §10）在 jcsl 与 J3R180 上实测能力，
  再把结论写回本文件与 [`../../../TODO.emrtd.md`](../../../TODO.emrtd.md)。
