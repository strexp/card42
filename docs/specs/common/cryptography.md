# 密码学规范

## 1. 可用 Java Card API

`javap api_classic-3.0.5.jar` 实测可用：

- `Signature.ALG_DES_MAC8_ISO9797_M2`、`ALG_AES_CMAC_128`、`ALG_HMAC_SHA_256`
- `Signature.ALG_RSA_SHA_ISO9796`、`javacard.security.Signature.ALG_RSA_SHA_ISO9796_MR`（消息恢复，
  Book 2 Annex A2.1；该常量定义在 `javacard.security.Signature`，`SignatureMessageRecovery`
  接口不含常量）、`ALG_RSA_SHA_PKCS1`、`ALG_RSA_SHA_256_PKCS1`
- `KeyBuilder.TYPE_DES`/`TYPE_AES`、`TYPE_RSA_PUBLIC`/`TYPE_RSA_PRIVATE`/`TYPE_RSA_CRT_PRIVATE`、
  `LENGTH_RSA_1024`/`LENGTH_RSA_2048`
- `KeyPair.ALG_RSA`/`ALG_RSA_CRT`、`Cipher.ALG_RSA_PKCS1`/`ALG_RSA_NOPAD`
- `MessageDigest.ALG_SHA`/`ALG_SHA_256`、`RandomData`
- `javacard.framework.OwnerPIN`、`JCSystem.beginTransaction/commit/abortTransaction`、
  `JCSystem.getAvailableMemory`

> jcsl **不实现** `Signature.ALG_DES_MAC*_ISO9797_1_M2_ALG3`（构造抛
> `CryptoException.NO_SUCH_ALGORITHM`），见 §4。
>
> jcsl 亦**不实现 AES-192/256**（`LENGTH_AES_256` / `ALG_AES_BLOCK_256_*` 抛
> `NO_SUCH_ALGORITHM`），故卡侧 CV '6' 仅 AES-128。
>
> 以上是 **API jar 的可用性**，不等于每张真卡都实现。实测 NXP J3R180（GP 2.3 / JavaCard v3）
> **不实现 `Signature.ALG_RSA_SHA_ISO9796_MR`**：标准 n/d（`TYPE_RSA_PRIVATE`）与 CRT
> （`TYPE_RSA_CRT_PRIVATE`）两种 DDA/CDA 私钥都在 `Signature.getInstance` 处失败
> （`DdaCrypto.setPrivateKey` 映射为 `6A80`），而 `KeyBuilder.TYPE_RSA_PRIVATE` +
> `Cipher.ALG_RSA_NOPAD`（加密 PIN）正常。故该卡无法个性化 DDA/CDA，只能 SDA + ICC PIN
> 密钥对（支持加密脱机 PIN `P2=88`；`perso/emv/sample-j3r180.perso` 的 CVM List 为明文
> `01 00`，真卡实测接触交易 CVM Results `01 00 02`；见
> [personalization.md](../emv/personalization.md) §6 的 `@sda records pin`）。

## 2. 会话密钥派生（`card/emv/crypto/SessionKey.java`）

`SK_AC`/`SK_MAC`/`SK_ENC` 共用同一派生函数，分别作用于独立的 AC / SM-MAC / SM-ENC 主密钥
（EMV v4.4 Book 2 §A1.3.1 公共形式）。

**3DES（CV '5'，n=8）**：

```
SK = DES3(MK)[R0 ‖ R1 ‖ F0 ‖ R3..R7] ‖ DES3(MK)[R0 ‖ R1 ‖ 0F ‖ R3..R7]
```

- AC/ARPC 用 `R = ATC ‖ 00×6`；`R2=00` 时即熟知的 `ATC ‖ F0 ‖ 00×5` 形式。
- **SM 会话密钥（`SK_MAC`/`SK_ENC`）用 `R = 第一次 GENERATE AC 的 8 B AC`**（v4.4 §A1.3.1），
  因此 SM 只能在首 AC 之后建立（`SecureMessaging.prepare` 接收首 AC）。
- 注：v4.4 §A1.3.1「Common Session Key Derivation Option」无树形派生（无 `b`/`H`/`IV`/`Φ`）。

**AES（CV '6'，n=16，仅 AES-128）**：

```
SK = AES(MK)[R]        R 为 16 B
```

- AC/ARPC 用 `R = ATC ‖ 00×14`；SM 用 `R = 首 AC(8) ‖ 00×8`（v4.4 §A1.3.1）。
- AES-192/256 的 `AES(MK)[F1] ‖ AES(MK)[F2]` 形式未实现（jcsl 无 AES-256）。

主密钥派生（Annex A1.4，主机侧，`host/emv/crypto/EmvKeys.java`）：全部三种方法均已实现——

- **Option A**（§A1.4.1，3DES）：`PAN‖PSN` 取最右 16 位十进制数字为 `Y`（8 B BCD），
  `MK = odd-parity(DES3(IMK)[Y] ‖ DES3(IMK)[Y⊕FF×8])`。
- **Option B**（§A1.4.2，3DES，CV '5' 强制，CCD §8.3/§9.4）：PAN ≤16 位时退化为 Option A；
  否则 `SHA-1(BCD(PAN‖PSN))` 取前 16 位十进制数字（不足时按 `A–F → 0–5` 十进制化），再走
  Option A 第 2 步。`desMasterKey` 即 Option B。
- **Option C**（§A1.4.3，AES，CV '6'）：AES-128 `MK=AES(IMK)[Y]`；AES-256
  `MK=AES(IMK)[Y] ‖ AES(IMK)[Y*]`，`Y* = Y ⊕ FF×16`，`Y` 为 `PAN‖PSN` 的 BCD 左补零 16 B。

`EmvKeys.iccMasterKeys(imkAc, imkMac, imkEnc, pan, psn, aes)` 一次派生 **AC / MAC / ENC**
三套 ICC 主密钥；`perso/emv/sample.perso` 用 `@key <slot> derive <imk> <pan> <psn> [3des|aes]`
在个性化时派生并注入（见 [personalization.md](../emv/personalization.md) §1）。Option A/B 由
`EmvKeysTest` 用 EFTlab / pyEMV 外部向量校验，避免卡机同错。

## 3. 应用密文（AC，`card/emv/crypto/EMVCrypto.java`）

- 输入：`CDOL 数据 ‖ AIP ‖ ATC ‖ IAD`（IAD 与响应 `9F10` 同源，32 B CCD Format 'A'）。
- 算法由 `CryptoProfile` 的 Cryptogram Version 决定（DGI `E003`，默认 CV '5'）：
  - **CV '5'**：ISO/IEC 9797-1 Algorithm 3（s=8），经 `RetailMac` 的流式 `start/update/doFinal`；
  - **CV '6'**：ISO/IEC 9797-1 Algorithm 5 / CMAC（s=8），经 `AesCmac` 流式接口。
  两者经 `MacAlgorithm` 抽象统一调用，消息跨多个缓冲区无需大瞬态数组。
- 密文类型 TC/ARQC/AAC 由 Card Action Analysis 与终端请求层级决定（见
  [transaction.md](../emv/transaction.md) §4）。

## 4. Retail MAC（`card/common/crypto/RetailMac.java`）

ISO/IEC 9797-1 Algorithm 3（ARPC Method 2、SM MAC）。CBC 段优先用平台 MAC 引擎：
`Signature.ALG_DES_MAC8_ISO9797_M2`（M2 填充消息）与 `ALG_DES_MAC8_NOPAD`（已对齐消息），
再补两步 `Cipher.ALG_DES_ECB_NOPAD` 的终变换 `DES_dec(K2)`/`DES_enc(K1)`；`Signature` 只
在首次 MAC 时探测（`ensureNative()`），平台报 `NO_SUCH_ALGORITHM`（如 jcsl 不支持这些或
`ALG_DES_MAC*_ISO9797_1_M2_ALG3`）即回退到用 `Cipher.ALG_DES_ECB_NOPAD` 手工逐块的等价构造。
两条路径源码同一份：真卡一次调用完成整段 CBC-MAC，模拟器走手工循环。会话密钥只在变化时
`setKey` 一次（`zeroize()` 清缓存）。主机侧 `AcCrypto.macAlg3` 用同一构造并以经典向量校验。
参考真机 ePassport applet（`tools/passportapplet` 的 `JCOP41PassportCrypto`）用完全相同的
「`ALG_DES_MAC8_ISO9797_M2` + 两次单 DES ECB」构造。

### 4.1. AES-CMAC（`card/common/crypto/AesCmac.java`）

ISO/IEC 9797-1 Algorithm 5（CMAC），CV '6' 的 AC、ARPC Method 2 与 SM MAC 均用它
（EMV v4.4 Book 2 §A1.2.2、§8.1.2、§9.2.3）。以 `Cipher.ALG_AES_BLOCK_128_ECB_NOPAD` 手工实现：
子密钥 `L=AES(KS)[0^16]`、`K1=L<<1`（`msb(L)=1` 时异或 `00..87`）、`K2=K1<<1`；末块按是否补
`80..` 异或 K1/K2；CBC 后取前 s 字节（AC/ARPC s=8/4）。流式 `start/update/doFinal` 缓冲末块，
SM 的已对齐消息不补块。瞬态缓冲在首次使用时分配（jcsl 的 AES `doFinal` 不接受输入输出
别名，故链值与异或结果分用两块）；子密钥 `L`/`K1`/`K2` 只在会话密钥变化时重算（缓存 16 B
会话密钥，`zeroize()` 清缓存）。主机侧 `host/common/crypto/AesCmac.java`
以 JCE 实现，并以 RFC 4493 / NIST SP 800-38B 向量校验。

## 5. ARPC 校验（`card/emv/crypto/Arpc.java`）

复用第一次 AC 的 `SK_AC`，**不重派生**；比对用常量时间（见 §8）。

- **Method 2**（CCD，Book 2 §8.2.2）：`ARPC = Alg3-MAC(SK_AC)[ARQC ‖ CSU ‖ proprietary]`，
  取 4 B；`91 = ARPC(4) ‖ CSU(4) ‖ proprietary`。**CSU byte1 b8「Proprietary Authentication
  Data Included」决定 proprietary 是否参与 ARPC**：为 0 时 proprietary 长度按 0 计算，尾随
  字节不受保护、不得驱动卡动作（v4.4 §8.2.2 注）。
- **Method 1**（通用，Book 2 §8.2.1）：8 B（单分组加密，不是 MAC）。CV '5' 为
  `ARPC = DES3_ECB(SK_AC)[ARQC ⊕ (ARC‖00×6)]`；CV '6' 为 `AES_ECB(SK_AC)[Y‖Y0]` 的最左 8 B，
  其中 `Y = ARQC ⊕ (ARC‖00×6)`、`Y0 = 00×8`（v4.4 §8.2.1 AES 形式）。

`INS=82`（通用 EXTERNAL AUTHENTICATE）**先按 Method 2、再按 Method 1** 校验：Method 2 无需 ARC，
标准 8 B `ARPC(4)‖CSU(4)` 直接命中并应用 CSU；Method 1 从 `Lc ≥ 10` 起生效，ARC 由项目约定置于
proprietary 前 2 B（标准数据域不含 ARC）。CCD 内联 `91` 走 Method 2。

## 6. DDA / CDA（`card/emv/crypto/DdaCrypto.java`、`RsaKey.java`）

- ICC DDA/CDA 私钥由 CPS DGI `8103`（模数）/`8101`（指数）注入，拼装为 `86 n 87 d` 容器，
  由 `RsaKey.parse` 构建为 `RSAPrivateKey`（非 CRT）。`RsaKey.parse` 同时支持 `81`–`85` 的 CRT
  容器（当前个性化脚本不产生该形式）。
- `INTERNAL AUTHENTICATE`（`INS=0x88`，P1=P2=`00`）：按 Book 2 Table 15 组装
  `05 01 LDD ‖ ICC Dynamic Data ‖ BB… ‖ DDOL`，用 `ALG_RSA_SHA_ISO9796_MR` 签名；CCD 口径
  返回 Format 2 `77 { 9F4B }`（Book 3 CCD §6.5.9.4 / Table CCD 5），通用口径返回 Format 1
  `80` SDAD。DDA/CDA 的 ISO 9796-2 消息缓冲按实际模长动态分配（支持 Table 43 的 ≤247 B），
  CDA 响应受 256 B 服务缓冲约束（`nic ≤ 205`，超限回 `6985`）。密钥缺失/长度不符 → `6985`；
  错误 P1/P2 → `6A81`。
- `GENERATE AC` 的 `P1` b5-b4=`10`（CDA）：按 Book 2 Table 18 组装（CID/AC/SHA-1 Transaction
  Data Hash Code 与终端 UN），以 Format 2 `77 {9F27, 9F36, 9F4B, 9F10}` 返回（CCD 口径的
  `9F10` 为 **M**（32 B），Book 2 CCD Table CCD 1；本项目随响应一并返回）；AAC 不含签名。
  b5-b4=`01`（XDA，未实现）→ `6A81`；b5-b4=`11`（RFU）按 Book 3 §6.3.6「不得校验 RFU」处理，
  视为「不请求 CDA/XDA 签名」。第一/第二 AC 的哈希输入含
  `PDOL 数据 ‖ CDOL 数据 ‖ 9F27‖CID‖9F36‖ATC‖9F10‖IAD`（顺序敏感）。
- ICC 公钥证书 `9F46`/`9F47`/`9F48` 随支付记录（记录 5）下发。ICC DDA/CDA 与 ICC PIN
  证书的 Certificate Format 均为 `04`（Book 2 Tables 14/23）；DDA/CDA 证书哈希含
  「Static Data to be Authenticated」（Book 2 §6.4 step 5），PIN 证书哈希不含（Table 23 注 31）。
- `RsaKey.parse` 校验 Book 2 Table 43 的模长上限（ICC DDA/CDA 与 PIN ≤247 B）：`86 n 87 d` 路径
  限 `n`；CRT 路径限素因子 ≤124 B 且 `p+q` ≤247 B（`n = p·q` 至多 `pLen+qLen` 字节）。该 CRT
  判定是**保守近似**：例如 `125 + 122 = 247` B 的合法模数（两个素因子乘积恰为 247 B）会因
  单个素因子超过 124 B 而被拒；在卡上精确计算 `n` 需要大整数乘法，而个性化脚本不产生 CRT
  容器，故保留保守界限（`RsaKey.java`）。超限回 `6A80`；支持 `86 n 87 d` 与 `81`–`85` CRT 容器。
- **模长上限（Book 2 Table 43）**：CA ≤248 B；issuer ≤247 B（SDA-only 可 248 B）；ICC DDA/CDA
  与 ICC PIN encipherment ≤247 B。卡侧证书字段随之下限：`90`（CA 签名，NCA）与 `93`（SSAD，NI）
  ≤248 B，`9F46`/`9F2D`（issuer 签名，NI）≤247 B，超限个性化回 `6A80`（`SdaCertificateData`）；单条记录
  含 tag/length ≤254 B（Book 3 §7），超限 `setRecord` 回 `6A80`（`EMVStaticData`）。主机
  `Sda.java` 生成后同样校验这些界限（`checkModulus`/`checkRecord`）。
- SDA：`8F`/`90`/`92`/`9F32`/`93` 证书链与 SSAD（记录 2/3），离线工具 `host/emv/oda/Sda.java` 用
  RSA-1024 + ISO 9796-2 生成测试链。

## 7. 离线 PIN

- **明文**（`VERIFY P2=80`）：定长 8 B 块 `C N P P P P P/F×8 F F`（16 nibble）：
  格式字节 `C=0010`（高半字节 `2`）、`N=4..12`（低半字节 `0x4`–`0xC`），其后为 BCD 数字与
  `0xF` 填充，末字节恒 `0xFF`（Book 3 §6.5.12.2 Table 25）。`Lc≠8` → `6700`；
  `N<4`/`C≠2`、奇数 N 的补齐半字节或填充字节非 `0xF` → `6A80`。
- **加密**（`VERIFY P2=88`，`card/emv/crypto/PinCrypto.java`）：ICC PIN 私钥由 CPS DGI `8104`
  （模数）/`8102`（指数）拼装为 `86 n 87 d` 容器构建。终端先 `GET CHALLENGE` 取 8 B ICC
  Unpredictable Number，按 Book 2 Table 25 组 `7F ‖ PIN block(8) ‖ ICC UN(8) ‖ 随机填充`
  为模长整块，并用 **RSA Recovery Function（B2.1.3，纯 `X^e mod n`）** 加密；卡用
  **RSA Signing Function（B2.1.2，`Cipher.ALG_RSA_NOPAD`）** 还原整块，依次校验头 `7F`、
  ICC UN（与本次 `GET CHALLENGE` 一致）与 PIN block 后才交 `OwnerPIN.check`。
  密钥缺失 `6985`、无/不匹配的 ICC UN 或还原失败 `6984`、PIN block 格式错 `6A80`、
  PIN 错误 `63Cx`、锁定 `6983`；成功置 `ENCRYPTED_PIN`（Book 2 §7.2，Book 3 §10.5.1）。
  卡保存最近一次 `GET CHALLENGE` 的 8 B ICC UN 供 P2=88 绑定，并按 Book 3 §6.5.6.1 实现
  「仅对下一条命令有效」：challenge 在 VERIFY（无论成败）或任一其它命令后即失效。
- PIN 统一 BCD（4–12 位，`0xF` 补齐），`OwnerPIN maxSize=8`，按 `Lc` 动态比对。
- 非接触角色一律 `6985`。

## 8. 安全报文（`card/emv/crypto/SecureMessaging.java`）

Format 1（CLA 低半字节 `C`），数据对象 `81`（明文）/`87`（密文）/`8E`（MAC）。MAC/ENC
会话密钥用**第一次 GENERATE AC 的 AC** 派生（§2），故 `prepare()` 以首 AC 为输入。

- MAC 输入按 Book 2 Annex D2.3.1：`ICV ‖ 命令头(补 80 00…) ‖ 数据对象(各自补 80 00…)`，
  按块长（3DES 8 / AES 16）对齐；已对齐消息不再补块。
- **CV '5'** 用 `RetailMac`（Alg 3）、`DES_CBC_NOPAD`、8 B ICV；**CV '6'** 用 `AesCmac`（Alg 5）、
  `AES_BLOCK_128_CBC_NOPAD`、16 B ICV（首 AC 右补 8 个 `00`，Book 2 §9.2.3.1）。MAC 取前 s
  （4–8）B 传输，链值用完整块长。
- `87` 加密按 Annex A1.1/D2.2：padding indicator `01` 时**总是**补一个完整块
  （3DES 8 B → 16 B 密文；AES 16 B → 32 B 密文），解密后剥离 ISO 7816-4 填充。
- MAC 链见 [transaction.md](../emv/transaction.md) §7。
- **瞬态**：MAC/ENC 会话密钥字节、ICV 与派生缓冲在首次 `prepare()`/`unwrap()`（applet 已选中）
  时分配；`SessionKey` 与 AC 路径（`EMVCrypto`）共享，MAC 对象亦共享；加密 PIN 恢复块、DDA/CDA
  消息与 ARPC 消息三块互斥大缓冲合并为 `EMVProtocolState.getWorkScratch()` 的单次分配
  （默认 256 B，按需增长）（见 [risks.md](risks.md)）。

## 9. 加固

- **会话密钥清零**：`PaymentApplet.onDeselect` 依次调用 `EMVCrypto.zeroizeSessionKeys()` 与
  `SecureMessaging.zeroizeSessionKeys()`，把所有**会话派生**的 Key 对象与字节缓冲清零
  （`clearKey()`/`Util.arrayFillNonAtomic`）；`RetailMac`/`AesCmac` 为省 `setKey` 而缓存的
  会话密钥字节随 `zeroize()` 一并复位，eMRTD 侧由 `Iso7816Sm.reset()`/`Iso7816SmAes.reset()`
  在应用重选时清零；`verifyEncryptedPin` 另在 `finally` 清零还原出的
  Table 25 整块，`Arpc` 清零 ARPC 工作缓冲，`SecureMessaging` MAC 失败时立即清零 MAC/ENC
  会话密钥**字节数组**与 ICV。ICC 主密钥与 SM 主密钥由个性化注入、须跨会话保留，不清。
  审计分类（`card/emv/crypto/`）：

  | Key 对象 | 位置 | 分类 | 会话结束清零 |
  |----------|------|------|-------------|
  | `mkDes` / `mkAes` | `EMVCrypto` | ICC 主密钥（个性化） | 否（保留） |
  | `skDes` / `skAes` | `EMVCrypto` | AC 会话密钥（主密钥 + ATC） | 是（`clearKey()`） |
  | `macMasterKey` / `macMasterAes` | `SecureMessaging` | SM MAC 主密钥（个性化） | 否（保留） |
  | `encMasterKey` / `encMasterAes` | `SecureMessaging` | SM ENC 主密钥（个性化） | 否（保留） |
  | `encSessionKey` / `encSessionAes` | `SecureMessaging` | SM ENC 会话密钥（主密钥 + 首 AC） | 是（`clearKey()`） |
  | `cbcKey` / `finalKey` | `RetailMac` | MAC 子密钥（会话密钥派生） | 是（`zeroize()`） |
  | `key128` | `AesCmac` | AES MAC 密钥（会话密钥） | 是（`zeroize()`） |
  | `pinKey` | `PinCrypto` | ICC PIN 私钥（个性化） | 否（保留） |
  | `ddaKey` | `DdaCrypto` | ICC DDA/CDA 私钥（个性化） | 否（保留） |

- **中间值清零**：`AesCmac` 的子密钥 `L`/`K1`/`K2` 与 `key128`、`RetailMac` 的
  `cbcKey`/`finalKey` 均为持久（EEPROM）字段，但在会话结束时由 `EMVCrypto.zeroizeSessionKeys`
  清零（`AesCmac.zeroize`/`RetailMac.zeroize`），交易间不驻留密钥材料
  （Book 2 §A1.2.2 注：all intermediate values must be kept secret）。
- **常量时间比对**（`card/common/crypto/ConstantTime.java`）：所有**秘密**比对统一走无短路 XOR 累加
  （`Util.arrayCompare` 不保证常量时间）：`Arpc.verifyMethod1/2`、`SecureMessaging.unwrap`
  （SM MAC）、`OfflinePin.challengeEquals`（ICC UN）；PIN 比对由 `OwnerPIN.check`（原子）承担。
  仅有的两处非秘密 `Util.arrayCompare` 已就地注释：`InstallParameters` 的实例 AID 比较、
  `SecureMessaging.prepare` 的 `derivedAc`（本会话 AC）比较。
- **事务纪律**：不得在 applet `beginTransaction` 内调用 `pin.check()`（回滚会恢复 PTC）；
  日志与累加器写入为小事务且不触碰 PIN。
- **异常映射**：`PersoHandler.applyAll` 区分 `ISOException` 透传、`CryptoException` → `6985`、
  其它 → `6F00`。
