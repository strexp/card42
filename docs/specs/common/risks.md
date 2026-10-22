# 风险与缓解

按类别组织。只列仍然有效的风险；已解决项不再保留。级别：高/中/低。

## 1. 工具链与部署

| 风险 | 级别 | 缓解 |
|------|------|------|
| GPPro-NG（模拟器传输）为上游实验特性 | 中 | 仅模拟器使用 `--ng --simulator`；真卡一律 classic PC/SC（不加 `--ng`）；锁定并记录 GPPro 版本（见 toolchain.md §4） |
| SCP02（3DES）在模拟器不可用 | 低 | 模拟器 SD 只宣告 SCP03；保留 GP SCP03 为主，保证真卡 SCP02 SD 路径可用（CPS v2.0 同时支持） |
| 大块 STORE DATA（>231 B） | 中 | 离线侧自行按 231 B 分块；单个 DGI 值建议 ≤200 B |
| 记录 DGI >200 B 需跨块拆分 | 中 | 记录 DGI 自动跨 231 B 块分块 |
| GP 导出目录名含空格破坏 converter | 低 | 当前目录无空格；若变化再拷贝到无空格路径 |

## 2. 平台与内存

| 风险 | 级别 | 缓解 |
|------|------|------|
| 模拟器不模拟非接触媒体 | 高 | 角色化实例 + `TEST_CONTACTLESS=1`；角色/CVM/PIN 行为不依赖 `getProtocol()`，但实例可选性依赖 |
| 静态字段 / `CLEAR_ON_DESELECT` 跨实例共享（同 context） | 中 | 每实例的**持久**状态一律用实例字段（role/media/lifecycle/生命周期标志、PIN/风控/日志、会话长度与标志），SELECT 时显式重置；唯一的卡级静态状态 `cardBlocked` 为刻意设计。**瞬态 scratch 则刻意用包级 static 共享**（`EmvScratch`/`EmrtdScratch`/`SmScratch`）：同一时刻只有一个实例在处理命令，共享一份即够，且顺带把「每实例惰性分配」从根上消除（见下行）。**（2026-10-12）持久工作缓冲也按包共享**：只服务于单个流程的每实例持久数组收为包级 static——`PersoHandler` 的 2048 B DGI 重组缓冲、`PaymentPerso` 的 1554 B RSA 密钥 scratch（dda/pin 的 modulus+exponent 各 256 + `keyContainer` 530）、`EMVStaticData` 的 128 B FCI 组装 scratch、`DirectoryApplet` 的 2×64 B scratch、`Pace` 的 ~435 B 工作 scratch（`nonceScalar`/`peer`/`ephPicc`/`mapped`/`scratch`/`tokenInput`/`tokenMac`）与 `ChipAuth` 的 64 B ECDH 输出；每多一个实例分别省该量。它们只在个性化期间或命令内短命存在，故共享安全；跨实例**交错**个性化由 `PersoHandler.owner`/`PaymentPerso.scratchOwner` 守卫（换实例即判定该片段不属于当前序列 → `6A81`）。**例外**：`EMVStaticData` 的 FCI/GPO（192+64 B）保留每实例——它们是整块交出、可能被按整缓冲扫描的响应缓冲，共享会暴露另一实例的陈旧尾部字节（纯 JVM 单测即因此失败）。**（2026-10-12 TA）** eMRTD 的 Terminal Authentication 状态（`card/emrtd/ta/TaContext`：最多两个
CVCA 信任点槽 + 导入公钥/引用/授权/当前日期，约 1 KB）与算法引擎（P-256 `ECPublicKey`/
`SIG_CIPHER_ECDSA_PLAIN` 及 RSA-1024/2048 `RSAPublicKey`/`ALG_RSA_SHA_256_PKCS1_PSS`）同样为
**包级 static 共享**：一张卡只有一组 CVCA 信任点与当前日期，且同一时刻只选一个实例；密钥/`Signature`
在首次使用（信任点个性化 DGI `FF07`）时建一次，命令路径不分配 |
| `getProtocol()` 在模拟器/真卡行为差异 | 低 | 角色/CVM/PIN 决策不依赖；实例可选性（`isSelectableOnCurrentMedia()`）依赖 |
| `getSecureChannel()` 需 SD 关联，可能返回 null | 中 | 判空；仅作交叉校验，不作决策 |
| 瞬态预算（同 context 多实例）不足 | 中 | **已改为包级共享、安装期分配一次**：`card42.emv` 的 `EmvScratch`（response 256、work 288、chain 255、pdol 64、firstCdol 128、cdaHeader/cdaUn 52、SM 密钥/ICV/derived 56、sessionKey/acScratch/lastAc 36、SessionKey 16、CVR 5、m1Length 2、volatileState/arqc/challenge 26、staticScratch 128 = **1312 B**）与 `card42.emrtd` 的 `EmrtdScratch`（io 320 + response 256 + 会话密钥/计数器 112 + BAC scratch 96 = 784）+ `SmScratch`（**352**：加密区与 MAC 输入区合并复用同一偏移——密文直接写入调用方输出缓冲，两区不再并存，见下行 + MAC 输出/两 K_enc 缓存/AES SSC/IV/le 82 = 434）= **1218 B**（`raw` 320 已改持久，见下行），同 context 多实例只占一份；命令路径没有任何 `makeTransient*`。每个分配都走共享的 `card42.common.TransientBuffers.makeByteArray/makeShortArray`（`RetailMac`/`AesCmac` 的小块同）：优先 `CLEAR_ON_DESELECT` 瞬态，**瞬态预算耗尽时回退到持久数组而非 `6F00`**（真卡实测直接 `makeTransient` 会在安装第 4 个 eMRTD 实例时抛 `SystemException` → `6F00`；回退后安装/命令继续，代价是相应 EEPROM 写）。**真卡余量已实测（TODO §A3）**：瞬态按 **context** 计——EMV context 余量 ~2176 B，eMRTD context 预算 ~2056 B；`SmScratch` 由 800 收到 352 后，eMRTD 热路径约 1218 B + 包级共享 `MacEngines`（`RetailMac`/`AesCmac` 小块 40 B，原每实例 3×RetailMac+2×AesCmac 的 ~88 B）≈ 1258 B，加 `AesCmac` 的 256 B CBC 批量暂存（一次性 `mac`/`macAligned` 的输出缓冲，每 context 一份）≈ **1514 B，余量仍约 540 B**（A3 时仅 ~32 B），此前关闭的 A4/A6 空间已重新打开。**（2026-10-13 算法变体）** 引入 RSA-1024 Terminal Authentication 后，`EmrtdScratch.io` 320→**512**（RSA `PSO:Verify Certificate` 明文可达 ~417 B）、`EmrtdScratch.raw` 320→**512**（持久）、`SmScratch` 352→**512**（对应 SM 信封 ~450 B）；eMRTD context 热路径约 **1570 B**（加 `AesCmac` 256 B ≈ 1826 B，余量 ~230 B），J3R180 安装与全部套件仍通过。**EMV 引擎归并（Plan A / P0.3，2026-10-11）**：`EMVCrypto` 原每实例 `new RetailMac()+new AesCmac()`（`AesCmac` 每实例含 256 B CBC 暂存瞬态），现收为包级共享 `EmvEngines`（并共享 `RandomData` 与 CDA 用 SHA-1）；生产 2 / 测试最多 5 个支付实例只占一份，消除多实例下 `cbcOut` 瞬态耗尽回退持久后每次 CMAC 256 B 的 EEPROM 写。eMRTD 的 `Sha1Kdf`（BAC/PACE/CA 原各一份）与 `RandomData`（`EmrtdApplet`+`AaCrypto`）收为包级 `KdfEngines`。共享对象一律放在各自 applet package（而非 `card42.common`），以留在本 context、保持 `CLEAR_ON_DESELECT` 与瞬态预算记账 |
| 持久内存不足（记录/证书） | 中 | `RecordStore` 变长共享池（1024 B），`JCSystem.getAvailableMemory` 监控 |
| 不必要的 EEPROM 写入（编程周期磨损；Java Card 不保证同值写免编程周期，故同值守卫有效） | 中 | 纯 JVM **双层计数基线**（`make test-unit` 的 `== nvm ==` 段）：`NvmWrite` 统计 `Util.*` 写入（含同值写），`NvmProbe` 统计持久对象图的逐 APDU 差分（只计变化值），**并列报告、不相加**。三条基线 `emrtd-bac-session-read5` ≈**167 B**、`emv-gpo-two-ac` 139 B、`emrtd-aa-inside-sm` ≈**525 B**，按字段给出 top writers（现热点：`AaCrypto.block/nonce/hash`（AA 路径）、`RetailMac.loadedKey`/`AesCmac` 缓存——均为 eMRTD 每实例持久，因 eMRTD context 无瞬态余量而保留；会话密钥/BAC scratch/SM 缓存已转包级瞬态，退出榜单）。已知盲区：同值字段写、未链接的 `EMVCrypto`/`CvrBuilder`/`Pace`；无 PACE 场景（需模拟器侧补，`TODO.emrtd.md`）；AaCrypto/随机数致 ±1 B 噪声，故暂不设硬阈值（阈值测试列在 `TODO.emv.md` B2）。**P1 无风险纯冗余已合**（GPO 按 `(内容, role)` 缓存 + `invalidateCache()` 统一失效、目录默认记录守卫、死字段 `bacDone`、标量同值守卫、引用赋值内移、`directView` 复用、日志比较写）。**P2 大额削减已合**：`EmrtdApplet.plain/response/smOut`（合计 ~1 KB/次会话）改为包级瞬态 `EmrtdScratch`（io 320 + response 256），BAC 读五组 DG 的基线由 4330 B 降至 498 B；`LdsCatalog` 的 COM 构造 scratch 由运行期局部数组改构造期字段；`DdaCrypto` 重灌密钥后显式 `JCSystem.requestObjectDeletion()`。**eMRTD 会话 scratch 收口（Plan A，2026-10-11）**：`AaCrypto`/`Pace`/`ChipAuth` scratch 保持持久（A4 关闭，见上行）；把 eMRTD 的 `raw`(320) 改持久、腾出的空间换成包级瞬态的会话密钥/BAC scratch/`SmScratch` 助手（288 B），BAC 读五组 DG 基线再降至 **96 B**；并把 `AbstractSecureMessaging.le` 与 `LdsFileSystem` 的当前 EF 选择移入瞬态，使 READ BINARY 热路径**零 EEPROM 写**（仅会话首个 SM 命令装载会话密钥）。后续削减项（EMV DOL 游标）见 `TODO.emv.md` B2。**MAC 引擎归并 / scratch 合并（2026-10-11）**：`SmScratch` 800→352（`wrap` 的密文直写调用方输出缓冲，加密区与 MAC 输入区不再并存），eMRTD context 余量 ~32→~800 B；`RetailMac`/`AesCmac` 收为包级共享 `MacEngines`（每 LDS1 实例省 ~200 B 持久 + ~48 B 瞬态）；`AesCmac.zeroize`/`RetailMac.zeroize` 在未装载密钥时**跳过清零**（同值写守卫）。BAC 基线的 state 差分由 96 升至 167 B 属**会话边界清零**：包级共享引擎下，SELECT 会清零上一次会话（含其它实例/其它测试场景）用过的 `AesCmac` 子密钥（64 B），非逐命令开销；3DES-only 部署无此写。`Util` 批量写由 199 降至 135 B |
| eMRTD 持久内存（perso 缓冲 + LDS 文件）在真卡受限 | 中 | 个性化改为**逐 DGI 流式落盘**：`DgiStream` 只缓存 ≤5 B 的 DGI 头，值字节直达目标，原来的 4096 B `persoBuffer` 已删除；LDS1/LDS2 透明 EF 改为 **256 B 分页**（按需分配、跨写复用，不复制增长、不需连续大数组），构造容量不再是按文件写死的上限：透明 EF 在个性化时按 DGI 声明长度一次性增长、上限为协议上限 `EmrtdTags.MAX_EF_BYTES`（32767），未写或很小的 EF 几乎不占空间。仍按实例预留：记录池（Travel：Certificates 1024 B + Entry/Exit 各 2048 B；Visa：Certificates 1024 B + VisaRecords 2048 B；Biometrics：Certificates 1024 B；相较原 1 KB 池每包 +3 KB 持久占用）、`LdsPerso` 键 scratch（≤520 B）与 `ChipAuth` P-256 私钥；`LdsCatalog` 按需生成 COM。**LDS1-only 分配已按角色门控**：LDS2（Travel/Visa/Biometrics）实例不再创建 `LdsCatalog`（含 19 个 `LdsFile` + 数组）、`LdsPerso`（seed+520 B scratch）、`BacCrypto` 与 2048-bit `AaCrypto`（合计每例约 1.5–1.8 KB），只保留 `Pace`/`ChipAuth`/SM 与 LDS2 文件系统——这是第 4 个 eMRTD 实例安装失败（`6F00`）的修复。**注意**：Java Card 不自动回收已删对象，反复失败的 INSTALL 会泄漏持久堆；改动后应在真卡上先 `make card-uninstall` 再 `make card-both-install`（或换新卡）。J3R180（JCOP4-180K，~180 KB 用户 NVM、RAM 仅数 KB）上 16 KB DG2 预算与 EMV 共存已在模拟器验证（`make test-both-sim`） |
| eMRTD 瞬态 / 持久缓冲 | 中 | `EmrtdApplet` 的明文/响应缓冲改为包级共享 `EmrtdScratch`：`io` 320 B（兼作解包后的命令数据与 SM 封装响应，AA 256 B 签名的 ~290 B 封装可容）＋ `response` 256 B；原来的三块实例持久数组（`plain`/`response` 各 256 B、静态 `smOut` 512 B）已删除，BAC 读五组 DG 的 EEPROM 写基线由 4330 B 降至 96 B（见 §2 的 Plan A）。SM 包装器的 scratch 改为包级共享 `SmScratch`（**352 B**：加密区与 MAC 输入区改为复用同一偏移——密文直接写入调用方输出缓冲，两区不再并存；原 800 B）。`EmrtdScratch`/`SmScratch` 均 `CLEAR_ON_DESELECT` 优先、预算不足回退持久（避免安装期 `6F00`）。`RetailMac`/`AesCmac` 由包级 `MacEngines` 共享（原每 LDS1 实例 3×`RetailMac`+2×`AesCmac`）。会话密钥只在变化时 `setKey`（`Iso7816Sm`/`Iso7816SmAes`/`RetailMac`/`AesCmac` 各缓存 16 B，`reset()`/`zeroize()` 清零，且未装载时不再重复清零）。Chip Authentication/PACE 复用同一 SM scratch 与 `ksEnc/ksMac/ssc`；`EmrtdScratch.raw` 320 B 现**固定为持久**（真卡实测 eMRTD context 瞬态紧张，把这块罕见的扩展命令缓冲让给热路径会话 scratch；见 §2）；eMRTD 热路径 **1218 B** 与 EMV（1312 B）的包级瞬态合计 **2530 B**（按 context 分配），另有 `AesCmac` 每个实例 256 B CBC 暂存（`MacEngines` 共享），eMRTD 余额约 540 B。**（2026-10-11）** `Sha1Kdf`/`RandomData` 收为包级 `KdfEngines`：原每 LDS1 实例 3×`Sha1Kdf`（各带一个 `MessageDigest`）与 2×`RandomData`，现每 package 一份；EMV 侧引擎共享见上行 `EmvEngines`。**（2026-10-22 扩展 Le READ RECORD）** LDS2 记录可到 900 B（EF.Certificates，Doc 9303-10 Table 83），而短 APDU 的 SM 窗口仅 231/223 B；新增 `EmrtdScratch.record`/`recordEnvelope` 各 1 KB **持久**缓冲（仅 LDS2 角色经 `initRecord()` 分配，LDS1 不付），由 `SecureMessaging.wrapLarge()` 以 `record` 兼作加密/MAC scratch，以扩展 Le 响应一次返回。不增大瞬态热路径（否则 eMRTD context 约 230 B 余量会被挤爆、热路径 scratch 回退 EEPROM）；代价是大记录读的 EEPROM 写与每包 2 KB 持久占用。Card 侧 allocation census 因此由 255 提到 **257**（本注记即对应理由，见 `AllocationCensusTest`）。 |
| jcsl/真卡 ECC 与 `KeyAgreement` 支持 | 中 | J3R180 实测支持完整 ECC（`ALG_EC_PACE_GM`、`ALG_EC_SVDP_DH_PLAIN_XY`、P-256 `KeyPair`）；PACE 卡侧/主机侧据此实现并已互操作。Chip Authentication 与 PACE 共用该门控，真卡部署前仍建议复测 CA |
| J3R180 不实现 `Signature.ALG_RSA_SHA_ISO9796_MR` | 中 | 该卡无法个性化 DDA/CDA，只能 SDA + ICC PIN 密钥对；真卡脚本用 `@sda records pin` 并去掉 AIP 的 DDA/CDA 位（见 toolchain.md §5）。DDA/CDA 仍由模拟器与支持该算法的卡覆盖 |

## 3. 规范与安全

| 风险 | 级别 | 缓解 |
|------|------|------|
| PA 信任根/证书策略简化 | 中 | `CscaKeyStore` 只信任显式给定 CSCA，`DscVerifier` 仅校验签发签名；生产需补有效期/策略/吊销。示例沿用 openssl 夹具 |
| ICAO 规范版本漂移（LDS2/PACE） | 中 | 以 Doc 9303 当前版为准；新增/调整在独立提交推进，回归失败即 revert |

## 4. 测试与流程

| 风险 | 级别 | 缓解 |
|------|------|------|
| `processData` 期间 applet 未被选中，`CLEAR_ON_DESELECT` 不可用 | 中 | 个性化路径用实例字段（不用 `selectingApplet()`）；流式状态（DGI 头、scratch）也是实例/持久字段，不依赖瞬态 |
| 逐块写入大 EF 依赖 SD 的 `processData` 事务粒度 | 中 | 每条 STORE DATA 只应用 ≤231 B（至多一个新 256 B 页），峰值日志与照片大小无关；模拟器/GPPro 实测 9943 B 序列通过。若换用整段持事务的 SD 管理端，需复测事务缓冲（`BUFFER_FULL`，真卡 T5.2） |
| 跨 APDU 事务不可用 | 中 | 原子性由应用负责（GP `Personalization.processData`）；applet 依赖 SD 的事务语义、不自行 `beginTransaction`（嵌套会 `BUFFER_FULL`），并以 `P2=0`/失败路径复位完成标志，避免「不完整却判成功」 |
| 个性化事务内构建加密引擎 | 中 | **不得在 SD 的 `processData` 事务内 `buildKey`/`getInstance`**：J3R180 实测在 TA 信任点 DGI `FF07` 处理中构建 `ECPublicKey` + ECDSA `Signature`（`SIG_CIPHER_ECDSA_PLAIN`）**会 `6F00`**（随后 `ecSig` 为空、验签失败表现为 `6A80`）。改为**安装期**构建（`EmrtdApplet` 构造器调用 `TaContext.ensureKeys()`），个性化只写密钥字节；`ChipAuth`/`AaCrypto` 等既有对象亦在构造器/首次使用构建，不受影响（2026-10-12） |
| AA 的 256 B RSA 签名无法装入 SM 短 APDU | 低 | AA 在明文下执行（DG15 为公钥，可无 BAC 读取），已在 `EmrtdBacTest` 固化 |
