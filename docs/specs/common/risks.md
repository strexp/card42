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
| 静态字段 / `CLEAR_ON_DESELECT` 跨实例共享（同 context） | 中 | 每实例的**持久**状态一律用实例字段（role/media/lifecycle/生命周期标志、PIN/风控/日志、会话长度与标志），SELECT 时显式重置；唯一的卡级静态状态 `cardBlocked` 为刻意设计。**瞬态 scratch 则刻意用包级 static 共享**（`EmvScratch`/`EmrtdScratch`/`SmScratch`）：同一时刻只有一个实例在处理命令，共享一份即够，且顺带把「每实例惰性分配」从根上消除（见下行） |
| `getProtocol()` 在模拟器/真卡行为差异 | 低 | 角色/CVM/PIN 决策不依赖；实例可选性（`isSelectableOnCurrentMedia()`）依赖 |
| `getSecureChannel()` 需 SD 关联，可能返回 null | 中 | 判空；仅作交叉校验，不作决策 |
| 瞬态预算（同 context 多实例）不足 | 中 | **已改为包级共享、安装期分配一次**：`card42.emv` 的 `EmvScratch`（response 256、work 288、chain 255、pdol 64、firstCdol 128、cdaHeader/cdaUn 52、SM 密钥/ICV/derived 56、sessionKey/acScratch/lastAc 36、SessionKey 16、CVR 5、m1Length 2、volatileState/arqc/challenge 26 = **1184 B**）与 `card42.emrtd` 的 `EmrtdScratch`（io 320 + response 256 = 576）+ `SmScratch`（800）= **1376 B**，同 context 多实例只占一份；命令路径没有任何 `makeTransient*`。每个分配都走共享的 `card42.common.TransientBuffers.makeByteArray/makeShortArray`（`RetailMac`/`AesCmac` 的小块同）：优先 `CLEAR_ON_DESELECT` 瞬态，**瞬态预算耗尽时回退到持久数组而非 `6F00`**（真卡实测直接 `makeTransient` 会在安装第 4 个 eMRTD 实例时抛 `SystemException` → `6F00`；回退后安装/命令继续，代价是相应 EEPROM 写）。真卡余量实测仍待做（TODO §A3），届时可据实测把回退关掉或调小 |
| 持久内存不足（记录/证书） | 中 | `RecordStore` 变长共享池（1024 B），`JCSystem.getAvailableMemory` 监控 |
| 不必要的 EEPROM 写入（编程周期磨损；Java Card 不保证同值写免编程周期，故同值守卫有效） | 中 | 纯 JVM **双层计数基线**（`make test-unit` 的 `== nvm ==` 段）：`NvmWrite` 统计 `Util.*` 写入（含同值写），`NvmProbe` 统计持久对象图的逐 APDU 差分（只计变化值），**并列报告、不相加**。三条基线 `emrtd-bac-session-read5` ≈**498 B**、`emv-gpo-two-ac` 139 B、`emrtd-aa-inside-sm` ≈**555 B**，按字段给出 top writers（现热点：`AaCrypto.block/nonce/hash`（AA 路径）、`Iso7816Sm`/`SmScratch` 会话缓存、`RetailMac.loadedKey`、`AbstractSecureMessaging.macBuffer`；`EmrtdApplet.smOut/response/plain` 已转瞬态，故退出榜单）。已知盲区：同值字段写、未链接的 `EMVCrypto`/`CvrBuilder`/`Pace`；无 PACE 场景（需模拟器侧补，`TODO.emrtd.md`）；AaCrypto/随机数致 ±1 B 噪声，故暂不设硬阈值（阈值测试列在 `TODO.emv.md` B2）。**P1 无风险纯冗余已合**（GPO 按 `(内容, role)` 缓存 + `invalidateCache()` 统一失效、目录默认记录守卫、死字段 `bacDone`、标量同值守卫、引用赋值内移、`directView` 复用、日志比较写）。**P2 大额削减已合**：`EmrtdApplet.plain/response/smOut`（合计 ~1 KB/次会话）改为包级瞬态 `EmrtdScratch`（io 320 + response 256），BAC 读五组 DG 的基线由 4330 B 降至 498 B；`LdsCatalog` 的 COM 构造 scratch 由运行期局部数组改构造期字段；`DdaCrypto` 重灌密钥后显式 `JCSystem.requestObjectDeletion()`。后续削减项（DOL 游标 / 会话缓冲 / 会话密钥 / 会话字段 / 选择状态转瞬态）见 `TODO.emv.md` B2 与 `TODO.emrtd.md` 的"会话数据转瞬态" |
| eMRTD 持久内存（perso 缓冲 + LDS 文件）在真卡受限 | 中 | 个性化改为**逐 DGI 流式落盘**：`DgiStream` 只缓存 ≤5 B 的 DGI 头，值字节直达目标，原来的 4096 B `persoBuffer` 已删除；LDS1/LDS2 透明 EF 改为 **256 B 分页**（按需分配、跨写复用，不复制增长、不需连续大数组），构造容量仅为上限（DG2 16384 / SOD 2048 / EF.CardAccess 256 / EF.CardSecurity 1792），未写或很小的 EF 几乎不占空间。仍按实例预留：记录池（Travel 3×1024 B、Visa/生物各 ≤2×1024 B）、`LdsPerso` 键 scratch（≤520 B）与 `ChipAuth` P-256 私钥；`LdsCatalog` 按需生成 COM。**LDS1-only 分配已按角色门控**：LDS2（Travel/Visa/Biometrics）实例不再创建 `LdsCatalog`（含 19 个 `LdsFile` + 数组）、`LdsPerso`（seed+520 B scratch）、`BacCrypto` 与 2048-bit `AaCrypto`（合计每例约 1.5–1.8 KB），只保留 `Pace`/`ChipAuth`/SM 与 LDS2 文件系统——这是第 4 个 eMRTD 实例安装失败（`6F00`）的修复。**注意**：Java Card 不自动回收已删对象，反复失败的 INSTALL 会泄漏持久堆；改动后应在真卡上先 `make card-uninstall` 再 `make card-install`（或换新卡）。J3R180（JCOP4-180K，~180 KB 用户 NVM、RAM 仅数 KB）上 16 KB DG2 预算与 EMV 共存已在模拟器验证（`make test`） |
| eMRTD 瞬态 / 持久缓冲 | 中 | `EmrtdApplet` 的明文/响应缓冲改为包级共享 `EmrtdScratch`：`io` 320 B（兼作解包后的命令数据与 SM 封装响应，AA 256 B 签名的 ~290 B 封装可容）＋ `response` 256 B；原来的三块实例持久数组（`plain`/`response` 各 256 B、静态 `smOut` 512 B）已删除，BAC 读五组 DG 的 EEPROM 写基线由 4330 B 降至 498 B。SM 包装器的 scratch 改为包级共享 `SmScratch`（800 B：加密区 512+272=784 的实测上界，原 1 KB）。`EmrtdScratch`/`SmScratch` 均 `CLEAR_ON_DESELECT` 优先、预算不足回退持久（避免安装期 `6F00`）。会话密钥只在变化时 `setKey`（`Iso7816Sm`/`Iso7816SmAes`/`RetailMac`/`AesCmac` 各缓存 16 B，`reset()`/`zeroize()` 清零）。Chip Authentication/PACE 复用同一 SM scratch 与 `ksEnc/ksMac/ssc`；eMRTD（1376 B）与 EMV（1184 B）共享瞬态共 2560 B |
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
| AA 的 256 B RSA 签名无法装入 SM 短 APDU | 低 | AA 在明文下执行（DG15 为公钥，可无 BAC 读取），已在 `EmrtdBacTest` 固化 |
