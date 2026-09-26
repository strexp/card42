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
| 静态字段 / `CLEAR_ON_DESELECT` 跨实例共享（同 context） | 中 | 每实例状态一律用实例字段，SELECT 时显式重置；唯一的卡级静态状态 `cardBlocked` 为刻意设计 |
| `getProtocol()` 在模拟器/真卡行为差异 | 低 | 角色/CVM/PIN 决策不依赖；实例可选性（`isSelectableOnCurrentMedia()`）依赖 |
| `getSecureChannel()` 需 SD 关联，可能返回 null | 中 | 判空；仅作交叉校验，不作决策 |
| 瞬态预算（同 context 多实例）不足 | 中 | `firstCdol` 按实际 CDOL1 长度分配、`pdolData` 按实际 PDOL 数据长度懒分配（`MAX_PDOL_DATA`=64，无 PDOL 实例不占）、SM 密钥/ICV 缓冲按需分配、`SessionKey` 与 MAC 对象共享、`cdaAc` 并入 `lastAc`、加密 PIN 恢复/DDA 消息/ARPC 三块互斥大缓冲合并为 `EMVProtocolState.getWorkScratch()`（单次分配 256 B，按需增长）；`response` 256 B 可容纳。J3R180 多实例（含测试实例）仍有耗尽路径，余量实测待做（TODO §A3/§B1） |
| 持久内存不足（记录/证书） | 中 | `RecordStore` 变长共享池（1024 B），`JCSystem.getAvailableMemory` 监控 |
| eMRTD 持久内存（perso 缓冲 + LDS 文件）在真卡受限 | 中 | 个性化改为**逐 DGI 流式落盘**：`DgiStream` 只缓存 ≤5 B 的 DGI 头，值字节直达目标，原来的 4096 B `persoBuffer` 已删除；LDS1/LDS2 透明 EF 改为 **256 B 分页**（按需分配、跨写复用，不复制增长、不需连续大数组），构造容量仅为上限（DG2 16384 / SOD 2048 / EF.CardAccess 256 / EF.CardSecurity 1792），未写或很小的 EF 几乎不占空间。仍按实例预留：记录池（Travel 3×1024 B、Visa/生物各 ≤2×1024 B）、`LdsPerso` 键 scratch（≤520 B）与 `ChipAuth` P-256 私钥；`LdsCatalog` 按需生成 COM。J3R180（JCOP4-180K，~180 KB 用户 NVM、RAM 仅数 KB）上 16 KB DG2 预算与 EMV 共存已验证（`make test`） |
| eMRTD 瞬态 / 持久缓冲 | 中 | `EmrtdApplet.plain`/`response` 各 256 B（实例持久）与静态 `smOut` 512 B（AA 256 B 签名封装）；SM 包装器的 1 KB scratch 改为包级共享的 `SmScratch`：优先 `CLEAR_ON_DESELECT` 瞬态、无余量时回退持久数组，整个 package 一份（仅选中时首次分配），故每个实例省 ~1 KB 持久内存且不再随实例数倍增瞬态需求；会话密钥只在变化时 `setKey`（`Iso7816Sm`/`Iso7816SmAes`/`RetailMac`/`AesCmac` 各缓存 16 B，`reset()`/`zeroize()` 清零）。Chip Authentication/PACE 复用同一 SM scratch 与 `ksEnc/ksMac/ssc`；与 EMV 实例同 context 时按部署矩阵（仅 emrtd / 仅 emv / 共存）控制占用 |
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
