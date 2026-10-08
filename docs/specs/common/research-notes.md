# 调研结论与关键事实

本文件汇总 Card42 立项阶段的平台实测结论，作为设计与工具链决策的依据。
参考标准与工具链版本的获取方式见 [`../../../tools/README.md`](../../../tools/README.md)。

## 1. 双界面机制

Java Card 3.0.5 classic API 提供 `APDU.getProtocol()` 与 `PROTOCOL_MEDIA_*` 常量
（`DEFAULT`=接触，`CONTACTLESS_TYPE_A/B/F`）。

**限制**：Oracle socket 模拟器（jcsl）报告 `PROTOCOL_MEDIA_DEFAULT`，无法在模拟器验证非接触
媒体。**方案**：用「角色化实例」——同一个 `PaymentApplet` 类安装两个实例，靠实例 AID 固定
CONTACT / CONTACTLESS 角色；CVM/PIN 策略由角色决定。`getProtocol()` 不参与角色/CVM/PIN 决策，
但参与**实例可选性**门控（`isSelectableOnCurrentMedia()` 据 `protocolState.getMedia()` 决定
PPSE/非接触实例在接触接口是否 `6A82`）。

## 2. PSE / PPSE 与 RID 约束

- 一个 CAP 可含多个 applet（classic conf 多条 `-applet`）。
- CAP **applet AID 的 RID 必须与 package RID 相同**（JCDK：`Applet RIDs must be equal to
  their package RID.`），但 **INSTALL 时选择的实例 AID 不受限**。
- `1PAY.SYS.DDF01`（RID `315041592E`）与 `2PAY.SYS.DDF01`（RID `325041592E`）都与 card42 RID
  `4341524442` 不同，仍可作为 `card42.emv` package 的实例安装并 SELECT（jcsl 实测）→
  **实例 AID 与 package RID 可分离**；据此 EMV（`card42.emv`，两个 applet）与 eMRTD
  （`card42.emrtd`）各为一个 CAP，公共层抽为库 CAP `card42common`。
- 同一机制允许 ICAO LDS1/LDS2 DF name（`A0000002471001` 等）作为 `card42.emrtd` 的实例 AID。

## 3. 安装 / 部署

主机侧部署/个性化统一到 GPPro，模拟器与真卡共用同一命令集，区别仅在传输与安全通道：

- 模拟器走 nextgen `--ng --simulator`（`apdu4j` JCSDK socket 直连 jcsl），安全域仅 SCP03。
- 真卡走 classic PC/SC，SCP02/SCP03 自动协商。

GPPro 命令：`--load <cap>` 后逐实例 `--create <instance> --applet <class> --package <pkg>`；
`--personalize` 发 `INSTALL [for personalization]`，`--store-data` 分块并管理 `P1`/`P2`。
`--create` 不从 applet AID 推断 package（NG 与 classic 均如此），必须显式传 `--package`。

INSTALL 参数按 JCRE 11.2.1 编码：`(L,V) instance AID ‖ (L,V) control info ‖ (L,V) applet data`。

## 4. package 与源码目录

Java Card package 与 `classdir` 必须匹配（如 `build/card/emv/bin/card42/emv/*.class`），但
**源码目录可自由拆分**：`javac` 显式传入文件列表时不要求目录名等于 package 名。因此三个
package（`card42.common` / `card42.emv` / `card42.emrtd`）的源码分别放在
`card/{common,emv,emrtd}/` 下按功能分组（EMV：`applet`/`command`/`constants`/`data`/`state`/
`risk`/`crypto`/`perso`/`tlv`；eMRTD：`applet`/`command`/`lds`/`access`/`crypto`/`tlv`），
Makefile 用 `find <dir> -name '*.java'` 收集。库 CAP `card42common`（无 `-applet`）先于业务
CAP 构建，业务 CAP 的 converter `-exportpath` 追加 common 导出根，`Import.cap` 记录 common 的
package AID（`43 41 52 44 42 00`）。

## 5. 个性化：STORE DATA + DGI/BER-TLV

- `STORE DATA`：`CLA=0x80`，`INS=0xE2`。
- `P1`：`bit8=1`=最后一块；`b1=1`=允许 applet 回传数据；`b7/b6`=逐 DGI 加密指示（K_DEK，
  卡内未实现）；`b5–b2` RFU（EMV CPS v2.0 §4.3.4.2 / Table 4-9）。
- `P2`=块序号；SD 校验块序，不匹配 `6A86`。
- **SD 不重组**：把每个 STORE DATA 命令原样逐块转发给 `processData`，applet 自行按 `P1/P2`
  重组。因此离线侧自行按 231 B 切块。
- 载荷为 DGI 容器序列；编号遵循 EMV CPS v2.0 Annex A（`9102`/`9104`/`3000`/`3001`/`8000`
  等），Card42 专有数据用项目 DGI（`E002`–`E003`，位于 CPS 保留段之外）；见
  [../emv/personalization.md](../emv/personalization.md)。

详细流程与约束见 [../emv/personalization.md](../emv/personalization.md)。

## 6. GP API 工具链与集成

**工具位置**：`tools/GlobalPlatform_Card_API-org.globalplatform-v1.7.1/`（目录名无空格，含
`1.5/`、`1.6/`、`1.7/`）。本项目固定用 **1.6**（与 jcsl 卡内 GP 包版本一致）：

- `1.6/gpapi-globalplatform.jar`（编译期 API）
- `1.6/exports23/org/globalplatform/javacard/globalplatform.exp`（converter 导出文件）

构建三件事：`javac -cp api_classic-3.0.5.jar:…/1.6/gpapi-globalplatform.jar --release 8`；
converter conf 加 `-exportpath …/1.6/exports23`。产物 CAP 的 `Import.cap` 引用 GP 包
（`a0 00 00 01 51 00`），**直接 LOAD/INSTALL，无需打补丁**（用更高版本的 export 时 LOAD 会因
包版本不匹配失败，故固定 1.6）。

两种 on-card 集成模型：

- **`Personalization` 接口（本项目采用）**：applet 实现
  `short processData(byte[] inBuf, short inOff, short inLen, byte[] outBuf, short outOff)`；
  SD 负责 SCP 解密后转发数据，applet 无需自己操作 `SecureChannel`。
- **`SecureChannel`（仅作交叉校验）**：`GPSystem.getSecureChannel()` → `unwrap`/`decryptData`/
  `processSecurity`；接口**没有 `verifyMAC`**（验 MAC 用 `unwrap`），且可能返回 null，必须判空。

## 7. 个性化端到端流程

GP 个性化 = **INSTALL [for personalization] + STORE DATA**：

1. 离线侧 SELECT ISD（`A000000151000000`）并打开安全通道（模拟器 SCP03；真卡 SCP02/03）。
2. 发 `INSTALL [for personalization]`：`80 E6 20 00`，数据域 `LV(实例AID) ‖ 00 00 00`。
3. 发分块 `STORE DATA`，SD 解密/验 MAC/校验 `P2` 后逐块转发。
4. SD 调用目标 applet 的 `Personalization.processData(...)`。
5. applet 自行解析 DGI；未知 DGI 回 `6A88`（CPS §5.4.2.3）；`outBuf` 回数据。

GPPro `--personalize` 自动发 INSTALL [for personalization]，`--store-data` 负责分块并管理
`P1`/`P2`，主机侧不自拼块。

## 8. 传输尺寸与 APDU

- 当前使用**短 APDU**（GPPro 走短 APDU）；扩展 APDU 见 [TODO §E6](../../../TODO.emv.md)。
- SCP 开销 24 B → 单块数据域 ≤ 231 B；单 DGI 值建议 ≤ 200 B；大对象（FCI/GPO/记录）控制在
  200 B 内，更大则拆成多个 DGI。

## 9. 可用密码学 API

见 [cryptography.md](cryptography.md) §1。

## 10. 平台实测结论（jcsl）

以下结论由一组临时探针（实现 `Personalization` 并回显的 applet，由客户端/多块/个性化探针
驱动）在 jcsl 上实测得出；探针已移除，结论保留于此：

| # | 问题 | 结论 |
|---|------|------|
| 1 | 实例 AID 可否用与 package 不同的 RID | **可行**（PPSE 与 `43415244420101` 均可 SELECT）→ 拓扑 A |
| 2 | SD 整段转发还是逐块转发 | **逐块转发**，applet 自行按 `P1/P2` 重组 |
| 3 | `processData` 的 `inBuf` | **整个 STORE DATA 命令**（`84 E2 …`），`inOff` 指向 `CLA` |
| 4 | `P1`/`P2` 语义 | `bit8` 最后一块；`b1` 允许回传（否则非 0 长度 → `6A86`）；`P2` 块序，不匹配 `6A86` |
| 5 | `outBuf` 回传 | applet 返回长度 → SD 以 `9000` + 数据返回 |
| 6 | 目标 applet 未实现 `Personalization` | `6985` |
| 7 | 未发 INSTALL [for personalization] | `6A88` |
| 8 | INSTALL [for personalization] 格式 | `80 E6 20 00 0C 00 00 06 <实例AID> 00 00 00` → `9000` |
| 9 | `GPSystem.getSecureChannel()` | 非 null，`getSecurityLevel()`=`0x81`（SCP03 会话内） |
| 10 | 静态字段跨实例 | **共享**（同 package 同 context）；`CLEAR_ON_DESELECT` transient 在整个 context 取消选择时才清空 → 双实例状态必须用实例字段 |
| 11 | on-card GP 包版本 | **1.6**（`A00000015100`） |

## 11. 模拟器能力（jcsl 自报 + 实测）

```
Oracle Java Card Simulator (v26.0) - Java Card v3.2 - GP Card v2.3 - Secure Channel Protocol '03'
```

- 原生实现 `org.globalplatform.*`、GP Security Domain、SCP03、DGI STORE DATA、
  `Personalization` 转发、CVM/全局 PIN、GP 权限/注册表。
- **SCP02 无法协商**：SD 在 SELECT FCI 中只宣告 SCP03（OID `1.2.840.114283.4.3`），
  `INITIALIZE UPDATE` 只接受 `P2=00` 并返回 `i=0x03`，其它 `P2` 回 `6A86`。
- `jcsl` 是 32-bit i386 程序，用自带 32-bit `libcrypto.so.3`；单 DES 在 legacy provider 中，
  `sim-start` 设 `OPENSSL_MODULES=$(JC_HOME_SIMULATOR)/runtime/bin` 消除启动告警
  （仅解决单 DES 原语，不等于 SCP02 可用）。
- jcsl 不实现 `ALG_DES_MAC*_ISO9797_1_M2_ALG3`（见 [cryptography.md](cryptography.md) §4）；
  `RetailMac` 因此探测 `ALG_DES_MAC8_ISO9797_M2` / `ALG_DES_MAC8_NOPAD` 并自动回退，两条路径
  在单测里同时以经典向量校验。
- jcsl 的 AES 仅支持 128-bit（`LENGTH_AES_256` / `ALG_AES_BLOCK_256_*` 抛
  `NO_SUCH_ALGORITHM`），且 AES `doFinal` 不接受输入输出别名；RFC 4493 向量、平台
  `Signature.ALG_AES_CMAC_128` 与手工 CMAC（ECB + K1/K2）均已实测一致。
- jcsl applet 实例上限 7 个；瞬态预算按 package context 共享，实例越多越紧。卡侧已把
  瞬态 scratch 改为**包级共享、安装期一次性分配**（`EmvScratch`/`EmrtdScratch`/`SmScratch`，
  全部 `CLEAR_ON_DESELECT`），命令路径不再 `makeTransient*`，同 context 多实例只占一份
  （见 [risks.md](risks.md) §2）。

## 12. C-8（Kernel 8）能力与 Java Card 3.0.5 / J3R180 的差距

EMV Contactless Book C-8 v1.2（`tools/specs-contactless-c8-1.2/`）以 **ECC + Book E
安全通道**为核心：Transaction Flow 里 GPO 携带临时 ECC 公钥、卡用私钥与 blinding factor
生成共享密钥（ECDH），记录用 AES-CTR 加密，并校验 EDA-MAC / IAD-MAC（AES-CMAC+）。
这些能力在本项目约束下**不可用**：

- **Java Card 3.0.5 classic API 提供部分 ECC 原语但无 BDH/EC-SDSA**：
  `api_classic-3.0.5.jar` 实测提供 `KeyPair.ALG_EC_FP`/`ALG_EC_F2M`、
  `Signature.ALG_ECDSA_SHA`（及 SHA-224/256/384/512）、`KeyBuilder.TYPE_EC_FP_PUBLIC/PRIVATE`
  （API 存在性已核实，运行期未验证）；但 Book E 所需的 **BDH（EC Diffie-Hellman 共享密钥）**
  与 Book C-8 的 EC-SDSA 签名方案不在 classic API 中。
- **J3R180 默认 ECC 不可用于 C-8**（融合位/个人化限制），且无法自行切换。
- jcsl（本项目使用的 3.0.5 模拟器）亦不承载 C-8 的 ECC/Book E 路径。

因此终端内核实际以 **EMV v4.4 Book 3/4 通用终端流程**实现（Entry Point → GPO →
READ RECORD → ODA → 风险管理 → GENERATE AC → 在线），**C-8 仅作概念参照**（不含其 ECC/Book E
安全通道、加密记录、卡选 CVM、IAD-MAC/EDA-MAC 或 §6 状态机）；密码学一律走 **RSA profile**
（SDA/DDA/CDA，EMV Book 2 §5/§6.5/§6.6），并在 `docs/specs/emv/contactless.md` §1 明确
ECC/XDA、Book E、RRP、DE/DS 为范围外。XDA/ODE 相关 TVR 位（ECC key recovery failed、CA ECC
key missing 等）不在 RSA profile 中使用（见 [contactless.md](../emv/contactless.md) §1.2）。

> 注：PACE / Chip Authentication 使用 classic API 的 `KeyAgreement`（`ALG_EC_PACE_GM` /
> `ALG_EC_SVDP_DH_PLAIN_XY`）与自包含 P-256，与 C-8 的 Book E 通道无关，J3R180 实测支持。

## 13. 库 CAP 可行性

在本项目的 Java Card Dev Kit Tools v26.0 / Simulator 上实测：

- 一个**不带 `-applet`** 转换的 package 产出库 CAP（`common.cap`/`common.exp`），0 错 0 警。
- 依赖它的 applet CAP 用 `-exportpath …/deliverables/card42common` 转换时，`Import.cap`
  记录库 package AID（`capdump` 显示 `43 41 52 44 42 00` = `card42.common`）。
- jcsl 先加载库 CAP 再加载依赖 CAP；实例选中并运行库代码。Class AID 必须共享 package RID，
  但**实例** AID 可为任意值（如 ICAO `A0000002471001`）。

## 14. 大照片（DG2）与 J3R180 内存

**平台**：真卡为 NXP JCOP4-180K（J3R180），Java Card 3.0.5 Classic、GP 2.3，标称约
180 KB 用户 NVM、RAM 仅数 KB 量级。Java Card 的内存分三类：持久（EEPROM/Flash，装对象与
数组，写有磨损、且事务会写日志）、ROM（只读）、瞬态（RAM，`makeTransient*`，极稀缺且按
context 共享）。因此"把照片放进内存"的正确目标是**持久**且**按需**，而绝不是瞬态。

**关键事实（本项目实测/推演结合实现）**：

- eMRTD 的 DG2（人脸）是唯一可能达到数 KB–数十 KB 的 LDS1 文件；其余 DG 都在 1–2 KB
  以内，而 EF.SOD/EF.CardSecurity 内嵌 Document Signer 证书链、实际可达数 KB（本项目一份
  真实 DSC 夹具即产生 1938 B 的 EF.CardSecurity 与 2005 B 的 EF.SOD），AA 私钥 516 B。
  DG2 的取值上限受两条约束：DGI 长度字段（CPS 编到 16 位）与 READ
  BINARY 的 15 位偏移，故任何 EF 实际 **≤32767 B**。
- **读路径本来就是流式的**：`READ BINARY` 每包明文受活动 SM profile 限制（3DES `0xE7`，AES
  `0xDF`；见 [emrtd.md](../emrtd/emrtd.md) §6），卡侧一次只搬一块到 `response`
   (256 B) 再经 `SmScratch` 封装，瞬态占用是常数，与 EF 大小无关；照片变大只增加往返次数。
- **个性化曾是瓶颈**：SD 逐条转发 STORE DATA（数据域 ≤231 B），旧实现把整段 DGI 序列攒进
  4096 B 的 `persoBuffer`，于是 DG2 一大就 `6700`，且缓冲区按包共享占持久内存。逐 DGI
  **流式**应用后，峰值 RAM 只与一条 STORE DATA 有关，照片大小只花持久字节。
- **持久增长要避免复制翻倍**：旧 `ensure()` 用"新开精确大小数组 + 拷贝旧内容"，对 n KB 照片
  是 O(n²) EEPROM 拷贝，最后一次增长还要旧+新两份同时在堆里。改用 **256 B 分页**后，每次
  最多分配一页，不需连续大数组，也不随写入复制历史。分页与"按容量一次分配"相比还省下未写
  满的持久空间（J3R180 NVM 虽大，但 180 KB 要与 EMV、SD、其他实例共享）。
- **事务**：GP SD 在 `processData` 期间持事务（本实现约定，CPS 未强制）。逐块写入使单条命令
  的日志很小；模拟器上 9943 B 的 LDS1 序列（DG2 7424 B）个性化通过，`make test` 的 EMV+eMRTD
  共存矩阵亦通过。真卡的 SD 事务粒度与 `getAvailableMemory(TRANSIENT_DESELECT)` 余量仍待
  T5.2 实测。

据此，卡侧实现为：`DgiStream`（增量 DGI 帧）+ `LdsPerso`/`Lds2Perso`（逐 DGI 路由到
`LdsFile`/`Lds2TransparentFile`/`Lds2RecordFile`）+ 分页 EF；透明 EF 不设按文件写死的容量，
由 DGI 头声明的长度驱动增长、上限为协议上限 `EmrtdTags.MAX_EF_BYTES` = 32767（DGI 长度字段
与 READ BINARY 15 位偏移；记录 EF 仍按规范的记录数/记录长预留池）。DG2 由输入头像生成
（默认 `perso/emrtd/portrait.png`），
裁到 4:5、最长边缩到 512 px 后编码（约 8 KB），足以覆盖流式/分页路径又不挤占与 EMV 共存的
jcsl 预算（见 [../emrtd/emrtd.md](../emrtd/emrtd.md) §2/§8/§11）。
