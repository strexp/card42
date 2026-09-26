# card42 规范文档 (docs/specs)

本目录是 card42 的**当前设计规范与参考事实**：只描述"系统现在是什么样、为什么这样设计"。
按三个模块组织：

- [`common/`](common/) — 公共层：卡侧 `card42common` 库 CAP、主机 `card42.host.common`、
  构建工具链、密码学原语、调研事实与风险。
- [`emv/`](emv/) — EMV 业务：个性化、交易链路、接触/非接触终端内核。
- [`emrtd/`](emrtd/) — eMRTD（ICAO 9303）：LDS1/LDS2、BAC、ISO/IEC 7816-4 安全报文、
  PA、AA、Chip Authentication、PACE。

未完成计划见仓库根 [`../../TODO.emv.md`](../../TODO.emv.md) /
[`../../TODO.emrtd.md`](../../TODO.emrtd.md)。参考标准与工具链版本见
[`../../tools/README.md`](../../tools/README.md)。

## 规范版本（基线）

| 领域 | 版本 | 出处 |
|------|------|------|
| EMV 接触 | **EMV v4.4 Book 1–4（2022-10）** | `tools/specs-4.4/` |
| 个性化 | **EMV CPS v2.0（2021-08，含 AES）** | `tools/cps-2.0/` |
| 非接触 | **EMV Contactless Book A/B v2.12** | `tools/specs-contactless-v2.12/` |
| 非接触内核（参照） | **EMV Contactless Book C-8 v1.2**（仅流程结构；ECC/Book E 范围外） | `tools/specs-contactless-c8-1.2/` |
| eMRTD | **ICAO Doc 9303 Part 3/9/10/11/12** | `tools/icao9303/` |
| PACE / CA | **BSI TR-03110 Part 1–4 v2.2** | `tools/bsi-tr-03110/` |

- v4.1 / v4.3 与 CPS v1.1 仅作历史对照（`tools/specs-v4.1/`、`tools/specs-v4.3/`、
  `tools/cps-1.1/`）。
- **v4.4 Book 1 删除 Part II**：T=0/T=1、GET RESPONSE、状态字、APDU case 现属
  *EMV Contact Interface Specification*；卡内传输层依赖 Java Card 运行时。
- **CPS 2.0 相对 1.1**：新增 SCP03/AES 分支与 `8105`/`8106`（ECC 私钥），其余 DGI 编号不变；
  SCP02 仍支持；长度编码、`7FFF` + `P1.b8` 完成信号、记录规则不变。

## 目录

### common/

| 文档 | 内容 |
|------|------|
| [common/architecture.md](common/architecture.md) | 三模块拓扑、AID/角色、生命周期、命令矩阵、目录与源码布局 |
| [common/toolchain.md](common/toolchain.md) | 构建（3 CAP + 3 jar）、配置项、模拟器、真卡安装、测试体系 |
| [common/cryptography.md](common/cryptography.md) | 会话密钥、应用密文（CV '5'/'6'）、ARPC、Retail MAC/AES-CMAC、DDA/CDA、离线 PIN、安全报文 |
| [common/research-notes.md](common/research-notes.md) | 调研结论与关键事实（GP API、jcsl、库 CAP、平台实测） |
| [common/risks.md](common/risks.md) | 分类风险与缓解 |

### emv/

| 文档 | 内容 |
|------|------|
| [emv/personalization.md](emv/personalization.md) | 个性化流程与安全方案、DGI/TLV 数据模型、人类可读脚本 |
| [emv/transaction.md](emv/transaction.md) | 交易链路行为：ATC/GPO/PDOL、风险管理、READ RECORD、发卡行认证、安全报文、日志、脱机风控 |
| [emv/contactless.md](emv/contactless.md) | 非接触 Entry Point / PPSE 与终端内核（RSA profile） |
| [emv/contact-kernel.md](emv/contact-kernel.md) | 接触终端内核（ContactKernel）：PSE / 直接 ADF、离线 PIN、共享 TransactionFlow |

### emrtd/

| 文档 | 内容 |
|------|------|
| [emrtd/emrtd.md](emrtd/emrtd.md) | LDS1/LDS2 文件系统、BAC、ISO/IEC 7816-4 SM、PA、AA、Chip Authentication、PACE、个性化、主机模块 |

## 约定

- 路径相对仓库根目录。
- 十六进制字节写作 `43 41 52 44 42`，短整数写作 `0x6A80`。
- 业务逻辑处标注 EMV/GP/ICAO/BSI 规范出处。
- 规范只描述当前状态；实现演进后同步本目录。
