# 构建与工具链规范

## 1. 前置条件

- **完整 JDK**（须含 `bin/javac` 与 `bin/jar`）；JDK 21 与 25 均可用，headless JRE 不够。
- Oracle **Java Card Development Kit Tools** 与 **Simulator**，解压在 `tools/` 下；
  Makefile 自动探测 `tools/java_card_devkit_tools-bin-*` 与
  `tools/java_card_devkit_simulator-linux-bin-*`。
- [GlobalPlatformPro](https://github.com/martijno/GlobalPlatformPro) 于
  `/usr/share/java/globalplatformpro/gp.jar`：部署与个性化统一由它承担——模拟器走
  nextgen `--simulator` 传输（需含 NG 的 GPPro 构建），真卡走 classic PC/SC。建议锁定并
  记录版本（见 §4）。
- 参考标准与工具链版本的获取方式见 [`../../../tools/README.md`](../../../tools/README.md)。

## 2. 构建

```
make                 # 三个 CAP + 三个主机 jar
make card            # card-common + card-emv + card-emrtd
make card-common     # 库 CAP card42common.cap/.exp（无 applet）
make card-emv        # card42-emv.cap（依赖 card42common）
make card-emrtd      # card42-emrtd.cap（依赖 card42common）
make host            # host-common + host-emv + host-emrtd
make verify          # 校验三个 export 文件
make TEST_CONTACTLESS=1   # 测试构建（EMV）
make test / test-emv / test-emrtd   # 三矩阵端到端
make clean           # 清理 build/
```

六个交付物：

- **库 CAP `card42common`**：`javac` 编译 `card/common` 到 `build/card/common/bin`；converter
  用 `build/card42common.conf`（**无 `-applet`**）生成 `card42common.cap/.exp`。
- **EMV CAP `card42-emv`**：编译 `card/emv`（classpath 追加 common bin，含生成的
  `BuildConfig`）到 `build/card/emv/bin`；converter 用 `build/card42-emv.conf`
  （`-exportpath <GPAPI>/exports23:<common 导出根>`，两个 `-applet`）。
- **eMRTD CAP `card42-emrtd`**：编译 `card/emrtd` 到 `build/card/emrtd/bin`；converter 用
  `build/card42-emrtd.conf`（一个 `-applet`）。
- **主机三 jar**：`javac` 只用 JDK 编译 `host/common` → `card42-common.jar`；再编译
  `host/emv`（cp common）→ `card42-emv.jar`（Main-Class `card42.host.emv.cli.Main`）；再编译
  `host/emrtd`（cp common）→ `card42-emrtd.jar`（Main-Class `card42.host.emrtd.cli.Main`）。
  业务 jar 的 Manifest 带 `Class-Path: card42-common.jar`，三 jar 同目录即可
  `java -jar … <command> <subcommand>`。

`make verify` 对三个 `.exp` 跑 `verifyexp.sh`；`carddump` 业务 `Import.cap` 可见
`card42.common` 的 package AID（`43 41 52 44 42 00`）。

部署计划（见 §4/§5）：`deploy.conf`（both）、`deploy-emv.conf`（EMV 生产）、
`deploy-emv-test.conf`（EMV 测试实例 04/06/08）、`deploy-emrtd.conf`（eMRTD LDS1/LDS2）。

`TEST_CONTACTLESS=1` 重新生成 `build/gen/card42/emv/BuildConfig.java`
（`ALLOW_CONTACTLESS_ON_CONTACT`），仅在值变化时改写。

## 3. 配置

可调默认值在 `config/*.mk`，每类一个文件：

| 文件 | 内容 |
|------|------|
| `config/build.mk` | 输出目录、三个源码目录（`CARD_COMMON_DIR`/`CARD_EMV_DIR`/`CARD_EMRTD_DIR`，含 EMV 别名 `CARD_DIR`）、`TEST_CONTACTLESS` |
| `config/toolchain.mk` | `JAVA_HOME`、`JAVA`、`JAVAC`、`JAR`、`JAVAC_RELEASE` |
| `config/externals.mk` | Java Card SDK、GlobalPlatform API、GPPro jar |
| `config/target.mk` | `JC_TARGET`、`JC_API_VERSION` |
| `config/ids.mk` | 统一 RID、三个 package/applet 名与 AID、common/emv 版本（eMRTD 无版本变量） |
| `config/simulator.mk` | 模拟器端口、SCP03 keyset、PIN、部署计划、`SIM_CAPS`/`SIM_BOTH_CAPS`、`GP_SIM` |
| `config/card.mk` | 真卡 GPPro 参数（`GP_ARGS`、`GP_PERSONALIZE`、`CARD_NEW_*`）+ eMRTD LDS1 安装（`EMRTD_LDS1_AID`/`EMRTD_LDS1_PRIVS`） |

覆盖优先级（递增）：分类默认值 < `config/local.mk`（复制 `config/local.mk.example`，
gitignore，用于私密密钥）< 环境变量 < 命令行，如 `make JAVA_HOME=/path/to/jdk`。

主要变量：

| 变量 | 默认 | 说明 |
|------|------|------|
| `JAVA_HOME` | `/usr/lib/jvm/java-21-openjdk` | 完整 JDK |
| `JAVAC_RELEASE` | `8` | applet 类的 `javac --release` |
| `JC_HOME_TOOLS` / `JC_HOME_SIMULATOR` | 自动探测 | Java Card 工具/模拟器 |
| `JC_TARGET` / `JC_API_VERSION` | `3.0.5` | converter 目标 / `api_classic-<v>.jar` |
| `CARD42_RID` | `0x43:0x41:0x52:0x44:0x42` | 统一私有 RID（CARDB） |
| `COMMON_PACKAGE_NAME` / `COMMON_PACKAGE_AID` | `card42.common` / `…:00` | 库 package |
| `PACKAGE_NAME` / `PACKAGE_AID` | `card42.emv` / `…:01` | EMV package |
| `APPLET_CLASS` / `APPLET_AID` | `card42.emv.PaymentApplet` / `…:01:01` | 支付 applet |
| `DIRECTORY_CLASS` / `DIRECTORY_AID` | `card42.emv.DirectoryApplet` / `…:01:03` | 目录 applet |
| `EMRTD_PACKAGE_NAME` / `EMRTD_PACKAGE_AID` | `card42.emrtd` / `…:02` | eMRTD package |
| `EMRTD_CLASS` / `EMRTD_AID` | `card42.emrtd.EmrtdApplet` / `…:02:01` | eMRTD applet |
| `TEST_CONTACTLESS` | `0` | `1`=允许非接触实例在接触接口被选中 |
| `DEPLOY_CONF` | `deploy/deploy-emv.conf` | EMV 生产实例 |
| `DEPLOY_EMV_TEST_CONF` | `deploy/deploy-emv-test.conf` | EMV 测试实例 |
| `DEPLOY_EMRTD_CONF` | `deploy/deploy-emrtd.conf` | eMRTD LDS1/LDS2 实例 |
| `DEPLOY_BOTH_CONF` | `deploy/deploy.conf` | both 矩阵 |
| `EMV_PERSO_KEYS` | `perso/emv/sample.perso.sda.keys` | 示例 SDA 密钥档案（两脚本共用） |
| `SIM_EMV_PERSO_SCRIPT` | `perso/emv/sample-test.perso` | 模拟器个性化脚本（生产 + 测试实例） |
| `CARD_EMV_PERSO_SCRIPT` | `perso/emv/sample.perso` | 真卡个性化脚本（仅生产实例） |
| `SIM_CAPS` | common,emv | EMV 矩阵加载的 CAP（逗号分隔） |
| `SIM_BOTH_CAPS` | common,emv,emrtd | both 矩阵加载的 CAP |
| `BUILD_DIR` | `build` | 输出目录 |
| `SIM_PORT` | `9025` | 模拟器端口 |
| `SIM_KVN` / `SIM_ENC_KEY` / `SIM_MAC_KEY` / `SIM_DEK_KEY` | `01` / `1111…` / `2222…` / `3333…` | SCP03 keyset |
| `SIM_GLOBAL_PIN` / `SIM_PIN_TRIES` | `000000000000` / `03` | 模拟器 GP PIN |
| `GP_JAR` | `/usr/share/java/globalplatformpro/gp.jar` | GPPro（sim + 真卡） |
| `GP_SIM` | `--ng --simulator localhost:$(SIM_PORT) --key-…` | 模拟器 GPPro 参数（nextgen + `SIM_*` keyset） |
| `GP_ARGS` | 空 | 真卡每次 `gp` 的额外参数（classic PC/SC，不加 `--ng`） |
| `GP_PERSONALIZE` | `0` | 真卡安装时追加 `INSTALL [for personalization]` |

## 4. 模拟器

命名约定：带 `emv`/`emrtd` 关键字的只针对该模块；**不带关键字的为公共/both**。

```
make test          # both 矩阵：EMV + eMRTD 共存（单次部署，不含 block）
make test-emv      # EMV 矩阵：部署 + 个性化 + 冒烟/目录/边界（test-emv-sim + test-emv-sim-block）
make test-emrtd    # eMRTD 矩阵：LDS1 + LDS2 + BAC + SM + PA + AA + PACE
make sim-install   # 启动 + 加载三个 CAP + 创建 both 实例（不含个性化）
make sim-emv-install    # 启动 + 加载 common/emv + 创建 EMV 实例（含测试实例）
make sim-emrtd-install  # 启动 + 加载 common/emrtd + 创建 LDS1/LDS2 实例
make sim-perso / sim-emv-perso / sim-emrtd-perso   # both / EMV / eMRTD 个性化
make test-emv-sim      # 部署 + 个性化 + 跑全部 EMV 集成 suite
make test-emv-sim-run S=<Suite>  # 起模拟器并只跑一个 EMV suite（默认 EmvFlowTest）
make sim-stop      # 停止模拟器
make test-unit     # 纯 JVM 单测（无需模拟器）
```

`make test`（both）= 单次部署跑生产 EMV suite + eMRTD suite；`make test-emv` = `test-emv-sim` +
第二个模拟器生命周期的 `test-emv-sim-block`（卡级 block 不可逆，须最后单独一轮）。加
`TEST_CONTACTLESS=1` 走非接触流（经 PPSE）。

`make test-emrtd`：`sim-emrtd-install` + `sim-emrtd-perso`（加载 `card42common` + `card42-emrtd`，
创建 `A0000002471001` 与 LDS2 DF，用 `EmrtdPersoExporter -script=$(EMRTD_PERSO_SCRIPT)` 把
`perso/emrtd/sample.perso` 的 DGI 序列经 GPPro `--store-data` 个性化样例护照），再跑
`EMRTD_SUITES`（`EmrtdBacTest`、`EmrtdLds2IntegrationTest`、`EmrtdLds2AppsIntegrationTest`、
`EmrtdPaceIntegrationTest`、`EmrtdChipAuthIntegrationTest`）；这些
suite 从仓库根读取 PA 的 CSCA 夹具 `perso/emrtd/csca.crt`。

`make test`（both）：`sim-install` + `sim-perso`（加载三个 CAP，按 `deploy.conf` 创建 EMV +
eMRTD 实例，EMV 用 `perso/emv/sample.perso`、eMRTD 用 `perso/emrtd/sample.perso`），再跑生产
EMV suite（`ContactKernelTest`、`DirectoryTest`）与 `EMRTD_SUITES`。

`make test-emv-sim-run S=<Suite>`（`S` 默认 `EmvFlowTest`）先执行 `sim-emv-install` +
`sim-emv-perso`（起模拟器、安装并个性化），再只运行 `test/emv/integration/` 中指定的一个入口
（如 `make test-emv-sim-run S=AesFlowTest`），便于针对单个流程迭代调试；`test-emv-sim` 按
`EMV_SUITES` 顺序把全部 suite 各起一个 JVM 运行。

`make sim-install`（both）/`make sim-emv-install`（EMV）安装步骤（个性化见 `sim-perso` /
`sim-emv-perso`）：

1. 复制 `jcsl` 到 `build/sim/`，用 `Configurator.jar` 注入 SCP03 密钥（stock `jcsl` 不带初始
   SCP 密钥，必须先配置）。
2. 启动模拟器并等待就绪。
3. 用 GPPro（`$(GP_SIM)`）加载 CAP 并安装实例：`--load` **只加载**（不自动 install），再逐条
   `--create <instance> --applet <class> --package <PACKAGE_AID 的 hex 形式>`（`--create` 不从
   applet AID 推断 package——nextgen 与 classic 均如此，因为实例尚未进入注册表；须显式传入；
   GPPro 不认 `0x…:…` 写法，故用去前缀/冒号的 `PACKAGE_AID_HEX`）。
   - `sim-emv-install`：`SIM_CAPS`（common+emv）+ `deploy-emv.conf` + `deploy-emv-test.conf`。
   - `sim-install`（both）：`SIM_BOTH_CAPS`（common+emv+emrtd）+ `deploy.conf`，按 class AID 前缀选
     emv/emrtd 的 package。
4. 个性化（SCP03）：
   - `sim-emv-perso`：`PersoExporter` 把 `$(SIM_EMV_PERSO_SCRIPT)`（默认 `perso/emv/sample-test.perso`，
     含测试实例）每实例的 DGI 序列导出为 hex，交给 GPPro `--personalize <AID> --store-data <hex>`。
   - `sim-perso`（both）：EMV 用 `$(CARD_EMV_PERSO_SCRIPT)`（生产集），eMRTD 用
     `EmrtdPersoExporter -script=$(EMRTD_PERSO_SCRIPT)`（DG1/DG2/DG15/SOD + K_seed + AA 私钥 +
     CA/PACE 密钥 + LDS2 EF）。

GPPro 与模拟器：`gp --ng --simulator localhost:<port>` 经 `apdu4j` 的 JCSDK socket 直连
jcsl（`GPTool.main` 检测到 `--ng`/`GP_NG=true` 后委托 `pro.javacard.gp.ng.GPToolNG`），无需
Oracle `socketprovider`。NG 被上游标注为**实验性**（`nextgen/README.md`：“experimental work in
progress. **Do not use.**”），故**只用于模拟器**；真卡一律不加 `--ng`（见 §5）。NG 选项/语义
随版本漂移，需含 NG 的 GPPro 构建；本项目验证版本 `globalplatformpro-git
26.06.04.r26.gb976523`（manifest 26.09.01-SNAPSHOT）。

### 模拟器限制

- 始终报告**接触**接口（`APDU.getProtocol()`）；非接触流只能用 `TEST_CONTACTLESS=1` 验证。
- `APDU.getProtocol()` 不参与角色/CVM/PIN 决策，但实例可选性（PPSE/非接触实例在接触接口
  是否 `6A82`）依据它。
- 安全域**仅支持 SCP03**（FCI 只宣告 SCP03，其他 `INITIALIZE UPDATE P2` 回 `6A86`）；
  SCP02 无法协商。详见 [research-notes.md](research-notes.md) §11。
- 不实现 `ALG_DES_MAC*_ISO9797_1_M2_ALG3`（见 [cryptography.md](cryptography.md) §4）。
- 每次 `make sim*`/`make test*` 都会重启模拟器，卡被清空，需重新部署与个性化。

## 5. 真卡安装

`make card-install` / `make card-emv-install` / `make card-emrtd-install` 用 GPPro 对 PC/SC
读卡器中的卡：**只 LOAD**（不自动 install，保证实例 AID 与部署计划一致），再按部署计划逐条
创建实例。`card-install`（both）加载 common+emv+emrtd 并按 `deploy.conf` 创建生产实例（不含
测试实例）；`card-emv-install` 加载 common+emv 并按 `deploy-emv.conf`（生产）+
`deploy-emv-test.conf`（测试）创建；`card-emrtd-install` 加载 common+emrtd 并按
`deploy-emrtd.conf` 创建 LDS1/LDS2 实例。与模拟器共用同一 GPPro 二进制和
`--load`/`--create`/`--personalize` 命令集，区别仅在传输（此处 classic PC/SC，不加 `--ng`）与
安全通道（真卡 SCP02/SCP03 自动协商）。

```
make card-install                          # both：加载三 CAP + 生产实例（deploy.conf）
make card-emv-install                      # EMV：common+emv + 生产/测试实例
make card-emrtd-install                    # eMRTD：common+emrtd + LDS1/LDS2
make card-uninstall                        # 删除全部实例 + emv/emrtd package（重装前清卡）
make card-emv-install GP_ARGS="--key-enc ... --key-mac ... --key-dek ..."
make card-emv-install GP_PERSONALIZE=1     # 追加 INSTALL [for personalization]
make card-perso / card-emv-perso / card-emrtd-perso   # 下发每实例 DGI 序列（见下）
```

> Java Card 不自动回收已删除对象；反复失败的 INSTALL 会在持久堆留下泄漏，之后某一实例的
> INSTALL 以 `6F00` 失败。真卡重装前先 `make card-uninstall`（用 `GP_ARGS` 的 SD 密钥删除
> 实例与 emv/emrtd package），或换用新卡。

个性化：`make card-emv-perso` 把 `$(CARD_EMV_PERSO_SCRIPT)`（默认 `perso/emv/sample.perso`，仅生产
实例）每实例的 DGI 序列（由 `PersoExporter` 输出为 hex，即 `PersoScript.sequence()`）交给 GPPro
`--personalize <AID> --store-data <DGI序列hex>`。`--store-data` 基值 `P1=0x01`
（bit0=1）、末块 `|0x80`、`P2` 为块序号，按 SD block size 自动分块，与 applet 的
`P1.b8` 完成信号一致；`--store-dgi-file` 的明文分支 `P1.bit0=0` 时 applet 返回 0 长度
报告（不回数据），同样可用。需手工控制 `P1` 时用 `--store-data-raw <APDU>`（`P2` 仍由
GPPro 管理）。applet 经 `Personalization.processData` 处理 DGI，与 SCP 无关，因此
SCP02 卡（J3R180 等）同样可用。

真卡实测（J3R180）：读卡器中的 J3R180 报告 **GP 2.3**、**SCP02**（i=15/35/55/75）、
DES3 keyset **version 0**；`config/local.mk` 里的非出厂 tk 直接建链，无需 `--key-ver`。默认
`GPAPI_VERSION=1.6` 构建的 CAP（import `org.globalplatform` 1.6）converter 0 错 0 警、
`--load` 成功（该卡未启用强制 DAP，ISD 无 `MandatedDAPVerification`）。真卡 `--create` 同样
须显式 `--package <PACKAGE_AID_HEX>`（见 §4）。两点已知现象：① `APPLET_AID`（`43415244420101`）
与生产实例 `...01` 的 AID 相同，classic `--create ...02` 会误报
`WARNING: Applet 43415244420101 already present on card`，但实例照常创建，属良性；② 个性化
脚本拆为生产集 `perso/emv/sample.perso`（`CARD_EMV_PERSO_SCRIPT` 默认）与含测试实例的
`perso/emv/sample-test.perso`（`SIM_EMV_PERSO_SCRIPT` 默认），只装生产实例（`DEPLOY_EMV_TEST_CONF=`）
时 `make card-emv-perso` 默认与之一致；个性化测试实例用
`make card-emv-perso CARD_EMV_PERSO_SCRIPT=perso/emv/sample-test.perso`。

**J3R180 无 DDA/CDA**：该卡不实现 `Signature.ALG_RSA_SHA_ISO9796_MR`（实测：标准 `@sda`
的 DDA 私钥 DGI `8103`/`8101` 回 `6A80`，改用 CRT 容器仍 `6A80`；而 PIN 密钥 `8104`/`8102`
成功）。所以含 DDA 密钥的 `perso/emv/sample.perso` 在这张卡上无法个性化。用
`perso/emv/sample-j3r180.perso`（`@sda records pin`，AIP 去 DDA/CDA：接触 `0x5800`、非接触
`0x4800`）可个性化 SDA + ICC PIN 密钥对（支持加密脱机 PIN `P2=88`；该脚本的 CVM List 仍为
明文 `01 00`，故接触交易实际走 `P2=80`）：

```
make card-emv-perso CARD_EMV_PERSO_SCRIPT=perso/emv/sample-j3r180.perso
```

真卡端到端：非接触与接触交易均走通（SDA、在线 ARQC→TC）；接触明文 PIN
CVM Results `01 00 02`。

真卡**测试实例**（`04`/`06`/`08`）用 J3R180 安全测试集 `perso/emv/sample-j3r180-test.perso`
（生产 01/02/PSE/PPSE + `04` + `06` `@sda records pin` + `08`）；部署全部 7 实例后可跑
`BoundaryTest`/`VelocityTest`/`AesFlowTest`（`CARD_PORTABLE_SUITES` 的接触部分）：

```
make card-emv-install
make card-emv-perso CARD_EMV_PERSO_SCRIPT=perso/emv/sample-j3r180-test.perso
make test-emv-card S=BoundaryTest CARD_HOST=pcsc:1
```

四个脚本（`sample.perso`/`sample-test.perso`/`sample-j3r180.perso`/`sample-j3r180-test.perso`）
的实例 01/02 均已补 IAC-Online/Default（`40 00 00 80 00`，SDA 失败/floor 联机、不对信息性
SDA-selected 置位），使 SDA-only 卡可离线批准。

GP 版本映射：真卡 GP 2.3 → `org.globalplatform` 1.6（与本项目 CAP 的 import 一致）；
GP 2.2.1 → 1.5，需 `GPAPI_VERSION=1.5` 构建（`tools/GlobalPlatform_Card_API-.../1.5/`
已存在）。`make card-emv-install` 只 LOAD/CREATE（`GP_PERSONALIZE=1` 补发
`INSTALL [for personalization]`），不下发 DGI。

eMRTD 真卡：`card-emrtd-install` 创建的 LDS1 实例带 GP `CardReset` 权限（Default Selected），
以便读卡器在选应用前于 MF 读 EF.CardAccess（PACE）。J3R180 上 LDS1/LDS2 安装、个性化与读取
（接触/非接触）均走通。

## 6. 测试体系

- **集成测试**（package `card42.test`）：
  - EMV `test/emv/integration/`：卡命令流 suite 在 `test/emv/integration/card/`
    （`EmvFlowTest`、`DirectoryTest`、`BoundaryTest`、`LogTest`、`VelocityTest`、`AesFlowTest`、
    `OnlineClosedLoopTest`、`IssuerScriptTest` 与 `CardBlockTest`，后者由 `test-emv-sim-block` 在
    第二个模拟器生命周期单独执行）；主机内核 suite 在
    `test/emv/integration/host/kernel/{contact,contactless}/`（`ContactKernelTest`、
    `ContactlessTest`）；CLI suite 在 `test/emv/integration/host/cli/`（`TerminalCliTest`）；
    测试替身与助手（`Checks`/`TestTerminals`）在 `test/emv/integration/support/`。
  - eMRTD `test/emrtd/integration/`：`EmrtdBacTest`（SELECT + AA + BAC + SM 读 DG1/DG2/COM/DG15/SOD
    + PA）、`EmrtdLds2IntegrationTest`（LDS2 Travel 记录 + CardAccess）、
    `EmrtdLds2AppsIntegrationTest`（LDS2 Visa/Additional Biometrics）、`EmrtdPaceIntegrationTest`
    （PACE 3DES/AES-128）、`EmrtdChipAuthIntegrationTest`（Chip Authentication ECDH）。
  - suite 与介质无关：`-host=socket:...` 打模拟器（`make test-emv-sim` / `test-emv-sim-run` /
    `test-emrtd` / `test`），`-host=pcsc` 打 PC/SC 真卡（`make test-emv-card S=<Suite>`）；
    eMRTD 真卡用 `make test-emrtd-card`（全部 `EMRTD_SUITES`）或
    `make test-emrtd-card-run S=<Suite>`，读卡器序号用 `CARD_HOST=pcsc:<idx>`（如 ACR1581 的
    PICC 口是 `pcsc:1`；默认 0 是 SAM 槽）。
    真卡并非全部 suite 可移植：`LogTest` 依赖测试实例 `06`；`ContactlessTest` 需非接触读卡器
    且断言 AIP `0x6900`/DDA/CDA（对 SDA-only 卡不可移植）；`CardBlockTest` 有不可逆副作用。
- **纯 JVM 单测**（package `card42.test`）：`make test-unit` 无需模拟器。
  - EMV 卡内类（`Tlv`/`TlvReader`/`DolReader`/`Dgi`/`DgiReader`/`TlvTags`/`EMVCommands`/
    `EMVStatus`/`EMVRoles`/`EMVCodes`/
    `EMVProtocolState`/`EMVStaticData`/`Defaults`/`PaymentData`/`FciBuilder`/`RecordBuilder`/
    `DirectoryBuilder`/`SdaCertificateData`/`CardRiskManagement`/`Iad`/`RecordStore`/
    `TransactionLog`/`OfflineRisk`/`ConstantTime`/`RetailMac`/`AesCmac`/`MacAlgorithm`/
    `CryptoProfile`/`SessionKey`/`SecureMessaging`/`PersoErrors`/`PersoRules`）链接
    `test/common/stubs` 的极小 `Util`/`ISOException`/`JCSystem`/`CryptoException` 桩，套件在
    `test/emv/unit/card/{tlv,data,state,risk,perso,crypto}`。
  - eMRTD 卡内类（`Tlv`/`BacCrypto`/`MrzKeySeed`/`SecureMessaging`/
    `AbstractSecureMessaging`/`Iso7816Sm`/`Iso7816SmAes`/`Pace`/
    `ChipAuth`/`LdsFileSystem`/`Lds2FileSystem`/`LdsCatalog`/`AaCrypto`/`EmrtdTags`）链接
    `test/common/stubs`（含 JCE 背书的 `MessageDigest`/`Signature`/`RandomData`/`KeyAgreement`/
    RSA 密钥桩），套件在 `test/emrtd/unit/card/`。
  - host 组件覆盖 `PersoScript`/`Sda`/`Tags`/`TagPolicy`/`AcCrypto`/`SmCrypto`/`ClearingHost`
    与终端内核数据/算法，套件在 `test/emv/unit/host/{codec,crypto,perso,clearing,cli,util,oda,transport,kernel}`；
    eMRTD host 套件在 `test/emrtd/unit/host/`（`EmrtdHostTest`/`EmrtdCardAccessTest`）。`UnitTests`
    为调度器（`test/emv/unit/`），`Asserts` 为断言助手（`test/emv/unit/support/`）。
- **参考主机栈 package `card42.host.<module>`**：`host/common/{util,codec,crypto,transport,report,cli}`
  为内核与各模块**共用**的原语；`host/emv/kernel/{core,data,entry,oda,analysis,cvm,script}`
  （package `card42.host.emv.kernel.<submodule>`）为终端内核；`host/emv/report`、
  `host/emv/app/{issuer,perso}`、`host/emv/cli`（入口 `Main`，命令适配器在
  `host/emv/cli/command`）；`host/emrtd/{transport,lds,access,pa,aa,perso,report,cli}` 为
  eMRTD 栈。依赖方向由 `LayeringTest` 守卫（`common` 无依赖；`emv.*` 内部分层；
  `emrtd → common`）。`host/` 只含产品栈：库层不依赖测试设施或测试数据——进度/诊断经
  `Reporter` 输出，ODA 验证返回结果对象并接受显式 `CaKeyStore`/`SdaKeys`，SDA 生成器从
  `-keys=<path>` 的 `SdaKeyProfile` 取密钥，发卡行主机 `IssuerHost` 由 CLI 与测试共用（无内置
  密钥）；测试替身（`ClearingHost`）、示例密钥（`TestKeys`）与测试助手分别在
  `test/emv/unit/host/clearing` 与 `test/common/fixtures`。测试依赖 `card42.host`，反向无依赖。
  `-host=socket:...` 经 `COMService` 的 `SocketCardTerminalProvider` 打模拟器；该 provider 由
  `card42.host.common.transport.Terminals` 在运行时按名解析，主机栈无编译期依赖。
- **条件跳过与覆盖边界**：下列 suite 只在各自门控构建/介质下执行，不在默认矩阵内，故其规范
  覆盖仅存在于对应矩阵；引用这些行为时以门控矩阵为准：
  - `ContactlessTest`（及 `TerminalCliTest` 的 contactless 路径）仅在 `TEST_CONTACTLESS=1`
    构建下执行，默认构建整体跳过（`docs/specs/common/architecture.md` §7）。
  - `CardBlockTest` 仅在 `test-emv-sim-block`（第二个模拟器生命周期）执行，不在 `EMV_SUITES`；
    卡级 block 不可逆，真卡按约束不跑。
  - `LogTest` 依赖 jcsl「SELECT 失败后仍选中」，不在 `CARD_PORTABLE_SUITES`，真卡不可移植。
  - `EmvFlowTest` 按 AIP/实例与个性化状态跳过接触less/通用断言；`LayeringTest` 非仓库根运行时跳过。
  - `test-emv-card` 仅接受 `CARD_PORTABLE_SUITES`（`test/rules.mk`），其余套件提示改用
    `test-emv-sim-run`，避免误跑不可移植套件。
  - 尚无端到端覆盖的规范区域（eMRTD 卡侧命令级、主机 CLI 流程、非接触 Entry Point/内核
    Restart/冲正等）登记在 `TODO.emv.md`/`TODO.emrtd.md`。

`make test` 的验收：`make`/`make verify` 0 错 0 警告；`make test-unit`、`make test`、
`make TEST_CONTACTLESS=1 test`、`make test-emrtd` 全绿。

## 7. 命令速查

```bash
make                       # 三个 CAP + 三个主机 jar
make card / card-common / card-emv / card-emrtd
make host / host-common / host-emv / host-emrtd
make TEST_CONTACTLESS=1    # 测试构建
make verify                # 校验三个 export
make sim-install / sim-emv-install / sim-emrtd-install   # both / EMV / eMRTD：启动 + 安装（加载 CAP + 建实例）
make sim-perso / sim-emv-perso / sim-emrtd-perso         # both / EMV / eMRTD：个性化
make test                  # both 矩阵
make test-emv              # EMV 矩阵（test-emv-sim + test-emv-sim-block）
make test-emrtd            # eMRTD 矩阵
make test-emv-sim              # 部署 + 个性化 + 跑全部 EMV 集成 suite
make test-emv-sim-run S=AesFlowTest # 起模拟器并只跑一个 EMV suite
make test-emv-card S=EmvFlowTest    # 对真卡（PC/SC）跑一个 EMV suite
make test-emrtd-card           # 对真卡（PC/SC）跑全部 eMRTD suite
make test-emrtd-card CARD_HOST=pcsc:1         # 指定读卡器序号（PICC=1）
make test-emrtd-card-run S=EmrtdBacTest       # 对真卡只跑一个 eMRTD suite
make sim-stop              # 停止模拟器
make card-install              # 真卡安装 both（common+emv+emrtd，deploy.conf 生产实例）
make card-emv-install          # 真卡安装 EMV（含 04/06/08 测试实例）
make card-emrtd-install        # 真卡安装 eMRTD（common+emrtd）
make card-perso                # 真卡个性化 both（EMV 生产集 + eMRTD 样例）
make card-emv-perso            # 真卡个性化 EMV（GPPro，perso/emv/sample.perso 生产集）
make card-emrtd-perso          # 真卡个性化 eMRTD（perso/emrtd/sample.perso）
make card-emv-perso CARD_EMV_PERSO_SCRIPT=perso/emv/sample-test.perso  # 真卡含测试实例
make card-emv-perso CARD_EMV_PERSO_SCRIPT=perso/emv/sample-j3r180.perso       # J3R180 生产集（无 DDA）
make card-emv-perso CARD_EMV_PERSO_SCRIPT=perso/emv/sample-j3r180-test.perso  # J3R180 测试集（04/06/08）
make clean                 # 清理 build/
```

### 7.1 主机 CLI

两个可执行 jar：`card42-emv.jar`（`card42.host.emv.cli.Main`）与 `card42-emrtd.jar`
（`card42.host.emrtd.cli.Main`），用
`java -jar build/deliverables/card42-emv.jar <command> <subcommand>` 运行。命令为子命令式：

```
# card42-emv
perso    export [-script=<path>] [-keys=<path>]   个性化脚本 → GPPro hex
terminal pay     [options]                        接触/非接触跑一笔完整交易
terminal entrypoint [options]                     Entry Point 诊断
terminal inspect [options]                        只读侦察（目录/FCI/记录/ODA）
terminal apdu    [options]                        发送原始命令 APDU（-apdu/-file/stdin）
issuer   authorize|arpc|script|keys               发卡行主机：ARPC/CSU、71/72 脚本、会话密钥
card     block-app|unblock-app|block|pin-change|pin-unblock|get-data|atc|last-online-atc
version / help [command]

# card42-emrtd
terminal emrtd read    -host=... -doc=... -dob=YYMMDD -doe=YYMMDD [-pace] [-json=1]  BAC/PACE+SM+PA+AA
terminal emrtd inspect -host=... [-json=1]                                    只读（COM/DG15）
terminal emrtd lds2    -host=... [-app=travel|visa|biometrics] [-json=1]      LDS2 CardAccess/记录
terminal emrtd apdu    -host=... -apdu=<hex>                                  原始 APDU
version / help
```

`terminal apdu` 从 `-apdu=<hex>`（可重复）、`-file=<path>`（每行一条，`#` 注释）或 stdin
读取命令 APDU，逐条打印 `> C-APDU` / `< R-APDU SW=xxxx`，用于验证卡侧边界与负例。

`issuer` 族是 `-issuer-cmd` 桥接的另一端：`issuer authorize` 读 stdin 的一行 JSON 请求
（`arqc/atc/tvr/aid`）并输出一行 JSON 授权（`arc/auth/scripts`）；`issuer arpc` 计算 ARPC
Method 1/2；`issuer script` 构建（并可用 Format 1 SM 保护）71/72 模板；`issuer keys` 打印
KCV 与 A1.3 会话密钥。例如：

```bash
java -p tools/java_card_devkit_simulator-linux-bin-*/client/COMService \
     --add-modules ALL-MODULE-PATH -jar build/deliverables/card42-emv.jar \
     terminal pay -iface=contact -host=socket:localhost:9025 \
     -ca-keys=perso/emv/sample.ca.keys -floor=0 -tac-online=0000008000 \
     -issuer-cmd="java -jar build/deliverables/card42-emv.jar issuer authorize \
       -icc-key=343864C2E085AB3E433D2F982945E61F"
```

`card` 族把卡侧后发行命令与 GET DATA 暴露给运维/调试：`block-app`/`unblock-app`/`block`
与 `pin-change`/`pin-unblock` 走 Format 1 安全报文（`-mac-key=`，PIN 改密另需 `-enc-key=`），
`get-data`/`atc`/`last-online-atc` 为普通 GET DATA。`card block` 不可逆，需 `-yes` 确认。
退出码：`0` 成功（SW=9000）、`1` 卡拒绝（非 9000）、`2` 用法或连接错误。

`terminal pay` 的传输描述符支持 `pcsc[:<idx>]`（真卡）与 `socket:<host>:<port>`（模拟器）。
打模拟器时需把模拟器的 socket provider 放到 module path：

```bash
java -p tools/java_card_devkit_simulator-linux-bin-*/client/COMService \
     --add-modules ALL-MODULE-PATH -jar build/deliverables/card42-emv.jar \
     terminal pay -iface=contact -host=socket:localhost:9025 \
     -ca-keys=perso/emv/sample.ca.keys -pin=1234 -floor=none
```

`terminal pay` 退出码：`0` 批准（TC）、`1` 拒绝（AAC）、`2` 用法或连接错误。`-json` 把结构化
报告写 stdout，诊断写 stderr；`-report=<path>` 写文件。`-trace` 打印每个 APDU。在线授权支持
闭环（`-icc-key=`/`-csu=`/`-arc=`）、外部子进程一行 JSON（`-issuer-cmd=`）与静态回放
（`-auth=`）；`-online=auto|always|never|decline` 覆盖策略。详细选项见
`Main help "terminal pay"`。

## 8. 备注

- 源码 UTF-8，applet 用 `-encoding UTF-8` 编译。
- 默认 converter 目标 Java Card `3.0.5`；仅用 classic API，其他目标（如 `3.1.0`）在
  `JC_API_VERSION` 匹配时可用。
- 模拟器卡内 `org.globalplatform` 包版本为 **1.6**；构建用
  `tools/GlobalPlatform_Card_API-org.globalplatform-v1.7.1/1.6/` 的 API jar + `exports23`
  同时供 `javac` 与 converter `-exportpath`，CAP 原生 import 1.6，无需后处理。
- **库 CAP 稳定性**：common 冻结；API 变更须升 `COMMON_VERSION` 并重建依赖 CAP；重建时可把
  上一版 `common.exp` 放入 exportpath 并用 `-exportmap` 钉 token。
- 依赖 CAP 的 `Import.cap` 记录 `card42.common` 的 package AID（`43 41 52 44 42 00`），
  jcsl 先 LOAD common 再 LOAD 业务 CAP。
