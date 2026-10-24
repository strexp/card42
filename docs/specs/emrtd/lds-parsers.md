# eMRTD LDS 字段模型（DG1–DG16、LDS2 Visa MRV）

> 本文描述 `card42.host.emrtd.lds` 的主机侧 LDS 解析层：它把卡片 EF 的原始 BER-TLV
> 转成不可变的字段模型，供 card42 CLI 与外部终端（如 card42-terminal）共用。
> 规范依据：ICAO Doc 9303-10 §4.6/§4.7（LDS1）、§5.2.3（Visa Records）、
> Doc 9303-4（TD1/TD2/TD3）、Doc 9303-7（MRV-A/MRV-B）、ISO/IEC 19794-2/-4/-5/-6。
>
> 解析层只依赖 JDK 与 `card42.host.common`，不依赖 JMRTD、JavaFX 或图像解码库。
> 该 API 随实际使用演进；新增以兼容方式为主，不承诺固定的版本号或二进制冻结。

## 1. 设计原则

- **raw 永远保留**：每个模型都携带解析时的完整 EF（含外层 tag），TIFF/TLV/hex
  展示可以随时回退。
- **不因数据问题抛异常**：畸形、截断、未知 tag、错误校验位都进入
  `ParseStatus` + `List<LdsIssue>`；只有 `null`/越界等编程错误抛
  `IllegalArgumentException`。
- **只解析一次字段**：DG 号、FID、外层 tag 的映射仍由 `LdsFileUtil` 提供；
  每个字段只有一处定义，CLI 与终端不再各自解释 TLV。
- **不解码、不比对**：图像只保留编码字节与元数据；指纹 minutiae、虹膜/人脸比对不在
  card42 范围内。
- **不记录个人数据**：`LdsIssue.message` 只描述字段名与结构，不含字段值；调用方可以
  安全记录 issue。

## 2. 公共模型

| 类型 | 作用 |
|---|---|
| `LdsDataGroup` | 所有 DG 的公共接口：`dg()`、`raw()`、`status()`、`issues()`；静态 `parse(int, byte[])` 按 DG 号分发 |
| `ParseStatus` | `OK` / `PARTIAL` / `INVALID` |
| `LdsIssue` | `Severity`（INFO/WARN/ERROR）+ 稳定 `Code` + `offset` + `dg` + 英文 message |
| `LdsParseResult<T>` | `value + status + issues + raw`，供通用分发/检查器使用 |
| `LdsTlv` | 基于 `TlvCursor` 的偏移感知遍历；`body(...)` 解外层 tag，`children(...)` 只取直接子节点，`tagList(...)` 解 5C |
| `LdsText` | US-ASCII → 严格 UTF-8 → ISO-8859-1（回退时 `fallback=true`）；`ascii()`/`latin1()` 辅助 |
| `LdsDate` | `YYMMDD`/`YYYYMMDD`/`YYYYMMDDhhmmss`；`LocalDate` 可空；非法日期只报 issue |
| `Cbeff` | BHT（A1）的 80/81/82/83/84/85/86/87/88；未知元素保留 raw |
| `ImageData` | `bytes + format + width/height/colorSpace/quality`；格式：JPEG/JPEG2000/PNG/WSQ/JPEG_LS/UNKNOWN |
| `MrzCheckDigit` | 7-3-1 校验位；`MrzKeySeed.checkDigit` 委托它，公开签名不变 |

状态判定：

- `OK`：必需结构与字段完整，且没有 WARN/ERROR issue。
- `PARTIAL`：外层可用，但存在编码回退、未知 tag、计数不符、校验位/日期错误等；
  字段仍尽量保留。
- `INVALID`：关键结构不可读（空 EF、无 MRZ、无 biometric template 等），
  此时通常只剩 `raw()` 有意义。

`offset` 是相对原始 EF 首字节（外层 tag 为 0）的偏移，便于定位损坏的 TLV。

## 3. DG 支持矩阵

| DG | 外层 tag | 结构 | 模型 | 状态/限制 |
|---|---|---|---|---|
| DG1 | `61` | `61 { 5F1F MRZ }` | `Dg1` + `Mrz`（TD1/TD2/TD3） | 完整字段、逐项/复合校验位、`LdsDate`、可选区；校验失败 → PARTIAL |
| DG2 | `75` | `75 { 7F61 { 02, 7F60 { A1, 5F2E } } }` | `Dg2` + `FaceImage` | 多脸、CBEFF、ISO 19794-5、图像尺寸/格式；无 ISO 头时签名扫描回退 → PARTIAL |
| DG3 | `63` | `63 { 7F61 { 02, 7F60 { A1, 5F2E } } }` | `Dg3` + `FingerImage` | ISO 19794-4 图像记录（指位/质量/impression）；ISO 19794-2 `FMR` 只保留 raw → INFO |
| DG4 | `76` | `76 { 7F61 { 02, 7F60 { A1, 5F2E } } }` | `Dg4` + `IrisImage` | ISO 19794-6；眼位/质量/旋转/图像；JPEG-LS/JPEG 2000 不解码 |
| DG5 | `65` | `65 { 02, 5F40 }` | `Dg5` | 显示肖像列表；无 CBEFF/ISO 头（Doc 9303-10 Table 58） |
| DG7 | `67` | `67 { 02, 5F43 }` | `Dg7` | 显示签名列表；无 CBEFF/ISO 头（Table 62） |
| DG8 | `68` | `68 { 02, <proprietary> }` | `Dg8` | 规范未定义；只暴露 count + 完整模板 TLV |
| DG9 | `69` | `69 { 02, <proprietary> }` | `Dg9` | 同上（Table 67） |
| DG10 | `6A` | `6A { 02, <proprietary> }` | `Dg10` | 同上（Table 69） |
| DG11 | `6B` | `6B { 5C, 5F0E, A0{02,5F0F*}, 5F10, 5F2B, 5F11, 5F42, 5F12, 5F13, 5F14, 5F15, 5F16, 5F17, 5F18 }` | `Dg11` | 全部字段、重复姓名/地址/电话、未知 tag 保留、UTF-8 回退 |
| DG12 | `6C` | `6C { 5C, 5F19, 5F26, A0{02,5F1A*}, 5F1B, 5F1C, 5F1D, 5F1E, 5F55, 5F56 }` | `Dg12` | 5F55 支持 ASCII 与 BCD 两种编码；正/反面图像 |
| DG13 | `6D` | `6D { <issuer-defined> }` | `Dg13` | 规范无字段表；只校验外层并保留 value |
| DG14 | `6E` | `6E { SecurityInfos }` | `Dg`（通用）/ `SecurityInfo` | 安全对象，保持原有专用解析 |
| DG15 | `6F` | `6F { SubjectPublicKeyInfo }` | `Dg15` | AA 公钥；保持原有专用解析 |
| DG16 | `70` | `70 { 02, A1..An { 5F50, 5F51, 5F52, 5F53 } }` | `Dg16` + `PersonToNotify` | 多联系人、日期/姓名/电话/地址、未知 tag 保留 |

DG6 保留；通用分发器对其与未知 DG 返回 `Dg` + raw TLV 视图。

## 4. MRZ 与日期

- TD1 = 3×30、TD2 = 2×36、TD3 = 2×44；按长度选择，CR/LF 会被忽略。
- 字段保留 `'<'` 填充；姓名按 `<<` 拆姓/名，但不做转写。
- 校验位：证件号、出生日期、有效期、TD3 个人号，以及复合校验位。
  复合校验位按 ICAO Doc 9303-3 Appendix A 的字段序列计算（TD1 50 字符、
  TD2 31 字符、TD3 39 字符），不是整行字符串。
- `LdsDate.birthDate(raw, referenceYear)`：选择不晚于参考年的最近世纪
  （69 + 2026 → 1969）。
- `LdsDate.expiryDate(raw, referenceYear)`：在 19xx/20xx 中选择离参考年最近的
  （94 + 2026 → 1994，30 → 2030）。
- 非法日期不会“修正”：`date == null`、`valid == false`，并产生 `BAD_DATE`。
- 参考年由调用方传入；单元测试固定参考年，避免跨年波动。

## 5. LDS2 Visa MRV

`VisaRecord` 原有字符串访问器（`machineReadableVisaA/B`、`effectiveDate` 等）保持不变；
新增：

- `mrvA()` / `mrvB()`：`Mrv` 模型（`MRV_A` 2×44、`MRV_B` 2×36），含签证号、国籍、
  出生/有效期、性别、可选区、逐项校验位与 `LdsDate`。
- `effectiveDateValue()` / `expirationDateValue()`：`5F25`/`5F24` 的 `LdsDate`
  （支持 6 位或 8 位日期）。
- Doc 9303-7 没有为 MRV-A/B 定义复合校验位，`Mrv` 只校验逐项校验位。

## 6. 样例与测试

- 个性化样例（`SampleData` / `BiometricRecordBuilder`）现在按规范构造
  DG3（ISO 19794-4）、DG4（ISO 19794-6）、DG5（`02+5F40`）、DG7（`02+5F43`）、
  DG16（`02+A1..An+5F50..5F53`），模拟器读出的 DG 可直接进入字段模型。
- 单元测试：
  - `LdsCommonTest`：TLV 偏移/截断、文本编码、日期世纪、校验位、分发器。
  - `MrzTest`：TD1/TD2/TD3、错误校验位、非法日期、CR/LF。
  - `DgBiometricTest`：DG2 多脸/回退、DG3 图像与 FMR、DG4 眼位、逐偏移截断。
  - `DgTextTest`：DG5/7/8-10/11/12/13/16、UTF-8 回退、BCD 日期、未知 tag。
  - `MrvTest`：MRV-A/B、错误校验位/日期、`VisaRecord` 往返与签名验证。
- 模拟器：`EmrtdLdsParsersIntegrationTest`（PACE → CA → TA → 读 DG1–DG16 并解析）。
- 依赖守卫：`LayeringTest` 禁止 `host/` 出现 `org.jmrtd`，禁止
  `host/emrtd/lds/` 使用 `java.awt`/`javax.imageio`。

## 7. 已知限制

- DG8/DG9/DG10 的规范结构仍是 “To Be Defined”，card42 不解释厂商语义。
- DG13 的内容由签发国决定，没有可移植的字段表。
- DG3 的 ISO 19794-2 指纹细节点（minutiae）记录只保留完整 raw，不解析细节点。
- WSQ、JPEG-LS、JPEG 2000、PNG 只识别格式并保留字节；需要显示时由终端解码。
- 图像尺寸/质量来自 ISO 记录；DG5/DG7 的 JFIF 流没有尺寸字段，宽度/高度为 0。
- MRTD 的扩展文档号（TD1/TD2 中超过 9 位、占用可选区）未建模；按标准 9 位字段读取，
  额外内容保留在 optional data 中。
- 真实卡片的厂商扩展、非标准 CBEFF 嵌套按 `PARTIAL` + raw 返回，不猜测语义。

## 8. 参考

- ICAO Doc 9303-10 §4.6/§4.7、§5.2.3；Doc 9303-4；Doc 9303-7；Doc 9303-3 Appendix A。
- ISO/IEC 7816-11（CBEFF）；ISO/IEC 19794-2/-4/-5/-6。
- 现有实现：`host/emrtd/lds/common/`、`host/emrtd/lds/lds1/`、`host/emrtd/lds/lds2/Mrv.java`。
