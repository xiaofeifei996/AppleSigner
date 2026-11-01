# AppleSigner 1.41.0

Standalone Objective-C/UIKit app scaffold for Dopamine rootless.

## New in 1.0.0 — signing preparation
- Generates per-component XML `.entitlements` templates from the imported provisioning profile.
- Checks each component Bundle ID against the selected profile's App ID pattern.
- Rewrites the template's `application-identifier` to the Team ID + component Bundle ID for compatible components.
- Expands wildcard keychain access group patterns conservatively.
- Writes a `SigningPlan.json` manifest and templates to `Documents/AppleSignerWork/Unpacked/SigningPreparation`.
- Components that do not match the selected profile are marked as requiring a separate provisioning profile; no template is generated for them.

## Important limitations
- **This release does not perform code signing.** It does not write a Mach-O code signature, CodeDirectory, CMS blob, CodeResources, or repackage an IPA.
- Entitlements templates are derived from the selected profile and are preparation artifacts only. Review them against the app's actual requirements and Apple's authorization rules before use.
- A single profile is not assumed to authorize every nested component. Non-matching extensions/frameworks are flagged.
- No cryptographic signature validation or trust-chain validation is performed.
- Automatic Apple ID enrollment is not implemented. The app does not collect Apple ID passwords or 2FA codes.
- ZIP64 archives are unsupported.
- Source has not been compiled with Theos or tested on a Dopamine device.

## Build
Requires Theos and an iOS SDK. Run `make package`.

\n## 1.1.0：Mach-O 签名数据只读解析\n\n新增 `MachOSignatureInspector`：\n- 扫描解包目录中各 `.app`、`.appex`、`.framework` 的 `Info.plist`，定位 `CFBundleExecutable`。\n- 识别 thin Mach-O 32/64 位及 fat/universal Mach-O slice，检查边界。\n- 解析 `LC_CODE_SIGNATURE` 的 dataoff/datasize。\n- 读取 EmbeddedSignature SuperBlob 索引，识别 CodeDirectory、CMS Blob、Entitlements Blob 和 DER Entitlements Blob。\n- 提取 CodeDirectory 的版本、flags、CodeLimit、CodeSlots、hash 类型/长度、页大小指数和 Identifier（若可读取）。\n- 新增“解析 Mach-O 签名数据（1.1）”按钮。\n\n**安全边界：**此功能只读，不修改二进制；不验证 CodeDirectory 哈希、CMS 签名与证书信任链，不代表签名有效。它不是签名器，也不会生成或伪造 CodeDirectory/CMS。Apple Developer 完整签名、资源封印、嵌套组件签名和 IPA 重打包仍未实现。\n\n本版本尚未使用 Theos 编译，亦未在 Dopamine / iOS 26 真机测试。Mach-O 解析器需要进一步用真实 arm64/arm64e 与 fat IPA 样本验证。\n
\n## 1.2.0：CodeDirectory 代码页哈希验证\n\n在 1.1.0 的只读 Mach-O 解析基础上，新增 CodeDirectory 代码页哈希校验：\n- 读取 CodeDirectory 的 hashOffset、hashSize、hashType、nCodeSlots、nSpecialSlots、codeLimit 与 pageSize。\n- 支持 SHA-1、SHA-256、截断 SHA-256 和 SHA-384 页面摘要计算。\n- 按 CodeDirectory 声明的页面大小重新计算代码页摘要，并与签名中的 code slot 摘要逐项比较。\n- 报告声明槽位数、成功匹配数、不匹配数及边界/算法不支持情况。\n- 新按钮显示哈希校验结果。\n\n**限制：**只验证 CodeDirectory 的代码页槽位；不验证 special slots（Info.plist、CodeResources 等）、CMS 签名、证书链、provisioning profile、entitlements 一致性或整个签名的可信状态。哈希全部匹配也不等于签名有效。当前不创建或写入签名，不修改 Mach-O。\n\n本版本尚未 Theos 编译，也未在 Dopamine / iOS 26 真机测试。需要用真实 arm64/arm64e、fat/universal 和不同 CodeDirectory 版本样本进一步验证。\n
\n## 1.3.0：独立 CodeDirectory 模板生成\n\n新增 `CodeDirectoryBuilder`：\n- 对 thin Mach-O 执行边界检查，解析 load commands 和已有 `LC_CODE_SIGNATURE`。\n- 按 4KB 页面计算 SHA-256 code slot 哈希。\n- 生成独立的 CodeDirectory 二进制模板文件，输出到 `Documents/AppleSignerWork/CodeDirectoryTemplates`。\n- 不修改原始 Mach-O，也不将模板嵌入签名区。\n\n**重要限制：**这是结构/哈希模板，不是可用签名。Identifier 使用 `AppleSigner.Template` 占位值，special slots 为 0，不含 CMS、不含完整 entitlements/CodeResources，也没有写入 Mach-O 的签名 load command。Fat/Universal Mach-O 当前拒绝处理，需先按架构切片。模板不可用于安装或宣称签名成功。\n\n本版本未 Theos 编译、未在 Dopamine / iOS 26 真机测试。真实签名仍需补齐正确的 CodeDirectory 版本与字段、special slots、SuperBlob、CMS 私钥签名、嵌套组件由内向外签名、资源封印和 IPA 重打包。\n
\n## 1.4.0：SuperBlob 结构封装\n\n新增 `SuperBlobBuilder`：\n- 读取并校验独立 CodeDirectory blob 的 magic 与长度字段。\n- 生成大端序 Embedded Signature SuperBlob 头和索引表。\n- 将 CodeDirectory 放入 `CSSLOT_CODEDIRECTORY`（slot 0）。\n- 输出独立 `.superblob.template` 文件，不修改原始 Mach-O。\n- 新增“封装 SuperBlob 模板（1.4）”按钮，批量处理 1.3 生成的模板。\n\n**限制：**当前 SuperBlob 只含一个 CodeDirectory 索引项，不含 CMS Blob、Entitlements、Requirements、DER Entitlements、CodeResources 或其他 special slots；未写入 `LC_CODE_SIGNATURE` 区域，也未更新 Mach-O load commands。该产物仅用于验证数据布局，不是可安装签名。\n\n本版本未 Theos 编译、未在 Dopamine / iOS 26 真机测试。下一阶段需处理签名区布局与 `LC_CODE_SIGNATURE` 的安全更新策略，再实现 CMS 签名与资源封印。\n
\n## 1.5.0：Mach-O 签名区安全暂存写入\n\n新增 `MachOSignatureStager`：\n- 校验 SuperBlob 基本头、Mach-O 格式和 Load Commands 边界。\n- 仅处理已有 `LC_CODE_SIGNATURE` 且签名区有效、16 字节对齐、容量足够的 thin Mach-O。\n- 将 SuperBlob 写入新生成的 staged 副本，并更新副本中 `LC_CODE_SIGNATURE.datasize`。\n- 不改原始解包二进制；不扩大文件、不移动代码段、不擅自新增 Load Command。\n- 无签名区或空间不足时明确拒绝，不做危险猜测。\n\n**重要限制：**目前写入的是无 CMS 的模板 SuperBlob；CodeDirectory Identifier 仍为占位值且没有 special slots，写入副本后并不构成有效签名，不可安装。该功能只是验证签名区写入路径和原文件保护策略。尚未处理 Fat/Universal 切片、无预留区 Mach-O 扩容、CMS、CodeResources、嵌套签名或 IPA 重打包。\n\n本版本未 Theos 编译、未在 Dopamine / iOS 26 真机测试。\n

## 1.6.0：P12 私钥签名能力验证（前置探测）

新增 `SigningIdentityVerifier`：
- 使用系统 `SecPKCS12Import` 在本地导入 P12 身份。
- 通过 `SecIdentityCopyPrivateKey` 取得内存中的私钥引用。
- 对本地测试消息执行 SHA-256 RSA PKCS#1 v1.5 或 ECDSA X9.62 签名。
- 使用对应公钥执行 `SecKeyVerifySignature` 自验证。
- UI 新增“验证 P12 私钥签名能力（1.6）”入口；密码不写入文件或日志。
- 测试签名和私钥引用在验证流程结束后释放；不导出私钥。

**重要限制：**这不是 CMS/PKCS#7 生成器，不会生成 Apple Code Signing CMS，不会修改 Mach-O，也不会使 IPA 可安装。验证通过只说明当前设备的 Security.framework 能使用该 P12 私钥完成所选算法的签名与公钥自验证；不代表证书链可信、证书有效期/撤销状态通过、profile 匹配或 Apple 签名格式完整。当前仍未实现 CodeResources、special slots、CMS blob、嵌套组件签名与 IPA 重打包。

本版本未使用 Theos 编译，未在 Dopamine / iOS 26 真机测试。请勿将此源码包视为可安装签名器。


## 1.7.0：CMS 前置条件检查

新增 `CMSPreflight`：
- 本地导入 P12，读取身份私钥和证书链条目。
- 识别 RSA / EC 私钥，并检查 Security.framework 对 SHA-256 签名算法的支持情况。
- 对待签数据计算 SHA-256 摘要，作为后续 CMS `messageDigest` 属性的输入检查。
- UI 增加“检查 CMS 签名前置条件（1.7）”。

**边界：**本版本没有生成 CMS ContentInfo / SignedData / SignerInfo，不会构造 signedAttrs，不会执行 CMS 签名，也不会修改 Mach-O 或 IPA。证书链条目数量不等于证书链信任验证；摘要计算不等于 CMS 签名。此模块只是 CMS 实现前的材料与算法预检。

本版本未使用 Theos 编译，未在 Dopamine / iOS 26 真机测试。


## 1.8.0：Detached CMS 测试生成（实验）

新增 `CMSDetachedBuilder`，尝试构造标准 CMS `ContentInfo(SignedData)` 的 detached 结构：
- `digestAlgorithms` 使用 SHA-256。
- `encapContentInfo` 使用 detached `id-data`。
- `signedAttrs` 包含 `contentType` 与 `messageDigest`。
- `SignerInfo` 使用证书 issuer + serialNumber 标识签名者。
- 附带 P12 导入得到的证书链 DER。
- 使用 Security.framework 的 RSA PKCS#1 v1.5 / ECDSA SHA-256 对 DER 编码的 signedAttrs SET 签名，并用公钥进行本地自验证。
- UI 仅对固定测试文本生成 `Documents/AppleSignerWork/CMS-Tests/detached-test.p7s`。

**非常重要：**这是实验性 detached CMS 编码器，不是 Apple Code Signing CMS。当前没有对输出执行独立 CMS 解析器互操作验证；证书链未做信任/有效期/撤销验证；未加入 Apple 代码签名所需的全部属性与特殊规则；没有将 CMS 放入 Mach-O SuperBlob，也没有生成 CodeResources、special slots、嵌套组件签名或重打包 IPA。不得将此 `.p7s` 用于安装或分发 IPA。

本版本未使用 Theos 编译，未在 Dopamine / iOS 26 真机测试。请先用 OpenSSL 等独立 CMS 工具对测试输出进行互操作验证，再推进 Code Signing 集成。


## 1.9.0：Detached CMS 本地验证

新增 `CMSDetachedVerifier`，用于检查本项目 1.8.0 实验生成器输出：
- 解析 CMS ContentInfo / SignedData / detached id-data / SignerInfo 基本结构。
- 按 issuer + serial 匹配签名者证书。
- 重新计算原始内容 SHA-256，并与 signedAttrs 的 messageDigest 比较。
- 使用签名者证书公钥验证 signedAttrs 签名值。
- UI 新增“验证独立 CMS 测试文件（1.9）”。

**验证边界：**该验证器仅支持本项目当前输出的窄子集：detached id-data、单一 SignerInfo、SHA-256、RSA PKCS#1 v1.5 或 ECDSA。它不是通用 CMS 验证器，不验证证书链信任、有效期、撤销状态、签名时间戳或 Apple Code Signing 规则。验证通过只说明摘要与签名值匹配。

本版本未使用 Theos 编译，未在 Dopamine / iOS 26 真机测试。请在真实设备编译后，再用独立 OpenSSL CMS 工具交叉验证，不能将本地自验证视为互操作性证明。


## 1.10.0：DER 编码约束收紧

- CMS 生成器按完整 DER 编码对证书集合执行 SET OF 排序，避免直接沿用 P12 导入顺序。
- 验证器增加 SignedData v1、单一 SHA-256 digestAlgorithm、signedAttrs `contentType=id-data` 检查。
- UI 增加 DER/CMS 约束检查入口，复用独立验证器核对摘要与签名值。

**范围限制：**此处的“DER 约束检查”只覆盖本项目当前支持的 detached CMS 子集，不是完整 ASN.1/CMS 标准验证器。尚未验证证书链信任、算法参数的全部规范化要求、证书有效期/撤销状态、Apple Code Signing 特殊属性或 Mach-O 集成。

本次仅做源码级检查与 ZIP 完整性检查；没有 Theos 编译、iOS 真机运行或 OpenSSL 交叉验证。请勿将测试 `.p7s` 用于 IPA 安装或分发。


## 1.11.0：OpenSSL 互操作导出

- 修正 1.10.0 严格检查中的版本字节判断和测试文件 URL 构造。
- 增加导出 detached CMS 与原始内容的系统分享入口。
- 增加 `CMS_OPENSSL_INTEROP.md` 与 `verify-cms-openssl.sh`，可在 macOS/Linux 用 OpenSSL 独立验证并比较输出内容。
- OpenSSL 尚未在本次自动运行中针对 iOS App 生成的 CMS 文件执行；需要用户从设备导出真实生成文件后运行脚本。未做 Theos 编译或 iOS 真机测试。


## 1.12.0：CMS 验证器约束强化

- 新增 SignerInfo v1 与 SHA-256 digestAlgorithm 一致性检查。
- signedAttrs 的 contentType/messageDigest 属性必须各出现且仅出现一次。
- 验证 CertificateSet 的 DER SET OF 排序。
- 更新互操作测试记录与错误反馈说明。
- 未进行 Theos 编译、iOS 真机运行或实际 iPhone 输出的 OpenSSL 交叉验证。


## 1.13.0：DER SET 与算法参数检查

- 增加 digestAlgorithms、signerInfos、signedAttrs 的 DER SET OF 顺序检查。
- 检查证书序列号 INTEGER 的正数规范编码。
- 检查 RSA/ECDSA CMS 签名算法参数形式。
- 检查 CertificateSet 是否完整解析，拒绝尾部截断/非法元素。
- 以上仍是受限子集检查，不能替代完整 ASN.1/CMS 库；尚未 Theos 编译或真机测试。


## 1.14.0：Provisioning Profile 授权能力审计

新增“描述文件授权能力审计”：报告描述文件中的 Team ID、Application ID 模式、DeveloperCertificates 数量、设备授权范围、`get-task-allow`、`aps-environment`、Keychain Access Groups 与 App Groups；若已导入 P12，则将 P12 Leaf 证书 DER 与描述文件 `DeveloperCertificates` 做精确匹配；若已选择 IPA，则逐个报告主 App 与扩展组件 Bundle ID 是否符合描述文件的 Application Identifier 模式。

本功能属于本地预检，不会生成或修改签名。它不读取 IPA 中现有签名的实际 Entitlements，也不验证 Apple 证书链信任、撤销状态或 Apple Code Signing CMS 规则；组件 ID 匹配不代表扩展的全部授权 Entitlements 都获准。描述文件和证书有效期仍需分别检查。

**验证状态：** 本源码包仅完成静态源码整理与 ZIP 完整性检查；当前环境没有 Theos/iOS SDK，未完成 Theos 编译，也未在 Dopamine / iOS 26 真机运行。


## 1.15.0：提取 IPA 现有 XML Entitlements

新增 `EntitlementsAudit`：
- 扫描已解包 IPA 中 App、App Extension、Framework 的可执行文件。
- 复用 Mach-O 签名结构解析结果，定位 `CSSLOT_ENTITLEMENTS`（magic `0xfade7171`）。
- 对每个支持的 Mach-O slice 读取 Blob，检查长度与 magic，再解析 XML/Binary plist。
- 将成功解析的字典导出为 XML `.entitlements.plist`，保存在 `Documents/AppleSignerWork/ExtractedEntitlements`。
- UI 新增“提取 IPA 现有 Entitlements（1.15）”入口。

**限制：**当前只提取 XML Entitlements Blob，不解码 DER Entitlements Blob（`0xfade7172`）；对无签名、结构异常或不受支持的二进制只报告状态，不猜测缺失授权。该功能不验证 CMS、CodeDirectory、资源封印、证书链或 Apple 授权有效性。提取成功不代表签名有效，也不执行签名或修改 IPA。

本版本源码尚未通过 Theos 编译，未在 Dopamine / iOS 26 真机验证。建议下一阶段将提取出的 Entitlements 与所选 provisioning profile 的授权集合逐项比对，并将“允许 / 不允许 / 无法判定”分开报告。


## 1.16.0：IPA Entitlements 与描述文件授权比较

新增 `EntitlementsProfileComparator` 与 UI 入口：
- 将已提取的 XML Entitlements 与已导入 provisioning profile 的 `Entitlements` 字典逐键比较。
- 字符串支持精确匹配及末尾 `*` 通配；数组逐项验证；字典递归比较。
- 输出允许、不允许、无法判定三类结果，并列出明确不匹配的键。
- 比较前自动重新扫描已解包目录并导出当前可识别的 XML Entitlements。

**限制：**这是一套通用授权值比较启发式规则，不是 Apple 全部 entitlement 语义的完整实现。布尔值、数组、通配符及特殊授权存在平台规则差异；DER Entitlements、扩展独立 profile、Apple 私有授权、CMS/CodeDirectory/资源封印及证书链信任不在本次验证范围。结果不能作为 IPA 可安装或签名有效的保证。本版本未通过 Theos 编译，也未在 Dopamine / iOS 26 真机验证。


## 1.17.0：DER Entitlements 解码

新增 `DEREntitlementsDecoder`：
- 识别签名 Blob magic `0xfade7172`，校验 Blob 长度和边界。
- 解码常见 Apple DER Entitlements 结构：外层 SET、每个 entitlement 的 SEQUENCE（UTF8String key + value）。
- 支持 UTF8String、BOOLEAN、INTEGER、SEQUENCE 数组；检查长度最短编码、边界、嵌套深度、重复 key 和 key 顺序。
- XML 与 DER 两种格式分别导出为 `.entitlements.plist`，供后续授权比较。
- 继续保留原始格式标签，避免把 DER 数据误报为 XML。

**限制：**这是受限 DER 解码器，不是通用 ASN.1 实现；遇到未知 Tag、非预期外层结构、复杂值类型或特殊 Apple 扩展会报错，不会猜测。BOOLEAN 接受 00/01/FF 以兼容实际样本差异，因此不是严格 X.690 DER 规范验证。尚未用真实 iOS 15+ Mach-O 样本或 Apple `codesign` 输出进行交叉验证。Apple 官方 TN3125 说明现代系统使用 DER 形式，并可通过 `codesign --display --entitlements` 查看；本工具仍需真实样本验证。参见 Apple TN3125：https://developer.apple.com/documentation/technotes/tn3125-inside-code-signing-provisioning-profiles

本版本未通过 Theos 编译，未在 Dopamine / iOS 26 真机验证；不执行签名，也不保证 IPA 可安装。


## 1.18.0：主 App / Extension 多描述文件匹配

新增批量导入 `.mobileprovision` 与组件映射报告：
- 一次选择多份 provisioning profile，逐份通过现有 `ProfileInspector` 解码并保存在内存列表。
- 根据 IPA 中已识别的主 App、App Extension Bundle ID，与每份 profile 的 `application-identifier` 精确匹配或末尾 `*` 通配匹配。
- 多候选时优先精确匹配，其次选择更具体的通配前缀。
- 检查所选 profile 是否过期，并显示 Team ID、App ID、候选数量。
- 若已导入 P12，比较 P12 leaf certificate DER 与 profile `DeveloperCertificates` 中证书是否完全一致；未导入则明确显示无法判断。
- Framework 明确标记为通常随宿主签名，不单独要求 profile。

**限制：**当前是 profile 候选筛选和证书 DER 相等性预检，不是完整签名策略引擎。不会自动识别开发/Ad Hoc/App Store/企业分发的全部选择规则；不验证 profile CMS 签名信任链、证书有效期/撤销、设备 UDID 包含、所有 entitlement 语义或最终代码签名。多候选 profile 仅按 App ID 精确程度排序，必须人工确认。批量导入的 profile 只保存在本次运行内存，未持久化。

本版本未通过 Theos 编译，未在 Dopamine / iOS 26 真机验证。


## 1.19.0：签名映射计划导出

新增 `SigningPlanExporter`：
- 将 IPA 组件列表与批量导入的 provisioning profiles 建立映射。
- 按精确 App ID、通配符具体程度选择候选，并将多候选标记为人工复核。
- 标记缺少 profile、profile 过期、P12 证书不匹配、证书状态未知。
- Framework 标记为由宿主签名流程覆盖，不独立要求 profile。
- 输出机器可读 JSON 到 `Documents/AppleSignerWork/SigningPlans/`，并通过系统分享面板导出。
- 计划含格式版本、IPA 身份、组件状态、所选 profile 摘要和总体统计。

**限制：**该计划只是签名前的映射/预检结果，不是签名任务执行器。当前 profile 选择仍依赖 Bundle ID 通配和候选排序；不会自动决定全部分发策略，也不验证设备 UDID、证书信任/撤销、所有 Entitlements 特例、CMS、CodeDirectory、资源封印或最终 IPA 可安装性。候选多于一个必须人工确认。不会修改原 IPA。

本版本未通过 Theos 编译，未在 Dopamine / iOS 26 真机验证。


## 1.20.0：签名顺序计划与 App ID 匹配修正

本版本修正一个影响映射结果的关键问题：描述文件的 `application-identifier` 通常包含 Team ID 前缀（例如 `TEAMID.com.example.app`），旧版直接拿它与 IPA 的 Bundle ID 比较，可能导致本应匹配的 profile 被误判为缺失。现在先按 Team ID / ApplicationIdentifierPrefix 去除前缀，再进行 Bundle ID 匹配；通配符限定为完整后缀 `.*`，避免 `com.example.*` 错误匹配 `com.exampleevil.app`。

签名计划增加：
- `bundlePath`、`infoPlistPath`、`executablePath`，用于追踪被识别组件在 IPA 中的位置。
- `signingOrder`：按 Bundle 嵌套深度由内向外排列，主 App 排在最后；同层组件采用稳定排序。
- `action`、`requiresProfile`、`executionReadiness`，明确 Framework 不单独要求 profile，但仍属于需要先处理的嵌套代码。
- `executionStatus`、`signingOrderPolicy` 和 `discoveryLimitations`，明确当前只生成计划，不执行签名，并列出未完整识别的载荷类型。

**重要限制：**顺序只覆盖 IPAInspector 当前识别的 App、App Extension、Framework；XPC Services、Watch、App Clips、独立 dylib、扩展内部嵌套代码等仍可能遗漏，不能据此直接执行签名。该版本没有实现签名执行器，也没有声称计划完整覆盖 IPA 中所有代码。

本版本尚未通过 Theos 编译，未在 Dopamine / iOS 26 真机验证；没有真实 Apple IPA 样本用于端到端验证。


## 1.21.0：修复编译语法并扩展嵌套 Bundle 扫描

- 修复 `SigningPlanExporter.m` 中 UUID 排序表达式的 Objective-C 字符串语法错误。
- `IPAInspector` 不再只识别主 App 直接子级的 PlugIns / Frameworks，而是扫描 `Payload/` 下标准 Bundle 目录中的 `Info.plist`，识别 `.app`、`.appex`、`.framework`、`.xpc`。
- 分类覆盖主 App、嵌套 App、Watch App、App Clip、App Extension、XPC Service、Framework；可识别扩展内部的 Framework / XPC 等标准 Bundle。
- 签名映射计划继续按路径嵌套深度由内向外排序，Framework 不分配 profile；扩展、XPC、Watch App、App Clip 和嵌套 App 会进入 profile 匹配流程。
- UI 版本和操作标签更新到 1.21.0。

**边界：**扫描器只识别标准 Bundle `Info.plist`，不等于完整识别所有签名代码。独立 dylib、裸 Mach-O、无标准 Info.plist 的代码载荷仍未覆盖；Watch / App Clip / XPC 的专用分发策略也未审计。路径深度排序只是计划提示，不是 Apple 签名工具认可的完整依赖拓扑。

**验证状态：**完成源码静态修改与 ZIP 完整性检查；未运行 Theos 编译，未进行 iOS 26 / Dopamine 真机测试，也未用真实 IPA 样本验证扫描结果。


## 1.22.0：独立动态库路径盘点

- IPAInspector 现在会记录 `Payload/` 下 ZIP 路径以 `.dylib` 结尾的文件，形成 `NestedCode` 清单。
- 签名映射 JSON 将 dylib 作为独立嵌套代码条目加入统一顺序表，不要求它单独匹配 provisioning profile。
- UI 的 IPA 解析结果会显示 Bundle 组件数量和 dylib 路径数量。
- 动态库条目标记为 `inventory-only`，明确它只是按文件扩展名发现，不代表已经验证 Mach-O 魔数、架构、签名状态或可执行性。

**限制：**无 `.dylib` 扩展名的裸 Mach-O、脚本加载的非标准代码、其他资源目录中的代码载荷仍可能遗漏。路径深度不是实际 Mach-O 依赖图。该版本仍不执行签名。

**验证状态：**仅做源码静态断言和 ZIP 完整性检查；未运行 Theos 编译，未在 iOS 26 / Dopamine 真机验证，也未用真实 IPA 样本验证扫描准确率。


## 1.23.0：Mach-O 头与架构盘点（只读）

- 对已发现 Bundle 的 `CFBundleExecutable` 路径及 Payload 内 `.dylib` 路径读取 ZIP 条目前缀，不将大型二进制完整解压到内存。
- 支持 ZIP stored / deflate 前缀读取；识别 thin Mach-O 32/64-bit 与 fat/fat64 架构表，记录 CPU type/subtype、架构名称和 thin 文件类型。
- 对非 Mach-O、截断头、ZIP 条目异常、压缩方式不支持、条目缺失分别记录状态，并把结果关联到签名计划。
- 这只是头部/架构清点，不验证 CodeDirectory、签名、fat slice 边界完整性、依赖关系或可安装性。未发现的裸 Mach-O 仍可能遗漏；ZIP64 不支持。
- 未在 Theos 编译，未在 Dopamine / iOS 26 真机运行，也未使用真实 IPA 样本验证。

## 1.24.0：Fat Mach-O 切片边界审计与 ZIP 本地头校验

- Fat / Fat64 架构表现在检查每个 slice 的偏移、长度是否落在完整二进制范围内，拒绝零长度、落入架构表的切片，并检测切片重叠及对齐指数异常。
- 架构清单逐项输出 `BoundsValid`、`AlignmentValid`、`SliceOffset`、`SliceSize` 和 `AlignmentExponent`；整体状态可为 `invalid-fat-slice-bounds`、`overlapping-fat-slices` 或 `invalid-fat-slice-alignment`。
- ZIP 前缀读取增加本地文件头加密标志与压缩方法一致性检查，避免仅依据中央目录方法读取不一致条目。
- 新增 `Tests/generate-ipa-fixtures.py`，可生成 stored/deflate、thin arm64、fat valid、fat overlap、fat out-of-bounds、fat CPU mismatch、非 Mach-O slice 七类合成 IPA，便于后续设备/编译环境手工验证。
- 合成 IPA 仅用于解析器测试，不是可安装 App，不包含有效代码签名。

限制：本版本只检查 Fat slice 的元数据范围/重叠/对齐，不读取每个 slice 内部的 Mach-O 头，也不检查 CodeDirectory、CMS、资源封印或签名有效性。ZIP64 仍不支持。尚未完成 Theos 编译及 iOS 26 / Dopamine 真机测试。


## 1.25.0：Fat Mach-O slice 内部头部核对（只读）

- 对 Fat / Fat64 中位于当前 ZIP 前缀缓冲区内、且边界有效的 slice，读取其内部 thin Mach-O magic、32/64 位格式、CPU type、CPU subtype 与 file type。
- 将 slice 内部头部的 CPU type/subtype 与 Fat 架构表逐项比较；不一致时标记 `fat-architecture-mismatch`，内部头部不是 Mach-O 或截断时标记 `invalid-fat-slice-header`。
- 对超出当前 128 KiB 前缀范围的 slice 明确标记 `header-outside-prefix`，整体状态为 `slice-header-not-read`；不会假称所有 slice 均已验证。
- 每个架构条目新增 `SliceHeaderStatus`，可用时附带 `SliceHeaderFormat`、`SliceFileType`、`HeaderCPUType` 与 `HeaderCPUSubtype`。

**限制：**当前 ZIP 读取器只保留文件开头最多 131080 bytes，不能随机解压读取偏移更大的 slice；因此某些真实通用二进制只会得到 `slice-header-not-read`。本功能不验证 slice 内部 load commands、CodeDirectory、CMS、资源封印或签名有效性。仍未完成 Theos 编译或 iOS 26 / Dopamine 真机测试。


## 1.27.0：ZIP 内 Fat 切片偏移读取与合成测试（只读）

- 新增 ZIP 条目逻辑偏移范围读取：stored 条目直接定位；deflate 条目从流起点分块解压并丢弃前段数据，只保留目标 Mach-O 切片头部。
- Fat/Fat64 架构表中位于前缀窗口之外的切片，现在尝试按切片偏移读取内部 Mach-O 头，并核对 CPU Type / CPU Subtype。
- 读取失败、压缩方式不支持、ZIP 本地头不一致和范围越界均保留为明确状态，不将未读取标记为有效。
- 新增 `Tests/test_ipa_fixtures.py`，对 9 种合成 IPA 进行独立参考测试，覆盖 ZIP stored/deflate、Fat 有效/异常切片，以及超过 128 KiB 的切片偏移读取。
- 本轮参考测试验证的是 ZIP 样本及独立 Python 参考读取逻辑，不是对 `IPAInspector.m` 的直接执行或等价性证明。仍不支持 ZIP64；deflate 偏移读取需要从流起点顺序解压，时间成本可能随切片偏移增加。
- 尚未通过 Theos 编译或 iOS 26 / Dopamine 真机验证。


## 1.28.0：ZIP 结构安全审计

- EOCD 必须位于文件尾部声明的 comment 结束位置，避免误认 ZIP comment 内的伪签名。
- 检查单磁盘 ZIP、EOCD 条目数、中央目录长度和记录数的一致性。
- 明确拒绝 ZIP64 哨兵值及分卷 ZIP，不把它们当作普通 ZIP 解析。
- 拒绝重复的 `Payload/` 路径，避免同名条目覆盖。
- 校验 Payload 本地文件头、压缩方法、flags、文件名及压缩数据边界与中央目录一致。
- 完整解压 Info.plist 后校验 CRC32；只读取二进制前缀时不声称 CRC 已完整验证。
- 对 bit 3 data descriptor 条目使用中央目录的大小/CRC 元数据，不要求本地头重复存储这些值。

**限制：**本版本仍不支持 ZIP64、多磁盘 ZIP、加密条目或非 UTF-8 文件名；不支持的输入应明确拒绝。CRC32 不是密码学完整性证明。对大型 Mach-O 只读取部分内容时，不会验证整个条目的 CRC。尚未在 iOS Objective-C 运行环境执行 IPAInspector 测试，未 Theos 编译，未在 Dopamine / iOS 26 真机验证。


## 1.29.0：IPA 解压路径与资源安全

- 解压到新建的唯一 staging 目录，不再先删除调用方传入的目标目录。
- 拒绝绝对路径、反斜杠路径、盘符/冒号路径、空路径组件、`.` 和 `..`。
- 对 NFC 规范化并忽略大小写后的路径键进行冲突检测。
- 拒绝符号链接、设备文件、FIFO 和其他特殊文件。
- 限制 ZIP 条目数（20,000）、单条目解压大小（256 MiB）、总解压大小（1 GiB）和压缩比（200:1）。
- 校验本地文件头与中央目录中的 flags、压缩方法、文件名和数据边界。
- 明确拒绝 ZIP64 和分卷 ZIP。
- 解压失败可能留下未完成的 staging 目录；本版本尚未实现失败后的统一回滚清理。
- 这是路径/资源策略的独立 Python 参考测试，不等于 Objective-C IPAExtractor 已被直接执行或编译验证。


## 1.30.0：解压事务与失败回滚

- 将原解压实现封装为内部执行方法，由公开入口统一管理 staging 生命周期。
- staging 目录创建后立即登记；任何解压失败或 Objective-C 异常都会尝试删除本次 staging 目录。
- 如果清理失败，将清理错误附加到原始错误信息，避免静默丢失。
- 成功时保留唯一 staging 目录并返回其 URL，调用方继续使用返回值。
- 增加文件/目录父子路径冲突检测；允许正常目录作为子项的父路径，但拒绝文件与其子路径冲突。
- 对失败回滚、成功保留和路径冲突添加独立 Python 参考测试。

**限制：**事务测试是 Python 模型测试，不是 Objective-C 运行测试。进程被系统强制终止、设备断电或文件系统故障时，无法保证执行清理；后续仍可增加启动时清理过期 staging 目录。尚未 Theos 编译，未在 Dopamine / iOS 26 真机验证。


## 1.31.0：过期解压临时目录清理

- staging 目录创建后立即写入专用标记文件；解压成功时移除标记，失败时由 1.30.0 回滚逻辑删除整个 staging。
- App 启动时仅扫描 `Documents/AppleSignerWork` 目录的直接子项。
- 仅清理名称以 `AppleSigner-Unpacked-` 开头、带有专用普通文件标记、确认为目录且最后修改时间早于 24 小时的项目。
- 跳过符号链接、无标记目录、最近修改目录和其他名称的目录。
- 增加过期清理策略参考测试。

**限制：**参考测试模拟清理策略，不执行 Objective-C 实现。清理函数忽略启动调用处的错误，不会阻断 App 启动；遇到属性读取或删除错误会保留项目。未进行 Theos 编译或 Dopamine / iOS 26 真机测试。


## 1.32.0：ZIP 本地记录与压缩流深度审计

- 所有 ZIP 条目（包括目录）都必须具有有效本地文件头；目录不再绕过本地头验证。
- 对无 Data Descriptor 的条目，核对本地头 CRC、压缩长度和解压长度与中央目录一致。
- 对带 bit 3 的条目，支持 32-bit、有签名或无签名的 Data Descriptor，并核对 CRC 与长度。
- 明确拒绝 ZIP64 extra field、损坏的 extra field，以及当前解压器不支持的通用标志位。
- Deflate 解压必须达到 `Z_STREAM_END`，完整消费声明的压缩输入，并精确产生声明的输出长度；尾随压缩数据不再被忽略。
- 对 Stored 条目核对压缩长度和解压长度，并对所有条目校验 CRC32。
- 收集每条本地记录（本地头、名称/扩展字段、压缩数据和 Data Descriptor）的区间，拒绝相互重叠或覆盖中央目录的记录。
- 保留 staging 回滚；ZIP 不得覆盖内部清理标记文件。
- 新增独立 Python 对抗样本测试，覆盖 Stored/Deflate、两种 Data Descriptor、CRC 不匹配、尾随 Deflate 数据和本地记录重叠。

**限制：**新增 8 项测试是独立 Python 参考验证器，不是 Objective-C 执行测试；已有 Python 测试也不直接执行 `IPAExtractor.m`。本版本未 Theos 编译，未在 Dopamine / iOS 26 真机测试。ZIP64 仍不支持。

## 1.33.0：签名文件结构审计语义修正

- 不再把 `_CodeSignature` 与 `CodeResources` 同时存在描述为“已签名”；`LooksSigned` 兼容字段固定为 false，新增 `HasSignatureArtifacts` 与 `SignatureArtifactStatus`。
- 检查 `_CodeSignature` 必须是目录，`CodeResources` 与 embedded profile 必须是文件形态（不接受目录冒充）。
- `CodeResources` 即使能解析为 plist，也必须同时包含字典类型的 `files` 与 `rules` 才会标记为结构完整。
- 报告明确标注 `CryptographicVerification=not-performed`；没有验证 CodeDirectory 页面哈希、CMS/证书信任、资源哈希或嵌套代码封印。

**限制：**这是签名工件的静态结构审计，不是代码签名验证器。本版本未 Theos 编译，未在 Dopamine/iOS 26 真机测试；Objective-C 实现仍需真实 IPA 与独立签名工具交叉验证。


## 1.34.0：CodeResources 资源哈希有限审计

- 对 `files` 中 SHA-1 摘要以及 `files2` 中 `hash`/`hash2`（SHA-1/SHA-256）执行资源文件摘要核对。
- 检查资源相对路径，拒绝绝对路径、反斜杠、空路径段、`.`/`..` 和冒号路径；仅读取 bundle 内普通文件。
- 单个资源文件读取上限为 256 MiB；报告已核对、哈希不匹配、缺失和不支持的条目数量。
- 对 `cdhash`、未知结构、目录资源及其他不能可靠解释的条目明确标记为不支持，不将部分核对称为完整封印验证。

**限制：**这只是 CodeResources 中可识别文件摘要的有限核对。尚未实现 Apple 规则正则表达式的完整匹配语义、规则排除项与嵌套代码封印验证，也未验证 CodeDirectory special slots、CMS/证书信任或整个代码签名链。SHA-1/SHA-256 摘要匹配不代表签名有效。当前仍未 Theos 编译、未在 Dopamine / iOS 26 真机测试。


## 1.35.0：CodeDirectory Special Slot 与资源封印关联审计

- 暴露 CodeDirectory 中 special-slot 哈希摘要（slot 1 起按 Apple 负槽位顺序读取）。
- 修正 CodeDirectory 布局解释：`hashOffset` 指向 code slot 0，special-slot 哈希位于其前方；此前代码把 code-slot 起点错误地向后偏移 `nSpecialSlots * hashSize`，本版本已纠正。
- 加强 `hashOffset - nSpecialSlots * hashSize` 下界检查，防止 special-slot 哈希区间下溢。
- 仅当审计目录中只有一个 Bundle 且只发现一个 Mach-O 可执行文件时，按 CodeDirectory 声明的摘要算法核对 `Info.plist`（slot 1）与 `_CodeSignature/CodeResources`（slot 3）。
- 报告匹配、摘要不匹配、文件不可用和不支持项；不把未出现的 special slot 当作通过。
- 多 Bundle 目录暂时标记为部分审计，避免把所有 Mach-O 切片错误归属到每个 Bundle。

**限制：**slot 1/3 检查只覆盖已知资源 special slots；未覆盖 requirements、entitlements、DER entitlements 等其他 slot，也未验证 CMS、证书链或 provisioning profile 信任关系。多 Mach-O/多 Bundle 精确归属、真实 IPA 兼容性和 ObjC 编译仍待验证。未执行真正签名或修改 IPA。

本版本未 Theos 编译，未在 Dopamine / iOS 26 真机测试。Python 测试为独立参考模型，不等于 Objective-C 实现测试。


## 1.36.0：Mach-O 与 Bundle 精确归属

- `MachOSignatureInspector` 为每条可执行文件审计记录增加完整 `BundlePath` 与 `ExecutablePath`。
- `SignatureAudit` 按规范化后的 Bundle 完整路径关联 Mach-O 记录，不再依赖 Bundle basename 或“全目录只有一个 Mach-O”的猜测。
- 一个 Bundle 可关联多个 Mach-O 审计记录；同名 Extension/Framework 位于不同父 Bundle 时不会互相串用。
- 没有可归属 Mach-O 的 Bundle 明确报告 `special-slot-not-present`，不把缺失记录算作通过。

**限制：**路径映射仍基于解包后的真实文件系统路径；符号链接、大小写敏感文件系统差异和特殊嵌套签名布局仍需真实 IPA 验证。Special-slot 检查仅覆盖当前实现的 Info.plist 与 CodeResources 槽位，不等于完整签名验证。未 Theos 编译，未 Dopamine/iOS 26 真机测试。


## 1.39.0：多架构与多 CodeDirectory 审计

- Fat Mach-O 记录每个 slice 的 CPU type/subtype、偏移、长度与对齐指数，并检查 slice 越界、重叠、重复架构及对齐。
- 将 Fat header 架构与 slice 内 Mach-O header 的 CPU type/subtype 对照；不一致时明确标记。
- SuperBlob 子 Blob 不得指向索引表、越界或彼此重叠；发现结构错误时不再静默跳过。
- 每个 slice 保留 `CodeDirectories` 数组，逐个记录 primary/alternate CodeDirectory；兼容字段 `CodeDirectory` 优先指向 slot 0 primary。
- Special Slot 审计逐个检查该 slice 的所有 CodeDirectory，不再只审计单个目录。
- 新增 Python reference tests 覆盖 slice 重叠、重复架构、SuperBlob 重叠、多 CodeDirectory 与 CPU mismatch 场景。

**限制：** Python reference tests 仅验证参考规则，不会执行 Objective-C 实现；本版本未进行 Theos 编译、Dopamine/iOS 26 真机测试，也未完成完整 IPA 签名闭环。CodeDirectory 的部分扩展结构（例如 scatter 等）仍需后续明确支持或标记为 unsupported，不能据此宣称所有 Apple 签名格式均已覆盖。

## 1.39.0：CodeDirectory 扩展结构与页面哈希边界

- 按 CodeDirectory 版本检查扩展头最小长度：scatter、team、codeLimit64、exec segment、pre-encrypt 与 linkage 字段不再只凭总长度猜测。
- 读取并报告 `scatterOffset`、`teamOffset`、`preEncryptOffset`；可选偏移越界时标记结构无效。
- 检测到非零 scatter offset 时明确标记 unsupported，不再把 scatter 页面布局当作连续页面哈希计算。
- 对未来未知 CodeDirectory 版本明确标记 unsupported。
- 校验 hashType 与 hashSize 的组合，防止摘要长度不匹配仍进入页面验证。
- 保留逐 CodeDirectory 页面哈希核对，并继续按 `codeLimit64`（存在时）计算页面范围。
- 新增 Python reference tests 覆盖扩展字段长度、scatter、未来版本、可选偏移、摘要长度及 CodeSlots 数量。

**限制：**scatter 结构目前是明确不支持，而不是完整解析与验证；exec segment / linkage 字段仅检查版本对应的头长度，不代表已验证其语义。Python reference tests 不执行 Objective-C 实现；本版本未 Theos 编译，未在 Dopamine / iOS 26 真机测试，也未完成完整 IPA 签名闭环。


## 1.39.0：CodeDirectory scatter 页面哈希验证

- 解析 scatter vector（count/base/targetOffset/spare）及全零终止项。
- 按 CodeSlot 索引建立页面到可执行文件偏移的映射，逐页验证实际页面摘要。
- 检查 slot 重复/遗漏、向量终止、spare 字段、页面对齐、文件边界和页面范围重叠。
- scatter 结构不合法时报告具体失败原因，不回退为连续页面验证。
- 新增 Python reference tests；这些测试不等同于 Objective-C 编译或运行测试。

限制：尚未完成 Theos 编译、Dopamine/iOS 26 真机验证和完整 IPA 签名闭环。


## 1.40.0：Mach-O 签名区域与 IPA 一致性边界审计

- 完整验证 Mach-O Load Commands：命令数量、cmdsize 下限、4 字节对齐、命令区域边界及总长度必须一致。
- 拒绝多个 `LC_CODE_SIGNATURE`，并拒绝签名数据区域与 Mach-O Header/Load Commands 重叠或越界。
- SuperBlob slot index 不允许重复，避免同一 slot 被重复声明而产生歧义。
- CodeDirectory 的 identifier 必须位于有效 Blob 范围内并以 NUL 终止，不能与哈希数组重叠。
- Team 与 pre-encrypt 偏移必须位于 CodeDirectory 内，且不能指向哈希数组区域。
- CodeLimit 必须位于签名区域之前；签名区域与 CodeDirectory 的哈希数组边界分别检查。

**验证限制：**本版本的 Python 测试是参考模型/源码回归测试，不会执行 Objective-C 实现。尚未进行 Theos 编译、Dopamine 或 iOS 26 真机测试；不能据此宣称 IPA 签名闭环已经可用。


## 1.41.0：IPA 嵌套 Bundle 关系与签名依赖盘点

- 为每个发现的 App、Extension、Framework、XPC 等组件记录 Bundle 相对路径与嵌套深度。
- 按路径层级寻找最近的父 Bundle，输出 ParentBundlePath、ParentBundleIdentifier 与关系类型；不以 Bundle ID 前缀猜测父子关系。
- 对重复 Bundle Identifier、重复组件路径、可执行文件路径冲突及缺失父 Bundle 关系生成明确诊断。
- 汇总主 App、嵌套组件和独立 dylib 的代码清单，报告由内向外签名时需要关注的嵌套顺序。
- 将关系审计作为静态盘点，不把存在父子关系或签名文件当作签名有效证明。

**限制：**本版本只根据 IPA ZIP 路径与各组件 Info.plist 建立静态关系；尚未完整解析 Apple 的 nested-code 规则、Framework/PlugIns 特殊位置、符号链接语义或实际签名依赖验证。未验证 CMS/证书链、profile 信任、全部 CodeResources 规则或真实签名结果。Python 参考测试不执行 Objective-C 实现；未 Theos 编译，未在 Dopamine/iOS 26 真机测试。
