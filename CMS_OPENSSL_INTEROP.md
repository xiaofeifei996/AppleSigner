# AppleSigner 1.12.0：CMS 互操作测试记录

本版将验证器的检查范围收紧。它仍然只支持本项目生成器使用的窄 CMS 子集。

## 1. 先在设备上生成并导出材料
- 导入测试用 P12（请勿把 P12 或密码发给他人）。
- 生成 detached CMS 测试文件。
- 导出 `detached-test.p7s` 与 `test-content.bin`。

## 2. 在电脑上运行
```sh
sh verify-cms-openssl.sh
```

预期输出：
```text
CMS Verification successful
OpenSSL CMS 互操作验证通过（未验证证书链信任）
```

## 3. 如果失败
请保留完整终端错误文本，并确认两个导出文件来自同一次生成操作。不要上传 P12、私钥或密码。可只分享 `.p7s` 与测试内容文件；若测试内容含隐私，请先换成无敏感信息的固定文本重新生成。

## 4. 1.12.0 验证器新增检查
- SignerInfo version 必须为 v1。
- SignerInfo digestAlgorithm 必须为 SHA-256。
- signedAttrs 中 contentType 和 messageDigest 各恰好出现一次。
- CertificateSet 的证书 DER 编码必须按 SET OF 字典序排列。

## 限制
这不是完整 DER/CMS 解析器；不会验证证书链信任、有效期、吊销、时间戳、Apple 专用 CMS 属性或 Apple Code Signing 的全部规则。本次没有 iOS SDK/Theos 编译环境，因此未编译 App；也没有从 iPhone 获取实际 `.p7s` 文件做 OpenSSL 交叉验证。


## 1.13.0 新增验证约束
- digestAlgorithms、signerInfos、signedAttrs 的 DER SET 排序。
- 证书序列号 INTEGER 正数规范编码。
- RSA/ECDSA 签名算法参数形式。
- CertificateSet 必须完整解析，不接受尾部损坏。
