#import "SigningIdentityVerifier.h"

static NSError *ASVerifierError(NSInteger code, NSString *message) {
    return [NSError errorWithDomain:@"AppleSigner.SigningIdentityVerifier"
                               code:code
                           userInfo:@{NSLocalizedDescriptionKey: message}];
}

@implementation SigningIdentityVerifier

+ (NSDictionary *)verifyP12AtURL:(NSURL *)url password:(NSString *)password error:(NSError **)error {
    NSData *p12 = [NSData dataWithContentsOfURL:url options:NSDataReadingMappedIfSafe error:error];
    if (!p12 || p12.length == 0) {
        if (error && !*error) *error = ASVerifierError(1, @"无法读取 P12 文件");
        return nil;
    }

    NSDictionary *options = @{(__bridge id)kSecImportExportPassphrase: password ?: @""};
    CFArrayRef imported = NULL;
    OSStatus status = SecPKCS12Import((__bridge CFDataRef)p12,
                                      (__bridge CFDictionaryRef)options,
                                      &imported);
    if (status != errSecSuccess || !imported || CFArrayGetCount(imported) == 0) {
        if (imported) CFRelease(imported);
        if (error) *error = [NSError errorWithDomain:NSOSStatusErrorDomain code:status userInfo:nil];
        return nil;
    }

    NSDictionary *entry = CFBridgingRelease(CFRetain(CFArrayGetValueAtIndex(imported, 0)));
    CFRelease(imported);
    SecIdentityRef identity = (__bridge SecIdentityRef)entry[(__bridge id)kSecImportItemIdentity];
    if (!identity) {
        if (error) *error = ASVerifierError(2, @"P12 中没有可用的身份对象");
        return nil;
    }

    SecKeyRef privateKey = NULL;
    status = SecIdentityCopyPrivateKey(identity, &privateKey);
    if (status != errSecSuccess || !privateKey) {
        if (error) *error = [NSError errorWithDomain:NSOSStatusErrorDomain code:status userInfo:nil];
        return nil;
    }

    NSDictionary *attributes = CFBridgingRelease(SecKeyCopyAttributes(privateKey));
    id keyType = attributes[(__bridge id)kSecAttrKeyType];
    SecKeyAlgorithm algorithm = NULL;
    NSString *algorithmName = nil;
    if ([keyType isEqual:(__bridge id)kSecAttrKeyTypeRSA]) {
        algorithm = kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA256;
        algorithmName = @"RSA / PKCS#1 v1.5 / SHA-256";
    } else if ([keyType isEqual:(__bridge id)kSecAttrKeyTypeECSECPrimeRandom]) {
        algorithm = kSecKeyAlgorithmECDSASignatureMessageX962SHA256;
        algorithmName = @"ECDSA / X9.62 / SHA-256";
    } else {
        CFRelease(privateKey);
        if (error) *error = ASVerifierError(3, @"暂不支持此私钥类型；仅探测 RSA 与椭圆曲线密钥");
        return nil;
    }

    if (!SecKeyIsAlgorithmSupported(privateKey, kSecKeyOperationTypeSign, algorithm)) {
        CFRelease(privateKey);
        if (error) *error = ASVerifierError(4, @"系统不支持此私钥的 SHA-256 签名算法");
        return nil;
    }

    SecKeyRef publicKey = SecKeyCopyPublicKey(privateKey);
    if (!publicKey) {
        CFRelease(privateKey);
        if (error) *error = ASVerifierError(5, @"无法从私钥取得公钥");
        return nil;
    }

    const uint8_t challengeBytes[] = "AppleSigner local key capability test v1";
    NSData *challenge = [NSData dataWithBytes:challengeBytes length:sizeof(challengeBytes) - 1];
    CFErrorRef signError = NULL;
    CFDataRef signature = SecKeyCreateSignature(privateKey, algorithm,
                                                 (__bridge CFDataRef)challenge, &signError);
    if (!signature) {
        if (signError) {
            if (error) *error = CFBridgingRelease(signError);
            else CFRelease(signError);
        } else if (error) {
            *error = ASVerifierError(6, @"私钥签名操作失败");
        }
        CFRelease(publicKey);
        CFRelease(privateKey);
        return nil;
    }

    CFErrorRef verifyError = NULL;
    BOOL verified = SecKeyVerifySignature(publicKey, algorithm,
                                           (__bridge CFDataRef)challenge,
                                           signature, &verifyError);
    CFRelease(signature);
    CFRelease(publicKey);
    CFRelease(privateKey);

    if (verifyError) {
        if (error) *error = CFBridgingRelease(verifyError);
        else CFRelease(verifyError);
    }
    if (!verified) {
        if (error && !*error) *error = ASVerifierError(7, @"本地签名结果无法通过公钥验证");
        return nil;
    }

    return @{@"algorithm": algorithmName,
             @"keyType": [keyType isKindOfClass:NSString.class] ? keyType : @"unknown",
             @"verified": @YES};
}
@end
