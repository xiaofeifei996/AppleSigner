#import "CMSPreflight.h"
#import <CommonCrypto/CommonDigest.h>

static NSError *ASCMSError(NSInteger code, NSString *message) {
    return [NSError errorWithDomain:@"AppleSigner.CMSPreflight"
                               code:code
                           userInfo:@{NSLocalizedDescriptionKey: message}];
}

@implementation CMSPreflight
+ (NSDictionary *)inspectP12AtURL:(NSURL *)url password:(NSString *)password
                   contentToDigest:(NSData *)content error:(NSError **)error {
    NSData *p12 = [NSData dataWithContentsOfURL:url options:NSDataReadingMappedIfSafe error:error];
    if (!p12.length) {
        if (error && !*error) *error = ASCMSError(1, @"无法读取 P12 文件");
        return nil;
    }
    NSDictionary *opts = @{(__bridge id)kSecImportExportPassphrase: password ?: @""};
    CFArrayRef imported = NULL;
    OSStatus status = SecPKCS12Import((__bridge CFDataRef)p12, (__bridge CFDictionaryRef)opts, &imported);
    if (status != errSecSuccess || !imported || CFArrayGetCount(imported) == 0) {
        if (imported) CFRelease(imported);
        if (error) *error = [NSError errorWithDomain:NSOSStatusErrorDomain code:status userInfo:nil];
        return nil;
    }
    NSDictionary *entry = (__bridge NSDictionary *)CFArrayGetValueAtIndex(imported, 0);
    SecIdentityRef identity = (__bridge SecIdentityRef)entry[(__bridge id)kSecImportItemIdentity];
    NSArray *chain = entry[(__bridge id)kSecImportItemCertChain];
    SecCertificateRef leaf = chain.firstObject;
    SecKeyRef privateKey = NULL;
    status = identity ? SecIdentityCopyPrivateKey(identity, &privateKey) : errSecItemNotFound;
    if (status != errSecSuccess || !privateKey || !leaf) {
        if (privateKey) CFRelease(privateKey);
        CFRelease(imported);
        if (error) *error = ASCMSError(2, @"P12 缺少身份私钥或证书链");
        return nil;
    }
    NSDictionary *attrs = CFBridgingRelease(SecKeyCopyAttributes(privateKey));
    id keyType = attrs[(__bridge id)kSecAttrKeyType];
    SecKeyAlgorithm algorithm = NULL;
    NSString *name = nil;
    if ([keyType isEqual:(__bridge id)kSecAttrKeyTypeRSA]) {
        algorithm = kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA256;
        name = @"rsaEncryption + SHA-256（候选）";
    } else if ([keyType isEqual:(__bridge id)kSecAttrKeyTypeECSECPrimeRandom]) {
        algorithm = kSecKeyAlgorithmECDSASignatureMessageX962SHA256;
        name = @"ecdsa-with-SHA256（候选）";
    } else {
        CFRelease(privateKey); CFRelease(imported);
        if (error) *error = ASCMSError(3, @"暂不支持此私钥类型");
        return nil;
    }
    BOOL supported = SecKeyIsAlgorithmSupported(privateKey, kSecKeyOperationTypeSign, algorithm);
    CFDataRef certDER = SecCertificateCopyData(leaf);
    unsigned char digest[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256(content.bytes, (CC_LONG)content.length, digest);
    NSMutableString *hex = [NSMutableString stringWithCapacity:CC_SHA256_DIGEST_LENGTH * 2];
    for (NSUInteger i = 0; i < sizeof(digest); i++) [hex appendFormat:@"%02x", digest[i]];
    NSDictionary *result = @{
        @"CertificateCount": @(chain.count),
        @"LeafCertificateDERLength": @((NSUInteger)CFDataGetLength(certDER)),
        @"Algorithm": supported ? name : [name stringByAppendingString:@"（系统不支持）"],
        @"ContentSHA256": hex,
        @"CanAttemptCMS": @(supported && chain.count > 0)
    };
    CFRelease(certDER); CFRelease(privateKey); CFRelease(imported);
    if (!supported && error) *error = ASCMSError(4, @"Security.framework 不支持此私钥算法");
    return supported ? result : nil;
}
@end
