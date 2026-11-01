#import "CMSDetachedBuilder.h"
#import <CommonCrypto/CommonDigest.h>

static NSError *ASCMSErr(NSInteger c, NSString *s) {
    return [NSError errorWithDomain:@"AppleSigner.CMSDetachedBuilder" code:c
                            userInfo:@{NSLocalizedDescriptionKey:s}];
}
static NSData *ASDERLength(NSUInteger n) {
    if (n < 128) { uint8_t b=(uint8_t)n; return [NSData dataWithBytes:&b length:1]; }
    uint8_t tmp[sizeof(NSUInteger)]; NSUInteger k=0;
    while(n){ tmp[sizeof(tmp)-1-k++]=(uint8_t)(n&0xff); n>>=8; }
    NSMutableData *d=[NSMutableData data]; uint8_t first=(uint8_t)(0x80|k);
    [d appendBytes:&first length:1]; [d appendBytes:tmp+sizeof(tmp)-k length:k]; return d;
}
static NSData *ASDER(uint8_t tag, NSData *body) {
    NSMutableData *d=[NSMutableData data]; [d appendBytes:&tag length:1];
    [d appendData:ASDERLength(body.length)]; [d appendData:body]; return d;
}
static NSData *ASJoin(NSArray<NSData *> *parts) {
    NSMutableData *d=[NSMutableData data]; for(NSData *p in parts) [d appendData:p]; return d;
}
static NSData *ASOID(const uint8_t *b, NSUInteger n) { return ASDER(0x06,[NSData dataWithBytes:b length:n]); }
static NSData *ASSeq(NSArray<NSData *> *p) { return ASDER(0x30,ASJoin(p)); }
static NSData *ASSet(NSArray<NSData *> *p) {
    NSArray *sorted=[p sortedArrayUsingComparator:^NSComparisonResult(NSData *a, NSData *b) {
        NSUInteger n=MIN(a.length,b.length); int c=memcmp(a.bytes,b.bytes,n);
        if(c<0)return NSOrderedAscending; if(c>0)return NSOrderedDescending;
        return a.length<b.length?NSOrderedAscending:(a.length>b.length?NSOrderedDescending:NSOrderedSame);
    }];
    return ASDER(0x31,ASJoin(sorted));
}
static BOOL ASReadTLV(NSData *d, NSUInteger *offset, uint8_t *tag, NSUInteger *start, NSUInteger *length) {
    if(*offset+2>d.length)return NO;
    const uint8_t *b=d.bytes; *start=*offset; *tag=b[(*offset)++];
    uint8_t l=b[(*offset)++]; NSUInteger n=0;
    if(!(l&0x80)) n=l;
    else { NSUInteger count=l&0x7f; if(!count||count>sizeof(NSUInteger)||*offset+count>d.length)return NO;
        for(NSUInteger i=0;i<count;i++) n=(n<<8)|b[(*offset)++]; }
    if(n>d.length-*offset)return NO; *length=n; return YES;
}
static NSData *ASCertificateIssuerSerial(NSData *cert) {
    NSUInteger o=0,s=0,n=0; uint8_t t=0;
    if(!ASReadTLV(cert,&o,&t,&s,&n)||t!=0x30)return nil;
    NSUInteger outerEnd=o+n; NSUInteger p=o,ts=0,tn=0; uint8_t tt=0;
    if(!ASReadTLV(cert,&p,&tt,&ts,&tn)||tt!=0x30)return nil;
    NSUInteger tbsEnd=p+tn, q=p, vs=0,vn=0; uint8_t vt=0;
    if(q<tbsEnd && ((const uint8_t *)cert.bytes)[q]==0xA0) {
        if(!ASReadTLV(cert,&q,&vt,&vs,&vn))return nil;
    }
    NSUInteger serialStart=0,serialLen=0;
    if(!ASReadTLV(cert,&q,&vt,&serialStart,&serialLen)||vt!=0x02)return nil;
    NSUInteger serialEnd=q;
    NSUInteger issuerStart=0,issuerLen=0;
    if(!ASReadTLV(cert,&q,&vt,&issuerStart,&issuerLen)||vt!=0x30)return nil;
    NSUInteger issuerTLVEnd=q+issuerLen;
    NSData *issuer=[cert subdataWithRange:NSMakeRange(issuerStart,issuerTLVEnd-issuerStart)];
    NSData *serial=[cert subdataWithRange:NSMakeRange(serialStart,serialEnd-serialStart)];
    (void)outerEnd;
    return ASSeq(@[issuer,serial]);
}
static NSData *ASAlgorithmIdentifier(const uint8_t *oid, NSUInteger oidLen, BOOL withNull) {
    NSData *o=ASOID(oid,oidLen);
    return ASSeq(withNull?@[o,ASDER(0x05,[NSData data])]:@[o]);
}
@implementation CMSDetachedBuilder
+ (NSURL *)createDetachedTestCMSForP12:(NSURL *)p12URL password:(NSString *)password
                            contentURL:(NSURL *)contentURL outputURL:(NSURL *)outputURL
                                 error:(NSError **)error {
    NSData *p12=[NSData dataWithContentsOfURL:p12URL options:NSDataReadingMappedIfSafe error:error];
    NSData *content=[NSData dataWithContentsOfURL:contentURL options:NSDataReadingMappedIfSafe error:error];
    if(!p12.length||!content){if(error&&!*error)*error=ASCMSErr(1,@"P12 或测试内容为空");return nil;}
    NSDictionary *opt=@{(__bridge id)kSecImportExportPassphrase:password?:@""};
    CFArrayRef imported=NULL; OSStatus st=SecPKCS12Import((__bridge CFDataRef)p12,(__bridge CFDictionaryRef)opt,&imported);
    if(st!=errSecSuccess||!imported||CFArrayGetCount(imported)==0){
        if(imported)CFRelease(imported); if(error)*error=[NSError errorWithDomain:NSOSStatusErrorDomain code:st userInfo:nil]; return nil;
    }
    NSDictionary *entry=(__bridge NSDictionary *)CFArrayGetValueAtIndex(imported,0);
    SecIdentityRef identity=(__bridge SecIdentityRef)entry[(__bridge id)kSecImportItemIdentity];
    NSArray *chain=entry[(__bridge id)kSecImportItemCertChain];
    SecCertificateRef leaf=(__bridge SecCertificateRef)chain.firstObject;
    SecKeyRef priv=NULL; st=identity?SecIdentityCopyPrivateKey(identity,&priv):errSecItemNotFound;
    if(st!=errSecSuccess||!priv||!leaf){if(priv)CFRelease(priv);CFRelease(imported);if(error)*error=ASCMSErr(2,@"P12 身份或私钥不可用");return nil;}
    NSDictionary *attrs=CFBridgingRelease(SecKeyCopyAttributes(priv));
    id kt=attrs[(__bridge id)kSecAttrKeyType];
    BOOL rsa=[kt isEqual:(__bridge id)kSecAttrKeyTypeRSA];
    BOOL ec=[kt isEqual:(__bridge id)kSecAttrKeyTypeECSECPrimeRandom];
    SecKeyAlgorithm alg=rsa?kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA256:
                        (ec?kSecKeyAlgorithmECDSASignatureMessageX962SHA256:NULL);
    if(!alg||!SecKeyIsAlgorithmSupported(priv,kSecKeyOperationTypeSign,alg)){
        CFRelease(priv);CFRelease(imported);if(error)*error=ASCMSErr(3,@"仅支持可用的 RSA / EC SHA-256 私钥");return nil;
    }
    CFDataRef leafRef=SecCertificateCopyData(leaf);
    NSData *leafDER=CFBridgingRelease(leafRef);
    NSData *sid=ASCertificateIssuerSerial(leafDER);
    if(!sid){CFRelease(priv);CFRelease(imported);if(error)*error=ASCMSErr(4,@"无法解析证书 issuer/serial");return nil;}
    uint8_t shaOID[]={0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x01};
    uint8_t dataOID[]={0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x07,0x01};
    uint8_t signedDataOID[]={0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x07,0x02};
    uint8_t contentTypeOID[]={0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x09,0x03};
    uint8_t messageDigestOID[]={0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x09,0x04};
    uint8_t rsaOID[]={0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x01,0x01};
    uint8_t ecdsaOID[]={0x2A,0x86,0x48,0xCE,0x3D,0x04,0x03,0x02};
    uint8_t digest[CC_SHA256_DIGEST_LENGTH]; CC_SHA256(content.bytes,(CC_LONG)content.length,digest);
    NSData *digestData=[NSData dataWithBytes:digest length:sizeof(digest)];
    NSData *attrContentType=ASSeq(@[ASOID(contentTypeOID,sizeof(contentTypeOID)),ASSet(@[ASOID(dataOID,sizeof(dataOID))])]);
    NSData *attrDigest=ASSeq(@[ASOID(messageDigestOID,sizeof(messageDigestOID)),ASSet(@[ASDER(0x04,digestData)])]);
    NSData *attrsSet=ASSet(@[attrContentType,attrDigest]);
    NSMutableData *implicitAttrs=[NSMutableData dataWithData:attrsSet];
    ((uint8_t *)implicitAttrs.mutableBytes)[0]=0xA0;
    CFErrorRef signErr=NULL;
    CFDataRef sigRef=SecKeyCreateSignature(priv,alg,(__bridge CFDataRef)attrsSet,&signErr);
    if(!sigRef){
        if(signErr){if(error)*error=CFBridgingRelease(signErr);else CFRelease(signErr);}
        CFRelease(priv);CFRelease(imported);return nil;
    }
    NSData *signature=CFBridgingRelease(sigRef);
    SecKeyRef pub=SecKeyCopyPublicKey(priv); CFErrorRef verifyErr=NULL;
    BOOL valid=pub&&SecKeyVerifySignature(pub,alg,(__bridge CFDataRef)attrsSet,(__bridge CFDataRef)signature,&verifyErr);
    if(pub)CFRelease(pub);
    if(!valid){
        if(verifyErr){if(error)*error=CFBridgingRelease(verifyErr);else CFRelease(verifyErr);}
        CFRelease(priv);CFRelease(imported);if(error&&!*error)*error=ASCMSErr(5,@"CMS signedAttrs 签名自验证失败");return nil;
    }
    NSData *shaAlg=ASAlgorithmIdentifier(shaOID,sizeof(shaOID),YES);
    NSData *sigAlg=ASAlgorithmIdentifier(rsa?rsaOID:ecdsaOID,rsa?sizeof(rsaOID):sizeof(ecdsaOID),rsa);
    NSData *signerInfo=ASSeq(@[ASDER(0x02,[NSData dataWithBytes:"\x01" length:1]),sid,shaAlg,
                              implicitAttrs, sigAlg, ASDER(0x04,signature)]);
    NSData *digestSet=ASSet(@[shaAlg]);
    NSData *encap=ASSeq(@[ASOID(dataOID,sizeof(dataOID))]); // detached content
    NSMutableArray *certs=[NSMutableArray array];
    for(id c in chain){CFDataRef der=SecCertificateCopyData((__bridge SecCertificateRef)c);if(der){[certs addObject:CFBridgingRelease(der)];}}
    // DER requires SET OF CertificateChoices elements to be sorted by their full DER encodings.
    [certs sortUsingComparator:^NSComparisonResult(NSData *a, NSData *b) {
        NSUInteger n=MIN(a.length,b.length);
        int c=memcmp(a.bytes,b.bytes,n);
        if(c<0)return NSOrderedAscending;
        if(c>0)return NSOrderedDescending;
        return a.length<b.length?NSOrderedAscending:(a.length>b.length?NSOrderedDescending:NSOrderedSame);
    }];
    NSMutableData *certSet=[NSMutableData dataWithData:ASJoin(certs)];
    NSData *certField=ASDER(0xA0,certSet);
    NSData *signerSet=ASSet(@[signerInfo]);
    NSData *signedData=ASSeq(@[ASDER(0x02,[NSData dataWithBytes:"\x01" length:1]),digestSet,encap,certField,signerSet]);
    NSData *contentInfo=ASSeq(@[ASOID(signedDataOID,sizeof(signedDataOID)),ASDER(0xA0,signedData)]);
    NSError *writeError=nil;
    if(![contentInfo writeToURL:outputURL options:NSDataWritingAtomic error:&writeError]){
        if(error)*error=writeError;CFRelease(priv);CFRelease(imported);return nil;
    }
    CFRelease(priv);CFRelease(imported);
    return outputURL;
}
@end
