#import "CMSDetachedVerifier.h"
#import <Security/Security.h>
#import <CommonCrypto/CommonDigest.h>

static NSError *ASVErr(NSInteger c, NSString *m) {
    return [NSError errorWithDomain:@"AppleSigner.CMSDetachedVerifier" code:c
                            userInfo:@{NSLocalizedDescriptionKey:m}];
}
typedef struct { uint8_t tag; NSUInteger start, header, length, end; } ASVTLV;
static BOOL ASVNext(NSData *d, NSUInteger *off, ASVTLV *v) {
    if (*off+2>d.length) return NO;
    const uint8_t *b=d.bytes; v->start=*off; v->tag=b[(*off)++];
    uint8_t l=b[(*off)++]; NSUInteger n=0;
    if (!(l&0x80)) n=l;
    else {
        NSUInteger count=l&0x7f;
        if (!count || count>sizeof(NSUInteger) || *off+count>d.length) return NO;
        if (count>1 && b[*off]==0) return NO;
        for(NSUInteger i=0;i<count;i++) n=(n<<8)|b[(*off)++];
        if(n<128) return NO;
    }
    v->header=*off-v->start; v->length=n;
    if(n>d.length-*off)return NO;
    v->end=*off+n; return YES;
}
static NSArray<NSData *> *ASVChildren(NSData *d, uint8_t expectedTag) {
    NSUInteger o=0; ASVTLV top;
    if(!ASVNext(d,&o,&top)||top.tag!=expectedTag||top.end!=d.length)return nil;
    NSMutableArray *a=[NSMutableArray array];
    while(o<top.end){NSUInteger s=o;ASVTLV x;if(!ASVNext(d,&o,&x))return nil;
        [a addObject:[d subdataWithRange:NSMakeRange(s,x.end-s)]];o=x.end;}
    return a;
}
static BOOL ASVGet(NSData *d, ASVTLV *v, NSUInteger *body) {
    NSUInteger o=0;if(!ASVNext(d,&o,v)||v->end!=d.length)return NO;*body=o;return YES;
}
static NSData *ASVBody(NSData *d, ASVTLV v, NSUInteger body) {
    return [d subdataWithRange:NSMakeRange(body,v.length)];
}
static NSData *ASVRetag(NSData *d,uint8_t tag) {
    NSMutableData *m=[d mutableCopy];((uint8_t *)m.mutableBytes)[0]=tag;return m;
}
static NSData *ASVFindAttribute(NSData *attrs, const uint8_t *oid, NSUInteger oidLen, uint8_t valueTag) {
    NSArray *items=ASVChildren(attrs,0x31); if(!items)return nil;
    NSData *target=[NSData dataWithBytes:oid length:oidLen];
    for(NSData *item in items){
        NSArray *pair=ASVChildren(item,0x30);if(pair.count!=2)continue;
        ASVTLV t;NSUInteger b;
        if(!ASVGet(pair[0],&t,&b)||t.tag!=0x06)continue;
        if(![ASVBody(pair[0],t,b) isEqual:target])continue;
        NSArray *vals=ASVChildren(pair[1],0x31);if(!vals.count)continue;
        if(!ASVGet(vals[0],&t,&b)||t.tag!=valueTag)continue;
        return ASVBody(vals[0],t,b);
    }
    return nil;
}
static NSUInteger ASVAttributeCount(NSData *attrs, const uint8_t *oid, NSUInteger oidLen) {
    NSArray *items=ASVChildren(attrs,0x31); if(!items)return 0;
    NSData *target=[NSData dataWithBytes:oid length:oidLen];
    NSUInteger count=0;
    for(NSData *item in items) {
        NSArray *pair=ASVChildren(item,0x30);
        if(pair.count!=2)continue;
        NSUInteger b=0;ASVTLV t;
        if(ASVGet(pair[0],&t,&b)&&t.tag==0x06&&
           [ASVBody(pair[0],t,b) isEqual:target]) count++;
    }
    return count;
}
static NSComparisonResult ASVDERCompare(NSData *a, NSData *b) {
    NSUInteger n=MIN(a.length,b.length);
    int c=memcmp(a.bytes,b.bytes,n);
    if(c<0)return NSOrderedAscending;
    if(c>0)return NSOrderedDescending;
    return a.length<b.length?NSOrderedAscending:(a.length>b.length?NSOrderedDescending:NSOrderedSame);
}

static BOOL ASVIsDERSetSorted(NSArray<NSData *> *items) {
    for(NSUInteger i=1;i<items.count;i++)
        if(ASVDERCompare(items[i-1],items[i])==NSOrderedDescending)return NO;
    return YES;
}
static BOOL ASVIsCanonicalPositiveInteger(NSData *tlv) {
    NSUInteger body=0;ASVTLV t;
    if(!ASVGet(tlv,&t,&body)||t.tag!=0x02||t.length==0)return NO;
    const uint8_t *b=(const uint8_t *)tlv.bytes+body;
    if(b[0]&0x80)return NO;
    if(t.length>1&&b[0]==0&&(b[1]&0x80)==0)return NO;
    return YES;
}

static NSData *ASVIssuerSerialFromCert(NSData *cert) {
    NSArray *certParts=ASVChildren(cert,0x30);if(certParts.count!=3)return nil;
    NSArray *tbs=ASVChildren(certParts[0],0x30);if(!tbs)return nil;
    NSUInteger i=0;
    if(tbs.count && ((const uint8_t *)((NSData *)tbs[0]).bytes)[0]==0xA0)i++;
    if(i+3>=tbs.count)return nil;
    NSData *serial=tbs[i++], *issuer=tbs[i+1];
    if(!ASVIsCanonicalPositiveInteger(serial))return nil;
    return [[NSString stringWithFormat:@"%@|%@",[serial base64EncodedStringWithOptions:0],
            [issuer base64EncodedStringWithOptions:0]] dataUsingEncoding:NSUTF8StringEncoding];
}
static NSData *ASVSIDFromSigner(NSData *sid) {
    NSArray *p=ASVChildren(sid,0x30);if(p.count!=2)return nil;
    return [[NSString stringWithFormat:@"%@|%@",[p[1] base64EncodedStringWithOptions:0],
            [p[0] base64EncodedStringWithOptions:0]] dataUsingEncoding:NSUTF8StringEncoding];
}

static BOOL ASVHasOID(NSData *tlv, const uint8_t *oid, NSUInteger oidLen) {
    NSUInteger b=0; ASVTLV t;
    return ASVGet(tlv,&t,&b) && t.tag==0x06 &&
        [ASVBody(tlv,t,b) isEqual:[NSData dataWithBytes:oid length:oidLen]];
}

@implementation CMSDetachedVerifier
+ (NSDictionary *)verifyCMSAtURL:(NSURL *)cmsURL contentURL:(NSURL *)contentURL error:(NSError **)error {
    NSData *cms=[NSData dataWithContentsOfURL:cmsURL options:NSDataReadingMappedIfSafe error:error];
    NSData *content=[NSData dataWithContentsOfURL:contentURL options:NSDataReadingMappedIfSafe error:error];
    if(!cms.length||!content){if(error&&!*error)*error=ASVErr(1,@"CMS 或原始内容为空");return nil;}
    NSArray *ci=ASVChildren(cms,0x30);
    if(ci.count!=2){if(error)*error=ASVErr(2,@"ContentInfo 结构错误");return nil;}
    const uint8_t signedOID[]={0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x07,0x02};
    ASVTLV t;NSUInteger b;
    if(!ASVGet(ci[0],&t,&b)||t.tag!=0x06||
       ![ASVBody(ci[0],t,b) isEqual:[NSData dataWithBytes:signedOID length:sizeof(signedOID)]]){
        if(error)*error=ASVErr(3,@"不是 CMS SignedData");return nil;
    }
    if(!ASVGet(ci[1],&t,&b)||t.tag!=0xA0){if(error)*error=ASVErr(4,@"SignedData 包装缺失");return nil;}
    NSData *sd=ASVBody(ci[1],t,b);
    NSArray *fields=ASVChildren(sd,0x30);
    if(fields.count<5){if(error)*error=ASVErr(5,@"SignedData 字段不足");return nil;}
    NSUInteger vb=0; ASVTLV versionTLV;
    if(!ASVGet(fields[0],&versionTLV,&vb)||versionTLV.tag!=0x02||
       ![ASVBody(fields[0],versionTLV,vb) isEqual:[NSData dataWithBytes:"\x01" length:1]]) {
        if(error)*error=ASVErr(20,@"SignedData version 不是当前支持的 v1");return nil;
    }
    const uint8_t sha256OID[]={0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x01};
    NSArray *digestSet=ASVChildren(fields[1],0x31);
    if(!digestSet||!ASVIsDERSetSorted(digestSet)) {
        if(error)*error=ASVErr(29,@"digestAlgorithms 不是规范 DER SET 排序");return nil;
    }
    if(digestSet.count!=1) {if(error)*error=ASVErr(21,@"当前仅支持单一 SHA-256 digestAlgorithm");return nil;}
    NSArray *digestParts=ASVChildren(digestSet[0],0x30);
    if(!digestParts.count||!ASVHasOID(digestParts[0],sha256OID,sizeof(sha256OID))) {
        if(error)*error=ASVErr(22,@"CMS digestAlgorithm 不是 SHA-256");return nil;
    }
    NSArray *encap=ASVChildren(fields[2],0x30);
    if(encap.count!=1){if(error)*error=ASVErr(6,@"当前验证器只接受 detached CMS");return nil;}
    const uint8_t dataOID[]={0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x07,0x01};
    if(!ASVGet(encap[0],&t,&b)||t.tag!=0x06||
       ![ASVBody(encap[0],t,b) isEqual:[NSData dataWithBytes:dataOID length:sizeof(dataOID)]]){
        if(error)*error=ASVErr(7,@"CMS 内容类型不是 id-data");return nil;
    }
    NSData *certField=nil,*signerField=nil;
    for(NSUInteger i=3;i<fields.count;i++){
        if(((const uint8_t *)((NSData *)fields[i]).bytes)[0]==0xA0)certField=fields[i];
        if(((const uint8_t *)((NSData *)fields[i]).bytes)[0]==0x31)signerField=fields[i];
    }
    if(!certField||!signerField){if(error)*error=ASVErr(8,@"缺少证书集合或 SignerInfo");return nil;}
    NSArray *signers=ASVChildren(signerField,0x31);
    if(!signers||!ASVIsDERSetSorted(signers)) {
        if(error)*error=ASVErr(30,@"signerInfos 不是规范 DER SET 排序");return nil;
    }
    if(signers.count!=1){if(error)*error=ASVErr(9,@"当前验证器要求恰好一个签名者");return nil;}
    NSArray *si=ASVChildren(signers[0],0x30);
    if(si.count!=6||((const uint8_t *)((NSData *)si[3]).bytes)[0]!=0xA0){if(error)*error=ASVErr(10,@"SignerInfo/signedAttrs 结构错误");return nil;}
    NSUInteger sivb=0;ASVTLV siv;
    if(!ASVGet(si[0],&siv,&sivb)||siv.tag!=0x02||
       ![ASVBody(si[0],siv,sivb) isEqual:[NSData dataWithBytes:"\x01" length:1]]) {
        if(error)*error=ASVErr(24,@"SignerInfo version 不是 v1");return nil;
    }
    NSArray *siDigest=ASVChildren(si[2],0x30);
    if(!siDigest.count||!ASVHasOID(siDigest[0],sha256OID,sizeof(sha256OID))) {
        if(error)*error=ASVErr(25,@"SignerInfo digestAlgorithm 与 SHA-256 不匹配");return nil;
    }
    NSData *sid=ASVSIDFromSigner(si[1]);
    ASVTLV at;NSUInteger ab;
    if(!ASVGet(si[3],&at,&ab)){if(error)*error=ASVErr(11,@"signedAttrs 编码错误");return nil;}
    NSMutableData *attrsDER=[NSMutableData dataWithData:si[3]];
    ((uint8_t *)attrsDER.mutableBytes)[0]=0x31;
    NSArray *attributeItems=ASVChildren(attrsDER,0x31);
    if(!attributeItems||!ASVIsDERSetSorted(attributeItems)) {
        if(error)*error=ASVErr(31,@"signedAttrs 属性集合不是规范 DER SET 排序");return nil;
    }
    const uint8_t ctOID[]={0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x09,0x03};
    const uint8_t dataOIDForAttr[]={0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x07,0x01};
    if(ASVAttributeCount(attrsDER,ctOID,sizeof(ctOID))!=1) {
        if(error)*error=ASVErr(26,@"signedAttrs 必须恰好包含一个 contentType");return nil;
    }
    NSData *contentType=ASVFindAttribute(attrsDER,ctOID,sizeof(ctOID),0x06);
    if(![contentType isEqual:[NSData dataWithBytes:dataOIDForAttr length:sizeof(dataOIDForAttr)]]) {
        if(error)*error=ASVErr(23,@"signedAttrs contentType 缺失或不是 id-data");return nil;
    }
    const uint8_t mdOID[]={0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x09,0x04};
    if(ASVAttributeCount(attrsDER,mdOID,sizeof(mdOID))!=1) {
        if(error)*error=ASVErr(27,@"signedAttrs 必须恰好包含一个 messageDigest");return nil;
    }
    NSData *expectedMD=ASVFindAttribute(attrsDER,mdOID,sizeof(mdOID),0x04);
    uint8_t digest[CC_SHA256_DIGEST_LENGTH];CC_SHA256(content.bytes,(CC_LONG)content.length,digest);
    NSData *actualMD=[NSData dataWithBytes:digest length:sizeof(digest)];
    if(!expectedMD||![expectedMD isEqual:actualMD]){if(error)*error=ASVErr(12,@"messageDigest 与原始内容不匹配");return nil;}
    NSData *matchingCert=nil;
    ASVTLV ct;NSUInteger cb;
    if(!ASVGet(certField,&ct,&cb)){if(error)*error=ASVErr(13,@"证书集合编码错误");return nil;}
    NSData *certBytes=ASVBody(certField,ct,cb);NSUInteger cp=0;
    NSData *previousCert=nil;
    while(cp<certBytes.length){NSUInteger start=cp;ASVTLV one;if(!ASVNext(certBytes,&cp,&one))break;
        NSData *der=[certBytes subdataWithRange:NSMakeRange(start,one.end-start)];
        if(previousCert && ASVDERCompare(previousCert,der)==NSOrderedDescending) {
            if(error)*error=ASVErr(28,@"CertificateSet 未按 DER SET OF 顺序排列");return nil;
        }
        previousCert=der;
        NSData *cs=ASVIssuerSerialFromCert(der);
        if(cs&&[cs isEqual:sid]){matchingCert=der;break;}cp=one.end;
    }
    if(cp!=certBytes.length){if(error)*error=ASVErr(34,@"CertificateSet 存在截断或无效 DER 元素");return nil;}
    if(!matchingCert){if(error)*error=ASVErr(14,@"找不到与 SignerInfo 匹配的签名者证书");return nil;}
    SecCertificateRef cert=SecCertificateCreateWithData(NULL,(__bridge CFDataRef)matchingCert);
    SecKeyRef pub=cert?SecCertificateCopyKey(cert):NULL;
    if(cert)CFRelease(cert);
    if(!pub){if(error)*error=ASVErr(15,@"无法从签名者证书提取公钥");return nil;}
    NSArray *sigAlg=ASVChildren(si[4],0x30);
    if(sigAlg.count<1){CFRelease(pub);if(error)*error=ASVErr(16,@"签名算法标识错误");return nil;}
    ASVTLV ot;NSUInteger ob;
    if(!ASVGet(sigAlg[0],&ot,&ob)||ot.tag!=0x06){CFRelease(pub);if(error)*error=ASVErr(17,@"签名算法 OID 缺失");return nil;}
    NSData *oid=ASVBody(sigAlg[0],ot,ob);
    const uint8_t rsaOID[]={0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x01,0x01};
    const uint8_t ecOID[]={0x2A,0x86,0x48,0xCE,0x3D,0x04,0x03,0x02};
    if([oid isEqual:[NSData dataWithBytes:rsaOID length:sizeof(rsaOID)]]) {
        if(sigAlg.count!=2||((const uint8_t *)((NSData *)sigAlg[1]).bytes)[0]!=0x05) {
            CFRelease(pub);if(error)*error=ASVErr(32,@"rsaEncryption 参数必须为 NULL");return nil;
        }
    } else if([oid isEqual:[NSData dataWithBytes:ecOID length:sizeof(ecOID)]]) {
        if(sigAlg.count!=1) {
            CFRelease(pub);if(error)*error=ASVErr(33,@"ECDSA-with-SHA256 不应带参数");return nil;
        }
    }
    SecKeyAlgorithm alg=nil;
    if([oid isEqual:[NSData dataWithBytes:rsaOID length:sizeof(rsaOID)]])alg=kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA256;
    else if([oid isEqual:[NSData dataWithBytes:ecOID length:sizeof(ecOID)]])alg=kSecKeyAlgorithmECDSASignatureMessageX962SHA256;
    if(!alg||!SecKeyIsAlgorithmSupported(pub,kSecKeyOperationTypeVerify,alg)){CFRelease(pub);if(error)*error=ASVErr(18,@"不支持 CMS 中声明的签名算法");return nil;}
    NSData *sig=nil;
    if(ASVGet(si[5],&t,&b)&&t.tag==0x04)sig=ASVBody(si[5],t,b);
    BOOL verified=sig&&SecKeyVerifySignature(pub,alg,(__bridge CFDataRef)attrsDER,(__bridge CFDataRef)sig,NULL);
    CFRelease(pub);
    if(!verified){if(error)*error=ASVErr(19,@"CMS 签名值验证失败");return nil;}
    return @{@"DigestMatched":@YES,@"SignatureVerified":@YES,@"SignerCertificateDERLength":@(matchingCert.length)};
}
@end
