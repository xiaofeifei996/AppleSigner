#import "ProfileInspector.h"
#import <Security/Security.h>

typedef struct {
    uint8_t tag;
    NSUInteger bodyStart;
    NSUInteger length;
    NSUInteger end;
} ASPI_TLV;

static BOOL ASPIReadTLV(NSData *data, NSUInteger *offset, ASPI_TLV *out) {
    if (!data || !offset || !out || *offset > data.length || data.length - *offset < 2) return NO;
    const uint8_t *bytes = data.bytes;
    NSUInteger start = *offset;
    out->tag = bytes[(*offset)++];
    uint8_t firstLength = bytes[(*offset)++];
    NSUInteger length = 0;
    if ((firstLength & 0x80) == 0) {
        length = firstLength;
    } else {
        NSUInteger count = firstLength & 0x7f;
        if (count == 0 || count > sizeof(NSUInteger) || count > data.length - *offset) return NO;
        if (bytes[*offset] == 0) return NO;
        for (NSUInteger i = 0; i < count; i++) {
            if (length > (NSUIntegerMax >> 8)) return NO;
            length = (length << 8) | bytes[(*offset)++];
        }
        if (length < 128) return NO;
    }
    out->bodyStart = *offset;
    out->length = length;
    if (length > data.length - *offset) return NO;
    out->end = *offset + length;
    (void)start;
    return YES;
}

static NSData *ASPIExactBody(NSData *tlvData, uint8_t expectedTag) {
    NSUInteger offset = 0;
    ASPI_TLV tlv;
    if (!ASPIReadTLV(tlvData, &offset, &tlv) || tlv.tag != expectedTag || tlv.end != tlvData.length) return nil;
    return [tlvData subdataWithRange:NSMakeRange(tlv.bodyStart, tlv.length)];
}

static NSArray<NSData *> *ASPIChildren(NSData *tlvData, uint8_t expectedTag) {
    NSData *body = ASPIExactBody(tlvData, expectedTag);
    if (!body) return nil;
    NSMutableArray<NSData *> *children = [NSMutableArray array];
    NSUInteger offset = 0;
    while (offset < body.length) {
        NSUInteger start = offset;
        ASPI_TLV child;
        if (!ASPIReadTLV(body, &offset, &child)) return nil;
        [children addObject:[body subdataWithRange:NSMakeRange(start, child.end - start)]];
        offset = child.end;
    }
    return children;
}

static BOOL ASPIAppendOctets(NSData *tlvData, NSMutableData *output, NSUInteger depth) {
    if (depth > 8) return NO;
    NSUInteger offset = 0;
    ASPI_TLV tlv;
    if (!ASPIReadTLV(tlvData, &offset, &tlv) || tlv.end != tlvData.length) return NO;
    if (tlv.tag == 0x04) {
        [output appendData:[tlvData subdataWithRange:NSMakeRange(tlv.bodyStart, tlv.length)]];
        return YES;
    }
    if (tlv.tag != 0x24) return NO; // constructed OCTET STRING
    NSData *body = [tlvData subdataWithRange:NSMakeRange(tlv.bodyStart, tlv.length)];
    NSUInteger childOffset = 0;
    while (childOffset < body.length) {
        NSUInteger start = childOffset;
        ASPI_TLV child;
        if (!ASPIReadTLV(body, &childOffset, &child)) return NO;
        NSData *childTLV = [body subdataWithRange:NSMakeRange(start, child.end - start)];
        if (!ASPIAppendOctets(childTLV, output, depth + 1)) return NO;
        childOffset = child.end;
    }
    return YES;
}

static NSData *ASPIProvisioningProfilePayload(NSData *cms, NSError **error) {
    NSArray<NSData *> *contentInfo = ASPIChildren(cms, 0x30);
    if (contentInfo.count != 2) {
        if (error) *error = [NSError errorWithDomain:@"AppleSigner.ProfileInspector" code:10 userInfo:@{NSLocalizedDescriptionKey:@"描述文件 CMS ContentInfo 结构无效"}];
        return nil;
    }
    const uint8_t signedDataOIDBytes[] = {0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x07,0x02};
    NSData *signedDataOID = [NSData dataWithBytes:signedDataOIDBytes length:sizeof(signedDataOIDBytes)];
    NSData *oidBody = ASPIExactBody(contentInfo[0], 0x06);
    NSData *wrappedSignedData = ASPIExactBody(contentInfo[1], 0xA0);
    if (![oidBody isEqual:signedDataOID] || !wrappedSignedData) {
        if (error) *error = [NSError errorWithDomain:@"AppleSigner.ProfileInspector" code:11 userInfo:@{NSLocalizedDescriptionKey:@"描述文件不是有效的 CMS SignedData"}];
        return nil;
    }
    NSArray<NSData *> *signedData = ASPIChildren(wrappedSignedData, 0x30);
    if (signedData.count < 3) {
        if (error) *error = [NSError errorWithDomain:@"AppleSigner.ProfileInspector" code:12 userInfo:@{NSLocalizedDescriptionKey:@"CMS SignedData 字段不完整"}];
        return nil;
    }
    NSArray<NSData *> *encapsulatedContent = ASPIChildren(signedData[2], 0x30);
    const uint8_t dataOIDBytes[] = {0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x07,0x01};
    NSData *dataOID = [NSData dataWithBytes:dataOIDBytes length:sizeof(dataOIDBytes)];
    if (encapsulatedContent.count != 2 ||
        ![ASPIExactBody(encapsulatedContent[0], 0x06) isEqual:dataOID]) {
        if (error) *error = [NSError errorWithDomain:@"AppleSigner.ProfileInspector" code:13 userInfo:@{NSLocalizedDescriptionKey:@"CMS 中缺少内嵌的描述文件内容"}];
        return nil;
    }
    NSData *explicitContent = ASPIExactBody(encapsulatedContent[1], 0xA0);
    NSMutableData *payload = [NSMutableData data];
    if (!explicitContent.length) {
        if (error) *error = [NSError errorWithDomain:@"AppleSigner.ProfileInspector" code:14 userInfo:@{NSLocalizedDescriptionKey:@"CMS 描述文件内容为空或编码无效"}];
        return nil;
    }
    NSUInteger offset = 0;
    while (offset < explicitContent.length) {
        NSUInteger start = offset;
        ASPI_TLV child;
        if (!ASPIReadTLV(explicitContent, &offset, &child)) break;
        NSData *childTLV = [explicitContent subdataWithRange:NSMakeRange(start, child.end - start)];
        if (!ASPIAppendOctets(childTLV, payload, 0)) {
            if (error) *error = [NSError errorWithDomain:@"AppleSigner.ProfileInspector" code:15 userInfo:@{NSLocalizedDescriptionKey:@"CMS 描述文件 OCTET STRING 编码无效"}];
            return nil;
        }
        offset = child.end;
    }
    if (offset != explicitContent.length || !payload.length) {
        if (error) *error = [NSError errorWithDomain:@"AppleSigner.ProfileInspector" code:16 userInfo:@{NSLocalizedDescriptionKey:@"无法完整提取 CMS 描述文件内容"}];
        return nil;
    }
    return payload;
}

@implementation ProfileInspector

+ (NSError *)error:(NSString *)message code:(NSInteger)code {
    return [NSError errorWithDomain:@"AppleSigner.ProfileInspector"
                               code:code
                           userInfo:@{NSLocalizedDescriptionKey: message}];
}

+ (NSDictionary *)inspectProfileAtURL:(NSURL *)url error:(NSError **)error {
    NSData *cmsData = [NSData dataWithContentsOfURL:url options:NSDataReadingMappedIfSafe error:error];
    if (!cmsData.length) {
        if (error && !*error) *error = [self error:@"无法读取描述文件" code:1];
        return nil;
    }

    // iOS SDK does not expose CMSDecoder.h. Extract the encapsulated profile
    // payload using bounded DER parsing; this operation does not validate the CMS signature.
    NSData *plistData = ASPIProvisioningProfilePayload(cmsData, error);
    if (!plistData.length) return nil;

    NSError *plistError = nil;
    id plist = [NSPropertyListSerialization propertyListWithData:plistData
                                                         options:NSPropertyListImmutable
                                                          format:nil
                                                           error:&plistError];
    if (![plist isKindOfClass:NSDictionary.class]) {
        if (error) *error = plistError ?: [self error:@"描述文件内容不是有效字典" code:3];
        return nil;
    }

    NSDictionary *profile = (NSDictionary *)plist;
    NSDate *expiry = profile[@"ExpirationDate"];
    NSDate *created = profile[@"CreationDate"];
    NSArray *teams = profile[@"TeamIdentifier"];
    NSDictionary *entitlements = profile[@"Entitlements"];
    NSString *appID = entitlements[@"application-identifier"];

    return @{
        @"Name": profile[@"Name"] ?: @"未命名",
        @"UUID": profile[@"UUID"] ?: @"未知",
        @"TeamIdentifier": teams.firstObject ?: @"未知",
        @"ApplicationIdentifier": appID ?: @"未声明",
        @"ExpirationDate": expiry ?: [NSNull null],
        @"CreationDate": created ?: [NSNull null],
        @"IsExpired": ([expiry isKindOfClass:NSDate.class] ? @([expiry timeIntervalSinceNow] <= 0) : @NO),
        @"ProvisionedDevices": profile[@"ProvisionedDevices"] ?: @[],
        @"DeveloperCertificates": profile[@"DeveloperCertificates"] ?: @[],
        @"Entitlements": entitlements ?: @{},
        @"Platform": profile[@"Platform"] ?: @[],
        @"ProvisionsAllDevices": profile[@"ProvisionsAllDevices"] ?: @NO,
        @"IsXcodeManaged": profile[@"IsXcodeManaged"] ?: @NO,
        @"ApplicationIdentifierPrefix": profile[@"ApplicationIdentifierPrefix"] ?: @[],
        @"HasGetTaskAllow": @([entitlements[@"get-task-allow"] boolValue]),
        @"APSEnvironment": entitlements[@"aps-environment"] ?: @"未声明",
        @"KeychainAccessGroups": entitlements[@"keychain-access-groups"] ?: @[],
        @"AppGroups": entitlements[@"com.apple.security.application-groups"] ?: @[]
    };
}
@end
