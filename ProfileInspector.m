#import "ProfileInspector.h"
#import <Security/Security.h>
#import <Security/CMSDecoder.h>

@implementation ProfileInspector

+ (NSError *)error:(NSString *)message code:(NSInteger)code {
    return [NSError errorWithDomain:@"AppleSigner.ProfileInspector"
                               code:code
                           userInfo:@{NSLocalizedDescriptionKey: message}];
}

+ (NSDictionary *)inspectProfileAtURL:(NSURL *)url error:(NSError **)error {
    NSData *cmsData = [NSData dataWithContentsOfURL:url];
    if (!cmsData) {
        if (error) *error = [self error:@"无法读取描述文件" code:1];
        return nil;
    }

    CMSDecoderRef decoder = NULL;
    OSStatus status = CMSDecoderCreate(&decoder);
    if (status == errSecSuccess) status = CMSDecoderUpdateMessage(decoder, cmsData.bytes, cmsData.length);
    if (status == errSecSuccess) status = CMSDecoderFinalizeMessage(decoder);

    CFDataRef content = NULL;
    if (status == errSecSuccess) status = CMSDecoderCopyContent(decoder, &content);
    if (decoder) CFRelease(decoder);

    if (status != errSecSuccess || !content) {
        if (content) CFRelease(content);
        if (error) *error = [self error:[NSString stringWithFormat:@"CMS 解码失败（%d）", (int)status] code:2];
        return nil;
    }

    NSData *plistData = CFBridgingRelease(content);
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
