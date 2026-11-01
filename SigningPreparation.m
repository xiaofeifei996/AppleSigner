#import "SigningPreparation.h"

@implementation SigningPreparation
+ (NSError *)failure:(NSString *)message code:(NSInteger)code {
    return [NSError errorWithDomain:@"AppleSigner.SigningPreparation" code:code
        userInfo:@{NSLocalizedDescriptionKey:message}];
}
+ (BOOL)pattern:(NSString *)pattern matches:(NSString *)bundleID {
    if (![pattern isKindOfClass:NSString.class] || ![bundleID isKindOfClass:NSString.class]) return NO;
    NSArray *p=[pattern componentsSeparatedByString:@"."], *b=[bundleID componentsSeparatedByString:@"."];
    if (p.count>b.count) return NO;
    for (NSUInteger i=0;i<p.count;i++) {
        if ([p[i] isEqualToString:@"*"] && i==p.count-1) return YES;
        if (![p[i] isEqualToString:b[i]]) return NO;
    }
    return p.count==b.count;
}
+ (id)replaceWildcard:(id)value withBundleID:(NSString *)bundleID {
    if (![value isKindOfClass:NSString.class]) return value;
    NSString *s=value;
    if ([s hasSuffix:@".*"]) return [[s substringToIndex:s.length-1] stringByAppendingString:bundleID];
    if ([s isEqualToString:@"*"]) return bundleID;
    return s;
}
+ (NSDictionary *)prepareAtDirectoryURL:(NSURL *)directory profileInfo:(NSDictionary *)profile error:(NSError **)error {
    if (!profile || ![profile[@"Entitlements"] isKindOfClass:NSDictionary.class]) {
        if(error)*error=[self failure:@"请先导入并解析 provisioning profile" code:1]; return nil;
    }
    NSArray *components=profile[@"IPAComponents"];
    if (![components isKindOfClass:NSArray.class] || !components.count) {
        if(error)*error=[self failure:@"没有 IPA 组件信息，请先选择并解包 IPA" code:2]; return nil;
    }
    NSString *appPattern=profile[@"ApplicationIdentifier"];
    NSString *team=profile[@"TeamIdentifier"];
    NSDictionary *base=profile[@"Entitlements"];
    NSMutableArray *plans=[NSMutableArray array], *issues=[NSMutableArray array];
    NSFileManager *fm=NSFileManager.defaultManager;
    NSURL *out=[directory URLByAppendingPathComponent:@"SigningPreparation" isDirectory:YES];
    [fm removeItemAtURL:out error:nil];
    if(![fm createDirectoryAtURL:out withIntermediateDirectories:YES attributes:nil error:error]) return nil;
    for (NSDictionary *component in components) {
        NSString *bundleID=component[@"BundleIdentifier"];
        NSString *type=component[@"Type"] ?: @"Unknown";
        if (![bundleID isKindOfClass:NSString.class] || !bundleID.length) continue;
        NSString *bundlePattern=appPattern;
        NSString *teamPrefix=[NSString stringWithFormat:@"%@.",team ?: @""];
        if ([bundlePattern hasPrefix:teamPrefix]) bundlePattern=[bundlePattern substringFromIndex:teamPrefix.length];
        BOOL match=[self pattern:bundlePattern matches:bundleID];
        NSMutableDictionary *item=[@{@"Type":type,@"BundleIdentifier":bundleID,
            @"ProfileAppIDPattern":appPattern ?: @"",@"TeamIdentifier":team ?: @"",
            @"ProfileCompatible":@(match),@"Status":match?@"Template generated":@"Separate profile required"} mutableCopy];
        if (!match) {
            [plans addObject:item];
            [issues addObject:[NSString stringWithFormat:@"%@ %@：当前描述文件不匹配，需要独立描述文件",type,bundleID]];
            continue;
        }
        NSMutableDictionary *ent=[base mutableCopy];
        NSString *appIdentifier=[NSString stringWithFormat:@"%@.%@",team,bundleID];
        ent[@"application-identifier"]=appIdentifier;
        if ([ent[@"com.apple.developer.team-identifier"] isKindOfClass:NSString.class])
            ent[@"com.apple.developer.team-identifier"]=team;
        id groups=ent[@"keychain-access-groups"];
        if ([groups isKindOfClass:NSArray.class]) {
            NSMutableArray *newGroups=[NSMutableArray array];
            for(id g in (NSArray *)groups) {
                if ([g isKindOfClass:NSString.class] && [g hasSuffix:@".*"]) {
                    NSString *group=(NSString *)g;
                    NSString *prefix=[group substringToIndex:group.length-1];
                    NSString *teamDot=[NSString stringWithFormat:@"%@.",team ?: @""];
                    NSString *bundlePrefix=[prefix hasPrefix:teamDot] ? [prefix substringFromIndex:teamDot.length] : @"";
                    NSString *suffix=bundleID;
                    if (bundlePrefix.length && [bundleID hasPrefix:[bundlePrefix stringByAppendingString:@"."]])
                        suffix=[bundleID substringFromIndex:bundlePrefix.length+1];
                    [newGroups addObject:[prefix stringByAppendingString:suffix]];
                } else [newGroups addObject:g];
            }
            ent[@"keychain-access-groups"]=newGroups;
        }
        // The exact application identifier is reported for review; do not silently invent missing entitlement keys.
        if (!ent[@"application-identifier"]) ent[@"application-identifier"]=appIdentifier;
        NSString *safe=[bundleID stringByReplacingOccurrencesOfString:@"." withString:@"_"];
        NSString *filename=[NSString stringWithFormat:@"%@.entitlements",safe];
        NSURL *file=[out URLByAppendingPathComponent:filename];
        NSError *writeError=nil;
        NSData *plist=[NSPropertyListSerialization dataWithPropertyList:ent format:NSPropertyListXMLFormat_v1_0 options:0 error:&writeError];
        if (!plist || ![plist writeToURL:file options:NSDataWritingAtomic error:&writeError]) {
            if(error)*error=writeError ?: [self failure:@"写入 Entitlements 模板失败" code:3]; return nil;
        }
        item[@"EntitlementsFile"]=filename;
        item[@"ApplicationIdentifier"]=ent[@"application-identifier"] ?: appIdentifier;
        [plans addObject:item];
    }
    NSDictionary *manifest=@{@"Version":@"1.0.0",@"Mode":@"PreparationOnly",
        @"TeamIdentifier":team ?: @"",@"ProfileName":profile[@"Name"] ?: @"",
        @"Components":plans,@"Warning":@"Templates are derived from the selected profile and require manual review. They are not signatures and do not prove entitlement authorization."};
    NSData *json=[NSJSONSerialization dataWithJSONObject:manifest options:NSJSONWritingPrettyPrinted error:nil];
    if(json) [json writeToURL:[out URLByAppendingPathComponent:@"SigningPlan.json"] options:NSDataWritingAtomic error:nil];
    return @{@"Directory":out.path,@"Components":plans,@"Issues":issues,
             @"Count":@(plans.count),@"GeneratedCount":@([plans filteredArrayUsingPredicate:[NSPredicate predicateWithFormat:@"EntitlementsFile != nil"]].count)};
}
@end
