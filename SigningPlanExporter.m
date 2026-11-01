#import "SigningPlanExporter.h"

static NSError *SPEError(NSString *message) {
    return [NSError errorWithDomain:@"AppleSigner.SigningPlanExporter" code:1
        userInfo:@{NSLocalizedDescriptionKey:message}];
}
static NSString *SPEBundlePatternForProfile(NSDictionary *profile) {
    NSString *pattern=profile[@"ApplicationIdentifier"];
    if (![pattern isKindOfClass:NSString.class] || !pattern.length) return @"";
    NSString *team=profile[@"TeamIdentifier"];
    if (![team isKindOfClass:NSString.class] || !team.length) {
        NSArray *prefixes=profile[@"ApplicationIdentifierPrefix"];
        if ([prefixes isKindOfClass:NSArray.class] && [prefixes.firstObject isKindOfClass:NSString.class])
            team=prefixes.firstObject;
    }
    if ([team isKindOfClass:NSString.class] && team.length) {
        NSString *teamDot=[team stringByAppendingString:@"."];
        if ([pattern hasPrefix:teamDot]) pattern=[pattern substringFromIndex:teamDot.length];
    }
    return pattern;
}
static BOOL SPEMatches(NSString *bundleID, NSString *pattern) {
    if (!bundleID.length || !pattern.length) return NO;
    if ([bundleID isEqualToString:pattern]) return YES;
    // Apple App ID wildcards are suffix wildcards; require the dot boundary.
    if ([pattern isEqualToString:@"*"]) return YES;
    if ([pattern hasSuffix:@".*"]) {
        NSString *prefix=[pattern substringToIndex:pattern.length-1];
        return [bundleID hasPrefix:prefix] && bundleID.length>prefix.length;
    }
    return NO;
}
static NSUInteger SPEPathDepth(NSString *path) {
    if (![path isKindOfClass:NSString.class] || !path.length) return NSUIntegerMax;
    return [[path pathComponents] count];
}
static NSInteger SPETypeRank(NSString *type) {
    if ([type isEqualToString:@"Framework"]) return 0;
    if ([type isEqualToString:@"App Extension"]) return 1;
    if ([type isEqualToString:@"App"]) return 3;
    return 2;
}
static NSString *SPEISODate(id value) {
    if (![value isKindOfClass:NSDate.class]) return @"未知";
    static NSISO8601DateFormatter *formatter;
    static dispatch_once_t once;
    dispatch_once(&once, ^{ formatter=[NSISO8601DateFormatter new]; });
    return [formatter stringFromDate:value];
}
@implementation SigningPlanExporter
+ (NSDictionary *)createPlanForIPAInfo:(NSDictionary *)ipaInfo profiles:(NSArray<NSDictionary *> *)profiles
                        certificateDER:(NSData *)certificateDER outputURL:(NSURL *)outputURL error:(NSError **)error {
    NSArray *components=ipaInfo[@"Components"];
    if (![components isKindOfClass:NSArray.class] || !components.count) {
        if(error)*error=SPEError(@"IPA 组件列表为空，请先解析 IPA"); return nil;
    }
    if (!profiles.count) { if(error)*error=SPEError(@"没有可用于映射的描述文件"); return nil; }

    NSMutableArray *componentPlans=[NSMutableArray array];
    NSUInteger ready=0, missing=0, expired=0, certMismatch=0, certUnknown=0, ambiguous=0;
    for (NSDictionary *component in components) {
        NSString *bundleID=component[@"BundleIdentifier"] ?: @"";
        NSString *kind=component[@"Type"] ?: @"Unknown";
        NSString *infoPath=[component[@"InfoPlistPath"] isKindOfClass:NSString.class]?component[@"InfoPlistPath"]:@"";
        NSString *bundlePath=[infoPath hasSuffix:@"/Info.plist"]?[infoPath substringToIndex:infoPath.length-@"/Info.plist".length]:@"";
        NSString *executable=component[@"Executable"];
        NSString *executablePath=(bundlePath.length && [executable isKindOfClass:NSString.class] && executable.length)
            ?[bundlePath stringByAppendingPathComponent:executable]:@"";
        NSMutableDictionary *entry=[@{@"bundleIdentifier":bundleID,@"type":kind,
            @"componentName":component[@"Name"] ?: bundleID,
            @"infoPlistPath":infoPath,@"bundlePath":bundlePath,
            @"executablePath":executablePath,
            @"requiresProfile":@(![kind isEqualToString:@"Framework"]),
            @"action":([kind isEqualToString:@"Framework"]?@"sign-nested-code-no-profile":([kind isEqualToString:@"App"]?@"sign-container-last":@"sign-nested-bundle")),
            @"signingOrder":@(-1),
            @"executionReadiness":@"not-executable-plan-only"} mutableCopy];
        if ([kind isEqualToString:@"Framework"]) {
            entry[@"status"]=@"host-signed-no-profile";
            entry[@"reason"]=@"Framework 属于嵌套代码，应在其外层 App 签名前处理；通常不单独分配 provisioning profile";
            entry[@"requiresProfile"]=@NO;
            [componentPlans addObject:entry]; continue;
        }
        NSMutableArray *candidates=[NSMutableArray array];
        for(NSDictionary *profile in profiles) {
            NSString *pattern=SPEBundlePatternForProfile(profile);
            if(SPEMatches(bundleID,pattern)) [candidates addObject:profile];
        }
        [candidates sortUsingComparator:^NSComparisonResult(NSDictionary *a, NSDictionary *b) {
            NSString *pa=SPEBundlePatternForProfile(a), *pb=SPEBundlePatternForProfile(b);
            BOOL exactA=[pa isEqualToString:bundleID], exactB=[pb isEqualToString:bundleID];
            if(exactA!=exactB) return exactA?NSOrderedAscending:NSOrderedDescending;
            if(pa.length!=pb.length) return pa.length>pb.length?NSOrderedAscending:NSOrderedDescending;
            return [(a[@"UUID"] ?: @"") compare:(b[@"UUID"] ?: @"") options:NSLiteralSearch];
        }];
        if(!candidates.count) {
            missing++; entry[@"status"]=@"missing-profile"; entry[@"reason"]=@"没有描述文件的 application-identifier 能匹配该 Bundle ID";
            [componentPlans addObject:entry]; continue;
        }
        NSDictionary *chosen=candidates.firstObject;
        BOOL isExpired=[chosen[@"IsExpired"] boolValue];
        BOOL certStateKnown=certificateDER.length>0;
        BOOL certOK=NO;
        for(id cert in chosen[@"DeveloperCertificates"] ?: @[]) if([cert isKindOfClass:NSData.class] && [cert isEqualToData:certificateDER]) { certOK=YES; break; }
        if(isExpired) expired++;
        if(candidates.count>1) ambiguous++;
        if(certStateKnown && !certOK) certMismatch++;
        if(!certStateKnown) certUnknown++;
        BOOL canProceed=!isExpired && certStateKnown && certOK;
        if(canProceed && candidates.count==1) ready++;
        NSMutableArray *reasons=[NSMutableArray array];
        if(isExpired) [reasons addObject:@"描述文件已过期"];
        if(certStateKnown && !certOK) [reasons addObject:@"P12 证书不在该描述文件 DeveloperCertificates 中"];
        if(candidates.count>1) [reasons addObject:@"存在多个匹配描述文件，需人工确认"];
        if(!certStateKnown) [reasons addObject:@"未导入 P12，证书匹配状态未知"];
        entry[@"status"]=isExpired?@"blocked":(certStateKnown?(certOK?(candidates.count>1?@"manual-review":@"candidate-ready"):@"blocked"):@"needs-certificate");
        entry[@"selectedProfile"]=@{@"name":chosen[@"Name"] ?: @"未命名",
            @"uuid":chosen[@"UUID"] ?: @"未知",
            @"applicationIdentifier":chosen[@"ApplicationIdentifier"] ?: @"",
            @"teamIdentifier":chosen[@"TeamIdentifier"] ?: @"",
            @"expirationDate":SPEISODate(chosen[@"ExpirationDate"]),
            @"isExpired":@(isExpired)};
        entry[@"candidateCount"]=@(candidates.count);
        entry[@"reasons"]=reasons;
        [componentPlans addObject:entry];
    }
    // Add standalone dynamic libraries to the inventory. They are nested code,
    // not provisioning-profile targets; their presence alone does not prove Mach-O validity.
    NSArray *nestedCode=ipaInfo[@"NestedCode"];
    if([nestedCode isKindOfClass:NSArray.class]) {
        for(NSDictionary *code in nestedCode) {
            NSString *codePath=[code[@"Path"] isKindOfClass:NSString.class]?code[@"Path"]:@"";
            if(!codePath.length) continue;
            [componentPlans addObject:[@{
                @"bundleIdentifier":@"",
                @"type":code[@"Type"] ?: @"Nested Code",
                @"componentName":code[@"Name"] ?: codePath.lastPathComponent,
                @"codePath":codePath,
                @"requiresProfile":@NO,
                @"action":@"sign-nested-code-no-profile",
                @"status":@"inventory-only",
                @"reason":@"按 IPA ZIP 路径扩展名发现；Mach-O 头部结果见 binaryStatus，尚未验证代码签名",
                @"signingOrder":@(-1),
                @"executionReadiness":@"not-executable-plan-only"
            } mutableCopy]];
        }
    }
    // Attach read-only Mach-O inventory findings to the corresponding plan rows.
    NSArray *binaryInventory=ipaInfo[@"BinaryInventory"];
    if([binaryInventory isKindOfClass:NSArray.class]) {
        NSMutableDictionary *byPath=[NSMutableDictionary dictionary];
        for(NSDictionary *binary in binaryInventory) if([binary[@"Path"] isKindOfClass:NSString.class]) byPath[binary[@"Path"]]=binary;
        for(NSMutableDictionary *entry in componentPlans) {
            NSString *path=entry[@"executablePath"] ?: entry[@"codePath"];
            NSDictionary *binary=byPath[path]; if(!binary) continue;
            entry[@"binaryFormat"]=binary[@"Format"] ?: @"Unknown";
            entry[@"binaryStatus"]=binary[@"Status"] ?: @"unknown";
            entry[@"architectures"]=binary[@"Architectures"] ?: @[];
            if(![binary[@"Status"] isEqualToString:@"macho"]) {
                entry[@"binaryReviewRequired"]=@YES;
                entry[@"binaryReviewReason"]=@"未能确认该路径是完整 Mach-O；签名计划不能据此视为可执行";
            }
        }
    }
    // Sign deepest nested code first; the containing app is always last.
    // Paths not discovered by IPAInspector are deliberately not assigned an inferred order.
    [componentPlans sortUsingComparator:^NSComparisonResult(NSDictionary *a, NSDictionary *b) {
        NSString *pa=a[@"bundlePath"] ?: a[@"codePath"] ?: @"";
        NSString *pb=b[@"bundlePath"] ?: b[@"codePath"] ?: @"";
        NSUInteger da=SPEPathDepth(pa), db=SPEPathDepth(pb);
        if(da!=db) return da>db?NSOrderedAscending:NSOrderedDescending;
        NSInteger ra=SPETypeRank(a[@"type"]), rb=SPETypeRank(b[@"type"]);
        if(ra!=rb) return ra<rb?NSOrderedAscending:NSOrderedDescending;
        return [pa compare:pb options:NSLiteralSearch];
    }];
    for(NSUInteger i=0;i<componentPlans.count;i++) {
        NSMutableDictionary *entry=componentPlans[i];
        entry[@"signingOrder"]=@(i+1);
        NSString *orderedPath=entry[@"bundlePath"] ?: entry[@"codePath"];
        if(![orderedPath isKindOfClass:NSString.class] || ![orderedPath length]) {
            entry[@"status"]=@"manual-review";
            entry[@"executionReadiness"]=@"manual-review";
            entry[@"reason"]=@"缺少可验证的 IPA 内部路径，不能自动安排签名顺序";
        }
    }
    NSDictionary *plan=@{@"formatVersion":@2,@"toolVersion":@"1.32.0",
        @"generatedAt":SPEISODate([NSDate date]),
        @"ipa":@{@"bundleIdentifier":ipaInfo[@"BundleIdentifier"] ?: @"",
                 @"name":ipaInfo[@"Name"] ?: @"",
                 @"version":ipaInfo[@"Version"] ?: @"未知"},
        @"certificate":@{@"available":@(certificateDER.length>0)},
        @"summary":@{@"componentCount":@(components.count),@"nestedCodeCount":@([nestedCode isKindOfClass:NSArray.class]?nestedCode.count:0),
            @"binaryCount":@([binaryInventory isKindOfClass:NSArray.class]?binaryInventory.count:0),
            @"machoCount":@([[binaryInventory filteredArrayUsingPredicate:[NSPredicate predicateWithBlock:^BOOL(NSDictionary *b, NSDictionary *bindings){return [b[@"Status"] isEqualToString:@"macho"];}]] count]),
            @"candidateReadyCount":@(ready),
            @"missingProfileCount":@(missing),@"expiredProfileCount":@(expired),
            @"certificateMismatchCount":@(certMismatch),@"certificateUnknownCount":@(certUnknown),
            @"ambiguousCount":@(ambiguous)},
        @"components":componentPlans,
        @"signingOrderPolicy":@"按 Bundle / 嵌套代码路径深度由内向外；嵌套代码和扩展先于主 App。该顺序是路径级计划，不代表完整 Mach-O 依赖拓扑。",
        @"executionStatus":@"plan-only-not-executed",
        @"discoveryCoverage":@[@"Payload 内所有可识别的 .app、.appex、.framework、.xpc Bundle 的 Info.plist",
            @"包含 App 内嵌套的 Watch App、App Clip、扩展及其内部 Framework / XPC Bundle（以 IPA 中存在标准 Info.plist 为前提）",
            @"按 ZIP 路径扩展名记录 Payload 内的 .dylib 文件，作为无 profile 的嵌套代码清单",
            @"读取 Bundle CFBundleExecutable 和 .dylib 的 ZIP 文件头，识别 thin/fat Mach-O；对 Fat slice 使用 ZIP 条目范围读取核对内部 Mach-O 头与架构表 CPU type/subtype"],
        @"discoveryLimitations":@[@"Mach-O 盘点仅覆盖已发现 Bundle executable 和 .dylib 路径；无扩展名的其他裸 Mach-O 仍可能遗漏",
            @"Fat Mach-O 会检查 slice 边界、重叠、对齐，并通过 ZIP 条目范围读取核对切片内部 Mach-O magic 与 CPU type/subtype；Deflate 条目需从流起点顺序解压到目标偏移。不会验证代码签名",
            @"ZIP64 不支持；前缀读取仅支持 stored/deflate，其他压缩方式标记为 unsupported-compression；ZIP 本地头加密标志或压缩方法不一致会拒绝读取",
            @"不解析 Watch / App Clip / XPC 的平台分发策略及专用签名约束",
            @"签名顺序仅按 IPA 路径深度推导，不能替代真实代码依赖关系分析"],
        @"warning":@"这是签名前映射与顺序计划，不是签名结果或可执行任务。未验证 CMS 信任链、证书撤销/有效期、设备授权、完整 Entitlements 语义、CodeDirectory、资源封印或最终可安装性。未知嵌套代码必须人工检查。"};
    NSError *jsonError=nil;
    NSData *json=[NSJSONSerialization dataWithJSONObject:plan options:NSJSONWritingPrettyPrinted error:&jsonError];
    if(!json || ![json writeToURL:outputURL options:NSDataWritingAtomic error:error]) {
        if(error && !*error)*error=jsonError ?: SPEError(@"签名计划写入失败");
        return nil;
    }
    return plan;
}
@end
