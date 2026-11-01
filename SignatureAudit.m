#import "SignatureAudit.h"
#import <CommonCrypto/CommonDigest.h>


static BOOL ASIsSafeResourcePath(NSString *path) {
    if (![path isKindOfClass:NSString.class] || path.length == 0 || path.length > 4096) return NO;
    if ([path hasPrefix:@"/"] || [path containsString:@"\\"] || [path rangeOfString:[NSString stringWithFormat:@"%c", 0]].location != NSNotFound) return NO;
    NSArray *parts = [path componentsSeparatedByString:@"/"];
    for (NSString *part in parts) if (part.length == 0 || [part isEqualToString:@"."] || [part isEqualToString:@".."] || [part containsString:@":"]) return NO;
    return YES;
}

static NSData *ASDigestForFile(NSURL *url, BOOL sha256) {
    NSDictionary *attrs = [NSFileManager.defaultManager attributesOfItemAtPath:url.path error:nil];
    if (![attrs[NSFileType] isEqualToString:NSFileTypeRegular] || [attrs[NSFileSize] unsignedLongLongValue] > 256ULL * 1024ULL * 1024ULL) return nil;
    NSData *data = [NSData dataWithContentsOfURL:url options:NSDataReadingMappedIfSafe error:nil];
    if (!data) return nil;
    if (sha256) { unsigned char digest[CC_SHA256_DIGEST_LENGTH]; CC_SHA256(data.bytes, (CC_LONG)data.length, digest); return [NSData dataWithBytes:digest length:sizeof(digest)]; }
    unsigned char digest[CC_SHA1_DIGEST_LENGTH]; CC_SHA1(data.bytes, (CC_LONG)data.length, digest); return [NSData dataWithBytes:digest length:sizeof(digest)];
}

static NSDictionary *ASAuditResourceHashes(NSURL *bundleURL, NSDictionary *plist) {
    NSFileManager *fm = NSFileManager.defaultManager;
    NSUInteger checked = 0, mismatch = 0, missing = 0, unsupported = 0;
    NSMutableArray *issues = [NSMutableArray array];
    for (NSString *section in @[@"files", @"files2"]) {
        id entries = plist[section];
        if (![entries isKindOfClass:NSDictionary.class]) continue;
        for (id rawPath in entries) {
            id value = entries[rawPath];
            if (!ASIsSafeResourcePath(rawPath)) { unsupported++; if (issues.count < 20) [issues addObject:@"资源路径不安全或格式无效"]; continue; }
            NSURL *target = [bundleURL URLByAppendingPathComponent:rawPath];
            NSString *resolved = [target.path stringByStandardizingPath].stringByResolvingSymlinksInPath;
            NSString *base = [bundleURL.path stringByStandardizingPath].stringByResolvingSymlinksInPath;
            if (![resolved hasPrefix:[base stringByAppendingString:@"/"]]) { unsupported++; if (issues.count < 20) [issues addObject:[NSString stringWithFormat:@"资源路径解析后越出 Bundle：%@", rawPath]]; continue; }
            NSDictionary *attrs = [fm attributesOfItemAtPath:target.path error:nil];
            if (!attrs || ![attrs[NSFileType] isEqualToString:NSFileTypeRegular]) { missing++; if (issues.count < 20) [issues addObject:[NSString stringWithFormat:@"资源缺失或不是普通文件：%@", rawPath]]; continue; }
            NSData *expected1 = nil, *expected2 = nil;
            if ([value isKindOfClass:NSData.class]) expected1 = value;
            else if ([value isKindOfClass:NSDictionary.class]) {
                id h1=value[@"hash"], h2=value[@"hash2"];
                if ([h1 isKindOfClass:NSData.class]) expected1=h1;
                if ([h2 isKindOfClass:NSData.class]) expected2=h2;
            }
            BOOL recognized = NO, matched = YES;
            if (expected1.length == CC_SHA1_DIGEST_LENGTH) { recognized=YES; NSData *actual=ASDigestForFile(target, NO); if (!actual || ![actual isEqualToData:expected1]) matched=NO; }
            if (expected2.length == CC_SHA256_DIGEST_LENGTH) { recognized=YES; NSData *actual=ASDigestForFile(target, YES); if (!actual || ![actual isEqualToData:expected2]) matched=NO; }
            if (!recognized) { unsupported++; continue; }
            checked++;
            if (!matched) { mismatch++; if (issues.count < 20) [issues addObject:[NSString stringWithFormat:@"资源哈希不匹配：%@", rawPath]]; }
        }
    }
    return @{ @"Checked":@(checked), @"Mismatched":@(mismatch), @"Missing":@(missing), @"Unsupported":@(unsupported), @"Issues":issues,
              @"Status":(mismatch || missing) ? @"resource-hash-failed" : (unsupported ? @"resource-hash-partial" : @"resource-hash-matched") };
}


static NSData *ASDigestForBytes(NSData *data, uint32_t hashType) {
    if (!data) return nil;
    unsigned char digest[CC_SHA384_DIGEST_LENGTH];
    if (hashType == 1) { CC_SHA1(data.bytes, (CC_LONG)data.length, digest); return [NSData dataWithBytes:digest length:CC_SHA1_DIGEST_LENGTH]; }
    if (hashType == 2 || hashType == 3) { CC_SHA256(data.bytes, (CC_LONG)data.length, digest); return [NSData dataWithBytes:digest length:(hashType == 3 ? 20 : CC_SHA256_DIGEST_LENGTH)]; }
    if (hashType == 4) { CC_SHA384(data.bytes, (CC_LONG)data.length, digest); return [NSData dataWithBytes:digest length:CC_SHA384_DIGEST_LENGTH]; }
    return nil;
}

static NSDictionary *ASAuditSpecialSlots(NSURL *bundleURL, NSArray *machOItems) {
    // Apple CodeDirectory special slots are numbered from 1 and stored
    // immediately before the code-slot hash array. Slot 1 seals Info.plist;
    // slot 3 seals _CodeSignature/CodeResources.
    NSUInteger checked = 0, mismatch = 0, unavailable = 0, unsupported = 0;
    NSMutableArray *issues = [NSMutableArray array];
    NSDictionary<NSNumber *, NSString *> *paths = @{@1:@"Info.plist", @3:@"_CodeSignature/CodeResources"};
    for (NSDictionary *item in machOItems) {
        NSDictionary *report = item[@"Report"];
        for (NSDictionary *slice in report[@"Slices"]) {
            NSArray *directories = slice[@"CodeDirectories"];
            if (![directories isKindOfClass:NSArray.class] || directories.count == 0) {
                unavailable++;
                if (issues.count < 20) [issues addObject:@"Mach-O slice 没有可审计的 CodeDirectory"];
                continue;
            }
            for (NSDictionary *cd in directories) {
            NSDictionary *hv = cd[@"HashVerification"];
            if (![hv isKindOfClass:NSDictionary.class]) { unsupported++; continue; }
            uint32_t hashType = [cd[@"HashType"] unsignedIntValue];
            NSArray *special = hv[@"SpecialSlotHashes"];
            if (![special isKindOfClass:NSArray.class]) continue;
            for (NSDictionary *entry in special) {
                NSNumber *slot = entry[@"Slot"];
                NSString *relative = paths[slot];
                if (!relative) { unsupported++; continue; }
                NSString *path = [bundleURL.path stringByAppendingPathComponent:relative];
                NSDictionary *attrs = [NSFileManager.defaultManager attributesOfItemAtPath:path error:nil];
                if (![attrs[NSFileType] isEqualToString:NSFileTypeRegular] ||
                    [attrs[NSFileSize] unsignedLongLongValue] > 32ULL*1024ULL*1024ULL) {
                    unavailable++;
                    if (issues.count < 20) [issues addObject:[NSString stringWithFormat:@"Special slot %@: 文件缺失或不可读（%@）", slot, relative]];
                    continue;
                }
                NSData *data = [NSData dataWithContentsOfFile:path];
                NSData *actual = ASDigestForBytes(data, hashType);
                NSData *expected = nil;
                NSString *hex = entry[@"Digest"];
                if ([hex isKindOfClass:NSString.class] && hex.length % 2 == 0) {
                    NSMutableData *decoded = [NSMutableData dataWithLength:hex.length/2];
                    uint8_t *out = decoded.mutableBytes;
                    for (NSUInteger i=0; i<decoded.length; i++) {
                        unsigned int v=0;
                        NSScanner *scanner=[NSScanner scannerWithString:[hex substringWithRange:NSMakeRange(i*2,2)]];
                        if (![scanner scanHexInt:&v]) { decoded=nil; break; }
                        out[i]=(uint8_t)v;
                    }
                    expected = decoded;
                }
                if (!actual || !expected || actual.length != expected.length) {
                    unsupported++;
                    continue;
                }
                checked++;
                if (![actual isEqualToData:expected]) {
                    mismatch++;
                    if (issues.count < 20) [issues addObject:[NSString stringWithFormat:@"Special slot %@ 哈希不匹配：%@", slot, relative]];
                }
            }
            }
        }
    }
    NSString *status = mismatch || unavailable ? @"special-slot-failed" :
                       (unsupported ? @"special-slot-partial" : (checked ? @"special-slot-matched" : @"special-slot-not-present"));
    return @{@"Checked":@(checked), @"Mismatched":@(mismatch), @"Unavailable":@(unavailable),
             @"Unsupported":@(unsupported), @"Status":status, @"Issues":issues};
}

@implementation SignatureAudit
+ (NSDictionary *)auditBundleAtURL:(NSURL *)url {
    NSFileManager *fm = NSFileManager.defaultManager;
    BOOL isDir = NO;
    if (![fm fileExistsAtPath:url.path isDirectory:&isDir] || !isDir) return nil;
    NSString *name = url.lastPathComponent;
    NSString *sigDir = [[url URLByAppendingPathComponent:@"_CodeSignature" isDirectory:YES] path];
    NSString *resources = [sigDir stringByAppendingPathComponent:@"CodeResources"];
    NSString *profile = [[url URLByAppendingPathComponent:@"embedded.mobileprovision"] path];
    BOOL sigDirIsDirectory = NO;
    BOOL hasSigDir = [fm fileExistsAtPath:sigDir isDirectory:&sigDirIsDirectory] && sigDirIsDirectory;
    BOOL resourcesIsDirectory = NO;
    BOOL hasResources = [fm fileExistsAtPath:resources isDirectory:&resourcesIsDirectory] && !resourcesIsDirectory;
    BOOL profileIsDirectory = NO;
    BOOL hasProfile = [fm fileExistsAtPath:profile isDirectory:&profileIsDirectory] && !profileIsDirectory;
    NSUInteger resourceCount = 0;
    NSDictionary *resourceHashAudit = nil;
    NSString *resourceStatus = @"不存在";
    if (hasResources) {
        NSDictionary *resourceAttrs = [fm attributesOfItemAtPath:resources error:nil];
        NSData *data = ([resourceAttrs[NSFileType] isEqualToString:NSFileTypeRegular] && [resourceAttrs[NSFileSize] unsignedLongLongValue] <= 32ULL * 1024ULL * 1024ULL)
            ? [NSData dataWithContentsOfFile:resources] : nil;
        NSError *e = nil;
        id plist = data ? [NSPropertyListSerialization propertyListWithData:data options:NSPropertyListImmutable format:nil error:&e] : nil;
        if ([plist isKindOfClass:NSDictionary.class]) {
            id files = plist[@"files"];
            id files2 = plist[@"files2"];
            id rules = plist[@"rules"];
            id rules2 = plist[@"rules2"];
            BOOL filesValid = [files isKindOfClass:NSDictionary.class] || [files2 isKindOfClass:NSDictionary.class];
            BOOL rulesValid = [rules isKindOfClass:NSDictionary.class] || [rules2 isKindOfClass:NSDictionary.class];
            if ([files isKindOfClass:NSDictionary.class]) resourceCount += [files count];
            if ([files2 isKindOfClass:NSDictionary.class]) resourceCount += [files2 count];
            if (filesValid && rulesValid) {
                resourceHashAudit = ASAuditResourceHashes(url, plist);
                resourceStatus = [NSString stringWithFormat:@"Plist 结构有效；资源哈希检查 %@（核对 %lu，失败 %lu，缺失 %lu，不支持 %lu）",
                    resourceHashAudit[@"Status"], (unsigned long)[resourceHashAudit[@"Checked"] unsignedIntegerValue],
                    (unsigned long)[resourceHashAudit[@"Mismatched"] unsignedIntegerValue],
                    (unsigned long)[resourceHashAudit[@"Missing"] unsignedIntegerValue],
                    (unsigned long)[resourceHashAudit[@"Unsupported"] unsignedIntegerValue]];
            } else {
                resourceStatus = [NSString stringWithFormat:@"Plist 可解析但结构不完整（files/files2 %@，rules/rules2 %@）",
                                  filesValid ? @"有效" : @"缺失/类型错误", rulesValid ? @"有效" : @"缺失/类型错误"];
            }
        } else {
            resourceStatus = @"存在但不是可解析的 plist 字典";
        }
    }
    NSDictionary *profileInfo = nil;
    NSString *profileStatus = @"不存在";
    if (hasProfile) {
        NSError *e = nil;
        profileInfo = [ProfileInspector inspectProfileAtURL:[NSURL fileURLWithPath:profile] error:&e];
        profileStatus = profileInfo ? [NSString stringWithFormat:@"存在：%@（%@）", profileInfo[@"Name"], [profileInfo[@"IsExpired"] boolValue] ? @"已过期" : @"未过期"] :
                                      [NSString stringWithFormat:@"存在但解析失败：%@", e.localizedDescription ?: @"未知错误"];
    }
    NSString *kind = [name.pathExtension.lowercaseString isEqualToString:@"appex"] ? @"App Extension" :
                     [name.pathExtension.lowercaseString isEqualToString:@"framework"] ? @"Framework" : @"App";
    NSMutableDictionary *result = [@{
        @"Name": name, @"Path": url.path, @"Type": kind,
        @"HasSignatureDirectory": @(hasSigDir),
        @"HasCodeResources": @(hasResources),
        @"CodeResourcesStatus": resourceStatus,
        @"CodeResourcesHashAudit": resourceHashAudit ?: @{},
        @"HasEmbeddedProfile": @(hasProfile),
        @"EmbeddedProfileStatus": profileStatus,
        // Artifact presence is not cryptographic verification.
        @"HasSignatureArtifacts": @(hasSigDir && hasResources),
        @"SignatureArtifactStatus": (hasSigDir && hasResources && [resourceStatus hasPrefix:@"Plist 结构有效"])
            ? @"artifacts-present-structure-only" : ((hasSigDir || hasResources) ? @"incomplete-or-malformed-artifacts" : @"no-signature-artifacts"),
        @"CryptographicVerification": @"not-performed",
        @"LooksSigned": @NO
    } mutableCopy];
    if (profileInfo) {
        result[@"EmbeddedProfileName"] = profileInfo[@"Name"] ?: @"未知";
        result[@"EmbeddedProfileExpired"] = profileInfo[@"IsExpired"] ?: @NO;
    }
    return result;
}
+ (NSDictionary *)auditDirectoryAtURL:(NSURL *)directory error:(NSError **)error {
    BOOL isDir = NO;
    if (![NSFileManager.defaultManager fileExistsAtPath:directory.path isDirectory:&isDir] || !isDir) {
        if (error) *error = [NSError errorWithDomain:@"AppleSigner.SignatureAudit" code:1
            userInfo:@{NSLocalizedDescriptionKey:@"解包目录不存在，请先解包 IPA"}];
        return nil;
    }
    NSDirectoryEnumerator *enumerator = [NSFileManager.defaultManager enumeratorAtURL:directory
        includingPropertiesForKeys:@[NSURLIsDirectoryKey] options:NSDirectoryEnumerationSkipsHiddenFiles
        errorHandler:^BOOL(NSURL *url, NSError *e) { return YES; }];
    NSMutableArray *bundles = [NSMutableArray array];
    for (NSURL *url in enumerator) {
        NSString *ext = url.pathExtension.lowercaseString;
        if (![@[@"app", @"appex", @"framework"] containsObject:ext]) continue;
        NSDictionary *item = [self auditBundleAtURL:url];
        if (item) [bundles addObject:item];
    }
    if (!bundles.count) {
        if (error) *error = [NSError errorWithDomain:@"AppleSigner.SignatureAudit" code:2
            userInfo:@{NSLocalizedDescriptionKey:@"没有发现 .app、.appex 或 .framework 组件"}];
        return nil;
    }
    NSDictionary *machOAudit = [MachOSignatureInspector inspectDirectoryAtURL:directory error:nil];
    NSArray *machOItems = [machOAudit[@"Items"] isKindOfClass:NSArray.class] ? machOAudit[@"Items"] : @[];
    NSMutableDictionary *specialByBundle = [NSMutableDictionary dictionary];
    for (NSDictionary *bundle in bundles) {
        NSString *bundlePath = bundle[@"Path"];
        NSURL *bundleURL = [NSURL fileURLWithPath:bundlePath isDirectory:YES];
        NSMutableArray *ownedMachOItems = [NSMutableArray array];
        for (NSDictionary *machOItem in machOItems) {
            NSString *ownerPath = [machOItem[@"BundlePath"] isKindOfClass:NSString.class] ? machOItem[@"BundlePath"] : @"";
            if (ownerPath.length && [ownerPath isEqualToString:bundlePath]) [ownedMachOItems addObject:machOItem];
        }
        NSDictionary *special = ownedMachOItems.count
            ? ASAuditSpecialSlots(bundleURL, ownedMachOItems)
            : @{@"Checked":@0, @"Mismatched":@0, @"Unavailable":@0, @"Unsupported":@0,
                @"Status":@"special-slot-not-present", @"Issues":@[@"该 Bundle 未发现可审计的 Mach-O 可执行文件"]};
        specialByBundle[bundlePath] = special;
    }
    NSUInteger artifactCount = 0, resourceCount = 0, profileCount = 0, malformedCount = 0, verifiedResourceHashes = 0, failedResourceHashes = 0, unsupportedResourceHashes = 0;
    NSUInteger specialChecked=0, specialFailed=0, specialUnavailable=0, specialUnsupported=0;
    NSMutableArray *lines = [NSMutableArray array];
    for (NSDictionary *b in bundles) {
        if ([b[@"HasSignatureArtifacts"] boolValue]) artifactCount++;
        if ([b[@"SignatureArtifactStatus"] isEqualToString:@"incomplete-or-malformed-artifacts"]) malformedCount++;
        if ([b[@"HasCodeResources"] boolValue]) resourceCount++;
        if ([b[@"HasEmbeddedProfile"] boolValue]) profileCount++;
        NSDictionary *ha = b[@"CodeResourcesHashAudit"];
        verifiedResourceHashes += [ha[@"Checked"] unsignedIntegerValue];
        failedResourceHashes += [ha[@"Mismatched"] unsignedIntegerValue] + [ha[@"Missing"] unsignedIntegerValue];
        unsupportedResourceHashes += [ha[@"Unsupported"] unsignedIntegerValue];
        NSDictionary *sa = specialByBundle[b[@"Path"]];
        specialChecked += [sa[@"Checked"] unsignedIntegerValue];
        specialFailed += [sa[@"Mismatched"] unsignedIntegerValue];
        specialUnavailable += [sa[@"Unavailable"] unsignedIntegerValue];
        specialUnsupported += [sa[@"Unsupported"] unsignedIntegerValue];
        [lines addObject:[NSString stringWithFormat:@"%@ %@\n  签名文件结构：%@\n  _CodeSignature：%@\n  CodeResources：%@\n  embedded.mobileprovision：%@\n  Special slots：%@（核对 %lu，失败 %lu，缺失 %lu，不支持 %lu）
  密码学验证：未执行",
            b[@"Type"], b[@"Name"], b[@"SignatureArtifactStatus"], [b[@"HasSignatureDirectory"] boolValue] ? @"存在" : @"缺失",
            b[@"CodeResourcesStatus"], b[@"EmbeddedProfileStatus"], sa[@"Status"],
            (unsigned long)[sa[@"Checked"] unsignedIntegerValue], (unsigned long)[sa[@"Mismatched"] unsignedIntegerValue],
            (unsigned long)[sa[@"Unavailable"] unsignedIntegerValue], (unsigned long)[sa[@"Unsupported"] unsignedIntegerValue]]];
    }
    return @{@"Components":bundles, @"ComponentCount":@(bundles.count),
             @"SignatureArtifactCount":@(artifactCount), @"MalformedArtifactCount":@(malformedCount),
             @"CodeResourcesCount":@(resourceCount), @"EmbeddedProfileCount":@(profileCount),
             @"ResourceHashChecks":@(verifiedResourceHashes),
             @"ResourceHashFailures":@(failedResourceHashes),
             @"ResourceHashUnsupported":@(unsupportedResourceHashes),
             @"SpecialSlotChecks":@(specialChecked), @"SpecialSlotFailures":@(specialFailed),
             @"SpecialSlotUnavailable":@(specialUnavailable), @"SpecialSlotUnsupported":@(specialUnsupported),
             @"SpecialSlotAuditByBundle":specialByBundle,
             @"CryptographicVerification":@"not-performed",
             @"Report":[lines componentsJoinedByString:@"\n\n"]};
}
@end
