#import "EntitlementsAudit.h"
#import "MachOSignatureInspector.h"
#import "DEREntitlementsDecoder.h"

static uint32_t EAReadBE32(const uint8_t *p) {
    return ((uint32_t)p[0]<<24)|((uint32_t)p[1]<<16)|((uint32_t)p[2]<<8)|p[3];
}
static BOOL EAIsDictionary(id value) { return [value isKindOfClass:NSDictionary.class]; }

@implementation EntitlementsAudit
+ (NSError *)failure:(NSString *)message code:(NSInteger)code {
    return [NSError errorWithDomain:@"AppleSigner.EntitlementsAudit" code:code
        userInfo:@{NSLocalizedDescriptionKey:message}];
}
+ (NSDictionary *)auditDirectoryAtURL:(NSURL *)directory outputDirectory:(NSURL *)outputDirectory error:(NSError **)error {
    BOOL isDir=NO;
    if (![NSFileManager.defaultManager fileExistsAtPath:directory.path isDirectory:&isDir] || !isDir) {
        if(error)*error=[self failure:@"IPA 解包目录不存在，请先解包 IPA" code:1]; return nil;
    }
    [NSFileManager.defaultManager createDirectoryAtURL:outputDirectory withIntermediateDirectories:YES attributes:nil error:nil];
    NSDirectoryEnumerator *en=[NSFileManager.defaultManager enumeratorAtURL:directory
        includingPropertiesForKeys:nil options:NSDirectoryEnumerationSkipsHiddenFiles errorHandler:^BOOL(NSURL *u,NSError *e){ return YES; }];
    NSMutableArray *items=[NSMutableArray array]; NSUInteger found=0, parsed=0, absent=0, failed=0;
    for (NSURL *infoURL in en) {
        if (![infoURL.lastPathComponent isEqualToString:@"Info.plist"]) continue;
        NSDictionary *info=[NSDictionary dictionaryWithContentsOfURL:infoURL];
        NSString *exe=info[@"CFBundleExecutable"];
        if (![exe isKindOfClass:NSString.class] || !exe.length) continue;
        NSURL *bundle=infoURL.URLByDeletingLastPathComponent;
        NSURL *binary=[bundle URLByAppendingPathComponent:exe];
        if (![NSFileManager.defaultManager fileExistsAtPath:binary.path]) continue;
        found++;
        NSError *inspectError=nil;
        NSDictionary *report=[MachOSignatureInspector inspectExecutableAtURL:binary error:&inspectError];
        if (!report) {
            failed++;
            [items addObject:@{@"Bundle":bundle.lastPathComponent,@"Executable":exe,@"Status":@"Mach-O 解析失败",@"Detail":inspectError.localizedDescription?:@"未知错误"}];
            continue;
        }
        NSData *file=[NSData dataWithContentsOfURL:binary options:NSDataReadingMappedIfSafe error:nil];
        if (!file) { failed++; continue; }
        const uint8_t *bytes=file.bytes; NSUInteger length=file.length;
        NSArray *slices=report[@"Slices"] ?: @[];
        NSUInteger foundBlobs=0;
        for (NSDictionary *slice in slices) {
            if (![slice[@"HasSignature"] boolValue] || ![slice[@"SignatureRegionValid"] boolValue] || ![slice[@"SuperBlobValid"] boolValue]) continue;
            uint64_t sliceOffset=[slice[@"Offset"] unsignedLongLongValue];
            uint64_t sigOffset=[slice[@"SignatureOffset"] unsignedLongLongValue];
            for (NSDictionary *blob in slice[@"Blobs"] ?: @[]) {
                NSString *type=blob[@"Type"];
                BOOL isXML=[type isEqual:@"Entitlements"];
                BOOL isDER=[type isEqual:@"DEREntitlements"];
                if (!isXML && !isDER) continue;
                foundBlobs++;
                uint64_t blobOffset=[blob[@"Offset"] unsignedLongLongValue];
                uint64_t blobLength=[blob[@"Length"] unsignedLongLongValue];
                uint64_t absolute=sliceOffset+sigOffset+blobOffset;
                if (absolute>length || blobLength>length-absolute || blobLength<8) {
                    failed++; [items addObject:@{@"Bundle":bundle.lastPathComponent,@"Status":@"Entitlements Blob 边界无效",@"Format":type?:@"未知"}]; continue;
                }
                const uint8_t *p=bytes+(NSUInteger)absolute;
                uint32_t expected=isXML?0xfade7171:0xfade7172;
                if (EAReadBE32(p)!=expected || EAReadBE32(p+4)!=blobLength) {
                    failed++; [items addObject:@{@"Bundle":bundle.lastPathComponent,@"Status":@"Entitlements Blob Header 无效",@"Format":type?:@"未知"}]; continue;
                }
                NSData *payload=[NSData dataWithBytes:p+8 length:(NSUInteger)blobLength-8];
                NSError *parseError=nil;
                id object=nil;
                if(isXML) object=[NSPropertyListSerialization propertyListWithData:payload options:NSPropertyListImmutable format:nil error:&parseError];
                else object=[DEREntitlementsDecoder decodeEntitlementsData:payload error:&parseError];
                if (!EAIsDictionary(object)) {
                    failed++;
                    [items addObject:@{@"Bundle":bundle.lastPathComponent,@"Status":@"Entitlements Blob 存在但解析失败",@"Format":type?:@"未知",@"Detail":parseError.localizedDescription?:@"不是有效字典"}];
                    continue;
                }
                parsed++;
                NSString *safe=[bundle.lastPathComponent stringByReplacingOccurrencesOfString:@"/" withString:@"_"];
                NSString *suffix=[NSString stringWithFormat:@"-%lu",(unsigned long)[slice[@"SliceIndex"] unsignedIntegerValue]];
                NSString *formatSuffix=isDER?@"-DER":@"-XML";
                NSString *name=[NSString stringWithFormat:@"%@%@%@.entitlements.plist",safe,slices.count>1?suffix:@"",formatSuffix];
                NSURL *dest=[outputDirectory URLByAppendingPathComponent:name];
                NSData *xml=[NSPropertyListSerialization dataWithPropertyList:object format:NSPropertyListXMLFormat_v1_0 options:0 error:nil];
                BOOL saved=xml && [xml writeToURL:dest options:NSDataWritingAtomic error:nil];
                [items addObject:@{@"Bundle":bundle.lastPathComponent,@"Status":saved?(isDER?@"已解码并导出 DER Entitlements":@"已提取 XML Entitlements"):@"解析成功但导出失败",
                    @"Format":type?:@"未知",@"Path":saved?dest.path:@"",@"Entitlements":object,@"Slice":slice[@"SliceIndex"]?:@0}];
            }
        }
        if (!foundBlobs) {
            absent++;
            [items addObject:@{@"Bundle":bundle.lastPathComponent,@"Status":@"未发现 XML/DER Entitlements Blob",
                @"Detail":@"可能未签名或签名结构不受当前解析器支持"}];
        }
    }
    if (!found) { if(error)*error=[self failure:@"没有找到可检查的 App/Extension/Framework 可执行文件" code:2]; return nil; }
    NSMutableArray *lines=[NSMutableArray array];
    for (NSDictionary *item in items) {
        [lines addObject:[NSString stringWithFormat:@"%@\n  格式：%@\n  状态：%@\n  %@",item[@"Bundle"],item[@"Format"]?:@"-",item[@"Status"],item[@"Path"]?:item[@"Detail"]?:@""]];
    }
    return @{@"ExecutableCount":@(found),@"ParsedCount":@(parsed),@"AbsentCount":@(absent),@"FailedCount":@(failed),
        @"Items":items,@"Report":[lines componentsJoinedByString:@"\n\n"],@"OutputDirectory":outputDirectory.path};
}
@end
