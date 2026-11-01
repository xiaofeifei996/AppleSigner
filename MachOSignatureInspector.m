#import "MachOSignatureInspector.h"
#import <CommonCrypto/CommonDigest.h>
#include <string.h>

static uint32_t U32(const uint8_t *p, BOOL little) {
    if (little) return (uint32_t)p[0] | ((uint32_t)p[1]<<8) | ((uint32_t)p[2]<<16) | ((uint32_t)p[3]<<24);
    return ((uint32_t)p[0]<<24) | ((uint32_t)p[1]<<16) | ((uint32_t)p[2]<<8) | p[3];
}
static NSString *MagicName(uint32_t m) {
    switch(m) {
        case 0xfade0cc0: return @"EmbeddedSignature";
        case 0xfade0c02: return @"CodeDirectory";
        case 0xfade7171: return @"Entitlements";
        case 0xfade7172: return @"DEREntitlements";
        case 0xfade0b01: return @"BlobWrapper(CMS)";
        default: return [NSString stringWithFormat:@"0x%08x",m];
    }
}
static NSArray<NSNumber *> *ASScatterOffsets(const uint8_t *cd, NSUInteger blobLength,
                                                   uint32_t scatterOffset, uint32_t codeSlots,
                                                   uint64_t pageBytes, uint64_t codeLimit,
                                                   NSUInteger fileSize, uint64_t hashStart,
                                                   uint64_t hashEnd, NSString **failure) {
    if (!scatterOffset) return nil;
    if (scatterOffset < 44 || scatterOffset > blobLength - 16) {
        if (failure) *failure = @"scatterOffset 指向无效区域";
        return nil;
    }
    NSMutableArray *offsets = [NSMutableArray arrayWithCapacity:codeSlots];
    for (uint32_t i=0; i<codeSlots; i++) [offsets addObject:NSNull.null];
    NSMutableArray<NSValue *> *ranges = [NSMutableArray array];
    BOOL terminated = NO;
    NSUInteger cursor = scatterOffset;
    NSUInteger maxEntries = (blobLength - scatterOffset) / 16;
    for (NSUInteger entry=0; entry<maxEntries; entry++, cursor+=16) {
        uint32_t count=U32(cd+cursor,NO), base=U32(cd+cursor+4,NO);
        uint32_t target=U32(cd+cursor+8,NO), spare=U32(cd+cursor+12,NO);
        if (count==0) {
            if (base || target || spare) { if(failure)*failure=@"scatter 终止项格式无效"; return nil; }
            terminated=YES; break;
        }
        if (spare!=0 || base>codeSlots || count>codeSlots-base || target%pageBytes!=0) {
            if(failure)*failure=@"scatter 项字段、slot 范围或页面对齐无效"; return nil;
        }
        for (uint32_t j=0; j<count; j++) {
            uint32_t slot=base+j;
            if (offsets[slot] != NSNull.null) { if(failure)*failure=@"scatter slot 重复映射"; return nil; }
            uint64_t fileOffset=(uint64_t)target+(uint64_t)j*pageBytes;
            if (fileOffset>=codeLimit || fileOffset>=fileSize) { if(failure)*failure=@"scatter 页面偏移超出 CodeLimit 或文件范围"; return nil; }
            uint64_t chunk=MIN(pageBytes, codeLimit-fileOffset);
            if (chunk>fileSize-fileOffset) { if(failure)*failure=@"scatter 页面越过文件边界"; return nil; }
            uint64_t end=fileOffset+chunk;
            for (NSValue *v in ranges) { NSRange old=v.rangeValue; if(fileOffset<NSMaxRange(old) && old.location<end) { if(failure)*failure=@"scatter 页面数据范围重叠"; return nil; } }
            [ranges addObject:[NSValue valueWithRange:NSMakeRange((NSUInteger)fileOffset,(NSUInteger)chunk)]];
            offsets[slot]=@(fileOffset);
        }
    }
    if (!terminated) { if(failure)*failure=@"scatter 向量缺少全零终止项"; return nil; }
    if (scatterOffset < hashEnd && hashStart < cursor) {
        if(failure)*failure=@"scatter 向量与 CodeDirectory 哈希数组重叠";
        return nil;
    }
    for (id value in offsets) if (value==NSNull.null) { if(failure)*failure=@"scatter 未覆盖全部 CodeSlots"; return nil; }
    return offsets;
}
@implementation MachOSignatureInspector
+ (NSDictionary *)inspectExecutableAtURL:(NSURL *)url error:(NSError **)error {
    NSData *d=[NSData dataWithContentsOfURL:url options:NSDataReadingMappedIfSafe error:error];
    if(!d) return nil;
    const uint8_t *b=d.bytes; NSUInteger n=d.length;
    if(n<4) { if(error)*error=[NSError errorWithDomain:@"AppleSigner.MachO" code:1 userInfo:@{NSLocalizedDescriptionKey:@"文件太短，不是有效 Mach-O"}]; return nil; }
    uint32_t magic=U32(b,YES); BOOL fat=(magic==0xbebafeca || magic==0xcafebabe || magic==0xbfbafeca || magic==0xcafebabf);
    NSMutableArray *slices=[NSMutableArray array]; NSMutableArray *fatRanges=[NSMutableArray array]; NSMutableSet *fatCPUs=[NSMutableSet set];
    if(fat) {
        BOOL little=(magic==0xbebafeca || magic==0xbfbafeca);
        BOOL fat64=(magic==0xbfbafeca || magic==0xcafebabf);
        if(n<8) goto malformed;
        uint32_t count=U32(b+4,little); NSUInteger stride=fat64?32:20;
        if(count>64 || 8+(uint64_t)count*stride>n) goto malformed;
        for(uint32_t i=0;i<count;i++) {
            const uint8_t *a=b+8+i*stride;
            uint64_t off=fat64?(((uint64_t)U32(a+8,little)<<32)|U32(a+12,little)):U32(a+8,little);
            uint64_t size=fat64?(((uint64_t)U32(a+16,little)<<32)|U32(a+20,little)):U32(a+12,little);
            uint32_t cpu=U32(a,little), subtype=U32(a+4,little);
            uint32_t align=U32(a+(fat64?24:16),little);
            if(off>n || size>n-off || size<28 || off<8+(uint64_t)count*stride || align>31 || (align && (off & ((((uint64_t)1)<<align)-1)))) goto malformed;
            NSString *cpuKey=[NSString stringWithFormat:@"%u:%u",cpu,subtype];
            if([fatCPUs containsObject:cpuKey]) goto malformed;
            [fatCPUs addObject:cpuKey];
            for(NSDictionary *range in fatRanges) { uint64_t oldOff=[range[@"Offset"] unsignedLongLongValue], oldSize=[range[@"Size"] unsignedLongLongValue]; if(off<oldOff+oldSize && oldOff<off+size) goto malformed; }
            [fatRanges addObject:@{@"Offset":@(off),@"Size":@(size)}];
            NSDictionary *s=[self inspectBytes:b+(NSUInteger)off length:(NSUInteger)size];
            NSMutableDictionary *m=[s mutableCopy]; m[@"SliceIndex"]=@(i); m[@"Offset"]=@(off); m[@"Size"]=@(size); m[@"CPUType"]=@(cpu); m[@"CPUSubtype"]=@(subtype); m[@"AlignmentExponent"]=@(align);
            if([s[@"IsMachO"] boolValue]) { BOOL headerLittle=[s[@"ByteOrder"] isEqualToString:@"Little Endian"]; uint32_t actualCPU=U32(b+(NSUInteger)off+4,headerLittle), actualSubtype=U32(b+(NSUInteger)off+8,headerLittle); m[@"HeaderCPUType"]=@(actualCPU); m[@"HeaderCPUSubtype"]=@(actualSubtype); m[@"ArchitectureMatchesFatHeader"]=@((actualCPU==cpu)&&(actualSubtype==subtype)); if(actualCPU!=cpu || actualSubtype!=subtype) m[@"ArchitectureError"]=@"Fat header 与 slice Mach-O header 的 CPU type/subtype 不一致"; }
            [slices addObject:m];
        }
    } else {
        [slices addObject:[self inspectBytes:b length:n]];
    }
    return @{@"File":url.lastPathComponent,@"FileSize":@(n),@"IsFat":@(fat),@"Slices":slices};
malformed:
    if(error)*error=[NSError errorWithDomain:@"AppleSigner.MachO" code:2 userInfo:@{NSLocalizedDescriptionKey:@"Mach-O fat header 或 slice 边界无效"}];
    return nil;
}
+ (NSDictionary *)inspectBytes:(const uint8_t *)b length:(NSUInteger)n {
    uint32_t m=U32(b,YES); BOOL little=(m==0xfeedface || m==0xfeedfacf);
    BOOL is64=(m==0xfeedfacf || m==0xcffaedfe);
    BOOL valid=(m==0xfeedface || m==0xfeedfacf || m==0xcefaedfe || m==0xcffaedfe);
    if(!valid || n<(is64?32:28)) return @{@"IsMachO":@NO,@"Format":@"未知或非 Mach-O",@"HasSignature":@NO};
    uint32_t ncmd=U32(b+16,little), sizeofcmds=U32(b+20,little);
    NSUInteger header=is64?32:28;
    if(ncmd>65536 || sizeofcmds>n-header) return @{@"IsMachO":@YES,@"Format":is64?@"64-bit":@"32-bit",@"MalformedLoadCommands":@YES,@"HasSignature":@NO};
    NSUInteger pos=header; uint32_t dataoff=0,datasize=0; BOOL found=NO, malformedCommands=NO, duplicateSignatureCommand=NO;
    uint64_t commandEnd=(uint64_t)header+sizeofcmds;
    for(uint32_t i=0;i<ncmd;i++) {
        if(pos+8>commandEnd) { malformedCommands=YES; break; }
        uint32_t cmd=U32(b+pos,little), cmdsize=U32(b+pos+4,little);
        if(cmdsize<8 || (cmdsize&3)!=0 || cmdsize>commandEnd-pos) { malformedCommands=YES; break; }
        if(cmd==0x1d) {
            if(cmdsize<16) { malformedCommands=YES; break; }
            if(found) duplicateSignatureCommand=YES;
            dataoff=U32(b+pos+8,little); datasize=U32(b+pos+12,little); found=YES;
        }
        pos+=cmdsize;
    }
    if(pos!=commandEnd) malformedCommands=YES;
    NSMutableDictionary *r=[@{@"IsMachO":@YES,@"Format":is64?@"64-bit":@"32-bit",@"ByteOrder":little?@"Little Endian":@"Big Endian",@"LoadCommandCount":@(ncmd),@"HasSignature":@(found),@"LoadCommandsValid":@(!malformedCommands)} mutableCopy];
    if(malformedCommands) { r[@"LoadCommandsError"]=@"Load command 数量、长度、对齐或总长度不一致"; return r; }
    if(duplicateSignatureCommand) { r[@"SignatureRegionValid"]=@NO; r[@"SignatureRegionError"]=@"存在多个 LC_CODE_SIGNATURE 命令"; return r; }
    if(!found) return r;
    r[@"SignatureOffset"]=@(dataoff); r[@"SignatureSize"]=@(datasize);
    if(dataoff>n || datasize>n-dataoff || datasize<12 || dataoff<commandEnd) {
        r[@"SignatureRegionValid"]=@NO;
        r[@"SignatureRegionError"]=@"签名区域越界、过短或与 Mach-O Header/Load Commands 重叠";
        return r;
    }
    r[@"SignatureRegionValid"]=@YES;
    const uint8_t *p=b+dataoff; uint32_t sm=U32(p,NO), length=U32(p+4,NO), count=U32(p+8,NO);
    if(sm!=0xfade0cc0 || length<12 || length>datasize || count>4096 || 12+(uint64_t)count*8>length) {
        r[@"SuperBlobValid"]=@NO; return r;
    }
    NSMutableArray *blobs=[NSMutableArray array]; NSMutableArray *codeDirectories=[NSMutableArray array]; NSMutableDictionary *primaryCD=[NSMutableDictionary dictionary]; NSMutableArray *blobRanges=[NSMutableArray array]; NSMutableSet *seenSlots=[NSMutableSet set];
    for(uint32_t i=0;i<count;i++) {
        uint32_t type=U32(p+12+i*8,NO), off=U32(p+16+i*8,NO);
        if([seenSlots containsObject:@(type)]) { r[@"SuperBlobValid"]=@NO; r[@"SuperBlobError"]=@"SuperBlob 存在重复 slot index"; return r; }
        [seenSlots addObject:@(type)];
        if(off<12+(uint64_t)count*8 || off>length-8) { r[@"SuperBlobValid"]=@NO; r[@"SuperBlobError"]=@"子 Blob offset 指向索引表或越界"; return r; }
        uint32_t bm=U32(p+off,NO), bl=U32(p+off+4,NO);
        if(bl<8 || bl>length-off) { r[@"SuperBlobValid"]=@NO; r[@"SuperBlobError"]=@"子 Blob 长度越界"; return r; }
        for(NSDictionary *range in blobRanges) { uint64_t oldOff=[range[@"Offset"] unsignedLongLongValue], oldLen=[range[@"Length"] unsignedLongLongValue]; if(off<oldOff+oldLen && oldOff<off+bl) { r[@"SuperBlobValid"]=@NO; r[@"SuperBlobError"]=@"SuperBlob 子 Blob 区域重叠"; return r; } }
        [blobRanges addObject:@{@"Offset":@(off),@"Length":@(bl)}];
        [blobs addObject:@{@"Slot":@(type),@"Type":MagicName(bm),@"Length":@(bl),@"Offset":@(off)}];
        if(bm==0xfade0c02 && bl>=44) {
            uint32_t ver=U32(p+off+8,NO), flags=U32(p+off+12,NO);
            uint32_t hashOffset=U32(p+off+16,NO);
            uint32_t identOffset=U32(p+off+20,NO);
            uint8_t hashSize=p[off+36], hashType=p[off+37], pageSize=p[off+39];
            uint32_t codeLimit=U32(p+off+32,NO);
            NSMutableDictionary *c=[@{@"Version":[NSString stringWithFormat:@"0x%08x",ver],@"Flags":@(flags),@"CodeLimit":@(codeLimit),@"HashSize":@(hashSize),@"HashType":@(hashType),@"PageSizeExponent":@(pageSize),@"HashOffset":@(hashOffset),@"IdentifierOffset":@(identOffset)} mutableCopy];
            if(bl>=44) { uint32_t slots=U32(p+off+28,NO); c[@"CodeSlots"]=@(slots); }
            NSUInteger ident=identOffset;
            if(ident<bl && ident>=44) {
                const char *s=(const char *)(p+off+ident); NSUInteger max=bl-ident, z=0; while(z<max && s[z])z++;
                if(z<max) c[@"Identifier"]=[[NSString alloc] initWithBytes:s length:z encoding:NSUTF8StringEncoding] ?: @"";
            }
            c[@"SuperBlobSlot"]=@(type);
            c[@"Role"]=(type==0)?@"Primary":(type>=0x1000?@"Alternate":@"CodeDirectoryOtherSlot");
            [codeDirectories addObject:c];
            if(type==0 || primaryCD.count==0) primaryCD=c;
            uint32_t nSpecial=U32(p+off+24,NO), nCode=U32(p+off+28,NO);
            // hashOffset points to code slot 0; special slots precede it.
            uint64_t hashArrayStart=(uint64_t)hashOffset;
            uint64_t required=(uint64_t)nCode*hashSize;
            uint64_t codeLimit64=codeLimit;
            uint32_t scatterOffset=0, teamOffset=0, preEncryptOffset=0;
            BOOL extensionLayoutValid=YES;
            if(ver>=0x20100) {
                if(bl<48) extensionLayoutValid=NO;
                else scatterOffset=U32(p+off+44,NO);
            }
            if(ver>=0x20200) {
                if(bl<52) extensionLayoutValid=NO;
                else teamOffset=U32(p+off+48,NO);
            }
            if(ver>=0x20300) {
                if(bl<64) extensionLayoutValid=NO;
                else {
                    uint64_t extended=((uint64_t)U32(p+off+56,NO)<<32)|U32(p+off+60,NO);
                    if(extended) codeLimit64=extended;
                }
            }
            if(ver>=0x20400 && bl<88) extensionLayoutValid=NO;
            if(ver>=0x20500) {
                if(bl<96) extensionLayoutValid=NO;
                else preEncryptOffset=U32(p+off+92,NO);
            }
            if(ver>=0x20600 && bl<108) extensionLayoutValid=NO;
            c[@"ScatterOffset"]=@(scatterOffset);
            c[@"TeamOffset"]=@(teamOffset);
            c[@"PreEncryptOffset"]=@(preEncryptOffset);
            c[@"ExtensionLayoutValid"]=@(extensionLayoutValid);
            NSMutableDictionary *verification=[NSMutableDictionary dictionary];
            verification[@"DeclaredCodeSlots"]=@(nCode);
            verification[@"DeclaredSpecialSlots"]=@(nSpecial);
            verification[@"CodeLimit"]=@(codeLimit64);
            verification[@"PageSizeBytes"]=(pageSize<31)?@((uint64_t)1<<pageSize):@0;
            BOOL supported=(hashType==1 || hashType==2 || hashType==3 || hashType==4);
            NSUInteger expectedHashSize=(hashType==1)?20:((hashType==2)?32:((hashType==3)?20:((hashType==4)?48:0)));
            verification[@"HashAlgorithm"]=(
                @{ @1:@"SHA-1", @2:@"SHA-256", @3:@"SHA-256-truncated", @4:@"SHA-384" }[@(hashType)] ?: @"Unsupported");
            uint64_t specialBytes=(uint64_t)nSpecial*hashSize;
            uint64_t hashArrayEnd=hashArrayStart+required;
            BOOL bounds=(hashSize>0 && hashSize==expectedHashSize && hashOffset>=specialBytes &&
                         hashOffset-specialBytes>=((ver>=0x20100)?48:44) && hashArrayStart<=bl && required<=bl-hashArrayStart &&
                         hashArrayEnd<=bl && codeLimit64<=dataoff && codeLimit64<=n && pageSize<31);
            BOOL optionalOffsetsValid=(!teamOffset || (teamOffset<bl && (teamOffset<hashOffset-specialBytes || teamOffset>=hashArrayEnd))) &&
                                      (!preEncryptOffset || (preEncryptOffset<bl && (preEncryptOffset<hashOffset-specialBytes || preEncryptOffset>=hashArrayEnd)));
            if(identOffset && (identOffset<44 || identOffset>=bl)) optionalOffsetsValid=NO;
            if(identOffset>=hashOffset-specialBytes && identOffset<hashArrayEnd) optionalOffsetsValid=NO;
            if(identOffset>=44 && identOffset<bl) {
                const uint8_t *identBytes=p+off+identOffset; NSUInteger remain=bl-identOffset; BOOL terminated=NO;
                for(NSUInteger k=0;k<remain;k++) if(identBytes[k]==0) { terminated=YES; break; }
                if(!terminated) optionalOffsetsValid=NO;
            }
            if(!extensionLayoutValid || !optionalOffsetsValid) {
                verification[@"Status"]=@"不支持：CodeDirectory 扩展字段长度或偏移无效";
            } else if(ver>0x20600) {
                verification[@"Status"]=@"不支持：未知的 CodeDirectory 未来版本";
            } else if(!bounds || !supported) {
                verification[@"Status"]=@"无法验证：哈希算法、摘要长度或边界不支持";
            } else {
                NSUInteger pageBytes=(NSUInteger)1<<pageSize;
                NSArray<NSNumber *> *scatterOffsets=nil;
                NSString *scatterFailure=nil;
                if (scatterOffset) scatterOffsets=ASScatterOffsets(p+off,bl,scatterOffset,nCode,pageBytes,codeLimit64,n,
                                                                    hashOffset-specialBytes,hashOffset+(uint64_t)nCode*hashSize,&scatterFailure);
                uint64_t expectedSlots=(codeLimit64+pageBytes-1)/pageBytes;
                BOOL slotLayoutValid = scatterOffset ? (scatterOffsets!=nil) : (expectedSlots==nCode);
                if(!slotLayoutValid) {
                    verification[@"Status"]=scatterOffset ? (scatterFailure ?: @"scatter 结构无效") : @"不匹配：CodeSlots 与 CodeLimit/PageSize 不一致";
                    verification[@"ScatterPresent"]=@(scatterOffset!=0);
                } else {
                    BOOL allMatch=YES; NSUInteger mismatch=0;
                    for(uint32_t slot=0;slot<nCode;slot++) {
                        uint64_t start=scatterOffset ? scatterOffsets[slot].unsignedLongLongValue : (uint64_t)slot*pageBytes;
                        NSUInteger chunk=(NSUInteger)MIN((uint64_t)pageBytes,codeLimit64-start);
                        const void *bytes=b+(NSUInteger)start;
                        unsigned char digest[CC_SHA384_DIGEST_LENGTH]; size_t digestLen=0;
                        if(hashType==1) { CC_SHA1(bytes,(CC_LONG)chunk,digest); digestLen=CC_SHA1_DIGEST_LENGTH; }
                        else if(hashType==2 || hashType==3) { CC_SHA256(bytes,(CC_LONG)chunk,digest); digestLen=hashType==3?20:CC_SHA256_DIGEST_LENGTH; }
                        else { CC_SHA384(bytes,(CC_LONG)chunk,digest); digestLen=CC_SHA384_DIGEST_LENGTH; }
                        if(digestLen!=hashSize || memcmp(digest,p+off+hashArrayStart+(uint64_t)slot*hashSize,hashSize)!=0) { allMatch=NO; mismatch++; }
                    }
                    verification[@"VerifiedSlots"]=@(nCode-mismatch);
                    verification[@"MismatchedSlots"]=@(mismatch);
                    verification[@"ScatterPresent"]=@(scatterOffset!=0);
                    verification[@"Status"]=allMatch?(scatterOffset?@"全部 scatter CodeDirectory 页面哈希匹配":@"全部 CodeDirectory 页面哈希匹配"):@"页面哈希不匹配";
                    NSMutableArray *special = [NSMutableArray arrayWithCapacity:nSpecial];
                    const uint8_t *specialBase = p+off+hashOffset-specialBytes;
                    for (uint32_t slot=1; slot<=nSpecial; slot++) {
                        const uint8_t *digestBytes = specialBase+(uint64_t)(nSpecial-slot)*hashSize;
                        NSMutableString *hex = [NSMutableString stringWithCapacity:hashSize*2];
                        for (uint8_t j=0; j<hashSize; j++) [hex appendFormat:@"%02x", digestBytes[j]];
                        [special addObject:@{@"Slot":@(slot), @"Digest":hex}];
                    }
                    verification[@"SpecialSlotHashes"] = special;
                }
            }
            c[@"HashVerification"]=verification;
        }
    }
    r[@"SuperBlobValid"]=@YES; r[@"Blobs"]=blobs;
    if(codeDirectories.count) { r[@"CodeDirectories"]=codeDirectories; r[@"CodeDirectory"]=primaryCD; }
    r[@"CodeDirectoryCount"]=@(codeDirectories.count);
    return r;
}
+ (NSDictionary *)inspectDirectoryAtURL:(NSURL *)url error:(NSError **)error {
    NSFileManager *fm=NSFileManager.defaultManager;
    NSDirectoryEnumerator *en=[fm enumeratorAtURL:url includingPropertiesForKeys:@[NSURLIsDirectoryKey] options:NSDirectoryEnumerationSkipsHiddenFiles errorHandler:^BOOL(NSURL *u,NSError *e){ return YES; }];
    NSMutableArray *results=[NSMutableArray array]; NSUInteger checked=0;
    for(NSURL *u in en) {
        if(![u.lastPathComponent isEqualToString:@"Info.plist"]) continue;
        NSDictionary *info=[NSDictionary dictionaryWithContentsOfURL:u];
        NSString *exe=info[@"CFBundleExecutable"];
        if(![exe isKindOfClass:NSString.class] || !exe.length) continue;
        NSURL *binary=[[u URLByDeletingLastPathComponent] URLByAppendingPathComponent:exe];
        BOOL dir=NO; if(![fm fileExistsAtPath:binary.path isDirectory:&dir] || dir) continue;
        NSError *e=nil; NSDictionary *report=[self inspectExecutableAtURL:binary error:&e];
        checked++;
        NSString *bundlePath = u.URLByDeletingLastPathComponent.path ?: @"";
        NSString *executablePath = binary.path ?: @"";
        if(report) [results addObject:@{@"Bundle":u.URLByDeletingLastPathComponent.lastPathComponent,
            @"BundlePath":bundlePath, @"Executable":exe, @"ExecutablePath":executablePath, @"Report":report}];
        else [results addObject:@{@"Bundle":u.URLByDeletingLastPathComponent.lastPathComponent,
            @"BundlePath":bundlePath, @"Executable":exe, @"ExecutablePath":executablePath,
            @"Error":e.localizedDescription?:@"解析失败"}];
    }
    return @{@"Count":@(checked),@"Items":results};
}
@end
