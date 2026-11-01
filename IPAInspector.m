#import "IPAInspector.h"
#import <zlib.h>
#import <string.h>

static uint16_t R16(const uint8_t *p){ return (uint16_t)p[0] | ((uint16_t)p[1]<<8); }
static uint32_t R32(const uint8_t *p){ return (uint32_t)p[0] | ((uint32_t)p[1]<<8) | ((uint32_t)p[2]<<16) | ((uint32_t)p[3]<<24); }

static BOOL IPAPathHasBundleSuffix(NSString *path, NSString *suffix) {
    NSArray<NSString *> *parts=[path pathComponents];
    for(NSString *part in parts) if([part.lowercaseString hasSuffix:suffix]) return YES;
    return NO;
}
static NSString *IPAComponentType(NSString *path) {
    NSString *lower=path.lowercaseString;
    NSArray<NSString *> *parts=[path pathComponents];
    NSString *bundle=parts.count>=2?parts[parts.count-2]:@"";
    NSString *bundleLower=bundle.lowercaseString;
    if([bundleLower hasSuffix:@".framework"]) return @"Framework";
    if([bundleLower hasSuffix:@".appex"]) return @"App Extension";
    if([bundleLower hasSuffix:@".xpc"]) return @"XPC Service";
    if([bundleLower hasSuffix:@".app"]) {
        if([lower containsString:@"/appclips/"]) return @"App Clip";
        if([lower containsString:@"/watch/"]) return @"Watch App";
        if(parts.count==3 && [parts[0] isEqualToString:@"Payload"]) return @"App";
        return @"Nested App";
    }
    return nil;
}
static BOOL IPAIsStandardCodeBundleInfoPath(NSString *path) {
    if(![path hasPrefix:@"Payload/"] || ![path hasSuffix:@"/Info.plist"]) return NO;
    return IPAPathHasBundleSuffix(path,@".app") ||
           IPAPathHasBundleSuffix(path,@".appex") ||
           IPAPathHasBundleSuffix(path,@".framework") ||
           IPAPathHasBundleSuffix(path,@".xpc");
}


static uint32_t R32BE(const uint8_t *p){ return ((uint32_t)p[0]<<24)|((uint32_t)p[1]<<16)|((uint32_t)p[2]<<8)|p[3]; }
static uint64_t R64(const uint8_t *p, BOOL little){ return little?((uint64_t)R32(p)|((uint64_t)R32(p+4)<<32)):(((uint64_t)R32BE(p)<<32)|R32BE(p+4)); }
static NSString *IPACPUName(uint32_t cpu, uint32_t subtype) {
    if(cpu==0x0100000c) return (subtype&0x00ffffff)==2?@"arm64e":@"arm64";
    if(cpu==12) return @"arm";
    if(cpu==0x01000007) return @"x86_64";
    if(cpu==7) return @"i386";
    if(cpu==0x0200000c) return @"arm64_32";
    return [NSString stringWithFormat:@"cpu-0x%08x",cpu];
}
static NSData *IPAReadPrefix(const uint8_t *archive, NSUInteger length, uint32_t offset, uint32_t compressed, uint32_t uncompressed, uint16_t method, NSString **status) {
    if((uint64_t)offset+30>length || R32(archive+offset)!=0x04034b50){ if(status)*status=@"zip-entry-invalid"; return nil; }
    uint16_t flags=R16(archive+offset+6), localMethod=R16(archive+offset+8);
    if((flags&1) || localMethod!=method){ if(status)*status=(flags&1)?@"encrypted-entry-unsupported":@"zip-method-mismatch"; return nil; }
    uint16_t nl=R16(archive+offset+26), el=R16(archive+offset+28);
    uint64_t pos=(uint64_t)offset+30+nl+el;
    if(pos+compressed>length){if(status)*status=@"zip-entry-invalid";return nil;}
    NSUInteger wanted=MIN((NSUInteger)131080,(NSUInteger)uncompressed);
    NSMutableData *out=[NSMutableData dataWithLength:wanted];
    if(method==0){ if(compressed!=uncompressed){if(status)*status=@"zip-entry-invalid";return nil;} if(wanted)memcpy(out.mutableBytes,archive+(NSUInteger)pos,wanted); if(status)*status=@"read"; return out; }
    if(method!=8){if(status)*status=@"unsupported-compression";return nil;}
    z_stream z={0}; z.next_in=(Bytef *)(archive+(NSUInteger)pos); z.avail_in=compressed;
    z.next_out=out.mutableBytes; z.avail_out=(uInt)wanted;
    if(inflateInit2(&z,-MAX_WBITS)!=Z_OK){if(status)*status=@"read-error";return nil;}
    int rc=inflate(&z,Z_SYNC_FLUSH); inflateEnd(&z);
    if(rc!=Z_OK && rc!=Z_STREAM_END && rc!=Z_BUF_ERROR){if(status)*status=@"read-error";return nil;}
    [out setLength:(NSUInteger)z.total_out];
    if(status)*status=out.length?@"read":@"read-error";
    return out.length?out:nil;
}
// Read a small uncompressed range from a ZIP member without materializing the
// complete executable. Deflate members are streamed from their beginning and
// discarded until the requested logical offset is reached.
static NSData *IPAReadEntryRange(const uint8_t *archive, NSUInteger length,
                                 uint32_t localOffset, uint32_t compressed,
                                 uint32_t uncompressed, uint16_t method,
                                 uint64_t logicalOffset, NSUInteger wanted,
                                 NSString **status) {
    if (logicalOffset > uncompressed || wanted > (uint64_t)uncompressed-logicalOffset) {
        if (status) *status = @"zip-range-out-of-bounds";
        return nil;
    }
    if ((uint64_t)localOffset + 30 > length || R32(archive+localOffset) != 0x04034b50) {
        if (status) *status = @"zip-entry-invalid";
        return nil;
    }
    uint16_t flags=R16(archive+localOffset+6), localMethod=R16(archive+localOffset+8);
    if (flags & 1) { if(status)*status=@"encrypted-entry-unsupported"; return nil; }
    if (localMethod != method) { if(status)*status=@"zip-method-mismatch"; return nil; }
    uint16_t nl=R16(archive+localOffset+26), el=R16(archive+localOffset+28);
    uint64_t dataPos=(uint64_t)localOffset+30+nl+el;
    if (dataPos+compressed > length) { if(status)*status=@"zip-entry-invalid"; return nil; }
    NSMutableData *result=[NSMutableData dataWithLength:wanted];
    if (wanted==0) { if(status)*status=@"read"; return result; }
    if (method==0) {
        if (compressed!=uncompressed) { if(status)*status=@"zip-entry-invalid"; return nil; }
        memcpy(result.mutableBytes, archive+(NSUInteger)dataPos+(NSUInteger)logicalOffset, wanted);
        if(status)*status=@"read";
        return result;
    }
    if (method!=8) { if(status)*status=@"unsupported-compression"; return nil; }
    z_stream z={0};
    z.next_in=(Bytef *)(archive+(NSUInteger)dataPos); z.avail_in=compressed;
    if (inflateInit2(&z,-MAX_WBITS)!=Z_OK) { if(status)*status=@"read-error"; return nil; }
    uint8_t scratch[16384]; uint64_t produced=0; NSUInteger copied=0; int rc=Z_OK;
    while (rc==Z_OK && copied<wanted) {
        z.next_out=scratch; z.avail_out=(uInt)sizeof(scratch);
        rc=inflate(&z,Z_NO_FLUSH);
        NSUInteger made=sizeof(scratch)-z.avail_out;
        uint64_t chunkStart=produced, chunkEnd=produced+made;
        uint64_t wantedEnd=logicalOffset+wanted;
        uint64_t copyStart=MAX(chunkStart,logicalOffset), copyEnd=MIN(chunkEnd,wantedEnd);
        if (copyEnd>copyStart) {
            NSUInteger n=(NSUInteger)(copyEnd-copyStart);
            memcpy((uint8_t *)result.mutableBytes+copied, scratch+(NSUInteger)(copyStart-chunkStart), n);
            copied+=n;
        }
        produced=chunkEnd;
        if (rc==Z_BUF_ERROR && made==0) break;
    }
    inflateEnd(&z);
    if (copied!=wanted) { if(status)*status=@"read-error"; return nil; }
    if(status)*status=@"read";
    return result;
}
static NSDictionary *IPACheckFatSliceHeader(NSData *header, NSDictionary *arch) {
    if (header.length<28) return @{ @"SliceHeaderStatus":@"truncated-header" };
    const uint8_t *p=header.bytes; uint32_t m=R32(p); BOOL little=NO, is64=NO, valid=YES;
    if(m==0xfeedface)little=YES; else if(m==0xcefaedfe)little=NO;
    else if(m==0xfeedfacf){little=YES;is64=YES;} else if(m==0xcffaedfe){little=NO;is64=YES;} else valid=NO;
    if(!valid)return @{ @"SliceHeaderStatus":@"not-macho" };
    if(header.length<(is64?32:28))return @{ @"SliceHeaderStatus":@"truncated-header" };
    uint32_t cpu=little?R32(p+4):R32BE(p+4), sub=little?R32(p+8):R32BE(p+8), ft=little?R32(p+12):R32BE(p+12);
    uint32_t expectedCPU=[arch[@"CPUType"] unsignedIntValue], expectedSub=[arch[@"CPUSubtype"] unsignedIntValue];
    BOOL match=(cpu==expectedCPU && ((sub^expectedSub)&0x00ffffff)==0);
    return @{ @"SliceHeaderStatus":match?@"macho-header-matched":@"architecture-mismatch",
              @"SliceHeaderFormat":is64?@"64-bit":@"32-bit", @"SliceFileType":@(ft),
              @"HeaderCPUType":@(cpu), @"HeaderCPUSubtype":@(sub) };
}
static NSDictionary *IPAMachOInfo(NSData *data, uint64_t fullFileSize) {
    if(data.length<4)return nil;
    const uint8_t *p=data.bytes; uint32_t magic=R32(p);
    BOOL little=NO, is64=NO, fat=NO, fat64=NO;
    if(magic==0xfeedface){little=YES;} else if(magic==0xcefaedfe){little=NO;} else if(magic==0xfeedfacf){little=YES;is64=YES;} else if(magic==0xcffaedfe){little=NO;is64=YES;}
    else if(magic==0xbebafeca){fat=YES;} else if(magic==0xcafebabe){fat=YES;little=YES;} else if(magic==0xbfbafeca){fat=YES;fat64=YES;} else if(magic==0xcafebabf){fat=YES;fat64=YES;little=YES;} else return nil;
    NSMutableArray *arches=[NSMutableArray array];
    if(!fat){ if(data.length<(is64?32:28))return @{ @"Format":@"Mach-O", @"Status":@"truncated-header", @"Architectures":@[] };
        uint32_t cpu=little?R32(p+4):R32BE(p+4), sub=little?R32(p+8):R32BE(p+8), type=little?R32(p+12):R32BE(p+12);
        [arches addObject:@{@"Name":IPACPUName(cpu,sub),@"CPUType":@(cpu),@"CPUSubtype":@(sub),@"FileType":@(type)}];
        return @{@"Format":is64?@"Mach-O 64-bit":@"Mach-O 32-bit",@"Status":@"macho",@"Architectures":arches};
    }
    if(data.length<8)return @{@"Format":@"Mach-O Fat",@"Status":@"truncated-header",@"Architectures":@[]};
    uint32_t count=little?R32(p+4):R32BE(p+4); NSUInteger stride=fat64?32:20;
    if(count>4096 || 8ULL+(uint64_t)count*stride>data.length)return @{@"Format":fat64?@"Mach-O Fat64":@"Mach-O Fat",@"Status":@"truncated-architecture-table",@"Architectures":@[]};
    BOOL invalidBounds=NO, invalidAlignment=NO, overlapping=NO, invalidSliceHeader=NO, architectureMismatch=NO, sliceHeaderUnavailable=NO;
    NSMutableArray<NSValue *> *ranges=[NSMutableArray array];
    uint64_t tableEnd=8ULL+(uint64_t)count*stride;
    for(uint32_t i=0;i<count;i++){
        const uint8_t *a=p+8+(NSUInteger)i*stride;
        uint32_t cpu=little?R32(a):R32BE(a),sub=little?R32(a+4):R32BE(a+4);
        uint64_t off=fat64?R64(a+8,little):(little?R32(a+8):R32BE(a+8));
        uint64_t size=fat64?R64(a+16,little):(little?R32(a+12):R32BE(a+12));
        uint32_t align=little?R32(a+(fat64?24:16)):R32BE(a+(fat64?24:16));
        BOOL boundsOK=(size>0 && off>=tableEnd && off<=fullFileSize && size<=fullFileSize-off);
        BOOL alignmentOK=(align<63 && (align==0 || (off % (1ULL<<align))==0));
        NSMutableDictionary *arch=[@{@"Name":IPACPUName(cpu,sub),@"CPUType":@(cpu),@"CPUSubtype":@(sub),@"SliceOffset":@(off),@"SliceSize":@(size),@"AlignmentExponent":@(align),@"BoundsValid":@(boundsOK),@"AlignmentValid":@(alignmentOK)} mutableCopy];
        if(!boundsOK) invalidBounds=YES;
        if(!alignmentOK) invalidAlignment=YES;
        if(boundsOK){
            for(NSValue *v in ranges){ NSRange r=v.rangeValue; uint64_t end=(uint64_t)r.location+r.length; if(off<end && (uint64_t)r.location<off+size) overlapping=YES; }
            if(off<=NSUIntegerMax && size<=NSUIntegerMax) [ranges addObject:[NSValue valueWithRange:NSMakeRange((NSUInteger)off,(NSUInteger)size)]];
            // Inspect a slice directly from the prefix when available; otherwise the caller performs a ZIP range read.
            if(off<=data.length && size>=4 && off+MIN((uint64_t)size,32)<=data.length){
                const uint8_t *sp=p+(NSUInteger)off; uint32_t sm=R32(sp); BOOL slittle=NO, s64=NO, validMagic=YES;
                if(sm==0xfeedface) slittle=YES; else if(sm==0xcefaedfe) slittle=NO; else if(sm==0xfeedfacf){slittle=YES;s64=YES;} else if(sm==0xcffaedfe){slittle=NO;s64=YES;} else validMagic=NO;
                if(!validMagic){arch[@"SliceHeaderStatus"]=@"not-macho";invalidSliceHeader=YES;}
                else {
                    NSUInteger need=s64?32:28;
                    if(size<need || off+need>data.length){arch[@"SliceHeaderStatus"]=@"truncated-header";invalidSliceHeader=YES;}
                    else {
                        uint32_t scpu=slittle?R32(sp+4):R32BE(sp+4), ssub=slittle?R32(sp+8):R32BE(sp+8), sft=slittle?R32(sp+12):R32BE(sp+12);
                        BOOL match=(scpu==cpu && ((ssub^sub)&0x00ffffff)==0);
                        arch[@"SliceHeaderStatus"]=match?@"macho-header-matched":@"architecture-mismatch";
                        arch[@"SliceHeaderFormat"]=s64?@"64-bit":@"32-bit"; arch[@"SliceFileType"]=@(sft);
                        arch[@"HeaderCPUType"]=@(scpu); arch[@"HeaderCPUSubtype"]=@(ssub);
                        if(!match) architectureMismatch=YES;
                    }
                }
            } else { arch[@"SliceHeaderStatus"]=@"header-outside-prefix"; sliceHeaderUnavailable=YES; }
        } else arch[@"SliceHeaderStatus"]=@"not-read-invalid-bounds";
        [arches addObject:arch];
    }
    NSString *fatStatus=overlapping?@"overlapping-fat-slices":(invalidBounds?@"invalid-fat-slice-bounds":(invalidAlignment?@"invalid-fat-slice-alignment":(invalidSliceHeader?@"invalid-fat-slice-header":(architectureMismatch?@"fat-architecture-mismatch":(sliceHeaderUnavailable?@"slice-header-not-read":@"macho")))));
    return @{@"Format":fat64?@"Mach-O Fat64":@"Mach-O Fat",@"Status":fatStatus,@"Architectures":arches};
}

@implementation IPAInspector
+ (NSError *)failure:(NSString *)m code:(NSInteger)c {
    return [NSError errorWithDomain:@"AppleSigner.IPAInspector" code:c userInfo:@{NSLocalizedDescriptionKey:m}];
}
+ (NSData *)dataForEntryAtOffset:(uint32_t)off compressed:(uint32_t)cs uncompressed:(uint32_t)us method:(uint16_t)method bytes:(const uint8_t *)b length:(NSUInteger)len error:(NSError **)error {
    if ((uint64_t)off + 30 > len || R32(b+off)!=0x04034b50) {
        if(error)*error=[self failure:@"ZIP 本地文件头无效" code:20]; return nil;
    }
    uint16_t flags=R16(b+off+6), localMethod=R16(b+off+8);
    if(flags&1){if(error)*error=[self failure:@"Info.plist ZIP 条目已加密，无法读取" code:27];return nil;}
    if(localMethod!=method){if(error)*error=[self failure:@"Info.plist ZIP 本地头与中央目录压缩方法不一致" code:28];return nil;}
    uint16_t nl=R16(b+off+26), el=R16(b+off+28);
    if((uint64_t)off+30+nl+el>len || nl==0) {if(error)*error=[self failure:@"ZIP 本地文件名或扩展区越界" code:29];return nil;}
    uint64_t pos=(uint64_t)off+30+nl+el;
    if(pos+cs>len || us>32*1024*1024) {
        if(error)*error=[self failure:@"Info.plist 数据越界或超过 32 MB" code:21]; return nil;
    }
    if(method==0) {
        if(cs!=us){if(error)*error=[self failure:@"ZIP 存储条目长度不一致" code:22];return nil;}
        return [NSData dataWithBytes:b+(NSUInteger)pos length:us];
    }
    if(method!=8){if(error)*error=[self failure:@"Info.plist 使用不支持的压缩方式" code:23];return nil;}
    NSMutableData *out=[NSMutableData dataWithLength:us];
    z_stream z={0}; z.next_in=(Bytef *)(b+(NSUInteger)pos); z.avail_in=cs;
    z.next_out=out.mutableBytes; z.avail_out=us;
    if(inflateInit2(&z,-MAX_WBITS)!=Z_OK){if(error)*error=[self failure:@"无法初始化 ZIP 解压器" code:24];return nil;}
    int status=inflate(&z,Z_FINISH); inflateEnd(&z);
    if(status!=Z_STREAM_END || z.total_out!=us){if(error)*error=[self failure:@"Info.plist 解压失败" code:25];return nil;}
    return out;
}
+ (NSDictionary *)inspectIPAAtURL:(NSURL *)url error:(NSError **)error {
    NSData *archive=[NSData dataWithContentsOfURL:url options:NSDataReadingMappedIfSafe error:error];
    if(!archive || archive.length<22){if(error && !*error)*error=[self failure:@"IPA 为空或不是有效 ZIP" code:1];return nil;}
    const uint8_t *b=archive.bytes; NSUInteger len=archive.length;
    // EOCD must be the record whose declared comment ends exactly at EOF.
    // This avoids accepting a false signature embedded in a ZIP comment.
    NSUInteger start=len>65557?len-65557:0; NSInteger eocd=-1;
    for(NSInteger i=(NSInteger)len-22;i>=(NSInteger)start;i--) {
        if(R32(b+i)==0x06054b50) {
            uint16_t commentLength=R16(b+i+20);
            if((uint64_t)i+22+commentLength==len){eocd=i;break;}
        }
    }
    if(eocd<0){if(error)*error=[self failure:@"找不到有效 ZIP EOCD（不支持 ZIP64）" code:2];return nil;}
    uint16_t diskNumber=R16(b+eocd+4), cdDisk=R16(b+eocd+6);
    uint16_t diskEntries=R16(b+eocd+8), entries=R16(b+eocd+10);
    uint32_t cdSize=R32(b+eocd+12), cdOff=R32(b+eocd+16);
    if(diskNumber!=0 || cdDisk!=0 || diskEntries!=entries) {
        if(error)*error=[self failure:@"不支持分卷 ZIP" code:3];return nil;
    }
    if(entries==0xffff || cdSize==0xffffffff || cdOff==0xffffffff) {
        if(error)*error=[self failure:@"检测到 ZIP64 标记；当前版本明确不支持 ZIP64" code:4];return nil;
    }
    if((uint64_t)cdOff+cdSize>(uint64_t)eocd || cdOff>len || cdSize>len) {
        if(error)*error=[self failure:@"ZIP 中央目录越界或覆盖 EOCD" code:5];return nil;
    }
    NSMutableArray *components=[NSMutableArray array];
    NSMutableArray *nestedCode=[NSMutableArray array];
    NSDictionary *mainApp=nil;
    NSMutableSet *seenPaths=[NSMutableSet set];
    NSMutableSet *seenCodePaths=[NSMutableSet set];
    NSMutableDictionary *zipEntries=[NSMutableDictionary dictionary];
    NSUInteger cur=cdOff;
    for(uint32_t n=0;n<entries;n++){
        if(cur>(uint64_t)cdOff+cdSize || (uint64_t)cdOff+cdSize-cur<46 || R32(b+cur)!=0x02014b50) {
            if(error)*error=[self failure:@"ZIP 中央目录记录数量或签名无效" code:6];return nil;
        }
        uint16_t centralFlags=R16(b+cur+8), method=R16(b+cur+10), nl=R16(b+cur+28), el=R16(b+cur+30), cl=R16(b+cur+32);
        uint32_t expectedCRC=R32(b+cur+16), cs=R32(b+cur+20), us=R32(b+cur+24), off=R32(b+cur+42);
        uint64_t rec=(uint64_t)46+nl+el+cl;
        if(rec>(uint64_t)cdOff+cdSize-cur) {if(error)*error=[self failure:@"ZIP 中央目录条目长度越界" code:7];return nil;}
        if(cs==0xffffffff || us==0xffffffff || off==0xffffffff) {if(error)*error=[self failure:@"检测到 ZIP64 条目；当前版本不支持 ZIP64" code:8];return nil;}
        NSString *path=[[NSString alloc]initWithBytes:b+cur+46 length:nl encoding:NSUTF8StringEncoding];
        if(nl && !path) {if(error)*error=[self failure:@"ZIP 文件名不是有效 UTF-8" code:9];return nil;}
        if(path && [path hasPrefix:@"Payload/"] && ![path hasSuffix:@"/"]) {
            if(zipEntries[path]) {if(error)*error=[self failure:@"ZIP 中存在重复 Payload 路径，拒绝歧义解析" code:10];return nil;}
            // Validate the corresponding local header and ensure its payload
            // remains before the central directory. Bit 3 permits a trailing
            // data descriptor, so local CRC/sizes are intentionally not trusted.
            if((uint64_t)off+30>(uint64_t)cdOff || R32(b+off)!=0x04034b50) {
                if(error)*error=[self failure:@"Payload 本地文件头无效或越过中央目录" code:12];return nil;
            }
            uint16_t localFlags=R16(b+off+6), localMethod=R16(b+off+8);
            uint16_t localNameLength=R16(b+off+26), localExtraLength=R16(b+off+28);
            uint64_t dataStart=(uint64_t)off+30+localNameLength+localExtraLength;
            if(localFlags!=centralFlags || localMethod!=method || localNameLength!=nl ||
               dataStart>(uint64_t)cdOff || (uint64_t)cs>(uint64_t)cdOff-dataStart ||
               memcmp(b+off+30,b+cur+46,nl)!=0) {
                if(error)*error=[self failure:@"Payload 本地头与中央目录不一致或数据区越界" code:13];return nil;
            }
            zipEntries[path]=@{@"offset":@(off),@"compressed":@(cs),@"uncompressed":@(us),@"method":@(method),@"crc":@(expectedCRC)};
        }
        // A .dylib is a common standalone nested-code payload. Record its path
        // without treating it as a Bundle or assigning it a provisioning profile.
        if(path && [path hasPrefix:@"Payload/"] && [path.lowercaseString hasSuffix:@".dylib"] &&
           ![seenCodePaths containsObject:path] && ![path hasSuffix:@"/"]) {
            [seenCodePaths addObject:path];
            [nestedCode addObject:@{@"Type":@"Dynamic Library",
                @"Path":path,
                @"Name":path.lastPathComponent ?: @"dylib",
                @"RequiresProfile":@NO,
                @"DiscoveryMethod":@"zip-entry-extension"}];
        }
        if(path && IPAIsStandardCodeBundleInfoPath(path) && ![seenPaths containsObject:path]){
            [seenPaths addObject:path];
            NSString *kind=IPAComponentType(path);
            if(kind) {
                NSError *readError=nil;
                NSData *pd=[self dataForEntryAtOffset:off compressed:cs uncompressed:us method:method bytes:b length:len error:&readError];
                if(!pd){if(error)*error=readError;return nil;}
                uLong actualCRC=crc32(0L, Z_NULL, 0);
                actualCRC=crc32(actualCRC, (const Bytef *)pd.bytes, (uInt)pd.length);
                if((uint32_t)actualCRC!=expectedCRC) {if(error)*error=[self failure:@"Info.plist ZIP CRC32 校验失败" code:14];return nil;}
                NSError *parseError=nil;
                id obj=[NSPropertyListSerialization propertyListWithData:pd options:NSPropertyListImmutable format:nil error:&parseError];
                if(![obj isKindOfClass:NSDictionary.class]){if(error)*error=parseError?:[self failure:@"组件 Info.plist 无效" code:26];return nil;}
                NSDictionary *info=obj; NSString *bid=info[@"CFBundleIdentifier"];
                if(![bid isKindOfClass:NSString.class] || !bid.length) continue;
                NSString *bundlePath=[path substringToIndex:path.length-@"/Info.plist".length];
                NSDictionary *item=@{@"Type":kind,@"BundleIdentifier":bid,
                    @"Name":info[@"CFBundleDisplayName"]?:info[@"CFBundleName"]?:bid,
                    @"Version":info[@"CFBundleShortVersionString"]?:@"未知",
                    @"Executable":info[@"CFBundleExecutable"]?:@"未知",
                    @"BundlePath":bundlePath,
                    @"InfoPlistPath":path};
                [components addObject:item];
                if([kind isEqualToString:@"App"] && !mainApp) mainApp=item;
            }
        }
        cur+=(NSUInteger)rec;
    }
    if(cur!=(uint64_t)cdOff+cdSize) {if(error)*error=[self failure:@"ZIP 中央目录长度与条目记录不一致" code:11];return nil;}
    if(!mainApp){if(error)*error=[self failure:@"没有找到主应用 Payload/*.app/Info.plist" code:11];return nil;}
    // Build nested-code relationships from exact archive paths. Bundle IDs are
    // labels, not reliable parent/child path evidence, so never infer ancestry
    // from identifier prefixes.
    NSMutableArray *relationshipAudit=[NSMutableArray array];
    NSMutableDictionary<NSString *, NSNumber *> *bundleIDCounts=[NSMutableDictionary dictionary];
    NSMutableDictionary<NSString *, NSDictionary *> *componentByPath=[NSMutableDictionary dictionary];
    for(NSDictionary *component in components){
        NSString *bid=component[@"BundleIdentifier"] ?: @"";
        bundleIDCounts[bid]=@([bundleIDCounts[bid] unsignedIntegerValue]+1);
        NSString *bp=component[@"BundlePath"] ?: @"";
        if(bp.length) componentByPath[bp]=component;
    }
    NSMutableSet *executablePaths=[NSMutableSet set];
    for(NSDictionary *component in components){
        NSString *bundlePath=component[@"BundlePath"] ?: @"";
        NSString *parentPath=nil;
        for(NSString *candidate in componentByPath.allKeys){
            if([candidate isEqualToString:bundlePath]) continue;
            NSString *prefix=[candidate stringByAppendingString:@"/"];
            if([bundlePath hasPrefix:prefix] && (!parentPath || candidate.length>parentPath.length)) parentPath=candidate;
        }
        NSDictionary *parent=parentPath?componentByPath[parentPath]:nil;
        NSString *exe=component[@"Executable"];
        NSString *executablePath=([exe isKindOfClass:NSString.class] && exe.length && ![exe isEqualToString:@"未知"])?[bundlePath stringByAppendingPathComponent:exe]:@"";
        BOOL executableCollision=executablePath.length && [executablePaths containsObject:executablePath];
        if(executablePath.length) [executablePaths addObject:executablePath];
        NSMutableArray *issues=[NSMutableArray array];
        if([bundleIDCounts[component[@"BundleIdentifier"]] unsignedIntegerValue]>1) [issues addObject:@"duplicate-bundle-identifier"];
        if(executableCollision) [issues addObject:@"duplicate-executable-path"];
        if(parentPath && !parent) [issues addObject:@"parent-bundle-not-indexed"];
        NSMutableDictionary *relationship=[@{
            @"BundlePath":bundlePath,
            @"BundleIdentifier":component[@"BundleIdentifier"] ?: @"",
            @"Type":component[@"Type"] ?: @"Unknown",
            @"Depth":@([[bundlePath pathComponents] count]),
            @"ExecutablePath":executablePath,
            @"Issues":issues
        } mutableCopy];
        if(parentPath) relationship[@"ParentBundlePath"]=parentPath;
        if(parent) relationship[@"ParentBundleIdentifier"]=parent[@"BundleIdentifier"] ?: @"";
        relationship[@"RelationshipType"]=parent?@"nested-component":@"top-level-component";
        [relationshipAudit addObject:relationship];
    }
    NSMutableDictionary *expected=[NSMutableDictionary dictionary];
    for(NSDictionary *component in components){
        NSString *infoPath=component[@"InfoPlistPath"] ?: @""; NSString *exe=component[@"Executable"];
        if([exe isKindOfClass:NSString.class] && exe.length && ![exe isEqualToString:@"未知"]){
            NSString *bundle=[infoPath hasSuffix:@"/Info.plist"]?[infoPath substringToIndex:infoPath.length-@"/Info.plist".length]:@"";
            NSString *binary=[bundle stringByAppendingPathComponent:exe]; if(binary.length) expected[binary]=@"bundle-executable";
        }
    }
    for(NSDictionary *code in nestedCode){NSString *path=code[@"Path"];if(path.length && !expected[path])expected[path]=@"dylib-extension";}
    NSMutableArray *binaryInventory=[NSMutableArray array];
    for(NSString *path in [[expected allKeys] sortedArrayUsingSelector:@selector(compare:)]){
        NSDictionary *meta=zipEntries[path]; NSString *readStatus=nil; NSData *prefix=nil;
        if(meta) prefix=IPAReadPrefix(b,len,[meta[@"offset"] unsignedIntValue],[meta[@"compressed"] unsignedIntValue],[meta[@"uncompressed"] unsignedIntValue],[meta[@"method"] unsignedShortValue],&readStatus);
        else readStatus=@"zip-entry-missing";
        NSDictionary *macho=prefix?IPAMachOInfo(prefix,[meta[@"uncompressed"] unsignedLongLongValue]):nil;
        NSMutableDictionary *item=[@{@"Path":path,@"DiscoveryMethod":expected[path],@"ReadStatus":readStatus ?: @"read-error"} mutableCopy];
        if(macho){
            NSMutableDictionary *machoMutable=[macho mutableCopy];
            NSMutableArray *checkedArchitectures=[NSMutableArray array];
            BOOL remoteHeaderFailure=NO, remoteMismatch=NO, remoteInvalid=NO;
            for(NSDictionary *arch in macho[@"Architectures"]){
                NSMutableDictionary *checked=[arch mutableCopy];
                if([arch[@"SliceHeaderStatus"] isEqualToString:@"header-outside-prefix"] && meta){
                    NSString *rangeStatus=nil;
                    NSData *header=IPAReadEntryRange(b,len,[meta[@"offset"] unsignedIntValue],[meta[@"compressed"] unsignedIntValue],[meta[@"uncompressed"] unsignedIntValue],[meta[@"method"] unsignedShortValue],[arch[@"SliceOffset"] unsignedLongLongValue],(NSUInteger)MIN((uint64_t)32,[arch[@"SliceSize"] unsignedLongLongValue]),&rangeStatus);
                    if(header){
                        [checked addEntriesFromDictionary:IPACheckFatSliceHeader(header,arch)];
                        if([checked[@"SliceHeaderStatus"] isEqualToString:@"architecture-mismatch"])remoteMismatch=YES;
                        if([checked[@"SliceHeaderStatus"] isEqualToString:@"not-macho"] || [checked[@"SliceHeaderStatus"] isEqualToString:@"truncated-header"])remoteInvalid=YES;
                    } else { checked[@"SliceHeaderStatus"]=rangeStatus?:@"slice-header-read-error"; remoteHeaderFailure=YES; }
                }
                [checkedArchitectures addObject:checked];
            }
            machoMutable[@"Architectures"]=checkedArchitectures;
            if(remoteMismatch)machoMutable[@"Status"]=@"fat-architecture-mismatch";
            else if(remoteInvalid)machoMutable[@"Status"]=@"invalid-fat-slice-header";
            else if(remoteHeaderFailure)machoMutable[@"Status"]=@"slice-header-read-error";
            else if([machoMutable[@"Status"] isEqualToString:@"slice-header-not-read"])machoMutable[@"Status"]=@"macho";
            [item addEntriesFromDictionary:machoMutable];
        }
        else if([readStatus isEqualToString:@"read"]){item[@"Format"]=@"Unknown";item[@"Status"]=@"not-macho";item[@"Architectures"]=@[];}
        else {item[@"Status"]=readStatus ?: @"read-error";item[@"Architectures"]=@[];}
        [binaryInventory addObject:item];
    }
    NSMutableDictionary *result=[mainApp mutableCopy];
    result[@"Components"]=[components copy];
    result[@"NestedCode"]=[nestedCode copy];
    result[@"ComponentDiscoveryCount"]=@(components.count);
    result[@"NestedCodeDiscoveryCount"]=@(nestedCode.count);
    result[@"BinaryInventory"]=[binaryInventory copy];
    result[@"BinaryDiscoveryCount"]=@(binaryInventory.count);
    result[@"BundleRelationships"]=[relationshipAudit copy];
    result[@"BundleRelationshipCount"]=@(relationshipAudit.count);
    NSUInteger relationshipIssueCount=0;
    for(NSDictionary *r in relationshipAudit) relationshipIssueCount += [r[@"Issues"] count];
    result[@"BundleRelationshipIssueCount"]=@(relationshipIssueCount);
    result[@"SigningOrderNote"]=@"嵌套代码通常需要先处理最内层组件，再处理外层 Bundle；此列表仅为路径盘点，不代表已验证 Apple 签名规则。";
    return result;
}
@end
