#import "IPAExtractor.h"
#import <zlib.h>
#import <sys/stat.h>
#import <string.h>
#import <limits.h>

static uint16_t X16(const uint8_t *p){return (uint16_t)p[0]|((uint16_t)p[1]<<8);}
static uint32_t X32(const uint8_t *p){return (uint32_t)p[0]|((uint32_t)p[1]<<8)|((uint32_t)p[2]<<16)|((uint32_t)p[3]<<24);}

static BOOL SafeZIPPath(NSString *name, BOOL *isDirectory, NSString **normalized) {
    if (!name.length || [name isEqualToString:@".applesigner-staging-marker"] ||
        [name hasPrefix:@"/"] || [name hasPrefix:@"\\"] ||
        [name containsString:@"\\"] || [name rangeOfString:@"\0"].location != NSNotFound ||
        [name containsString:@":"]) return NO;
    BOOL directory=[name hasSuffix:@"/"];
    NSString *trimmed=directory ? [name substringToIndex:name.length-1] : name;
    if (!trimmed.length) return NO;
    NSArray *parts=[trimmed componentsSeparatedByString:@"/"];
    for (NSString *part in parts) {
        if (!part.length || [part isEqualToString:@"."] || [part isEqualToString:@".."]) return NO;
    }
    NSString *n=[parts componentsJoinedByString:@"/"];
    if (isDirectory) *isDirectory=directory;
    if (normalized) *normalized=n;
    return YES;
}
static BOOL IsWithinRoot(NSString *root, NSString *target) {
    NSString *prefix=[root stringByAppendingString:@"/"];
    return [target hasPrefix:prefix] && target.length>prefix.length;
}
static BOOL ZIPExtraFieldsAreSupported(const uint8_t *bytes, uint16_t length) {
    NSUInteger offset=0;
    while(offset<length) {
        if((NSUInteger)length-offset<4)return NO;
        uint16_t identifier=X16(bytes+offset);
        uint16_t fieldLength=X16(bytes+offset+2);
        offset+=4;
        if(fieldLength>(NSUInteger)length-offset)return NO;
        if(identifier==0x0001)return NO; // ZIP64 extra field is intentionally unsupported.
        offset+=fieldLength;
    }
    return offset==length;
}

@interface IPAExtractor (TransactionalPrivate)
+ (NSURL *)extractIPAAtURL:(NSURL *)ipaURL toDirectory:(NSURL *)directory stagingURL:(NSURL **)stagingURL error:(NSError **)error;
@end

@implementation IPAExtractor
+ (NSError *)err:(NSString *)s code:(NSInteger)c {
    return [NSError errorWithDomain:@"AppleSigner.IPAExtractor" code:c userInfo:@{NSLocalizedDescriptionKey:s}];
}
+ (NSURL *)extractIPAAtURL:(NSURL *)ipaURL toDirectory:(NSURL *)directory error:(NSError **)error {
    NSURL *stagingURL=nil;
    NSError *innerError=nil;
    NSURL *result=nil;
    @try {
        result=[self extractIPAAtURL:ipaURL toDirectory:directory stagingURL:&stagingURL error:&innerError];
    } @catch (NSException *exception) {
        innerError=[self err:[NSString stringWithFormat:@"解压过程中发生异常：%@",exception.reason ?: @"未知异常"] code:28];
    }
    if(!result && stagingURL) {
        NSError *cleanupError=nil;
        [[NSFileManager defaultManager] removeItemAtURL:stagingURL error:&cleanupError];
        if(cleanupError && innerError) {
            NSMutableDictionary *info=[innerError.userInfo mutableCopy] ?: [NSMutableDictionary dictionary];
            info[@"AppleSignerCleanupError"]=cleanupError.localizedDescription ?: @"临时目录清理失败";
            innerError=[NSError errorWithDomain:innerError.domain code:innerError.code userInfo:info];
        }
    }
    if(!result && !innerError) innerError=[self err:@"IPA 解压失败，未生成可交付目录" code:29];
    if(error)*error=innerError;
    return result;
}
+ (NSURL *)extractIPAAtURL:(NSURL *)ipaURL toDirectory:(NSURL *)directory stagingURL:(NSURL **)stagingURL error:(NSError **)error {
    NSData *zip=[NSData dataWithContentsOfURL:ipaURL options:NSDataReadingMappedIfSafe error:error];
    if(!zip || zip.length<22){if(error && !*error)*error=[self err:@"IPA 文件无效" code:1];return nil;}
    const uint8_t *b=zip.bytes; NSUInteger len=zip.length;
    NSUInteger floor=len>65557?len-65557:0; NSInteger e=-1;
    for(NSInteger i=(NSInteger)len-22;i>=(NSInteger)floor;i--) {
        if(X32(b+i)==0x06054b50 && (uint64_t)i+22+X16(b+i+20)==len){e=i;break;}
    }
    if(e<0){if(error)*error=[self err:@"找不到有效 ZIP 目录，ZIP64 暂不支持" code:2];return nil;}
    if(X16(b+e+4)!=0 || X16(b+e+6)!=0 || X16(b+e+8)!=X16(b+e+10)){if(error)*error=[self err:@"不支持跨磁盘或条目计数不一致的 ZIP" code:3];return nil;}
    uint16_t count=X16(b+e+10); uint32_t cdSize=X32(b+e+12), cdOff=X32(b+e+16);
    if(count==0xffff || cdSize==0xffffffff || cdOff==0xffffffff){if(error)*error=[self err:@"检测到 ZIP64，当前版本明确不支持" code:27];return nil;}
    if((uint64_t)cdOff+cdSize>(uint64_t)e || cdOff>len || cdSize>len){if(error)*error=[self err:@"ZIP 中央目录越界或覆盖 EOCD" code:4];return nil;}
    NSFileManager *fm=NSFileManager.defaultManager;
    NSURL *parent=directory.URLByDeletingLastPathComponent;
    if(![fm createDirectoryAtURL:parent withIntermediateDirectories:YES attributes:nil error:error])return nil;
    NSURL *staging=[parent URLByAppendingPathComponent:[NSString stringWithFormat:@"AppleSigner-Unpacked-%@",[[NSUUID UUID] UUIDString]] isDirectory:YES];
    if(![fm createDirectoryAtURL:staging withIntermediateDirectories:NO attributes:nil error:error])return nil;
    if(stagingURL)*stagingURL=staging;
    NSString *markerName=@".applesigner-staging-marker";
    NSString *markerToken=NSUUID.UUID.UUIDString;
    NSURL *markerURL=[staging URLByAppendingPathComponent:markerName];
    if(![[markerToken dataUsingEncoding:NSUTF8StringEncoding] writeToURL:markerURL options:NSDataWritingAtomic error:error])return nil;
    directory=staging;
    uint64_t expandedTotal=0; NSUInteger cur=cdOff;
    const uint32_t maxEntries=20000;
    const uint64_t maxEntrySize=256ULL*1024*1024;
    const uint64_t maxTotalSize=1024ULL*1024*1024;
    NSMutableDictionary *seenPaths=[NSMutableDictionary dictionary];
    NSMutableArray<NSDictionary *> *localRanges=[NSMutableArray arrayWithCapacity:count];
    if(count>maxEntries){if(error)*error=[self err:@"ZIP 条目数量超过安全限制" code:21];return nil;}
    for(uint32_t idx=0;idx<count;idx++){
        if(cur>(uint64_t)cdOff+cdSize || (uint64_t)cdOff+cdSize-cur<46 || X32(b+cur)!=0x02014b50){if(error)*error=[self err:@"ZIP 中央目录记录损坏" code:5];return nil;}
        uint16_t flags=X16(b+cur+8), method=X16(b+cur+10);
        uint32_t crc=X32(b+cur+16), cs=X32(b+cur+20), us=X32(b+cur+24);
        uint16_t nl=X16(b+cur+28), el=X16(b+cur+30), cl=X16(b+cur+32);
        uint32_t external=X32(b+cur+38), off=X32(b+cur+42);
        uint64_t rec=(uint64_t)46+nl+el+cl;
        if(rec>(uint64_t)cdOff+cdSize-cur){if(error)*error=[self err:@"ZIP 文件名或扩展字段越界" code:6];return nil;}
        if(!ZIPExtraFieldsAreSupported(b+cur+46+nl,el)){if(error)*error=[self err:@"ZIP 中央目录扩展字段损坏或包含 ZIP64" code:33];return nil;}
        NSString *name=[[NSString alloc]initWithBytes:b+cur+46 length:nl encoding:NSUTF8StringEncoding];
        cur+=(NSUInteger)rec;
        BOOL trailingDirectory=NO; NSString *relative=nil;
        if(!name || !SafeZIPPath(name,&trailingDirectory,&relative)){
            if(error)*error=[self err:@"ZIP 包含绝对路径、路径穿越或无效文件名" code:7];return nil;
        }
        NSString *collisionKey=relative.precomposedStringWithCanonicalMapping.lowercaseString;
        if([collisionKey isEqualToString:@".applesigner-staging-marker"]) {
            if(error)*error=[self err:@"ZIP 条目使用了 AppleSigner 保留的临时标记路径" code:42];return nil;
        }
        if(seenPaths[collisionKey]!=nil){if(error)*error=[self err:@"ZIP 存在重复或大小写冲突路径" code:22];return nil;}
        BOOL isDirEntry=trailingDirectory || ((X32(b+(NSUInteger)(cur-rec)+38)>>16 & 0170000)==0040000);
        for(NSString *existing in seenPaths) {
            BOOL existingIsDir=[seenPaths[existing] boolValue];
            if([collisionKey hasPrefix:[existing stringByAppendingString:@"/"]] && !existingIsDir) {
                if(error)*error=[self err:@"ZIP 文件路径与其子路径冲突" code:30];return nil;
            }
            if([existing hasPrefix:[collisionKey stringByAppendingString:@"/"]] && !isDirEntry) {
                if(error)*error=[self err:@"ZIP 文件路径与已有子路径冲突" code:30];return nil;
            }
        }
        seenPaths[collisionKey]=@(isDirEntry);
        if(flags & 1){if(error)*error=[self err:@"IPA 含加密 ZIP 条目，无法解包" code:9];return nil;}
        uint16_t allowedFlags=(uint16_t)(0x0008|0x0800|(method==8?0x0006:0));
        if((flags & (uint16_t)~allowedFlags)!=0 || (method!=8 && (flags & 0x0006)!=0)) {
            if(error)*error=[self err:@"ZIP 使用了当前解压器不支持的通用标志位" code:41];return nil;
        }
        if(us>maxEntrySize || expandedTotal>maxTotalSize-us || (cs==0 && us>0) ||
           (cs>0 && us>(uint64_t)cs*200ULL)){
            if(error)*error=[self err:@"解包大小或压缩比超过安全限制" code:10];return nil;
        }
        expandedTotal+=us;
        NSURL *target=[directory URLByAppendingPathComponent:relative];
        NSString *root=[directory.path stringByStandardizingPath];
        NSString *targetPath=[target.path stringByStandardizingPath];
        if(!IsWithinRoot(root,targetPath)){
            if(error)*error=[self err:@"解包目标超出工作目录" code:12];return nil;
        }
        uint32_t unixMode=external>>16;
        uint32_t fileType=unixMode & 0170000;
        if(fileType==0120000){if(error)*error=[self err:@"IPA 中包含符号链接条目，拒绝解包" code:13];return nil;}
        if(fileType!=0 && fileType!=0100000 && fileType!=0040000){if(error)*error=[self err:@"IPA 包含设备文件、FIFO 或其他特殊文件，拒绝解包" code:23];return nil;}
        BOOL isDir=trailingDirectory || fileType==0040000;
        if((uint64_t)off+30>cdOff || X32(b+off)!=0x04034b50){if(error)*error=[self err:@"ZIP 本地文件头损坏或位于中央目录之后" code:14];return nil;}
        uint16_t localFlags=X16(b+off+6), localMethod=X16(b+off+8);
        uint32_t localCRC=X32(b+off+14), localCS=X32(b+off+18), localUS=X32(b+off+22);
        uint16_t lnl=X16(b+off+26), lel=X16(b+off+28);
        uint64_t dataPos=(uint64_t)off+30+lnl+lel;
        NSUInteger centralNameOffset=(NSUInteger)(cur-rec)+46;
        if(localFlags!=flags || localMethod!=method || lnl!=nl ||
           (uint64_t)off+30+lnl+lel>cdOff ||
           memcmp(b+off+30,b+centralNameOffset,nl)!=0 ||
           !ZIPExtraFieldsAreSupported(b+off+30+lnl,lel) ||
           dataPos>cdOff || cs>(uint64_t)cdOff-dataPos) {
            if(error)*error=[self err:@"ZIP 本地头与中央目录不一致、扩展字段不受支持或数据区越界" code:24];return nil;
        }
        BOOL hasDescriptor=(flags & 0x0008)!=0;
        if(hasDescriptor) {
            BOOL crcUnset=(localCRC==0 || localCRC==crc);
            BOOL csUnset=(localCS==0 || localCS==cs);
            BOOL usUnset=(localUS==0 || localUS==us);
            if(!crcUnset || !csUnset || !usUnset) {
                if(error)*error=[self err:@"ZIP Data Descriptor 标志与本地头字段冲突" code:34];return nil;
            }
        } else if(localCRC!=crc || localCS!=cs || localUS!=us) {
            if(error)*error=[self err:@"ZIP 本地头 CRC 或长度与中央目录不一致" code:35];return nil;
        }
        uint64_t dataEnd=dataPos+(uint64_t)cs;
        uint64_t recordEnd=dataEnd;
        if(hasDescriptor) {
            if(dataEnd>cdOff || (uint64_t)cdOff-dataEnd<12) {
                if(error)*error=[self err:@"ZIP Data Descriptor 越界" code:36];return nil;
            }
            NSUInteger descriptorOffset=(NSUInteger)dataEnd;
            BOOL descriptorValid=NO;
            NSUInteger descriptorLength=0;
            if((uint64_t)cdOff-dataEnd>=16 && X32(b+descriptorOffset)==0x08074b50 &&
               X32(b+descriptorOffset+4)==crc &&
               X32(b+descriptorOffset+8)==cs &&
               X32(b+descriptorOffset+12)==us) {
                descriptorValid=YES; descriptorLength=16;
            } else if(X32(b+descriptorOffset)==crc &&
                      X32(b+descriptorOffset+4)==cs &&
                      X32(b+descriptorOffset+8)==us) {
                descriptorValid=YES; descriptorLength=12;
            }
            if(!descriptorValid) {
                if(error)*error=[self err:@"ZIP Data Descriptor 的 CRC 或长度不匹配" code:37];return nil;
            }
            recordEnd=dataEnd+descriptorLength;
        }
        if(recordEnd>cdOff) {
            if(error)*error=[self err:@"ZIP 本地记录覆盖中央目录" code:38];return nil;
        }
        [localRanges addObject:@{@"start":@(off),@"end":@(recordEnd)}];
        if(isDir) {
            if(cs!=0 || us!=0 || crc!=(uint32_t)crc32(0,Z_NULL,0)) {
                if(error)*error=[self err:@"ZIP 目录条目包含非空数据" code:39];return nil;
            }
            if(![fm createDirectoryAtURL:target withIntermediateDirectories:YES attributes:nil error:error])return nil;
            continue;
        }
        NSData *out=nil;
        if(method==0) {
            if(cs!=us){if(error)*error=[self err:@"存储条目长度不一致" code:16];return nil;}
            out=[zip subdataWithRange:NSMakeRange((NSUInteger)dataPos,us)];
        } else if(method==8) {
            if(cs>UINT_MAX || us>=UINT_MAX){if(error)*error=[self err:@"ZIP 条目长度超出当前解压器限制" code:25];return nil;}
            NSMutableData *buf=[NSMutableData dataWithLength:(NSUInteger)us+1];
            z_stream z={0};
            z.next_in=(Bytef *)(b+(NSUInteger)dataPos);
            z.avail_in=(uInt)cs;
            z.next_out=buf.mutableBytes;
            z.avail_out=(uInt)(us+1);
            if(inflateInit2(&z,-MAX_WBITS)!=Z_OK){if(error)*error=[self err:@"解压初始化失败" code:17];return nil;}
            int st=inflate(&z,Z_FINISH);
            uLong consumed=z.total_in, produced=z.total_out;
            inflateEnd(&z);
            if(st!=Z_STREAM_END || consumed!=cs || produced!=us) {
                if(error)*error=[self err:@"Deflate 数据流未完整消费，或解压长度与 ZIP 声明不一致" code:18];return nil;
            }
            [buf setLength:(NSUInteger)us];
            out=buf;
        } else {
            if(error)*error=[self err:@"不支持的 ZIP 压缩方法" code:19];return nil;
        }
        if((uint32_t)crc32(0,out.bytes,(uInt)out.length)!=crc){if(error)*error=[self err:@"ZIP CRC 校验失败，文件可能损坏" code:20];return nil;}
        if(![fm createDirectoryAtURL:target.URLByDeletingLastPathComponent withIntermediateDirectories:YES attributes:nil error:error])return nil;
        if(![out writeToURL:target options:NSDataWritingAtomic error:error])return nil;
        if(unixMode){
            mode_t perms=unixMode & 0777;
            [fm setAttributes:@{NSFilePosixPermissions:@(perms)} ofItemAtPath:target.path error:nil];
        }
    }
    if(cur!=(uint64_t)cdOff+cdSize){if(error)*error=[self err:@"ZIP 中央目录长度与条目数量不一致" code:26];return nil;}
    [localRanges sortUsingComparator:^NSComparisonResult(NSDictionary *a, NSDictionary *b) {
        return [a[@"start"] compare:b[@"start"]];
    }];
    uint64_t previousEnd=0;
    BOOL hasPrevious=NO;
    for(NSDictionary *range in localRanges) {
        uint64_t start=[range[@"start"] unsignedLongLongValue];
        uint64_t end=[range[@"end"] unsignedLongLongValue];
        if(end<start || (hasPrevious && start<previousEnd)) {
            if(error)*error=[self err:@"ZIP 本地文件记录的数据区发生重叠" code:40];return nil;
        }
        previousEnd=end; hasPrevious=YES;
    }
    NSError *markerError=nil;
    if(![fm removeItemAtURL:[directory URLByAppendingPathComponent:@".applesigner-staging-marker"] error:&markerError]) {
        if(error)*error=markerError ?: [self err:@"无法移除临时目录标记" code:31];
        return nil;
    }
    return directory;
}

+ (NSUInteger)cleanupStaleStagingDirectoriesAtURL:(NSURL *)parent olderThan:(NSTimeInterval)age error:(NSError **)error {
    if(age<0) {
        if(error)*error=[self err:@"临时目录清理时间阈值无效" code:32];
        return 0;
    }
    NSFileManager *fm=NSFileManager.defaultManager;
    NSArray<NSURL *> *children=[fm contentsOfDirectoryAtURL:parent
                                 includingPropertiesForKeys:@[NSURLIsDirectoryKey,NSURLIsSymbolicLinkKey,NSURLContentModificationDateKey]
                                                    options:NSDirectoryEnumerationSkipsHiddenFiles
                                                      error:error];
    if(!children)return 0;
    NSDate *cutoff=[NSDate dateWithTimeIntervalSinceNow:-age];
    NSUInteger removed=0;
    NSError *firstError=nil;
    for(NSURL *candidate in children) {
        NSString *name=candidate.lastPathComponent;
        if(![name hasPrefix:@"AppleSigner-Unpacked-"])continue;
        NSNumber *isDirectory=nil,*isSymlink=nil;
        NSDate *modified=nil;
        NSError *valuesError=nil;
        if(![candidate getResourceValue:&isDirectory forKey:NSURLIsDirectoryKey error:&valuesError] ||
           ![candidate getResourceValue:&isSymlink forKey:NSURLIsSymbolicLinkKey error:&valuesError] ||
           ![candidate getResourceValue:&modified forKey:NSURLContentModificationDateKey error:&valuesError]) {
            if(!firstError)firstError=valuesError;
            continue;
        }
        if(!isDirectory.boolValue || isSymlink.boolValue || !modified || [modified compare:cutoff]==NSOrderedDescending)continue;
        NSURL *marker=[candidate URLByAppendingPathComponent:@".applesigner-staging-marker"];
        NSDictionary *markerAttrs=[fm attributesOfItemAtPath:marker.path error:nil];
        if(![markerAttrs[NSFileType] isEqualToString:NSFileTypeRegular])continue;
        NSString *markerToken=[[NSString alloc] initWithData:[NSData dataWithContentsOfURL:marker] encoding:NSUTF8StringEncoding];
        NSString *directoryToken=[name substringFromIndex:[@"AppleSigner-Unpacked-" length]];
        NSUUID *parsedToken=[[NSUUID alloc] initWithUUIDString:directoryToken];
        if(!parsedToken || ![markerToken isEqualToString:directoryToken])continue;
        NSError *removeError=nil;
        if([fm removeItemAtURL:candidate error:&removeError])removed++;
        else if(!firstError)firstError=removeError;
    }
    if(error)*error=firstError;
    return removed;
}
@end
