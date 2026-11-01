#import "CodeDirectoryBuilder.h"
#import <CommonCrypto/CommonDigest.h>
#include <string.h>

static void Put32(uint8_t *p, uint32_t v) { p[0]=(v>>24)&255; p[1]=(v>>16)&255; p[2]=(v>>8)&255; p[3]=v&255; }
static uint32_t Get32(const uint8_t *p, BOOL little) { return little ? ((uint32_t)p[0]|((uint32_t)p[1]<<8)|((uint32_t)p[2]<<16)|((uint32_t)p[3]<<24)) : (((uint32_t)p[0]<<24)|((uint32_t)p[1]<<16)|((uint32_t)p[2]<<8)|p[3]); }

@implementation CodeDirectoryBuilder
+ (NSDictionary *)buildTemplateForExecutableAtURL:(NSURL *)url outputDirectory:(NSURL *)directory error:(NSError **)error {
    NSData *data=[NSData dataWithContentsOfURL:url options:NSDataReadingMappedIfSafe error:error];
    if(!data) return nil;
    const uint8_t *b=data.bytes; NSUInteger n=data.length;
    if(n<32) { if(error)*error=[NSError errorWithDomain:@"AppleSigner.CodeDirectory" code:1 userInfo:@{NSLocalizedDescriptionKey:@"文件过短"}]; return nil; }
    uint32_t magic=Get32(b,YES);
    BOOL little=(magic==0xfeedface || magic==0xfeedfacf);
    BOOL is64=(magic==0xfeedfacf || magic==0xcffaedfe);
    if(!(magic==0xfeedface || magic==0xfeedfacf || magic==0xcefaedfe || magic==0xcffaedfe)) {
        if(error)*error=[NSError errorWithDomain:@"AppleSigner.CodeDirectory" code:2 userInfo:@{NSLocalizedDescriptionKey:@"当前模板生成器仅接受 thin Mach-O；Fat 文件请先按架构切片处理"}]; return nil;
    }
    NSUInteger header=is64?32:28;
    uint32_t ncmd=Get32(b+16,little), cmdbytes=Get32(b+20,little);
    if(header+cmdbytes>n || ncmd>65536) { if(error)*error=[NSError errorWithDomain:@"AppleSigner.CodeDirectory" code:3 userInfo:@{NSLocalizedDescriptionKey:@"Load Commands 边界异常"}]; return nil; }
    NSUInteger pos=header; uint64_t codeLimit=n; BOOL hasSignature=NO;
    for(uint32_t i=0;i<ncmd;i++) {
        if(pos+8>header+cmdbytes) break;
        uint32_t cmd=Get32(b+pos,little), size=Get32(b+pos+4,little);
        if(size<8 || size>header+cmdbytes-pos) { if(error)*error=[NSError errorWithDomain:@"AppleSigner.CodeDirectory" code:4 userInfo:@{NSLocalizedDescriptionKey:@"Load Command 格式异常"}]; return nil; }
        if(cmd==0x1d && size>=16) {
            uint32_t off=Get32(b+pos+8,little), len=Get32(b+pos+12,little);
            if(off>n || len>n-off) { if(error)*error=[NSError errorWithDomain:@"AppleSigner.CodeDirectory" code:5 userInfo:@{NSLocalizedDescriptionKey:@"已有签名区越界"}]; return nil; }
            codeLimit=off; hasSignature=YES;
        }
        pos+=size;
    }
    const uint32_t pageExp=12, pageSize=1u<<pageExp;
    uint64_t slots=(codeLimit+pageSize-1)/pageSize;
    if(slots>UINT32_MAX || codeLimit>UINT32_MAX) { if(error)*error=[NSError errorWithDomain:@"AppleSigner.CodeDirectory" code:6 userInfo:@{NSLocalizedDescriptionKey:@"文件过大，基础 CodeDirectory 模板暂不支持 4GB 以上"}]; return nil; }
    const uint32_t headerLen=44, identOffset=headerLen, hashOffset=headerLen+sizeof("AppleSigner.Template") ;
    uint64_t total=(uint64_t)hashOffset+slots*CC_SHA256_DIGEST_LENGTH;
    if(total>NSUIntegerMax || total>64*1024*1024) { if(error)*error=[NSError errorWithDomain:@"AppleSigner.CodeDirectory" code:7 userInfo:@{NSLocalizedDescriptionKey:@"CodeDirectory 模板超过 64MB 限制"}]; return nil; }
    NSMutableData *cd=[NSMutableData dataWithLength:(NSUInteger)total];
    uint8_t *o=cd.mutableBytes;
    Put32(o,0xfade0c02); Put32(o+4,(uint32_t)total); Put32(o+8,0x20001); Put32(o+12,0);
    Put32(o+16,hashOffset); Put32(o+20,identOffset); Put32(o+24,0); Put32(o+28,(uint32_t)slots); Put32(o+32,(uint32_t)codeLimit);
    o[36]=CC_SHA256_DIGEST_LENGTH; o[37]=2; o[38]=0; o[39]=pageExp; Put32(o+40,0);
    memcpy(o+identOffset,"AppleSigner.Template",sizeof("AppleSigner.Template"));
    for(uint32_t i=0;i<(uint32_t)slots;i++) {
        uint64_t start=(uint64_t)i*pageSize;
        NSUInteger chunk=(NSUInteger)MIN((uint64_t)pageSize,codeLimit-start);
        unsigned char digest[CC_SHA256_DIGEST_LENGTH];
        CC_SHA256(b+(NSUInteger)start,(CC_LONG)chunk,digest);
        memcpy(o+hashOffset+(uint64_t)i*CC_SHA256_DIGEST_LENGTH,digest,sizeof(digest));
    }
    NSError *dirErr=nil;
    [[NSFileManager defaultManager] createDirectoryAtURL:directory withIntermediateDirectories:YES attributes:nil error:&dirErr];
    if(dirErr) { if(error)*error=dirErr; return nil; }
    NSString *safe=[url.lastPathComponent stringByAppendingString:@".codedirectory.template"];
    NSURL *out=[directory URLByAppendingPathComponent:safe];
    if(![cd writeToURL:out options:NSDataWritingAtomic error:error]) return nil;
    return @{@"Output":out.path,@"Bytes":@(cd.length),@"CodeLimit":@(codeLimit),@"CodeSlots":@(slots),@"PageSize":@(pageSize),@"HashAlgorithm":@"SHA-256",@"HadExistingSignature":@(hasSignature),@"Status":@"仅生成独立 CodeDirectory 模板，未嵌入 Mach-O"};
}
@end
