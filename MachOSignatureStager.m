#import "MachOSignatureStager.h"
#include <string.h>

static uint32_t R32(const uint8_t *p, BOOL le) {
    return le ? ((uint32_t)p[0]|((uint32_t)p[1]<<8)|((uint32_t)p[2]<<16)|((uint32_t)p[3]<<24))
              : (((uint32_t)p[0]<<24)|((uint32_t)p[1]<<16)|((uint32_t)p[2]<<8)|p[3]);
}
static void W32(uint8_t *p,uint32_t v,BOOL le) {
    if(le) { p[0]=v&255;p[1]=(v>>8)&255;p[2]=(v>>16)&255;p[3]=(v>>24)&255; }
    else { p[0]=(v>>24)&255;p[1]=(v>>16)&255;p[2]=(v>>8)&255;p[3]=v&255; }
}
@implementation MachOSignatureStager
+ (NSDictionary *)stageSuperBlobAtURL:(NSURL *)sbURL intoExecutableAtURL:(NSURL *)exeURL outputURL:(NSURL *)outURL error:(NSError **)error {
    NSData *sb=[NSData dataWithContentsOfURL:sbURL options:NSDataReadingMappedIfSafe error:error];
    NSData *orig=[NSData dataWithContentsOfURL:exeURL options:NSDataReadingMappedIfSafe error:error];
    if(!sb || !orig) return nil;
    const uint8_t *sp=sb.bytes; const uint8_t *b=orig.bytes; NSUInteger n=orig.length;
    NSMutableData *copy = nil; uint8_t *dst = NULL;
    if(sb.length<20 || R32(sp,NO)!=0xfade0cc0 || R32(sp+4,NO)!=sb.length || R32(sp+8,NO)<1) {
        if(error)*error=[NSError errorWithDomain:@"AppleSigner.Stager" code:1 userInfo:@{NSLocalizedDescriptionKey:@"输入不是有效的 SuperBlob"}]; return nil;
    }
    if(n<28) goto invalid;
    uint32_t magic=R32(b,YES); BOOL little=(magic==0xfeedface || magic==0xfeedfacf);
    BOOL is64=(magic==0xfeedfacf || magic==0xcffaedfe);
    if(!(magic==0xfeedface || magic==0xfeedfacf || magic==0xcefaedfe || magic==0xcffaedfe)) goto invalid;
    NSUInteger header=is64?32:28; uint32_t ncmd=R32(b+16,little),cmdbytes=R32(b+20,little);
    if(header+cmdbytes>n || ncmd>65536) goto invalid;
    NSUInteger pos=header; BOOL found=NO; uint32_t oldOff=0,oldSize=0; NSUInteger sizeField=0;
    for(uint32_t i=0;i<ncmd;i++) {
        if(pos+8>header+cmdbytes) goto invalid;
        uint32_t cmd=R32(b+pos,little),sz=R32(b+pos+4,little);
        if(sz<8 || sz>header+cmdbytes-pos) goto invalid;
        if(cmd==0x1d && sz>=16) {
            oldOff=R32(b+pos+8,little); oldSize=R32(b+pos+12,little); sizeField=pos+12; found=YES; break;
        }
        pos+=sz;
    }
    if(!found) {
        if(error)*error=[NSError errorWithDomain:@"AppleSigner.Stager" code:2 userInfo:@{NSLocalizedDescriptionKey:@"未找到 LC_CODE_SIGNATURE。当前版本不擅自扩展 Mach-O load commands；拒绝修改"}];
        return nil;
    }
    if(oldOff>n || oldSize>n-oldOff || sb.length>oldSize) {
        if(error)*error=[NSError errorWithDomain:@"AppleSigner.Stager" code:3 userInfo:@{NSLocalizedDescriptionKey:@"签名模板大于原签名预留区，或原签名区越界；拒绝移动代码段/扩大文件"}];
        return nil;
    }
    if(oldOff%16!=0) {
        if(error)*error=[NSError errorWithDomain:@"AppleSigner.Stager" code:4 userInfo:@{NSLocalizedDescriptionKey:@"原签名区未按 16 字节对齐；拒绝写入"}]; return nil;
    }
    copy=[orig mutableCopy]; dst=copy.mutableBytes;
    memset(dst+oldOff,0,oldSize); memcpy(dst+oldOff,sp,sb.length);
    W32(dst+sizeField,(uint32_t)sb.length,little);
    if(![copy writeToURL:outURL options:NSDataWritingAtomic error:error]) return nil;
    return @{@"Output":outURL.path,@"Original":exeURL.path,@"SignatureOffset":@(oldOff),@"ReservedBytes":@(oldSize),@"WrittenBytes":@(sb.length),@"Status":@"已写入独立副本；原文件未修改",@"Installable":@NO};
invalid:
    if(error)*error=[NSError errorWithDomain:@"AppleSigner.Stager" code:5 userInfo:@{NSLocalizedDescriptionKey:@"Mach-O 格式或 Load Commands 边界无效"}];
    return nil;
}
@end
