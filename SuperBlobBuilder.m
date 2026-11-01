#import "SuperBlobBuilder.h"
#include <string.h>

static uint32_t ReadBE32(const uint8_t *p) { return ((uint32_t)p[0]<<24)|((uint32_t)p[1]<<16)|((uint32_t)p[2]<<8)|p[3]; }
static void WriteBE32(uint8_t *p,uint32_t v) { p[0]=(v>>24)&255; p[1]=(v>>16)&255; p[2]=(v>>8)&255; p[3]=v&255; }

@implementation SuperBlobBuilder
+ (NSDictionary *)wrapCodeDirectoryAtURL:(NSURL *)cdURL outputDirectory:(NSURL *)outDir error:(NSError **)error {
    NSData *cd=[NSData dataWithContentsOfURL:cdURL options:NSDataReadingMappedIfSafe error:error];
    if(!cd) return nil;
    if(cd.length<44 || cd.length>UINT32_MAX || ReadBE32(cd.bytes)!=0xfade0c02 || ReadBE32((const uint8_t *)cd.bytes+4)!=cd.length) {
        if(error)*error=[NSError errorWithDomain:@"AppleSigner.SuperBlob" code:1 userInfo:@{NSLocalizedDescriptionKey:@"输入不是长度有效的 CodeDirectory blob"}];
        return nil;
    }
    uint64_t total=20+(uint64_t)cd.length;
    if(total>UINT32_MAX) { if(error)*error=[NSError errorWithDomain:@"AppleSigner.SuperBlob" code:2 userInfo:@{NSLocalizedDescriptionKey:@"SuperBlob 超过 4GB"}]; return nil; }
    NSMutableData *data=[NSMutableData dataWithLength:(NSUInteger)total];
    uint8_t *p=data.mutableBytes;
    WriteBE32(p,0xfade0cc0); // CSMAGIC_EMBEDDED_SIGNATURE
    WriteBE32(p+4,(uint32_t)total);
    WriteBE32(p+8,1); // one index
    WriteBE32(p+12,0); // CSSLOT_CODEDIRECTORY
    WriteBE32(p+16,20); // blob offset
    memcpy(p+20,cd.bytes,cd.length);
    NSError *dirError=nil;
    [[NSFileManager defaultManager] createDirectoryAtURL:outDir withIntermediateDirectories:YES attributes:nil error:&dirError];
    if(dirError) { if(error)*error=dirError; return nil; }
    NSString *name=[[cdURL.lastPathComponent stringByDeletingPathExtension] stringByAppendingString:@".superblob.template"];
    NSURL *output=[outDir URLByAppendingPathComponent:name];
    if(![data writeToURL:output options:NSDataWritingAtomic error:error]) return nil;
    return @{@"Output":output.path,@"Bytes":@(data.length),@"BlobCount":@1,@"ContainsCodeDirectory":@YES,@"ContainsCMS":@NO,@"Status":@"SuperBlob 结构模板已生成；不含 CMS"};
}
@end
