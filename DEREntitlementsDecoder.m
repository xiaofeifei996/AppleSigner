#import "DEREntitlementsDecoder.h"

@interface DERNode : NSObject
@property(nonatomic) uint8_t tag;
@property(nonatomic, strong) NSData *value;
@property(nonatomic, strong) NSArray<DERNode *> *children;
@end
@implementation DERNode
@end

static NSError *DEDMakeError(NSString *message, NSInteger code) {
    return [NSError errorWithDomain:@"AppleSigner.DEREntitlements" code:code
        userInfo:@{NSLocalizedDescriptionKey:message}];
}
static BOOL DEDReadNode(const uint8_t *b, NSUInteger n, NSUInteger *cursor, NSUInteger depth,
                        DERNode **out, NSError **error) {
    if (depth > 32 || *cursor >= n) {
        if(error)*error=DEDMakeError(@"DER 嵌套过深或数据提前结束",1); return NO;
    }
    NSUInteger start=*cursor;
    uint8_t tag=b[(*cursor)++];
    if ((tag & 0x1f)==0x1f) {
        if(error)*error=DEDMakeError(@"不支持高位 Tag 编码",2); return NO;
    }
    if (*cursor>=n) { if(error)*error=DEDMakeError(@"DER 长度字段缺失",3); return NO; }
    uint8_t first=b[(*cursor)++];
    uint64_t length=0;
    if ((first & 0x80)==0) length=first;
    else {
        NSUInteger count=first&0x7f;
        if (count==0 || count>4 || count>n-*cursor || b[*cursor]==0) {
            if(error)*error=DEDMakeError(@"DER 长度编码非法或不是最短形式",4); return NO;
        }
        for(NSUInteger i=0;i<count;i++) length=(length<<8)|b[(*cursor)++];
        if(length<128) { if(error)*error=DEDMakeError(@"DER 长度使用了非最短编码",5); return NO; }
    }
    if(length>n-*cursor) { if(error)*error=DEDMakeError(@"DER 值超出数据边界",6); return NO; }
    NSUInteger content=(NSUInteger)length, valueStart=*cursor;
    DERNode *node=[DERNode new]; node.tag=tag;
    if ((tag & 0x20)!=0) {
        NSMutableArray *children=[NSMutableArray array];
        NSUInteger end=valueStart+content;
        while(*cursor<end) {
            DERNode *child=nil;
            if(!DEDReadNode(b,end,cursor,depth+1,&child,error)) return NO;
            [children addObject:child];
        }
        if(*cursor!=end) { if(error)*error=DEDMakeError(@"DER 构造节点长度不匹配",7); return NO; }
        node.children=children;
        node.value=[NSData data];
    } else {
        node.value=[NSData dataWithBytes:b+valueStart length:content];
        *cursor=valueStart+content;
    }
    if(*cursor<=start) { if(error)*error=DEDMakeError(@"DER 解析未前进",8); return NO; }
    *out=node; return YES;
}
static NSString *DEDString(DERNode *node) {
    if(node.tag!=0x0c || !node.value.length) return nil;
    NSString *s=[[NSString alloc] initWithData:node.value encoding:NSUTF8StringEncoding];
    if(!s || [s rangeOfString:@"\0"].location!=NSNotFound) return nil;
    return s;
}
static id DEDValue(DERNode *node, NSUInteger depth, NSError **error) {
    if(depth>32) { if(error)*error=DEDMakeError(@"Entitlements 值嵌套过深",9); return nil; }
    if(node.tag==0x0c) {
        NSString *s=DEDString(node);
        if(!s && error)*error=DEDMakeError(@"Entitlements 字符串不是有效 UTF-8",10);
        return s;
    }
    if(node.tag==0x01) {
        const uint8_t *p=node.value.bytes;
        if(node.value.length!=1 || (p[0]!=0 && p[0]!=1 && p[0]!=0xff)) {
            if(error)*error=DEDMakeError(@"DER BOOLEAN 长度或取值非法",11); return nil;
        }
        return @((BOOL)(p[0]!=0));
    }
    if(node.tag==0x02) {
        const uint8_t *p=node.value.bytes; NSUInteger n=node.value.length;
        if(n==0 || n>8) { if(error)*error=DEDMakeError(@"DER INTEGER 长度不受支持",12); return nil; }
        if(n>1 && ((p[0]==0x00 && !(p[1]&0x80)) || (p[0]==0xff && (p[1]&0x80)))) {
            if(error)*error=DEDMakeError(@"DER INTEGER 不是最短编码",13); return nil;
        }
        uint64_t raw=0;
        for(NSUInteger i=0;i<n;i++) raw=(raw<<8)|p[i];
        if ((p[0]&0x80) && n<8) raw |= (UINT64_MAX << (n*8));
        return @((int64_t)raw);
    }
    if(node.tag==0x30) {
        NSMutableArray *array=[NSMutableArray array];
        for(DERNode *child in node.children) {
            id v=DEDValue(child,depth+1,error); if(!v)return nil;
            [array addObject:v];
        }
        return array;
    }
    if(error)*error=DEDMakeError([NSString stringWithFormat:@"不支持的 Entitlements DER 类型 Tag 0x%02x",node.tag],14);
    return nil;
}

@implementation DEREntitlementsDecoder
+ (NSDictionary *)decodeEntitlementsData:(NSData *)data error:(NSError **)error {
    if(!data.length || data.length>16*1024*1024) {
        if(error)*error=DEDMakeError(@"DER Entitlements 为空或超过 16MB 限制",15); return nil;
    }
    const uint8_t *bytes=data.bytes; NSUInteger cursor=0;
    DERNode *root=nil;
    if(!DEDReadNode(bytes,data.length,&cursor,0,&root,error)) return nil;
    if(cursor!=data.length) { if(error)*error=DEDMakeError(@"DER Entitlements 尾部存在多余数据",16); return nil; }
    if(root.tag!=0x31 || !root.children.count) {
        if(error)*error=DEDMakeError(@"外层结构不是预期的 SET OF Entitlement",17); return nil;
    }
    NSMutableDictionary *result=[NSMutableDictionary dictionary];
    NSString *previous=nil;
    for(DERNode *entry in root.children) {
        if(entry.tag!=0x30 || entry.children.count!=2) {
            if(error)*error=DEDMakeError(@"Entitlement 条目必须是包含 key/value 的 SEQUENCE",18); return nil;
        }
        NSString *key=DEDString(entry.children[0]);
        if(!key.length) { if(error)*error=DEDMakeError(@"Entitlement key 不是有效 UTF8String",19); return nil; }
        if(result[key]) { if(error)*error=DEDMakeError([NSString stringWithFormat:@"存在重复 Entitlement key：%@",key],20); return nil; }
        // Apple DER entitlement entries are conventionally ordered by key.
        if(previous && [previous compare:key options:NSLiteralSearch]!=NSOrderedAscending) {
            if(error)*error=DEDMakeError(@"Entitlement key 顺序异常或存在重复项",21); return nil;
        }
        id value=DEDValue(entry.children[1],0,error);
        if(!value) return nil;
        result[key]=value; previous=key;
    }
    return result;
}
@end
