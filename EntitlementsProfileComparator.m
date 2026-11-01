#import "EntitlementsProfileComparator.h"

static BOOL EPCStringAllowed(NSString *actual, NSString *allowed) {
    if ([allowed isEqualToString:actual]) return YES;
    if ([allowed hasSuffix:@"*"]) {
        NSString *prefix=[allowed substringToIndex:allowed.length-1];
        return [actual hasPrefix:prefix];
    }
    return NO;
}
static BOOL EPCValueAllowed(id actual, id allowed) {
    if ([actual isKindOfClass:NSString.class] && [allowed isKindOfClass:NSString.class])
        return EPCStringAllowed(actual,allowed);
    if ([actual isKindOfClass:NSNumber.class] && [allowed isKindOfClass:NSNumber.class])
        return [actual isEqual:allowed] || ([allowed boolValue] && ![actual boolValue]);
    if ([actual isKindOfClass:NSArray.class] && [allowed isKindOfClass:NSArray.class]) {
        for (id value in actual) {
            BOOL matched=NO;
            for (id candidate in allowed) if (EPCValueAllowed(value,candidate)) { matched=YES; break; }
            if (!matched) return NO;
        }
        return YES;
    }
    if ([actual isKindOfClass:NSDictionary.class] && [allowed isKindOfClass:NSDictionary.class]) {
        for (id key in actual) {
            id allowedValue=allowed[key];
            if (!allowedValue || !EPCValueAllowed(actual[key],allowedValue)) return NO;
        }
        return YES;
    }
    return [actual isEqual:allowed];
}
@implementation EntitlementsProfileComparator
+ (NSDictionary *)compareEntitlements:(NSDictionary *)actual againstProfile:(NSDictionary *)profileEntitlements {
    NSMutableArray *allowed=[NSMutableArray array], *denied=[NSMutableArray array], *unknown=[NSMutableArray array];
    NSArray *keys=[[actual allKeys] sortedArrayUsingSelector:@selector(compare:)];
    for (id key in keys) {
        id value=actual[key];
        id grant=profileEntitlements[key];
        if (!grant) {
            [denied addObject:@{@"Key":[key description],@"Actual":value,@"Reason":@"描述文件未声明该授权键"}];
        } else if (EPCValueAllowed(value,grant)) {
            [allowed addObject:@{@"Key":[key description],@"Actual":value,@"ProfileGrant":grant,@"Status":@"允许"}];
        } else {
            [denied addObject:@{@"Key":[key description],@"Actual":value,@"ProfileGrant":grant,@"Reason":@"实际值超出描述文件授权范围"}];
        }
    }
    // These profile-wide identity constraints are important but are not all represented
    // as ordinary app entitlements in every signed binary.
    for (NSString *key in @[@"application-identifier",@"com.apple.developer.team-identifier"]) {
        if (!actual[key]) [unknown addObject:@{@"Key":key,@"Reason":@"IPA Entitlements 中未发现此键；需结合 Bundle ID / Team ID 单独核对"}];
    }
    return @{@"Allowed":allowed,@"Denied":denied,@"Unknown":unknown,
             @"AllowedCount":@(allowed.count),@"DeniedCount":@(denied.count),@"UnknownCount":@(unknown.count),
             @"Overall":denied.count?@"存在明确不匹配":(unknown.count?@"部分无法判定":@"已提取项目均在描述文件授权范围内")};
}
@end
