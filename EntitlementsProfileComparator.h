#import <Foundation/Foundation.h>
NS_ASSUME_NONNULL_BEGIN
@interface EntitlementsProfileComparator : NSObject
+ (NSDictionary *)compareEntitlements:(NSDictionary *)actual againstProfile:(NSDictionary *)profileEntitlements;
@end
NS_ASSUME_NONNULL_END
