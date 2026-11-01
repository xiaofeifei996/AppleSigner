#import <Foundation/Foundation.h>
NS_ASSUME_NONNULL_BEGIN
@interface DEREntitlementsDecoder : NSObject
+ (nullable NSDictionary *)decodeEntitlementsData:(NSData *)data error:(NSError **)error;
@end
NS_ASSUME_NONNULL_END
