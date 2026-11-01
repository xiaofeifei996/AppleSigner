#import <Foundation/Foundation.h>
#import <Security/Security.h>

NS_ASSUME_NONNULL_BEGIN
@interface CMSPreflight : NSObject
+ (NSDictionary * _Nullable)inspectP12AtURL:(NSURL *)url
                                   password:(NSString *)password
                            contentToDigest:(NSData *)content
                                      error:(NSError * _Nullable * _Nullable)error;
@end
NS_ASSUME_NONNULL_END
