#import <Foundation/Foundation.h>
#import <Security/Security.h>

NS_ASSUME_NONNULL_BEGIN
@interface SigningIdentityVerifier : NSObject
+ (NSDictionary * _Nullable)verifyP12AtURL:(NSURL *)url
                                  password:(NSString *)password
                                     error:(NSError * _Nullable * _Nullable)error;
@end
NS_ASSUME_NONNULL_END
