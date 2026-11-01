#import <Foundation/Foundation.h>
#import <Security/Security.h>
NS_ASSUME_NONNULL_BEGIN
@interface CMSDetachedBuilder : NSObject
+ (NSURL * _Nullable)createDetachedTestCMSForP12:(NSURL *)p12URL
                                        password:(NSString *)password
                                      contentURL:(NSURL *)contentURL
                                      outputURL:(NSURL *)outputURL
                                           error:(NSError * _Nullable * _Nullable)error;
@end
NS_ASSUME_NONNULL_END
