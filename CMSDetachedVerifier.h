#import <Foundation/Foundation.h>
NS_ASSUME_NONNULL_BEGIN
@interface CMSDetachedVerifier : NSObject
+ (NSDictionary * _Nullable)verifyCMSAtURL:(NSURL *)cmsURL
                                contentURL:(NSURL *)contentURL
                                     error:(NSError * _Nullable * _Nullable)error;
@end
NS_ASSUME_NONNULL_END
