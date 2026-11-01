#import <Foundation/Foundation.h>
@interface SigningPreparation : NSObject
+ (nullable NSDictionary *)prepareAtDirectoryURL:(NSURL *)directory
                                     profileInfo:(NSDictionary *)profile
                                            error:(NSError **)error;
@end
