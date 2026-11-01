#import <Foundation/Foundation.h>
NS_ASSUME_NONNULL_BEGIN
@interface EntitlementsAudit : NSObject
+ (nullable NSDictionary *)auditDirectoryAtURL:(NSURL *)directory outputDirectory:(NSURL *)outputDirectory error:(NSError **)error;
@end
NS_ASSUME_NONNULL_END
