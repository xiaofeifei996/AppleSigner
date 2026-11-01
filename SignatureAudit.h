#import <Foundation/Foundation.h>
@interface SignatureAudit : NSObject
+ (nullable NSDictionary *)auditDirectoryAtURL:(NSURL *)directory error:(NSError **)error;
@end
