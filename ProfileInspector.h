#import <Foundation/Foundation.h>
@interface ProfileInspector : NSObject
+ (nullable NSDictionary *)inspectProfileAtURL:(NSURL *)url error:(NSError **)error;
@end
