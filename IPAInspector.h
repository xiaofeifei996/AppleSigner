#import <Foundation/Foundation.h>

@interface IPAInspector : NSObject
+ (nullable NSDictionary *)inspectIPAAtURL:(NSURL *)url error:(NSError **)error;
@end
