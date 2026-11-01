#import <Foundation/Foundation.h>
NS_ASSUME_NONNULL_BEGIN
@interface MachOSignatureInspector : NSObject
+ (NSDictionary *)inspectExecutableAtURL:(NSURL *)url error:(NSError **)error;
+ (NSDictionary *)inspectDirectoryAtURL:(NSURL *)url error:(NSError **)error;
@end
NS_ASSUME_NONNULL_END
