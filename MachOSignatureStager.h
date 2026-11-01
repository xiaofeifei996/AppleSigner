#import <Foundation/Foundation.h>
NS_ASSUME_NONNULL_BEGIN
@interface MachOSignatureStager : NSObject
+ (nullable NSDictionary *)stageSuperBlobAtURL:(NSURL *)superBlobURL intoExecutableAtURL:(NSURL *)executableURL outputURL:(NSURL *)outputURL error:(NSError **)error;
@end
NS_ASSUME_NONNULL_END
