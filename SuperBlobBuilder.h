#import <Foundation/Foundation.h>
NS_ASSUME_NONNULL_BEGIN
@interface SuperBlobBuilder : NSObject
+ (nullable NSDictionary *)wrapCodeDirectoryAtURL:(NSURL *)codeDirectoryURL outputDirectory:(NSURL *)outputDirectory error:(NSError **)error;
@end
NS_ASSUME_NONNULL_END
