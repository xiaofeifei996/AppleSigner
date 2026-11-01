#import <Foundation/Foundation.h>
NS_ASSUME_NONNULL_BEGIN
@interface CodeDirectoryBuilder : NSObject
+ (nullable NSDictionary *)buildTemplateForExecutableAtURL:(NSURL *)url outputDirectory:(NSURL *)directory error:(NSError **)error;
@end
NS_ASSUME_NONNULL_END
