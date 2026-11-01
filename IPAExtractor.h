#import <Foundation/Foundation.h>
// Extraction uses a unique staging directory; failed extraction rolls it back.
@interface IPAExtractor : NSObject
+ (nullable NSURL *)extractIPAAtURL:(NSURL *)ipaURL toDirectory:(NSURL *)directory error:(NSError **)error;
// Removes only marked AppleSigner staging directories older than the supplied age.\n+ (NSUInteger)cleanupStaleStagingDirectoriesAtURL:(NSURL *)parent olderThan:(NSTimeInterval)age error:(NSError **)error;\n@end
