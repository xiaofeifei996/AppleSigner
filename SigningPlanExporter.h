#import <Foundation/Foundation.h>
NS_ASSUME_NONNULL_BEGIN
@interface SigningPlanExporter : NSObject
+ (nullable NSDictionary *)createPlanForIPAInfo:(NSDictionary *)ipaInfo
                                      profiles:(NSArray<NSDictionary *> *)profiles
                                certificateDER:(nullable NSData *)certificateDER
                                      outputURL:(NSURL *)outputURL
                                         error:(NSError **)error;
@end
NS_ASSUME_NONNULL_END
