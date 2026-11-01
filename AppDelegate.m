#import "AppDelegate.h"
#import "ViewController.h"\n#import "IPAExtractor.h"
@implementation AppDelegate
- (BOOL)application:(UIApplication *)application didFinishLaunchingWithOptions:(NSDictionary *)launchOptions {
    NSURL *documents=[NSFileManager.defaultManager URLsForDirectory:NSDocumentDirectory inDomains:NSUserDomainMask].firstObject;
    NSURL *work=[documents URLByAppendingPathComponent:@"AppleSignerWork" isDirectory:YES];
    [IPAExtractor cleanupStaleStagingDirectoriesAtURL:work olderThan:24.0*60.0*60.0 error:nil];
    self.window = [[UIWindow alloc] initWithFrame:UIScreen.mainScreen.bounds];
    self.window.rootViewController = [[UINavigationController alloc] initWithRootViewController:[ViewController new]];
    [self.window makeKeyAndVisible];
    return YES;
}
@end
