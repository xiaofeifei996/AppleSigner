#import "ViewController.h"
#import "ProfileInspector.h"
#import "EntitlementsAudit.h"
#import "EntitlementsProfileComparator.h"
#import "SigningPlanExporter.h"
#import "IPAInspector.h"
#import "IPAExtractor.h"
#import "SignatureAudit.h"
#import "SigningPreparation.h"
#import "MachOSignatureInspector.h"
#import "CodeDirectoryBuilder.h"
#import "SuperBlobBuilder.h"
#import "MachOSignatureStager.h"
#import "SigningIdentityVerifier.h"
#import "CMSPreflight.h"
#import "CMSDetachedBuilder.h"
#import "CMSDetachedVerifier.h"
#import <UniformTypeIdentifiers/UniformTypeIdentifiers.h>
#import <Security/Security.h>

@interface ViewController () <UIDocumentPickerDelegate>
@property(nonatomic,strong) UILabel *accountValue;
@property(nonatomic,strong) UILabel *certificateValue;
@property(nonatomic,strong) UILabel *profileValue;
@property(nonatomic,strong) UILabel *ipaValue;
@property(nonatomic,strong) UILabel *activityValue;
@property(nonatomic,strong) NSString *pendingImportType;
@property(nonatomic,strong) NSURL *selectedIPAURL;
@property(nonatomic,strong) NSURL *selectedP12URL;
@property(nonatomic,strong) NSURL *selectedProfileURL;
@property(nonatomic,strong) NSData *certificateDER;
@property(nonatomic,strong) NSString *certificateFingerprint;
@property(nonatomic,strong) NSString *certificateSubject;
@property(nonatomic,strong) NSDictionary *profileInfo;
@property(nonatomic,strong) NSArray<NSDictionary *> *profileInfos;
@property(nonatomic,strong) NSDictionary *ipaInfo;
@end

@implementation ViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    self.title = @"AppleSigner";
    self.view.backgroundColor = UIColor.systemGroupedBackgroundColor;
    [self buildInterface];
}

- (UILabel *)label:(NSString *)text font:(UIFont *)font color:(UIColor *)color {
    UILabel *v = [UILabel new]; v.translatesAutoresizingMaskIntoConstraints = NO;
    v.text = text; v.font = font; v.textColor = color; v.numberOfLines = 0; return v;
}
- (UIButton *)button:(NSString *)title action:(SEL)action {
    UIButton *b = [UIButton buttonWithType:UIButtonTypeSystem]; b.translatesAutoresizingMaskIntoConstraints = NO;
    UIButtonConfiguration *configuration = [UIButtonConfiguration plainButtonConfiguration];
    configuration.title = title;
    configuration.titleTextAttributesTransformer = ^NSDictionary<NSAttributedStringKey,id> *(NSDictionary<NSAttributedStringKey,id> *attributes) {
        NSMutableDictionary *updated = [attributes mutableCopy];
        updated[NSFontAttributeName] = [UIFont systemFontOfSize:15 weight:UIFontWeightSemibold];
        return updated;
    };
    configuration.baseBackgroundColor = UIColor.secondarySystemGroupedBackgroundColor;
    configuration.contentInsets = NSDirectionalEdgeInsetsMake(13, 15, 13, 15);
    b.configuration = configuration;
    b.layer.cornerRadius = 12; b.clipsToBounds = YES;
    [b addTarget:self action:action forControlEvents:UIControlEventTouchUpInside]; return b;
}
- (UIView *)card:(NSString *)title value:(UILabel * __strong *)value {
    UIView *v = [UIView new]; v.translatesAutoresizingMaskIntoConstraints = NO;
    v.backgroundColor = UIColor.secondarySystemGroupedBackgroundColor; v.layer.cornerRadius = 15;
    UILabel *h = [self label:title font:[UIFont systemFontOfSize:14 weight:UIFontWeightSemibold] color:UIColor.labelColor];
    *value = [self label:@"尚未导入" font:[UIFont systemFontOfSize:13] color:UIColor.secondaryLabelColor];
    [v addSubview:h]; [v addSubview:*value];
    [NSLayoutConstraint activateConstraints:@[
        [h.topAnchor constraintEqualToAnchor:v.topAnchor constant:14], [h.leadingAnchor constraintEqualToAnchor:v.leadingAnchor constant:15],
        [h.trailingAnchor constraintEqualToAnchor:v.trailingAnchor constant:-15], [(*value).topAnchor constraintEqualToAnchor:h.bottomAnchor constant:7],
        [(*value).leadingAnchor constraintEqualToAnchor:h.leadingAnchor], [(*value).trailingAnchor constraintEqualToAnchor:h.trailingAnchor],
        [(*value).bottomAnchor constraintEqualToAnchor:v.bottomAnchor constant:-14]
    ]]; return v;
}
- (void)buildInterface {
    UIStackView *s = [UIStackView new]; s.translatesAutoresizingMaskIntoConstraints = NO; s.axis = UILayoutConstraintAxisVertical; s.spacing = 10;
    [s addArrangedSubview:[self label:@"本地签名工作台 · 1.32.0" font:[UIFont systemFontOfSize:14] color:UIColor.secondaryLabelColor]];
    [s addArrangedSubview:[self card:@"Apple ID 自动申请" value:&_accountValue]];
    [s addArrangedSubview:[self card:@"P12 证书身份" value:&_certificateValue]];
    [s addArrangedSubview:[self card:@"描述文件解析" value:&_profileValue]];
    [s addArrangedSubview:[self card:@"IPA 文件" value:&_ipaValue]];
    [s addArrangedSubview:[self card:@"预检状态" value:&_activityValue]];
    [s addArrangedSubview:[self button:@"Apple ID 自动申请说明" action:@selector(autoEnroll)]];
    [s addArrangedSubview:[self button:@"导入并验证 P12" action:@selector(importP12)]];
    [s addArrangedSubview:[self button:@"验证 P12 私钥签名能力（1.6）" action:@selector(verifyPrivateKeyCapability)]];
    [s addArrangedSubview:[self button:@"检查 CMS 签名前置条件（1.7）" action:@selector(prepareCMSPreflight)]];
    [s addArrangedSubview:[self button:@"生成独立 CMS 测试文件（1.8）" action:@selector(createDetachedCMSTest)]];
    [s addArrangedSubview:[self button:@"验证独立 CMS 测试文件（1.9）" action:@selector(verifyDetachedCMSTest)]];
    [s addArrangedSubview:[self button:@"检查 CMS DER 结构约束（1.10）" action:@selector(auditCMSOutput)]];
    [s addArrangedSubview:[self button:@"导出 OpenSSL 互操作测试材料（1.11）" action:@selector(exportCMSInteropFiles)]];
    [s addArrangedSubview:[self button:@"严格 DER 规范检查（1.13）" action:@selector(auditCMSOutput)]];
    [s addArrangedSubview:[self button:@"描述文件授权能力审计（1.14）" action:@selector(auditProfileAuthorization)]];
    [s addArrangedSubview:[self button:@"提取 IPA 现有 Entitlements（1.17）" action:@selector(extractExistingEntitlements)]];
    [s addArrangedSubview:[self button:@"Entitlements 与描述文件授权逐项比对（1.18）" action:@selector(compareIPAEntitlementsWithProfile)]];
    [s addArrangedSubview:[self button:@"导入并解析描述文件" action:@selector(importProfile)]];
    [s addArrangedSubview:[self button:@"批量导入描述文件并匹配 App / Extension（1.18）" action:@selector(importProfiles)]];
    [s addArrangedSubview:[self button:@"按 Bundle ID 匹配各组件描述文件（1.21）" action:@selector(matchProfilesToIPAComponents)]];
    [s addArrangedSubview:[self button:@"生成并导出签名映射计划（1.22）" action:@selector(exportSigningPlan)]];
    [s addArrangedSubview:[self button:@"选择 IPA" action:@selector(importIPA)]];
    [s addArrangedSubview:[self button:@"解包 IPA 到工作目录" action:@selector(extractIPA)]];
    [s addArrangedSubview:[self button:@"检查现有签名结构（0.9）" action:@selector(auditSignature)]];
    [s addArrangedSubview:[self button:@"生成 CodeDirectory 模板（1.3）" action:@selector(buildCodeDirectoryTemplates)]];
    [s addArrangedSubview:[self button:@"封装 SuperBlob 模板（1.4）" action:@selector(buildSuperBlobTemplates)]];
    [s addArrangedSubview:[self button:@"写入 Mach-O 测试副本（1.5）" action:@selector(stageMachOSignatures)]];
    [s addArrangedSubview:[self button:@"验证 CodeDirectory 页面哈希（1.2）" action:@selector(inspectMachOSignatures)]];
    [s addArrangedSubview:[self button:@"生成签名配置模板（1.0）" action:@selector(prepareSigning)]];
    [s addArrangedSubview:[self button:@"检查签名材料匹配" action:@selector(checkMaterials)]];
    UIScrollView *scroll = [UIScrollView new]; scroll.translatesAutoresizingMaskIntoConstraints = NO; [self.view addSubview:scroll]; [scroll addSubview:s];
    [NSLayoutConstraint activateConstraints:@[
        [scroll.topAnchor constraintEqualToAnchor:self.view.safeAreaLayoutGuide.topAnchor], [scroll.leadingAnchor constraintEqualToAnchor:self.view.leadingAnchor],
        [scroll.trailingAnchor constraintEqualToAnchor:self.view.trailingAnchor], [scroll.bottomAnchor constraintEqualToAnchor:self.view.bottomAnchor],
        [s.topAnchor constraintEqualToAnchor:scroll.contentLayoutGuide.topAnchor constant:16], [s.leadingAnchor constraintEqualToAnchor:scroll.frameLayoutGuide.leadingAnchor constant:16],
        [s.trailingAnchor constraintEqualToAnchor:scroll.frameLayoutGuide.trailingAnchor constant:-16], [s.bottomAnchor constraintEqualToAnchor:scroll.contentLayoutGuide.bottomAnchor constant:-20]
    ]];
}
- (NSURL *)importsDirectory {
    NSURL *docs = [[[NSFileManager defaultManager] URLsForDirectory:NSDocumentDirectory inDomains:NSUserDomainMask] firstObject];
    NSURL *dir = [docs URLByAppendingPathComponent:@"Imports" isDirectory:YES];
    [[NSFileManager defaultManager] createDirectoryAtURL:dir withIntermediateDirectories:YES attributes:nil error:nil]; return dir;
}
- (void)pickExtension:(NSString *)ext kind:(NSString *)kind {
    self.pendingImportType = kind; UTType *t = [UTType typeWithFilenameExtension:ext];
    if (!t) t = [UTType typeWithIdentifier:@"public.data"];
    UIDocumentPickerViewController *p = [[UIDocumentPickerViewController alloc] initForOpeningContentTypes:(t ? @[t] : @[]) asCopy:YES];
    p.delegate = self; p.allowsMultipleSelection = NO; [self presentViewController:p animated:YES completion:nil];
}
- (void)extractIPA {
    if (!self.selectedIPAURL) { self.activityValue.text = @"请先导入 IPA"; return; }
    NSURL *docs=[[[NSFileManager defaultManager] URLsForDirectory:NSDocumentDirectory inDomains:NSUserDomainMask] firstObject];
    NSURL *work=[docs URLByAppendingPathComponent:@"AppleSignerWork" isDirectory:YES];
    NSURL *unpacked=[work URLByAppendingPathComponent:@"Unpacked" isDirectory:YES];
    NSError *error=nil;
    NSURL *result=[IPAExtractor extractIPAAtURL:self.selectedIPAURL toDirectory:unpacked error:&error];
    if (!result) {
        self.activityValue.text=error.localizedDescription ?: @"解包失败";
        return;
    }
    NSString *payload=[result.path stringByAppendingPathComponent:@"Payload"];
    NSArray *apps=[[NSFileManager defaultManager] contentsOfDirectoryAtPath:payload error:nil];
    NSUInteger appCount=0;
    for(NSString *name in apps) if([name.pathExtension.lowercaseString isEqualToString:@"app"]) appCount++;
    self.activityValue.text=[NSString stringWithFormat:@"IPA 解包成功\\n主目录：%@\\nPayload 中发现 %lu 个 .app", result.path, (unsigned long)appCount];
}
- (void)auditSignature {
    NSURL *docs=[[[NSFileManager defaultManager] URLsForDirectory:NSDocumentDirectory inDomains:NSUserDomainMask] firstObject];
    NSURL *unpacked=[[docs URLByAppendingPathComponent:@"AppleSignerWork" isDirectory:YES] URLByAppendingPathComponent:@"Unpacked" isDirectory:YES];
    NSError *error=nil;
    NSDictionary *report=[SignatureAudit auditDirectoryAtURL:unpacked error:&error];
    if (!report) { self.activityValue.text=error.localizedDescription ?: @"签名结构检查失败"; return; }
    self.activityValue.text=[NSString stringWithFormat:@"签名文件结构审计完成：%lu 个组件，%lu 个组件存在签名文件结构，%lu 个结构不完整/异常\n\n%@\n\n注意：文件存在不代表签名有效。本功能CodeResources 仅对识别的 SHA-1/SHA-256 文件哈希做有限核对；尚未验证 CodeDirectory special slots、CMS 签名/证书信任、规则覆盖范围或嵌套代码封印。",
        (unsigned long)[report[@"ComponentCount"] unsignedIntegerValue],
        (unsigned long)[report[@"SignatureArtifactCount"] unsignedIntegerValue],
        (unsigned long)[report[@"MalformedArtifactCount"] unsignedIntegerValue], report[@"Report"]];
}
- (void)stageMachOSignatures {
    NSURL *docs=[[[NSFileManager defaultManager] URLsForDirectory:NSDocumentDirectory inDomains:NSUserDomainMask] firstObject];
    NSURL *work=[docs URLByAppendingPathComponent:@"AppleSignerWork" isDirectory:YES];
    NSURL *sbDir=[work URLByAppendingPathComponent:@"SuperBlobTemplates" isDirectory:YES];
    NSURL *outDir=[work URLByAppendingPathComponent:@"StagedMachO" isDirectory:YES];
    NSArray *sbFiles=[[NSFileManager defaultManager] contentsOfDirectoryAtURL:sbDir includingPropertiesForKeys:nil options:NSDirectoryEnumerationSkipsHiddenFiles error:nil];
    NSDirectoryEnumerator *en=[[NSFileManager defaultManager] enumeratorAtURL:[work URLByAppendingPathComponent:@"Unpacked" isDirectory:YES] includingPropertiesForKeys:nil options:NSDirectoryEnumerationSkipsHiddenFiles errorHandler:nil];
    NSMutableArray *binaries=[NSMutableArray array];
    for(NSURL *u in en) {
        if([u.lastPathComponent isEqualToString:@"Info.plist"]) {
            NSDictionary *info=[NSDictionary dictionaryWithContentsOfURL:u];
            NSString *exe=info[@"CFBundleExecutable"];
            if([exe isKindOfClass:NSString.class] && exe.length) {
                NSURL *candidate=[u.URLByDeletingLastPathComponent URLByAppendingPathComponent:exe];
                if([[NSFileManager defaultManager] fileExistsAtPath:candidate.path]) [binaries addObject:candidate];
            }
        }
    }
    NSError *dirError=nil;
    [[NSFileManager defaultManager] createDirectoryAtURL:outDir withIntermediateDirectories:YES attributes:nil error:&dirError];
    NSMutableArray *lines=[NSMutableArray array]; NSUInteger done=0;
    for(NSURL *sb in sbFiles) {
        if(![sb.lastPathComponent hasSuffix:@".superblob.template"]) continue;
        NSString *prefix=[sb.lastPathComponent stringByReplacingOccurrencesOfString:@".codedirectory.superblob.template" withString:@""];
        NSURL *binary=nil;
        for(NSURL *candidate in binaries) if([candidate.lastPathComponent isEqualToString:prefix]) { binary=candidate; break; }
        if(!binary) { [lines addObject:[NSString stringWithFormat:@"%@：找不到对应 Mach-O",sb.lastPathComponent]]; continue; }
        NSURL *out=[outDir URLByAppendingPathComponent:[binary.lastPathComponent stringByAppendingString:@".staged"]];
        NSError *e=nil; NSDictionary *r=[MachOSignatureStager stageSuperBlobAtURL:sb intoExecutableAtURL:binary outputURL:out error:&e];
        if(r) { done++; [lines addObject:[NSString stringWithFormat:@"%@：%@",binary.lastPathComponent,r[@"Status"]]]; }
        else [lines addObject:[NSString stringWithFormat:@"%@：%@",binary.lastPathComponent,e.localizedDescription?:@"写入失败"]];
    }
    if(!sbFiles.count) [lines addObject:@"未找到 SuperBlob 模板，请先运行 1.4"];
    [lines addObject:[NSString stringWithFormat:@"\n完成：%lu 个副本；输出目录：%@",(unsigned long)done,outDir.path]];
    [lines addObject:@"警告：副本仅用于签名区布局实验。当前 SuperBlob 不含 CMS，CodeDirectory 也没有真实 Bundle Identifier / special slots；不可安装或视为签名成功。原 IPA 解包文件保持不变。"];
    self.activityValue.text=[lines componentsJoinedByString:@"\n"];
}
- (void)buildSuperBlobTemplates {
    NSURL *docs=[[[NSFileManager defaultManager] URLsForDirectory:NSDocumentDirectory inDomains:NSUserDomainMask] firstObject];
    NSURL *work=[[docs URLByAppendingPathComponent:@"AppleSignerWork" isDirectory:YES] URLByAppendingPathComponent:@"CodeDirectoryTemplates" isDirectory:YES];
    NSURL *out=[[docs URLByAppendingPathComponent:@"AppleSignerWork" isDirectory:YES] URLByAppendingPathComponent:@"SuperBlobTemplates" isDirectory:YES];
    NSArray *files=[[NSFileManager defaultManager] contentsOfDirectoryAtURL:work includingPropertiesForKeys:nil options:NSDirectoryEnumerationSkipsHiddenFiles error:nil];
    NSMutableArray *lines=[NSMutableArray array];
    NSUInteger count=0;
    for(NSURL *file in files) {
        if(![file.lastPathComponent hasSuffix:@".codedirectory.template"]) continue;
        NSError *e=nil;
        NSDictionary *r=[SuperBlobBuilder wrapCodeDirectoryAtURL:file outputDirectory:out error:&e];
        if(r) { count++; [lines addObject:[NSString stringWithFormat:@"%@：%@（%@ bytes）",file.lastPathComponent,r[@"Status"],r[@"Bytes"]]]; }
        else [lines addObject:[NSString stringWithFormat:@"%@：%@",file.lastPathComponent,e.localizedDescription?:@"封装失败"]];
    }
    if(!count && !lines.count) [lines addObject:@"没有找到 CodeDirectory 模板，请先运行 1.3 模板生成"];
    [lines addObject:[NSString stringWithFormat:@"\n输出目录：%@",out.path]];
    [lines addObject:@"注意：当前仅包含 CSSLOT_CODEDIRECTORY；没有 CMS Blob、Entitlements、Requirements 或资源封印。它不是可用签名，未写入 Mach-O。"];
    self.activityValue.text=[lines componentsJoinedByString:@"\n"];
}
- (void)buildCodeDirectoryTemplates {
    NSURL *docs=[[[NSFileManager defaultManager] URLsForDirectory:NSDocumentDirectory inDomains:NSUserDomainMask] firstObject];
    NSURL *unpacked=[[docs URLByAppendingPathComponent:@"AppleSignerWork" isDirectory:YES] URLByAppendingPathComponent:@"Unpacked" isDirectory:YES];
    NSURL *out=[[docs URLByAppendingPathComponent:@"AppleSignerWork" isDirectory:YES] URLByAppendingPathComponent:@"CodeDirectoryTemplates" isDirectory:YES];
    NSDictionary *scan=[MachOSignatureInspector inspectDirectoryAtURL:unpacked error:nil];
    NSArray *items=scan[@"Items"];
    if(!items.count) { self.activityValue.text=@"请先导入并解包 IPA"; return; }
    NSMutableArray *lines=[NSMutableArray array];
    for(NSDictionary *item in items) {
        NSString *exe=item[@"Executable"];
        NSString *bundle=item[@"Bundle"];
            // Locate executable under its bundle, including nested paths discovered from Info.plist.
        NSDirectoryEnumerator *en=[[NSFileManager defaultManager] enumeratorAtURL:unpacked includingPropertiesForKeys:nil options:NSDirectoryEnumerationSkipsHiddenFiles errorHandler:nil];
        NSURL *binary=nil;
        for(NSURL *candidate in en) if([candidate.lastPathComponent isEqualToString:exe] && [[candidate.URLByDeletingLastPathComponent.lastPathComponent lowercaseString] hasSuffix:@".app"]) { binary=candidate; break; }
        if(!binary) { [lines addObject:[NSString stringWithFormat:@"%@：找不到可执行文件 %@",bundle,exe]]; continue; }
        NSError *e=nil;
        NSDictionary *r=[CodeDirectoryBuilder buildTemplateForExecutableAtURL:binary outputDirectory:out error:&e];
        [lines addObject:r?[NSString stringWithFormat:@"%@：%@（%@ bytes，%@ slots）",bundle,r[@"Status"],r[@"Bytes"],r[@"CodeSlots"]]:[NSString stringWithFormat:@"%@：%@",bundle,e.localizedDescription?:@"生成失败"]];
    }
    [lines addObject:[NSString stringWithFormat:@"\n模板输出目录：%@",out.path]];
    [lines addObject:@"注意：模板使用占位 Identifier、无 special slots，不含 CMS，不可直接用于安装或冒充有效签名。"];
    self.activityValue.text=[lines componentsJoinedByString:@"\n"];
}
- (void)inspectMachOSignatures {
    NSURL *docs=[[[NSFileManager defaultManager] URLsForDirectory:NSDocumentDirectory inDomains:NSUserDomainMask] firstObject];
    NSURL *unpacked=[[docs URLByAppendingPathComponent:@"AppleSignerWork" isDirectory:YES] URLByAppendingPathComponent:@"Unpacked" isDirectory:YES];
    BOOL isDir=NO;
    if(![[NSFileManager defaultManager] fileExistsAtPath:unpacked.path isDirectory:&isDir] || !isDir) { self.activityValue.text=@"请先选择 IPA 并解包"; return; }
    NSError *error=nil;
    NSDictionary *result=[MachOSignatureInspector inspectDirectoryAtURL:unpacked error:&error];
    if(!result) { self.activityValue.text=error.localizedDescription ?: @"Mach-O 解析失败"; return; }
    NSMutableArray *lines=[NSMutableArray arrayWithObject:[NSString stringWithFormat:@"Mach-O 扫描完成：%lu 个可执行文件",(unsigned long)[result[@"Count"] unsignedIntegerValue]]];
    for(NSDictionary *item in result[@"Items"]) {
        NSDictionary *report=item[@"Report"];
        if(!report) { [lines addObject:[NSString stringWithFormat:@"%@：%@",item[@"Bundle"],item[@"Error"]]]; continue; }
        [lines addObject:[NSString stringWithFormat:@"\n%@ / %@：%@",item[@"Bundle"],item[@"Executable"],[report[@"IsFat"] boolValue]?@"Universal/Fat":@"Thin"]];
        for(NSDictionary *slice in report[@"Slices"]) {
            NSDictionary *cd=slice[@"CodeDirectory"] ?: @{};
            NSDictionary *hv=cd[@"HashVerification"] ?: @{};
            [lines addObject:[NSString stringWithFormat:@"  %@，签名区%@，SuperBlob%@，CodeDirectory%@，标识 %@，CodeLimit %@，HashType %@",
                slice[@"Format"] ?: @"未知",
                [slice[@"HasSignature"] boolValue]?@"存在":@"不存在",
                [slice[@"SuperBlobValid"] boolValue]?@"有效":([slice[@"HasSignature"] boolValue]?@"无效/未识别":@"—"),
                cd.count?@"已解析":@"未发现",
                cd[@"Identifier"] ?: @"—",cd[@"CodeLimit"] ?: @"—",cd[@"HashType"] ?: @"—"]];
            if(hv.count) [lines addObject:[NSString stringWithFormat:@"  哈希校验：%@（匹配 %@ / 声明 %@，不匹配 %@）",hv[@"Status"] ?: @"未执行",hv[@"VerifiedSlots"] ?: @"—",hv[@"DeclaredCodeSlots"] ?: @"—",hv[@"MismatchedSlots"] ?: @"—"]];
        }
    }
    [lines addObject:@"\n说明：只读验证 CodeDirectory 的代码页哈希；不验证特殊槽、CMS 信任链、资源封印或整体签名有效性，也不修改二进制。"];
    self.activityValue.text=[lines componentsJoinedByString:@"\n"];
}
- (void)prepareSigning {
    if (!self.profileInfo) { self.activityValue.text=@"请先导入并解析描述文件"; return; }
    if (!self.ipaInfo) { self.activityValue.text=@"请先选择 IPA 并完成解析"; return; }
    NSURL *docs=[[[NSFileManager defaultManager] URLsForDirectory:NSDocumentDirectory inDomains:NSUserDomainMask] firstObject];
    NSURL *unpacked=[[docs URLByAppendingPathComponent:@"AppleSignerWork" isDirectory:YES] URLByAppendingPathComponent:@"Unpacked" isDirectory:YES];
    BOOL isDir=NO;
    if (![[NSFileManager defaultManager] fileExistsAtPath:unpacked.path isDirectory:&isDir] || !isDir) {
        self.activityValue.text=@"请先解包 IPA"; return;
    }
    NSMutableDictionary *profile=[self.profileInfo mutableCopy];
    profile[@"IPAComponents"]=self.ipaInfo[@"Components"] ?: @[];
    NSError *error=nil;
    NSDictionary *result=[SigningPreparation prepareAtDirectoryURL:unpacked profileInfo:profile error:&error];
    if (!result) { self.activityValue.text=error.localizedDescription ?: @"生成签名配置失败"; return; }
    NSMutableArray *lines=[NSMutableArray array];
    [lines addObject:[NSString stringWithFormat:@"签名配置模板已生成：%lu 个组件，成功生成 %lu 份 Entitlements",
        (unsigned long)[result[@"Count"] unsignedIntegerValue],
        (unsigned long)[result[@"GeneratedCount"] unsignedIntegerValue]]];
    [lines addObject:[NSString stringWithFormat:@"保存位置：%@",result[@"Directory"]]];
    for (NSDictionary *item in result[@"Components"]) {
        [lines addObject:[NSString stringWithFormat:@"%@ %@：%@",item[@"Type"],item[@"BundleIdentifier"],item[@"Status"]]];
    }
    [lines addObject:@"注意：这是准备文件，不是签名。必须逐项核对 Entitlements；扩展组件若不匹配当前描述文件，需要单独描述文件。"];
    self.activityValue.text=[lines componentsJoinedByString:@"\\n"];
}
- (void)importIPA { [self pickExtension:@"ipa" kind:@"ipa"]; }
- (void)importP12 { [self pickExtension:@"p12" kind:@"p12"]; }
- (void)importProfile { [self pickExtension:@"mobileprovision" kind:@"profile"]; }
- (void)importProfiles {
    self.pendingImportType = @"profiles";
    UTType *t = [UTType typeWithFilenameExtension:@"mobileprovision"];
    if (!t) t = [UTType typeWithIdentifier:@"public.data"];
    UIDocumentPickerViewController *picker = [[UIDocumentPickerViewController alloc] initForOpeningContentTypes:(t ? @[t] : @[]) asCopy:YES];
    picker.delegate = self;
    picker.allowsMultipleSelection = YES;
    [self presentViewController:picker animated:YES completion:nil];
}

- (void)documentPicker:(UIDocumentPickerViewController *)controller didPickDocumentsAtURLs:(NSArray<NSURL *> *)urls {
    if ([self.pendingImportType isEqualToString:@"profiles"]) {
        NSMutableArray *loaded = [NSMutableArray array];
        NSMutableArray *errors = [NSMutableArray array];
        for (NSURL *profileURL in urls) {
            BOOL access = [profileURL startAccessingSecurityScopedResource];
            NSString *name = profileURL.lastPathComponent ?: @"profile.mobileprovision";
            NSURL *destination = [[self importsDirectory] URLByAppendingPathComponent:[NSString stringWithFormat:@"%lu-%@", (unsigned long)loaded.count, name]];
            NSError *copyError = nil;
            if ([[NSFileManager defaultManager] fileExistsAtPath:destination.path]) [[NSFileManager defaultManager] removeItemAtURL:destination error:nil];
            BOOL copied = [[NSFileManager defaultManager] copyItemAtURL:profileURL toURL:destination error:&copyError];
            if (access) [profileURL stopAccessingSecurityScopedResource];
            if (!copied) { [errors addObject:[NSString stringWithFormat:@"%@：%@", name, copyError.localizedDescription ?: @"复制失败"]]; continue; }
            NSError *parseError = nil;
            NSDictionary *info = [ProfileInspector inspectProfileAtURL:destination error:&parseError];
            if (info) {
                NSMutableDictionary *entry = [info mutableCopy];
                entry[@"ImportedFile"] = name;
                [loaded addObject:entry];
            } else {
                [errors addObject:[NSString stringWithFormat:@"%@：%@", name, parseError.localizedDescription ?: @"解析失败"]];
            }
        }
        self.profileInfos = loaded;
        if (loaded.count) {
            self.profileInfo = loaded.firstObject;
            self.profileValue.text = [NSString stringWithFormat:@"已导入 %lu 份描述文件\n%@", (unsigned long)loaded.count,
                [[loaded valueForKey:@"Name"] componentsJoinedByString:@"、"]];
            self.activityValue.text = [NSString stringWithFormat:@"描述文件批量解析成功：%lu 份\n%@", (unsigned long)loaded.count,
                [errors componentsJoinedByString:@"\n"]];
        } else {
            self.activityValue.text = [NSString stringWithFormat:@"没有成功解析的描述文件\n%@", [errors componentsJoinedByString:@"\n"]];
        }
        return;
    }
    NSURL *source = urls.firstObject; if (!source) return;
    BOOL scoped = [source startAccessingSecurityScopedResource];
    NSString *filename = source.lastPathComponent ?: @"imported";
    NSURL *dest = [[self importsDirectory] URLByAppendingPathComponent:filename];
    NSError *copyError = nil;
    if ([[NSFileManager defaultManager] fileExistsAtPath:dest.path]) [[NSFileManager defaultManager] removeItemAtURL:dest error:nil];
    BOOL copied = [[NSFileManager defaultManager] copyItemAtURL:source toURL:dest error:&copyError];
    if (scoped) [source stopAccessingSecurityScopedResource];
    if (!copied) { self.activityValue.text = copyError.localizedDescription ?: @"复制失败"; return; }

    if ([self.pendingImportType isEqualToString:@"ipa"]) {
        self.selectedIPAURL = dest;
        NSError *ipaError = nil;
        self.ipaInfo = [IPAInspector inspectIPAAtURL:dest error:&ipaError];
        if (self.ipaInfo) {
            self.ipaValue.text = [NSString stringWithFormat:@"%@\n%@\nBundle ID：%@\n版本：%@ (%@)",
                                  filename, self.ipaInfo[@"DisplayName"], self.ipaInfo[@"BundleIdentifier"],
                                  self.ipaInfo[@"Version"], self.ipaInfo[@"Build"]];
            NSArray *components = self.ipaInfo[@"Components"] ?: @[];
            NSArray *nestedCode = self.ipaInfo[@"NestedCode"] ?: @[];
            NSArray *binaryInventory = self.ipaInfo[@"BinaryInventory"] ?: @[];
            NSUInteger machoCount = [[binaryInventory filteredArrayUsingPredicate:[NSPredicate predicateWithBlock:^BOOL(NSDictionary *item, NSDictionary *bindings) {
                return [item[@"Status"] isEqualToString:@"macho"];
            }]] count];
            NSMutableArray *lines = [NSMutableArray arrayWithObject:[NSString stringWithFormat:@"IPA 解析成功：%lu 个 Bundle、%lu 个 dylib 路径、%lu 个二进制路径（识别到 %lu 个 Mach-O）",
                (unsigned long)components.count, (unsigned long)nestedCode.count,
                (unsigned long)binaryInventory.count, (unsigned long)machoCount]];
            for (NSDictionary *component in components) {
                [lines addObject:[NSString stringWithFormat:@"%@：%@", component[@"Type"], component[@"BundleIdentifier"]]];
            }
            for (NSDictionary *binary in binaryInventory) {
                NSArray *archs = binary[@"Architectures"] ?: @[];
                NSMutableArray *names = [NSMutableArray array];
                for (NSDictionary *arch in archs) if ([arch[@"Name"] isKindOfClass:NSString.class]) [names addObject:arch[@"Name"]];
                [lines addObject:[NSString stringWithFormat:@"二进制 %@：%@%@", binary[@"Path"] ?: @"未知路径", binary[@"Status"] ?: @"unknown",
                    names.count ? [NSString stringWithFormat:@"（%@）", [names componentsJoinedByString:@", "]] : @""]];
                for (NSDictionary *arch in archs) {
                    NSString *sliceStatus = arch[@"SliceHeaderStatus"];
                    if ([sliceStatus isKindOfClass:NSString.class]) [lines addObject:[NSString stringWithFormat:@"  %@ slice header：%@", arch[@"Name"] ?: @"架构未知", sliceStatus]];
                }
            }
            self.activityValue.text = [lines componentsJoinedByString:@"\n"];
        } else {
            self.ipaValue.text = filename;
            self.activityValue.text = ipaError.localizedDescription ?: @"IPA 解析失败";
        }
    } else if ([self.pendingImportType isEqualToString:@"p12"]) {
        self.selectedP12URL = dest; self.certificateValue.text = filename; [self promptP12Password];
    } else {
        self.selectedProfileURL = dest;
        NSError *e = nil; self.profileInfo = [ProfileInspector inspectProfileAtURL:dest error:&e];
        self.profileInfos = self.profileInfo ? @[self.profileInfo] : @[];
        if (self.profileInfo) {
            NSDate *expiry = self.profileInfo[@"ExpirationDate"];
            NSString *expiryText = [expiry isKindOfClass:NSDate.class] ? [NSDateFormatter localizedStringFromDate:expiry dateStyle:NSDateFormatterMediumStyle timeStyle:NSDateFormatterNoStyle] : @"未知";
            self.profileValue.text = [NSString stringWithFormat:@"%@\nTeam: %@\nApp ID: %@\n到期：%@%@", self.profileInfo[@"Name"], self.profileInfo[@"TeamIdentifier"], self.profileInfo[@"ApplicationIdentifier"], expiryText, [self.profileInfo[@"IsExpired"] boolValue] ? @"（已过期）" : @""];
            NSArray *devCerts = self.profileInfo[@"DeveloperCertificates"];
            self.activityValue.text = [NSString stringWithFormat:@"描述文件 CMS 解码成功 · 内含 %lu 个开发者证书", (unsigned long)devCerts.count];
        } else {
            self.profileValue.text = @"描述文件无法解析";
            self.activityValue.text = e.localizedDescription ?: @"解析失败";
        }
    }
}
- (void)documentPickerWasCancelled:(UIDocumentPickerViewController *)controller { self.activityValue.text = @"已取消"; }

- (void)promptP12Password {
    UIAlertController *a = [UIAlertController alertControllerWithTitle:@"P12 密码" message:@"密码仅在本地用于解析，不会上传。" preferredStyle:UIAlertControllerStyleAlert];
    [a addTextFieldWithConfigurationHandler:^(UITextField *f) { f.placeholder = @"输入 P12 密码"; f.secureTextEntry = YES; }];
    [a addAction:[UIAlertAction actionWithTitle:@"取消" style:UIAlertActionStyleCancel handler:nil]];
    [a addAction:[UIAlertAction actionWithTitle:@"验证" style:UIAlertActionStyleDefault handler:^(UIAlertAction *action) {
        [self validateP12:self.selectedP12URL password:a.textFields.firstObject.text ?: @""];
    }]];
    [self presentViewController:a animated:YES completion:nil];
}
- (void)validateP12:(NSURL *)url password:(NSString *)password {
    NSData *data = [NSData dataWithContentsOfURL:url]; if (!data) { self.activityValue.text = @"无法读取 P12"; return; }
    NSDictionary *opts = @{(__bridge id)kSecImportExportPassphrase:password};
    CFArrayRef items = NULL;
    OSStatus status = SecPKCS12Import((__bridge CFDataRef)data, (__bridge CFDictionaryRef)opts, &items);
    if (status != errSecSuccess || !items || CFArrayGetCount(items) == 0) {
        self.activityValue.text = [NSString stringWithFormat:@"P12 验证失败：%d", (int)status];
        if (items) CFRelease(items); return;
    }
    NSDictionary *item = CFBridgingRelease(CFRetain(CFArrayGetValueAtIndex(items, 0)));
    SecIdentityRef identity = (__bridge SecIdentityRef)item[(__bridge id)kSecImportItemIdentity];
    SecCertificateRef cert = NULL; SecIdentityCopyCertificate(identity, &cert);
    NSString *summary = cert ? CFBridgingRelease(SecCertificateCopySubjectSummary(cert)) : @"未知证书";
    if (cert) {
        CFDataRef der = SecCertificateCopyData(cert);
        self.certificateDER = der ? CFBridgingRelease(der) : nil;
    } else {
        self.certificateDER = nil;
    }
    self.certificateSubject = summary ?: @"未知证书";
    NSDate *expiry = nil;
    if (cert) CFRelease(cert);
    NSString *expiryText = expiry ? [NSDateFormatter localizedStringFromDate:expiry dateStyle:NSDateFormatterMediumStyle timeStyle:NSDateFormatterNoStyle] : @"未知";
    self.certificateValue.text = [NSString stringWithFormat:@"%@\n%@ · 到期 %@", url.lastPathComponent, summary ?: @"证书身份已读取", expiryText];
    self.activityValue.text = @"P12 身份读取成功；可与描述文件核对证书。私钥未持久化。";
    CFRelease(items);
}

- (void)verifyPrivateKeyCapability {
    if (!self.selectedP12URL) {
        self.activityValue.text = @"请先导入 P12 文件";
        return;
    }
    UIAlertController *a = [UIAlertController alertControllerWithTitle:@"验证 P12 私钥"
        message:@"密码只用于本次本地导入。应用会对随机用途明确的测试消息执行签名，再用对应公钥验证；不会保存密码或测试签名。"
        preferredStyle:UIAlertControllerStyleAlert];
    [a addTextFieldWithConfigurationHandler:^(UITextField *f) {
        f.placeholder = @"输入 P12 密码";
        f.secureTextEntry = YES;
    }];
    [a addAction:[UIAlertAction actionWithTitle:@"取消" style:UIAlertActionStyleCancel handler:nil]];
    [a addAction:[UIAlertAction actionWithTitle:@"开始验证" style:UIAlertActionStyleDefault handler:^(UIAlertAction *action) {
        NSString *password = a.textFields.firstObject.text ?: @"";
        NSError *error = nil;
        NSDictionary *result = [SigningIdentityVerifier verifyP12AtURL:self.selectedP12URL
                                                               password:password
                                                                  error:&error];
        password = nil;
        if (result[@"verified"]) {
            self.activityValue.text = [NSString stringWithFormat:@"私钥能力验证通过：%@。这只证明本地私钥可执行并通过自验证，不代表 Apple Code Signing CMS 或 IPA 签名有效。",
                                       result[@"algorithm"] ?: @"未知算法"];
        } else {
            self.activityValue.text = [NSString stringWithFormat:@"私钥能力验证失败：%@", error.localizedDescription ?: @"未知错误"];
        }
    }]];
    [self presentViewController:a animated:YES completion:nil];
}


- (void)prepareCMSPreflight {
    if (!self.selectedP12URL) {
        self.activityValue.text = @"请先导入 P12 文件";
        return;
    }
    UIAlertController *a = [UIAlertController alertControllerWithTitle:@"CMS 前置检查"
        message:@"输入 P12 密码。此操作只检查证书链、私钥算法和待签内容摘要，不生成 CMS，也不修改 IPA。"
        preferredStyle:UIAlertControllerStyleAlert];
    [a addTextFieldWithConfigurationHandler:^(UITextField *f) {
        f.placeholder = @"P12 密码";
        f.secureTextEntry = YES;
    }];
    [a addAction:[UIAlertAction actionWithTitle:@"取消" style:UIAlertActionStyleCancel handler:nil]];
    [a addAction:[UIAlertAction actionWithTitle:@"检查" style:UIAlertActionStyleDefault handler:^(UIAlertAction *action) {
        NSString *password = a.textFields.firstObject.text ?: @"";
        NSURL *docs = [[[NSFileManager defaultManager] URLsForDirectory:NSDocumentDirectory inDomains:NSUserDomainMask] firstObject];
        NSURL *templates = [[docs URLByAppendingPathComponent:@"AppleSignerWork" isDirectory:YES]
                            URLByAppendingPathComponent:@"SuperBlobTemplates" isDirectory:YES];
        NSArray *files = [[NSFileManager defaultManager] contentsOfDirectoryAtURL:templates
                                                        includingPropertiesForKeys:nil options:0 error:nil];
        NSURL *candidate = nil;
        for (NSURL *u in files) {
            if ([u.lastPathComponent hasSuffix:@".superblob.template"]) { candidate = u; break; }
        }
        NSData *content = candidate ? [NSData dataWithContentsOfURL:candidate] : [@"CMS preflight probe" dataUsingEncoding:NSUTF8StringEncoding];
        NSError *error = nil;
        NSDictionary *report = [CMSPreflight inspectP12AtURL:self.selectedP12URL
                                                    password:password
                                             contentToDigest:content
                                                       error:&error];
        password = nil;
        if (report) {
            self.activityValue.text = [NSString stringWithFormat:
                @"CMS 前置检查完成（1.7）\\n证书链条目：%@\\n签名算法候选：%@\\n待签内容 SHA-256：%@\\n\\n注意：尚未生成 CMS SignedData；本检查不代表 Apple Code Signing 有效。",
                report[@"CertificateCount"], report[@"Algorithm"], report[@"ContentSHA256"]];
        } else {
            self.activityValue.text = [NSString stringWithFormat:@"CMS 前置检查失败：%@", error.localizedDescription ?: @"未知错误"];
        }
    }]];
    [self presentViewController:a animated:YES completion:nil];
}


- (void)createDetachedCMSTest {
    if (!self.selectedP12URL) { self.activityValue.text = @"请先导入 P12 文件"; return; }
    UIAlertController *a = [UIAlertController alertControllerWithTitle:@"生成独立 CMS 测试文件"
        message:@"此功能仅签署一段测试文本，生成 detached CMS .p7s 并进行本地签名自验证。它不是 Mach-O CodeDirectory 签名，不能用于安装 IPA。"
        preferredStyle:UIAlertControllerStyleAlert];
    [a addTextFieldWithConfigurationHandler:^(UITextField *f) { f.placeholder=@"P12 密码"; f.secureTextEntry=YES; }];
    [a addAction:[UIAlertAction actionWithTitle:@"取消" style:UIAlertActionStyleCancel handler:nil]];
    [a addAction:[UIAlertAction actionWithTitle:@"生成" style:UIAlertActionStyleDefault handler:^(UIAlertAction *action) {
        NSString *password=a.textFields.firstObject.text ?: @"";
        NSURL *docs=[[[NSFileManager defaultManager] URLsForDirectory:NSDocumentDirectory inDomains:NSUserDomainMask] firstObject];
        NSURL *dir=[[docs URLByAppendingPathComponent:@"AppleSignerWork" isDirectory:YES] URLByAppendingPathComponent:@"CMS-Tests" isDirectory:YES];
        [[NSFileManager defaultManager] createDirectoryAtURL:dir withIntermediateDirectories:YES attributes:nil error:nil];
        NSData *payload=[@"AppleSigner detached CMS test payload v1.8" dataUsingEncoding:NSUTF8StringEncoding];
        NSURL *content=[dir URLByAppendingPathComponent:@"test-content.bin"];
        NSURL *output=[dir URLByAppendingPathComponent:@"detached-test.p7s"];
        [payload writeToURL:content atomically:YES];
        NSError *error=nil;
        NSURL *result=[CMSDetachedBuilder createDetachedTestCMSForP12:self.selectedP12URL password:password
            contentURL:content outputURL:output error:&error];
        password=nil;
        self.activityValue.text=result ? [NSString stringWithFormat:@"独立 CMS 测试文件已生成：%@\\n已完成签名与公钥自验证。此文件仅针对测试文本，不是 Apple Code Signing CMS。",result.path]
                                        : [NSString stringWithFormat:@"CMS 测试生成失败：%@",error.localizedDescription ?: @"未知错误"];
    }]];
    [self presentViewController:a animated:YES completion:nil];
}


- (void)verifyDetachedCMSTest {
    NSURL *docs=[[[NSFileManager defaultManager] URLsForDirectory:NSDocumentDirectory inDomains:NSUserDomainMask] firstObject];
    NSURL *dir=[[docs URLByAppendingPathComponent:@"AppleSignerWork" isDirectory:YES] URLByAppendingPathComponent:@"CMS-Tests" isDirectory:YES];
    NSURL *content=[dir URLByAppendingPathComponent:@"test-content.bin"];
    NSURL *cms=[dir URLByAppendingPathComponent:@"detached-test.p7s"];
    NSError *error=nil;
    NSDictionary *result=[CMSDetachedVerifier verifyCMSAtURL:cms contentURL:content error:&error];
    if(result) {
        self.activityValue.text=@"CMS 独立结构/摘要/签名验证通过（1.9）。这不代表证书链可信，也不代表它符合 Apple Code Signing 规范。";
    } else {
        self.activityValue.text=[NSString stringWithFormat:@"CMS 验证失败：%@",error.localizedDescription ?: @"请先生成 1.8 测试文件"];
    }
}


- (void)auditCMSOutput {
    NSURL *docs=[[[NSFileManager defaultManager] URLsForDirectory:NSDocumentDirectory inDomains:NSUserDomainMask] firstObject];
    NSURL *dir=[[docs URLByAppendingPathComponent:@"AppleSignerWork" isDirectory:YES]
                URLByAppendingPathComponent:@"CMS-Tests" isDirectory:YES];
    NSURL *cms=[dir URLByAppendingPathComponent:@"detached-test.p7s"];
    NSURL *content=[dir URLByAppendingPathComponent:@"test-content.bin"];
    NSError *error=nil;
    NSDictionary *result=[CMSDetachedVerifier verifyCMSAtURL:cms contentURL:content error:&error];
    self.activityValue.text=result ?
      @"1.10 DER/CMS 约束检查通过。仍需外部 OpenSSL 互操作验证。" :
      [NSString stringWithFormat:@"1.10 检查未通过：%@",error.localizedDescription ?: @"请先生成 CMS 测试文件"];
}

- (void)exportCMSInteropFiles {
    NSURL *docs=[[[NSFileManager defaultManager] URLsForDirectory:NSDocumentDirectory inDomains:NSUserDomainMask] firstObject];
    NSURL *dir=[[docs URLByAppendingPathComponent:@"AppleSignerWork" isDirectory:YES]
                URLByAppendingPathComponent:@"CMS-Tests" isDirectory:YES];
    NSURL *cms=[dir URLByAppendingPathComponent:@"detached-test.p7s"];
    NSURL *content=[dir URLByAppendingPathComponent:@"test-content.bin"];
    if(![[NSFileManager defaultManager] fileExistsAtPath:cms.path] ||
       ![[NSFileManager defaultManager] fileExistsAtPath:content.path]) {
        self.activityValue.text=@"请先生成独立 CMS 测试文件（1.8）";
        return;
    }
    UIActivityViewController *share=[[UIActivityViewController alloc] initWithActivityItems:@[cms,content] applicationActivities:nil];
    if(share.popoverPresentationController) share.popoverPresentationController.sourceView=self.view;
    [self presentViewController:share animated:YES completion:nil];
}

- (void)autoEnroll {
    UIAlertController *a = [UIAlertController alertControllerWithTitle:@"Apple ID 自动申请" message:@"Apple ID 本身不是签名证书。自动申请必须通过安全的开发者账户授权及苹果开发者门户流程；本版本不收集密码或双重认证码。当前先支持手动导入 P12 和描述文件。" preferredStyle:UIAlertControllerStyleAlert];
    [a addAction:[UIAlertAction actionWithTitle:@"知道了" style:UIAlertActionStyleDefault handler:nil]];
    [self presentViewController:a animated:YES completion:nil];
}

- (BOOL)profileAppID:(NSString *)pattern allowsBundleID:(NSString *)bundleID {
    if (![pattern isKindOfClass:NSString.class] || ![bundleID isKindOfClass:NSString.class]) return NO;
    NSArray *p = [pattern componentsSeparatedByString:@"."];
    NSArray *b = [bundleID componentsSeparatedByString:@"."];
    if (p.count > b.count) return NO;
    for (NSUInteger i = 0; i < p.count; i++) {
        if ([p[i] isEqualToString:@"*"] && i == p.count - 1) return YES;
        if (![p[i] isEqualToString:b[i]]) return NO;
    }
    return p.count == b.count;
}




- (BOOL)profile:(NSDictionary *)profile matchesBundleIdentifier:(NSString *)bundleID {
    NSString *pattern = profile[@"ApplicationIdentifier"];
    if (![pattern isKindOfClass:NSString.class] || !pattern.length || ![bundleID isKindOfClass:NSString.class]) return NO;
    if ([pattern isEqualToString:bundleID]) return YES;
    if ([pattern hasSuffix:@"*"]) return [bundleID hasPrefix:[pattern substringToIndex:pattern.length-1]];
    return NO;
}


- (void)exportSigningPlan {
    if (!self.ipaInfo) { self.activityValue.text=@"请先选择并解析 IPA"; return; }
    NSArray *profiles=self.profileInfos.count?self.profileInfos:(self.profileInfo?@[self.profileInfo]:@[]);
    if (!profiles.count) { self.activityValue.text=@"请先导入一份或多份描述文件"; return; }
    NSURL *docs=[[[NSFileManager defaultManager] URLsForDirectory:NSDocumentDirectory inDomains:NSUserDomainMask] firstObject];
    NSURL *dir=[[docs URLByAppendingPathComponent:@"AppleSignerWork" isDirectory:YES] URLByAppendingPathComponent:@"SigningPlans" isDirectory:YES];
    [[NSFileManager defaultManager] createDirectoryAtURL:dir withIntermediateDirectories:YES attributes:nil error:nil];
    NSString *file=[NSString stringWithFormat:@"%@-signing-plan.json",self.ipaInfo[@"BundleIdentifier"]?:@"ipa"];
    file=[file stringByReplacingOccurrencesOfString:@"/" withString:@"_"];
    NSURL *url=[dir URLByAppendingPathComponent:file];
    NSError *error=nil;
    NSDictionary *plan=[SigningPlanExporter createPlanForIPAInfo:self.ipaInfo profiles:profiles certificateDER:self.certificateDER outputURL:url error:&error];
    if (!plan) { self.activityValue.text=error.localizedDescription?:@"签名计划生成失败"; return; }
    NSDictionary *summary=plan[@"summary"];
    self.activityValue.text=[NSString stringWithFormat:@"签名映射计划已生成\\n组件：%@\\n候选可继续：%@\\n缺少描述文件：%@\\n过期：%@\\n证书不匹配：%@\\n证书未知：%@\\n多候选需人工确认：%@\\n\\n文件：%@\\n\\n注意：该 JSON 是预检计划，不会修改 IPA，也不会执行签名。",
        summary[@"componentCount"],summary[@"candidateReadyCount"],summary[@"missingProfileCount"],summary[@"expiredProfileCount"],
        summary[@"certificateMismatchCount"],summary[@"certificateUnknownCount"],summary[@"ambiguousCount"],url.path];
    UIActivityViewController *share=[[UIActivityViewController alloc] initWithActivityItems:@[url] applicationActivities:nil];
    if (share.popoverPresentationController) share.popoverPresentationController.sourceView=self.view;
    [self presentViewController:share animated:YES completion:nil];
}

- (void)matchProfilesToIPAComponents {
    if (!self.ipaInfo) { self.activityValue.text = @"请先选择 IPA"; return; }
    if (!self.profileInfos.count && self.profileInfo) self.profileInfos = @[self.profileInfo];
    if (!self.profileInfos.count) { self.activityValue.text = @"请先批量导入描述文件"; return; }

    NSArray *components = self.ipaInfo[@"Components"] ?: @[];
    NSMutableArray *lines = [NSMutableArray array];
    NSUInteger matched = 0, missing = 0, expired = 0, certMatched = 0, certMismatch = 0, certUnknown = 0;
    for (NSDictionary *component in components) {
        NSString *bundleID = component[@"BundleIdentifier"] ?: @"";
        NSString *type = component[@"Type"] ?: @"组件";
        if ([type isEqualToString:@"Framework"]) {
            [lines addObject:[NSString stringWithFormat:@"%@ (%@)：Framework 通常不单独使用 provisioning profile；随宿主 App 签名，需单独核验其签名与授权。", bundleID, type]];
            continue;
        }
        NSMutableArray *candidates = [NSMutableArray array];
        for (NSDictionary *profile in self.profileInfos) if ([self profile:profile matchesBundleIdentifier:bundleID]) [candidates addObject:profile];
        if (!candidates.count) {
            missing++;
            [lines addObject:[NSString stringWithFormat:@"%@ (%@)：未找到 Bundle ID 匹配的描述文件。", bundleID, type]];
            continue;
        }
        // Prefer exact App ID match, then the narrowest wildcard pattern.
        [candidates sortUsingComparator:^NSComparisonResult(NSDictionary *a, NSDictionary *b) {
            NSString *pa=a[@"ApplicationIdentifier"] ?: @"", *pb=b[@"ApplicationIdentifier"] ?: @"";
            BOOL ea=[pa isEqualToString:bundleID], eb=[pb isEqualToString:bundleID];
            if (ea!=eb) return ea?NSOrderedAscending:NSOrderedDescending;
            return [pb length]>[pa length]?NSOrderedAscending:([pb length]<[pa length]?NSOrderedDescending:NSOrderedSame);
        }];
        NSDictionary *chosen = candidates.firstObject;
        BOOL isExpired = [chosen[@"IsExpired"] boolValue];
        if (isExpired) expired++; else matched++;
        NSArray *devCerts = chosen[@"DeveloperCertificates"] ?: @[];
        BOOL certOK = NO;
        if (self.certificateDER.length) {
            for (NSData *der in devCerts) if ([der isEqualToData:self.certificateDER]) { certOK=YES; break; }
            if (certOK) certMatched++; else certMismatch++;
        } else {
            certUnknown++;
        }
        [lines addObject:[NSString stringWithFormat:@"%@ (%@)\n  描述文件：%@\n  App ID：%@\n  Team ID：%@\n  有效期：%@\n  候选数量：%lu\n  当前 P12 证书：%@",
            bundleID, type, chosen[@"Name"] ?: @"未命名", chosen[@"ApplicationIdentifier"] ?: @"未声明",
            chosen[@"TeamIdentifier"] ?: @"未知", isExpired?@"已过期":@"未过期",
            (unsigned long)candidates.count, self.certificateDER.length?(certOK?@"匹配":@"不匹配"):@"尚未导入 P12，无法判断"]];
        if (candidates.count>1) [lines addObject:@"  注意：存在多个匹配描述文件，当前按精确 App ID 和通配范围优先级选择；请人工确认签名类型和设备范围。"];
    }
    [lines insertObject:[NSString stringWithFormat:@"组件：%lu；有效匹配：%lu；缺少匹配：%lu；已过期：%lu\nP12 证书匹配：%lu；不匹配：%lu；无法判断：%lu",
        (unsigned long)components.count,(unsigned long)matched,(unsigned long)missing,(unsigned long)expired,
        (unsigned long)certMatched,(unsigned long)certMismatch,(unsigned long)certUnknown] atIndex:0];
    [lines addObject:@"限制：此步骤按 Bundle ID / ApplicationIdentifier 选择描述文件，并比较 P12 导入证书 DER 与 profile DeveloperCertificates。它不验证 CMS 信任链、证书有效期/撤销、设备 UDID 是否包含、Entitlements 全量语义或最终签名；Framework 不单独匹配 profile。多个候选时仅作优先级选择，不保证选中正确发布配置。"];
    self.activityValue.text=[lines componentsJoinedByString:@"\n\n"];
}

- (void)compareIPAEntitlementsWithProfile {
    if (!self.profileInfo) { self.activityValue.text=@"请先导入并解析 provisioning profile"; return; }
    NSURL *docs=[[[NSFileManager defaultManager] URLsForDirectory:NSDocumentDirectory inDomains:NSUserDomainMask] firstObject];
    NSURL *work=[docs URLByAppendingPathComponent:@"AppleSignerWork" isDirectory:YES];
    NSURL *unpacked=[work URLByAppendingPathComponent:@"Unpacked" isDirectory:YES];
    NSURL *output=[work URLByAppendingPathComponent:@"ExtractedEntitlements" isDirectory:YES];
    NSError *error=nil;
    NSDictionary *extraction=[EntitlementsAudit auditDirectoryAtURL:unpacked outputDirectory:output error:&error];
    if (!extraction) { self.activityValue.text=error.localizedDescription?:@"请先选择并解包 IPA"; return; }
    NSDictionary *grants=self.profileInfo[@"Entitlements"] ?: @{};
    NSMutableArray *lines=[NSMutableArray array];
    [lines addObject:[NSString stringWithFormat:@"总体结论：%@", extraction[@"ParsedCount"] && [extraction[@"ParsedCount"] unsignedIntegerValue]>0 ? @"已完成已提取项目的授权比较" : @"没有可比较的 XML Entitlements"]];
    for (NSDictionary *item in extraction[@"Items"] ?: @[]) {
        NSDictionary *actual=item[@"Entitlements"];
        if (![actual isKindOfClass:NSDictionary.class]) {
            [lines addObject:[NSString stringWithFormat:@"%@：无法判定（%@）",item[@"Bundle"]?:@"未知组件",item[@"Status"]?:@"未提取"]];
            continue;
        }
        NSDictionary *comparison=[EntitlementsProfileComparator compareEntitlements:actual againstProfile:grants];
        [lines addObject:[NSString stringWithFormat:@"%@\n结论：%@\n允许：%@ 项；不允许：%@ 项；无法判定：%@ 项",
            item[@"Bundle"]?:@"未知组件",comparison[@"Overall"],comparison[@"AllowedCount"],comparison[@"DeniedCount"],comparison[@"UnknownCount"]]];
        for (NSDictionary *entry in comparison[@"Denied"] ?: @[]) {
            [lines addObject:[NSString stringWithFormat:@"  [不允许] %@：%@",entry[@"Key"],entry[@"Reason"]]];
        }
        for (NSDictionary *entry in comparison[@"Unknown"] ?: @[]) {
            [lines addObject:[NSString stringWithFormat:@"  [无法判定] %@：%@",entry[@"Key"],entry[@"Reason"]]];
        }
    }
    [lines addObject:@"\n比较规则：字符串支持精确匹配和末尾 * 通配；数组逐项检查；字典递归检查；布尔值按授权上限比较。对 IPA 中成功提取的 XML/DER Entitlements 分别做比较。"];
    [lines addObject:@"重要限制：仍不覆盖未知 DER 类型、Apple 私有授权语义、全部 entitlement 特例、扩展各自应使用的独立 profile、证书链信任、CMS 和资源封印。显示“允许”不代表 IPA 一定能安装或签名有效。"];
    self.activityValue.text=[lines componentsJoinedByString:@"\n\n"];
}

- (void)extractExistingEntitlements {
    NSURL *docs=[[[NSFileManager defaultManager] URLsForDirectory:NSDocumentDirectory inDomains:NSUserDomainMask] firstObject];
    NSURL *work=[docs URLByAppendingPathComponent:@"AppleSignerWork" isDirectory:YES];
    NSURL *unpacked=[work URLByAppendingPathComponent:@"Unpacked" isDirectory:YES];
    NSURL *output=[work URLByAppendingPathComponent:@"ExtractedEntitlements" isDirectory:YES];
    NSError *error=nil;
    NSDictionary *result=[EntitlementsAudit auditDirectoryAtURL:unpacked outputDirectory:output error:&error];
    if (!result) { self.activityValue.text=error.localizedDescription?:@"Entitlements 提取失败"; return; }
    NSMutableArray *lines=[NSMutableArray array];
    [lines addObject:[NSString stringWithFormat:@"检查可执行文件：%@\n成功提取：%@\n未发现 XML/DER Blob：%@\n失败：%@",
        result[@"ExecutableCount"],result[@"ParsedCount"],result[@"AbsentCount"],result[@"FailedCount"]]];
    [lines addObject:result[@"Report"]?:@""];
    [lines addObject:[NSString stringWithFormat:@"导出目录：%@",result[@"OutputDirectory"]]];
    [lines addObject:@"\n说明：同时提取 XML（0xfade7171）和受限 DER（0xfade7172）Entitlements；不验证 CMS、CodeDirectory、资源封印或授权有效性。提取成功不代表签名有效。"];
    self.activityValue.text=[lines componentsJoinedByString:@"\n\n"];
}

- (void)auditProfileAuthorization {
    if (!self.profileInfo) { self.activityValue.text = @"请先导入并解析 provisioning profile"; return; }
    NSMutableArray *lines = [NSMutableArray array];
    NSArray *devCerts = self.profileInfo[@"DeveloperCertificates"] ?: @[];
    BOOL certMatched = NO;
    if (self.certificateDER) {
        for (id cert in devCerts) if ([cert isKindOfClass:NSData.class] && [cert isEqualToData:self.certificateDER]) { certMatched = YES; break; }
        [lines addObject:certMatched ? @"证书：P12 Leaf 证书 DER 与 DeveloperCertificates 精确匹配" : @"证书：未匹配（请确认 P12 与描述文件来自同一开发团队/证书）"];
    } else {
        [lines addObject:@"证书：尚未导入并验证 P12，跳过证书匹配"];
    }
    NSString *team = self.profileInfo[@"TeamIdentifier"];
    NSString *appPattern = self.profileInfo[@"ApplicationIdentifier"];
    [lines addObject:[NSString stringWithFormat:@"Team ID：%@", team ?: @"未知"]];
    [lines addObject:[NSString stringWithFormat:@"Application ID 授权模式：%@", appPattern ?: @"未声明"]];
    [lines addObject:[NSString stringWithFormat:@"描述文件开发者证书数量：%@", @(devCerts.count)]];
    [lines addObject:[NSString stringWithFormat:@"设备注册数量：%@；全设备授权：%@", @([self.profileInfo[@"ProvisionedDevices"] count]), [self.profileInfo[@"ProvisionsAllDevices"] boolValue] ? @"是" : @"否"]];
    [lines addObject:[NSString stringWithFormat:@"调试授权 get-task-allow：%@", [self.profileInfo[@"HasGetTaskAllow"] boolValue] ? @"YES" : @"NO"]];
    [lines addObject:[NSString stringWithFormat:@"推送环境 aps-environment：%@", self.profileInfo[@"APSEnvironment"] ?: @"未声明"]];
    [lines addObject:[NSString stringWithFormat:@"Keychain groups：%@ 项；App Groups：%@ 项", @([self.profileInfo[@"KeychainAccessGroups"] count]), @([self.profileInfo[@"AppGroups"] count])]];
    if ([self.profileInfo[@"IsExpired"] boolValue]) [lines addObject:@"严重问题：描述文件已过期"];
    else [lines addObject:@"有效期：当前未过期（仍需核对证书自身有效期与撤销状态）"];
    if (self.ipaInfo) {
        NSString *bundle = self.ipaInfo[@"BundleIdentifier"] ?: @"";
        NSString *prefix = [NSString stringWithFormat:@"%@.", team ?: @""];
        NSString *pattern = [appPattern hasPrefix:prefix] ? [appPattern substringFromIndex:prefix.length] : appPattern;
        [lines addObject:[NSString stringWithFormat:@"主 App %@：%@", bundle, [self profileAppID:pattern allowsBundleID:bundle] ? @"匹配" : @"不匹配"]];
        for (NSDictionary *component in self.ipaInfo[@"Components"] ?: @[]) {
            NSString *componentID = component[@"BundleIdentifier"] ?: @"";
            if ([componentID isEqualToString:bundle]) continue;
            [lines addObject:[NSString stringWithFormat:@"%@ %@：%@（扩展可能需要独立描述文件）", component[@"Type"] ?: @"组件", componentID, [self profileAppID:pattern allowsBundleID:componentID] ? @"App ID 匹配" : @"不匹配"]];
        }
    } else {
        [lines addObject:@"IPA：未选择，跳过 Bundle ID 授权核对"];
    }
    [lines addObject:@"\n限制：这是描述文件授权信息预检；不解析 IPA 内现有签名的实际 Entitlements，不验证 Apple 证书链信任/撤销，也不执行签名。不能据此认定 IPA 可安装。"];
    self.activityValue.text = [lines componentsJoinedByString:@"\n"];
}

- (void)checkMaterials {
    NSMutableArray *issues = [NSMutableArray array];
    if (!self.selectedIPAURL) [issues addObject:@"未选择 IPA"];
    if (!self.selectedP12URL || !self.certificateDER) [issues addObject:@"尚未成功验证 P12 证书身份"];
    if (!self.profileInfo) [issues addObject:@"描述文件未成功解析"];

    if (self.profileInfo) {
        if ([self.profileInfo[@"IsExpired"] boolValue]) [issues addObject:@"描述文件已过期"];
        NSArray *developerCertificates = self.profileInfo[@"DeveloperCertificates"];
        BOOL matched = NO;
        for (id item in developerCertificates) {
            if ([item isKindOfClass:NSData.class] && [item isEqualToData:self.certificateDER]) {
                matched = YES;
                break;
            }
        }
        if (self.certificateDER && matched) {
            [issues addObject:@"P12 证书与描述文件匹配成功"];
        } else if (self.certificateDER) {
            [issues addObject:@"P12 证书不在此描述文件的 DeveloperCertificates 中"];
        }
        NSString *teamID = self.profileInfo[@"TeamIdentifier"];
        NSString *appID = self.profileInfo[@"ApplicationIdentifier"];
        if (teamID.length && ![teamID isEqualToString:@"未知"])
            [issues addObject:[NSString stringWithFormat:@"描述文件 Team ID：%@", teamID]];
        if (appID.length && ![appID isEqualToString:@"未声明"])
            [issues addObject:[NSString stringWithFormat:@"允许的 App ID：%@", appID]];
        if (self.ipaInfo && appID.length) {
            NSString *bundleID = self.ipaInfo[@"BundleIdentifier"];
            NSArray *parts = [appID componentsSeparatedByString:@"."];
            if (parts.count > 1) appID = [[parts subarrayWithRange:NSMakeRange(1, parts.count - 1)] componentsJoinedByString:@"."];
            NSArray *patternParts = [appID componentsSeparatedByString:@"."];
            NSArray *bundleParts = [bundleID componentsSeparatedByString:@"."];
            BOOL allowed = patternParts.count <= bundleParts.count;
            if (allowed) {
                for (NSUInteger i = 0; i < patternParts.count; i++) {
                    BOOL isFinalWildcard = [patternParts[i] isEqualToString:@"*"] && i == patternParts.count - 1;
                    if (isFinalWildcard) break;
                    if (![patternParts[i] isEqualToString:bundleParts[i]]) {
                        allowed = NO; break;
                    }
                }
            }
            if (allowed && ![patternParts.lastObject isEqualToString:@"*"])
                allowed = patternParts.count == bundleParts.count;
            [issues addObject:allowed ? @"主应用 Bundle ID 与描述文件 App ID 匹配" : @"主应用 Bundle ID 与描述文件 App ID 不匹配"];
            NSArray *components = self.ipaInfo[@"Components"] ?: @[];
            for (NSDictionary *component in components) {
                if ([component[@"Type"] isEqualToString:@"App"]) continue;
                NSString *componentID = component[@"BundleIdentifier"];
                NSArray *cp = [componentID componentsSeparatedByString:@"."];
                BOOL componentAllowed = patternParts.count <= cp.count;
                if (componentAllowed) {
                    for (NSUInteger j=0; j<patternParts.count; j++) {
                        BOOL wildcard = [patternParts[j] isEqualToString:@"*"] && j==patternParts.count-1;
                        if (wildcard) break;
                        if (![patternParts[j] isEqualToString:cp[j]]) { componentAllowed=NO; break; }
                    }
                }
                if (componentAllowed && ![patternParts.lastObject isEqualToString:@"*"])
                    componentAllowed = patternParts.count == cp.count;
                [issues addObject:[NSString stringWithFormat:@"%@ %@：%@", component[@"Type"], componentID,
                                   componentAllowed ? @"App ID 格式匹配" : @"App ID 不匹配"]];
            }
        } else if (self.ipaInfo) {
            [issues addObject:@"描述文件未声明 application-identifier，无法核对 Bundle ID"];
        }
    }

    if (issues.count) {
        self.activityValue.text = [issues componentsJoinedByString:@"\n"];
    } else {
        self.activityValue.text = @"未发现材料错误。注意：本版尚未执行代码签名或导出。";
    }
}
@end
