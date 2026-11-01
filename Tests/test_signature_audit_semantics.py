from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = (ROOT / "SignatureAudit.m").read_text()
UI = (ROOT / "ViewController.m").read_text()
README = (ROOT / "README.md").read_text()


def test_presence_is_not_called_verified_signature():
    assert '@"LooksSigned": @NO' in SRC
    assert '@"HasSignatureArtifacts"' in SRC
    assert '@"CryptographicVerification": @"not-performed"' in SRC


def test_code_resources_requires_files_and_rules_dictionaries():
    assert 'BOOL filesValid = [files isKindOfClass:NSDictionary.class] || [files2 isKindOfClass:NSDictionary.class];' in SRC
    assert 'BOOL rulesValid = [rules isKindOfClass:NSDictionary.class] || [rules2 isKindOfClass:NSDictionary.class];' in SRC
    assert 'if (filesValid && rulesValid)' in SRC


def test_artifact_paths_have_expected_file_types():
    assert 'isDirectory:&sigDirIsDirectory' in SRC
    assert 'isDirectory:&resourcesIsDirectory' in SRC
    assert 'isDirectory:&profileIsDirectory' in SRC


def test_ui_warns_that_crypto_validation_is_not_performed():
    assert '尚未验证 CodeDirectory special slots、CMS 签名/证书信任' in UI


def test_release_notes_state_scope_and_limits():
    assert '1.33.0：签名文件结构审计语义修正' in README
    assert '不是代码签名验证器' in README


def test_resource_hash_audit_supports_sha1_and_sha256_sections():
    assert 'for (NSString *section in @[@"files", @"files2"])' in SRC
    assert 'CC_SHA1(data.bytes' in SRC
    assert 'CC_SHA256(data.bytes' in SRC
    assert 'expected1=value[@"hash"]' not in SRC  # dictionary access remains explicit and typed
    assert 'id h1=value[@"hash"], h2=value[@"hash2"];' in SRC

def test_resource_paths_are_contained_and_symlink_resolved():
    assert 'ASIsSafeResourcePath' in SRC
    assert '[part isEqualToString:@".."]' in SRC
    assert 'stringByResolvingSymlinksInPath' in SRC

def test_hash_report_distinguishes_partial_and_failed():
    assert 'resource-hash-failed' in SRC
    assert 'resource-hash-partial' in SRC
    assert 'ResourceHashFailures' in SRC
    assert 'ResourceHashUnsupported' in SRC
