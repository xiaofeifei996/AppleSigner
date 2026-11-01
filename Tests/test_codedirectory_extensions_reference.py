"""Reference tests for CodeDirectory extension handling in 1.38.0.
These tests do not execute or compile the Objective-C implementation.
"""

MIN_LENGTH = {
    0x20001: 48,  # scatterOffset
    0x20200: 52,  # teamOffset
    0x20300: 64,  # codeLimit64
    0x20400: 88,  # exec segment fields
    0x20500: 96,  # preEncryptOffset
    0x20600: 108, # linkage fields
}

HASH_SIZES = {1: 20, 2: 32, 3: 20, 4: 48}


def required_length(version):
    required = 44
    for boundary, length in MIN_LENGTH.items():
        if version >= boundary:
            required = max(required, length)
    return required


def classify_cd(*, version, blob_length, scatter_offset=0, team_offset=0,
                pre_encrypt_offset=0, hash_type=2, hash_size=32,
                hash_offset=160, n_special=0, n_code=1,
                code_limit=4096, file_size=8192, signature_offset=4096,
                page_exp=12):
    if version > 0x20600:
        return "unsupported-future-version"
    if blob_length < required_length(version):
        return "invalid-extension-length"
    if team_offset and team_offset >= blob_length:
        return "invalid-team-offset"
    if pre_encrypt_offset and pre_encrypt_offset >= blob_length:
        return "invalid-preencrypt-offset"
    if scatter_offset:
        return "unsupported-scatter"
    if hash_type not in HASH_SIZES or hash_size != HASH_SIZES.get(hash_type):
        return "unsupported-hash-format"
    special_bytes = n_special * hash_size
    if (hash_offset < special_bytes or hash_offset - special_bytes < required_length(version)
            or hash_offset > blob_length or n_code * hash_size > blob_length - hash_offset
            or code_limit > signature_offset or code_limit > file_size or page_exp >= 31):
        return "invalid-hash-bounds"
    page_size = 1 << page_exp
    if (code_limit + page_size - 1) // page_size != n_code:
        return "slot-count-mismatch"
    return "eligible-for-contiguous-page-verification"


def test_scatter_is_never_misreported_as_contiguous_hash_success():
    assert classify_cd(version=0x20001, blob_length=256, scatter_offset=80) == "unsupported-scatter"


def test_versioned_extension_minimum_lengths_are_enforced():
    assert classify_cd(version=0x20300, blob_length=60) == "invalid-extension-length"
    assert classify_cd(version=0x20500, blob_length=92) == "invalid-extension-length"
    assert classify_cd(version=0x20600, blob_length=104) == "invalid-extension-length"


def test_future_versions_are_explicitly_unsupported():
    assert classify_cd(version=0x20700, blob_length=256) == "unsupported-future-version"


def test_optional_offsets_must_point_inside_blob():
    assert classify_cd(version=0x20200, blob_length=256, team_offset=256) == "invalid-team-offset"
    assert classify_cd(version=0x20500, blob_length=256, pre_encrypt_offset=256) == "invalid-preencrypt-offset"


def test_hash_type_and_digest_length_must_agree():
    assert classify_cd(version=0x20000, blob_length=256, hash_type=2, hash_size=20) == "unsupported-hash-format"
    assert classify_cd(version=0x20000, blob_length=256, hash_type=4, hash_size=48) == "eligible-for-contiguous-page-verification"


def test_code_slot_count_must_match_code_limit_and_page_size():
    assert classify_cd(version=0x20000, blob_length=256, n_code=2) == "slot-count-mismatch"


def test_extended_code_directory_header_can_be_validated():
    assert required_length(0x20000) == 44
    assert required_length(0x20100) == 48
    assert required_length(0x20200) == 52
    assert required_length(0x20300) == 64
    assert required_length(0x20400) == 88
    assert required_length(0x20500) == 96
    assert required_length(0x20600) == 108
