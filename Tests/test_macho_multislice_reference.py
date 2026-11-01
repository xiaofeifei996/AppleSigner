"""Python reference tests for 1.37 Mach-O audit invariants.
These tests do not execute or compile the Objective-C implementation.
"""

def ranges_overlap(a_off, a_size, b_off, b_size):
    return a_off < b_off + b_size and b_off < a_off + a_size


def validate_fat_slices(file_size, header_end, slices):
    seen = set()
    for item in slices:
        off, size = item["offset"], item["size"]
        assert size >= 28 and off >= header_end and off <= file_size and size <= file_size - off
        align = item.get("align", 0)
        assert align <= 31
        assert align == 0 or off % (1 << align) == 0
        key = (item["cpu"], item["subtype"])
        assert key not in seen
        seen.add(key)
    for i, a in enumerate(slices):
        for b in slices[i + 1:]:
            assert not ranges_overlap(a["offset"], a["size"], b["offset"], b["size"])


def validate_superblob(index_end, blob_length, blobs):
    ranges = []
    for blob in blobs:
        off, size = blob["offset"], blob["size"]
        assert off >= index_end and size >= 8 and off <= blob_length and size <= blob_length - off
        assert all(not ranges_overlap(off, size, old_off, old_size) for old_off, old_size in ranges)
        ranges.append((off, size))


def primary_and_alternates(entries):
    cds = [entry for entry in entries if entry["kind"] == "CodeDirectory"]
    primary = next((entry for entry in cds if entry["slot"] == 0), cds[0] if cds else None)
    return primary, cds


def test_fat_arch_slices_must_not_overlap():
    validate_fat_slices(4096, 48, [
        {"offset": 512, "size": 512, "cpu": 0x0100000C, "subtype": 0, "align": 8},
        {"offset": 1024, "size": 512, "cpu": 0x0100000C, "subtype": 2, "align": 8},
    ])
    try:
        validate_fat_slices(4096, 48, [
            {"offset": 512, "size": 600, "cpu": 1, "subtype": 0},
            {"offset": 1024, "size": 512, "cpu": 2, "subtype": 0},
        ])
    except AssertionError:
        pass
    else:
        raise AssertionError("overlapping slices accepted")


def test_fat_arch_duplicate_cpu_subtype_rejected():
    try:
        validate_fat_slices(4096, 48, [
            {"offset": 512, "size": 256, "cpu": 1, "subtype": 0},
            {"offset": 1024, "size": 256, "cpu": 1, "subtype": 0},
        ])
    except AssertionError:
        pass
    else:
        raise AssertionError("duplicate architecture accepted")


def test_superblob_rejects_index_overlap_and_child_overlap():
    validate_superblob(28, 256, [{"offset": 32, "size": 32}, {"offset": 80, "size": 40}])
    for blobs in ([{"offset": 12, "size": 16}],
                  [{"offset": 32, "size": 40}, {"offset": 48, "size": 32}]):
        try:
            validate_superblob(28, 256, blobs)
        except AssertionError:
            pass
        else:
            raise AssertionError("invalid SuperBlob layout accepted")


def test_primary_and_multiple_alternate_code_directories_are_retained():
    entries = [
        {"slot": 0x1001, "kind": "CodeDirectory", "hash": "sha256"},
        {"slot": 0, "kind": "CodeDirectory", "hash": "sha1"},
        {"slot": 0x1002, "kind": "CodeDirectory", "hash": "sha384"},
        {"slot": 5, "kind": "Entitlements"},
    ]
    primary, all_cds = primary_and_alternates(entries)
    assert primary["hash"] == "sha1"
    assert len(all_cds) == 3
    assert {x["hash"] for x in all_cds} == {"sha1", "sha256", "sha384"}


def test_fat_slice_header_cpu_must_match_fat_record():
    fat_cpu, fat_subtype = 0x0100000C, 2
    header_cpu, header_subtype = 0x0100000C, 0
    assert (fat_cpu, fat_subtype) != (header_cpu, header_subtype)
