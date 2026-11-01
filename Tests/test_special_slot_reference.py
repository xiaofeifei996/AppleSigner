import hashlib

def code_slot_region(hash_offset, hash_size, n_code, blob):
    if hash_size <= 0 or hash_offset > len(blob) or n_code * hash_size > len(blob) - hash_offset:
        raise ValueError("invalid code-slot bounds")
    return blob[hash_offset:hash_offset+n_code*hash_size]

def special_slot_digest_array(hash_offset, hash_size, n_special, blob):
    special_bytes = n_special * hash_size
    if hash_size <= 0 or hash_offset < special_bytes or hash_offset > len(blob):
        raise ValueError("invalid special-slot bounds")
    start = hash_offset - special_bytes
    # Apple slot 1 is nearest to hashOffset; slot N is farthest.
    return {
        slot: blob[start + (n_special-slot)*hash_size:
                   start + (n_special-slot+1)*hash_size]
        for slot in range(1, n_special+1)
    }

def verify_special_slot(slot_hashes, slot, data, algorithm="sha256"):
    expected = slot_hashes.get(slot)
    if expected is None:
        return "not-present"
    actual = hashlib.new(algorithm, data).digest()
    return "matched" if actual == expected else "mismatch"

def test_slot_one_is_nearest_to_hash_offset():
    blob = b"AAAA" + b"BBBB" + b"CODE"
    got = special_slot_digest_array(8, 4, 2, blob)
    assert got[1] == b"BBBB"
    assert got[2] == b"AAAA"

def test_slot_three_resource_hash_matches():
    resource = b"CodeResources fixture"
    digest = hashlib.sha256(resource).digest()
    hashes = {3: digest}
    assert verify_special_slot(hashes, 3, resource) == "matched"

def test_slot_one_info_plist_hash_mismatch():
    hashes = {1: hashlib.sha1(b"old plist").digest()}
    assert verify_special_slot(hashes, 1, b"changed plist", "sha1") == "mismatch"

def test_absent_slot_is_not_misreported_as_match():
    assert verify_special_slot({}, 3, b"resource") == "not-present"

def test_rejects_underflow_in_special_hash_region():
    try:
        special_slot_digest_array(7, 4, 2, b"1234567890")
    except ValueError:
        pass
    else:
        raise AssertionError("must reject hashOffset < nSpecialSlots * hashSize")

def test_rejects_hash_offset_past_blob():
    try:
        special_slot_digest_array(20, 4, 2, b"1234567890")
    except ValueError:
        pass
    else:
        raise AssertionError("must reject hashOffset beyond blob")


def test_hash_offset_starts_code_slot_array_not_after_special_slots():
    blob = b"AAAA" + b"BBBB" + b"CODE"
    assert code_slot_region(8, 4, 1, blob) == b"CODE"
