"""Reference tests for CodeDirectory scatter-vector validation in 1.39.0.
These tests model the expected rules; they do not execute Objective-C code.
"""

import struct


def parse_scatter(data, offset, code_slots, page_size, code_limit, file_size):
    if offset < 44 or offset > len(data) - 16:
        return None, "invalid-offset"
    slots = [None] * code_slots
    ranges = []
    terminated = False
    cursor = offset
    while cursor + 16 <= len(data):
        count, base, target, spare = struct.unpack_from(">IIII", data, cursor)
        cursor += 16
        if count == 0:
            if base or target or spare:
                return None, "invalid-terminator"
            terminated = True
            break
        if spare or base > code_slots or count > code_slots - base or target % page_size:
            return None, "invalid-entry"
        for j in range(count):
            slot = base + j
            file_offset = target + j * page_size
            if slots[slot] is not None:
                return None, "duplicate-slot"
            if file_offset >= code_limit or file_offset >= file_size:
                return None, "out-of-bounds"
            chunk = min(page_size, code_limit - file_offset)
            if chunk > file_size - file_offset:
                return None, "out-of-bounds"
            end = file_offset + chunk
            if any(file_offset < old_end and old_start < end for old_start, old_end in ranges):
                return None, "overlap"
            ranges.append((file_offset, end))
            slots[slot] = file_offset
    if not terminated:
        return None, "missing-terminator"
    if any(v is None for v in slots):
        return None, "incomplete-coverage"
    return slots, None


def vector(*entries):
    return b"".join(struct.pack(">IIII", *e) for e in (*entries, (0, 0, 0, 0)))


def test_scatter_vector_maps_slots_to_non_contiguous_file_pages():
    data = b"\0" * 44 + vector((1, 1, 4096, 0), (1, 0, 0, 0))
    offsets, error = parse_scatter(data, 44, 2, 4096, 8192, 8192)
    assert error is None
    assert offsets == [0, 4096]


def test_scatter_rejects_duplicate_slot_mapping():
    data = b"\0" * 44 + vector((1, 0, 0, 0), (1, 0, 4096, 0))
    assert parse_scatter(data, 44, 1, 4096, 8192, 8192)[1] == "duplicate-slot"


def test_scatter_rejects_incomplete_slot_coverage():
    data = b"\0" * 44 + vector((1, 0, 0, 0))
    assert parse_scatter(data, 44, 2, 4096, 8192, 8192)[1] == "incomplete-coverage"


def test_scatter_rejects_unaligned_page_target():
    data = b"\0" * 44 + vector((1, 0, 1, 0))
    assert parse_scatter(data, 44, 1, 4096, 8192, 8192)[1] == "invalid-entry"


def test_scatter_rejects_target_outside_code_limit():
    data = b"\0" * 44 + vector((1, 0, 8192, 0))
    assert parse_scatter(data, 44, 1, 4096, 8192, 16384)[1] == "out-of-bounds"


def test_scatter_rejects_nonzero_spare_and_terminator_fields():
    bad_entry = b"\0" * 44 + struct.pack(">IIII", 1, 0, 0, 1) + struct.pack(">IIII", 0, 0, 0, 0)
    assert parse_scatter(bad_entry, 44, 1, 4096, 8192, 8192)[1] == "invalid-entry"
    bad_term = b"\0" * 44 + struct.pack(">IIII", 1, 0, 0, 0) + struct.pack(">IIII", 0, 1, 0, 0)
    assert parse_scatter(bad_term, 44, 1, 4096, 8192, 8192)[1] == "invalid-terminator"


def test_scatter_requires_zero_terminator():
    data = b"\0" * 44 + struct.pack(">IIII", 1, 0, 0, 0)
    assert parse_scatter(data, 44, 1, 4096, 8192, 8192)[1] == "missing-terminator"


def test_scatter_rejects_overlapping_page_ranges():
    data = b"\0" * 44 + vector((1, 0, 0, 0), (1, 1, 0, 0))
    assert parse_scatter(data, 44, 2, 4096, 8192, 8192)[1] == "overlap"
