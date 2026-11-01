"""Reference tests for Mach-O signature/load-command boundaries in 1.40.0.
These tests model the rules and inspect source guards; they do not execute Objective-C.
"""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def validate_commands(commands, command_bytes):
    cursor = 0
    for cmdsize in commands:
        if cmdsize < 8 or cmdsize % 4 or cmdsize > command_bytes - cursor:
            return False
        cursor += cmdsize
    return cursor == command_bytes


def validate_signature_region(offset, size, file_size, command_end):
    return size >= 12 and offset >= command_end and offset <= file_size and size <= file_size - offset


def validate_slots(slots):
    return len(slots) == len(set(slots))


def test_load_commands_must_exactly_fill_declared_region():
    assert validate_commands([16, 24], 40)
    assert not validate_commands([16, 20], 40)


def test_load_command_rejects_short_unaligned_and_overrun():
    assert not validate_commands([4], 4)
    assert not validate_commands([10], 10)
    assert not validate_commands([32], 24)


def test_signature_region_must_be_after_commands():
    assert validate_signature_region(128, 64, 512, 128)
    assert not validate_signature_region(120, 64, 512, 128)


def test_signature_region_must_fit_file_and_minimum_superblob_header():
    assert not validate_signature_region(480, 64, 512, 128)
    assert not validate_signature_region(128, 8, 512, 128)


def test_superblob_slot_indices_must_be_unique():
    assert validate_slots([0, 2, 0x1000])
    assert not validate_slots([0, 2, 0])


def test_source_rejects_duplicate_signature_commands_and_duplicate_slots():
    source = (ROOT / "MachOSignatureInspector.m").read_text()
    assert "duplicateSignatureCommand" in source
    assert "多个 LC_CODE_SIGNATURE" in source
    assert "seenSlots" in source
    assert "SuperBlob 存在重复 slot index" in source


def test_source_checks_command_region_and_signature_overlap():
    source = (ROOT / "MachOSignatureInspector.m").read_text()
    assert "pos!=commandEnd" in source
    assert "dataoff<commandEnd" in source
    assert "LoadCommandsValid" in source


def test_source_checks_identifier_termination_and_hash_array_overlap():
    source = (ROOT / "MachOSignatureInspector.m").read_text()
    assert "BOOL terminated=NO" in source
    assert "identOffset>=hashOffset-specialBytes" in source
    assert "hashArrayEnd" in source
