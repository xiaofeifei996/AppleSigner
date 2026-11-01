#!/usr/bin/env python3
"""Generate tiny synthetic IPA fixtures for manual AppleSigner inventory testing.

These are parser fixtures, not installable apps and not validly code-signed IPAs.
"""
import argparse
import plistlib
import struct
import zipfile
from pathlib import Path


def thin_arm64():
    # MH_MAGIC_64, CPU_TYPE_ARM64, MH_EXECUTE, no load commands.
    return struct.pack("<IiiIIIII", 0xFEEDFACF, 0x0100000C, 0, 2, 0, 0, 0, 0)


def fat_binary(kind="valid"):
    arm = thin_arm64()
    x64 = struct.pack("<IiiIIIII", 0xFEEDFACF, 0x01000007, 3, 2, 0, 0, 0, 0)
    # FAT_MAGIC and fat_arch are big-endian. Slices are aligned to 2^12.
    if kind == "valid":
        entries = [(0x0100000C, 0, 0x1000, len(arm), 12),
                   (0x01000007, 3, 0x2000, len(x64), 12)]
        total = 0x2000 + len(x64)
    elif kind == "overlap":
        entries = [(0x0100000C, 0, 0x1000, len(arm), 12),
                   (0x01000007, 3, 0x1000, len(x64), 12)]
        total = 0x1000 + max(len(arm), len(x64))
    elif kind == "out-of-bounds":
        entries = [(0x0100000C, 0, 0x7000, len(arm), 12)]
        total = 0x1000
    elif kind == "cpu-mismatch":
        # Fat table claims arm64, but the embedded thin header claims x86_64.
        entries = [(0x0100000C, 0, 0x1000, len(x64), 12)]
        total = 0x1000 + len(x64)
    elif kind == "not-macho-slice":
        entries = [(0x0100000C, 0, 0x1000, 32, 12)]
        total = 0x1000 + 32
    elif kind == "large-offset":
        # Exercise ZIP range reads beyond the 128 KiB prefix window.
        entries = [(0x0100000C, 0, 0x30000, len(arm), 12),
                   (0x01000007, 3, 0x40000, len(x64), 12)]
        total = 0x40000 + len(x64)
    else:
        raise ValueError(kind)
    header = struct.pack(">II", 0xCAFEBABE, len(entries))
    table = b"".join(struct.pack(">iiIII", *e) for e in entries)
    blob = bytearray(total)
    blob[:8] = header
    blob[8:8 + len(table)] = table
    for cpu, sub, offset, size, align in entries:
        if offset + size <= total:
            if kind == "cpu-mismatch":
                blob[offset:offset + size] = x64
            elif kind == "not-macho-slice":
                blob[offset:offset + size] = b"\x00" * size
            else:
                blob[offset:offset + size] = arm if cpu == 0x0100000C else x64
    return bytes(blob)


def write_ipa(path: Path, executable: bytes, compression: int):
    info = {
        "CFBundleIdentifier": "com.example.fixture",
        "CFBundleName": "Fixture",
        "CFBundleExecutable": "Fixture",
        "CFBundlePackageType": "APPL",
        "CFBundleVersion": "1",
        "CFBundleShortVersionString": "1.0",
    }
    with zipfile.ZipFile(path, "w", compression=compression) as zf:
        zf.writestr("Payload/Fixture.app/Info.plist", plistlib.dumps(info), compress_type=compression)
        zf.writestr("Payload/Fixture.app/Fixture", executable, compress_type=compression)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", default="ipa-fixtures")
    args = parser.parse_args()
    out = Path(args.output)
    out.mkdir(parents=True, exist_ok=True)
    write_ipa(out / "thin-stored.ipa", thin_arm64(), zipfile.ZIP_STORED)
    write_ipa(out / "thin-deflate.ipa", thin_arm64(), zipfile.ZIP_DEFLATED)
    write_ipa(out / "fat-valid.ipa", fat_binary("valid"), zipfile.ZIP_STORED)
    write_ipa(out / "fat-overlap.ipa", fat_binary("overlap"), zipfile.ZIP_DEFLATED)
    write_ipa(out / "fat-out-of-bounds.ipa", fat_binary("out-of-bounds"), zipfile.ZIP_STORED)
    write_ipa(out / "fat-cpu-mismatch.ipa", fat_binary("cpu-mismatch"), zipfile.ZIP_DEFLATED)
    write_ipa(out / "fat-not-macho-slice.ipa", fat_binary("not-macho-slice"), zipfile.ZIP_STORED)
    write_ipa(out / "fat-large-offset-stored.ipa", fat_binary("large-offset"), zipfile.ZIP_STORED)
    write_ipa(out / "fat-large-offset-deflate.ipa", fat_binary("large-offset"), zipfile.ZIP_DEFLATED)
    print(f"Generated 9 synthetic IPA fixtures in {out.resolve()}")


if __name__ == "__main__":
    main()
