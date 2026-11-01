#!/usr/bin/env python3
"""Integration checks for AppleSigner synthetic IPA fixtures.

These tests validate fixture construction, ZIP member range extraction semantics,
and expected Mach-O fixture metadata. They do NOT execute IPAInspector.m or prove
the Objective-C implementation compiles or behaves identically.
"""
import pathlib
import struct
import subprocess
import sys
import tempfile
import unittest
import zipfile
import zlib

HERE = pathlib.Path(__file__).resolve().parent
GENERATOR = HERE / "generate-ipa-fixtures.py"


def read_member_range(zf, name, offset, length):
    """Independent streaming reference for stored/deflate ZIP member ranges."""
    info = zf.getinfo(name)
    if offset < 0 or length < 0 or offset + length > info.file_size:
        raise ValueError("range outside member")
    fp = zf.fp
    fp.seek(info.header_offset)
    local = fp.read(30)
    if len(local) != 30 or local[:4] != b"PK\x03\x04":
        raise ValueError("invalid local header")
    name_len, extra_len = struct.unpack_from("<HH", local, 26)
    data_pos = info.header_offset + 30 + name_len + extra_len
    if info.compress_type == zipfile.ZIP_STORED:
        fp.seek(data_pos + offset)
        data = fp.read(length)
        if len(data) != length:
            raise ValueError("short stored range")
        return data
    if info.compress_type != zipfile.ZIP_DEFLATED:
        raise ValueError("unsupported compression")
    decoder = zlib.decompressobj(-15)
    fp.seek(data_pos)
    remaining = info.compress_size
    produced = 0
    copied = bytearray()
    range_end = offset + length
    while remaining:
        chunk = fp.read(min(65536, remaining))
        if not chunk:
            raise ValueError("truncated compressed stream")
        remaining -= len(chunk)
        plain = decoder.decompress(chunk)
        chunk_start, chunk_end = produced, produced + len(plain)
        copy_start, copy_end = max(chunk_start, offset), min(chunk_end, range_end)
        if copy_end > copy_start:
            copied.extend(plain[copy_start - chunk_start:copy_end - chunk_start])
        produced = chunk_end
        if len(copied) == length:
            break
    if len(copied) != length:
        raise ValueError("short deflate range")
    return bytes(copied)


def read_fat_table(data):
    if len(data) < 8:
        raise ValueError("short fat header")
    magic, count = struct.unpack(">II", data[:8])
    if magic != 0xCAFEBABE:
        raise ValueError("not FAT_MAGIC")
    if count > 4096 or 8 + count * 20 > len(data):
        raise ValueError("bad architecture table")
    arches = []
    for i in range(count):
        cpu, subtype, off, size, align = struct.unpack(">iiIII", data[8 + i*20:28 + i*20])
        arches.append((cpu & 0xffffffff, subtype & 0xffffffff, off, size, align))
    return arches


class FixtureIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.out = pathlib.Path(cls.temp.name) / "fixtures"
        subprocess.run([sys.executable, str(GENERATOR), "--output", str(cls.out)], check=True)
        cls.expected = {
            "thin-stored.ipa", "thin-deflate.ipa", "fat-valid.ipa",
            "fat-overlap.ipa", "fat-out-of-bounds.ipa",
            "fat-cpu-mismatch.ipa", "fat-not-macho-slice.ipa",
            "fat-large-offset-stored.ipa", "fat-large-offset-deflate.ipa",
        }

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def ipa_binary(self, filename):
        with zipfile.ZipFile(self.out / filename) as zf:
            return zf.read("Payload/Fixture.app/Fixture")

    def test_all_nine_fixtures_exist_and_zip_test(self):
        self.assertEqual({p.name for p in self.out.glob("*.ipa")}, self.expected)
        for name in self.expected:
            with zipfile.ZipFile(self.out / name) as zf:
                self.assertIsNone(zf.testzip(), name)

    def test_stored_and_deflate_thin_headers_match(self):
        for name in ("thin-stored.ipa", "thin-deflate.ipa"):
            blob = self.ipa_binary(name)
            magic, cpu, subtype = struct.unpack("<Iii", blob[:12])
            self.assertEqual(magic, 0xFEEDFACF)
            self.assertEqual(cpu & 0xffffffff, 0x0100000C)
            self.assertEqual(subtype, 0)

    def test_valid_fat_slices_have_in_bounds_non_overlapping_ranges(self):
        blob = self.ipa_binary("fat-valid.ipa")
        arches = read_fat_table(blob)
        self.assertEqual(len(arches), 2)
        table_end = 8 + len(arches) * 20
        ranges = []
        for cpu, subtype, off, size, align in arches:
            self.assertGreaterEqual(off, table_end)
            self.assertGreater(size, 0)
            self.assertLessEqual(off + size, len(blob))
            self.assertEqual(off % (1 << align), 0)
            ranges.append((off, off + size))
            header = blob[off:off + 32]
            magic, inner_cpu = struct.unpack("<Ii", header[:8])
            self.assertEqual(magic, 0xFEEDFACF)
            self.assertEqual(inner_cpu & 0xffffffff, cpu)
        self.assertFalse(ranges[0][0] < ranges[1][1] and ranges[1][0] < ranges[0][1])

    def test_malformed_fat_cases_are_distinguishable(self):
        overlap = read_fat_table(self.ipa_binary("fat-overlap.ipa"))
        self.assertTrue(overlap[0][2] < overlap[1][2] + overlap[1][3] and
                        overlap[1][2] < overlap[0][2] + overlap[0][3])

        oob = read_fat_table(self.ipa_binary("fat-out-of-bounds.ipa"))
        self.assertGreater(oob[0][2] + oob[0][3], len(self.ipa_binary("fat-out-of-bounds.ipa")))

        mismatch = self.ipa_binary("fat-cpu-mismatch.ipa")
        arch = read_fat_table(mismatch)[0]
        _, inner_cpu = struct.unpack("<Ii", mismatch[arch[2]:arch[2] + 8])
        self.assertNotEqual(inner_cpu & 0xffffffff, arch[0])

        nonmacho = self.ipa_binary("fat-not-macho-slice.ipa")
        arch = read_fat_table(nonmacho)[0]
        self.assertNotEqual(nonmacho[arch[2]:arch[2] + 4], struct.pack("<I", 0xFEEDFACF))

    def test_zip_range_reads_match_expected_bytes_for_both_methods(self):
        for name in ("thin-stored.ipa", "thin-deflate.ipa"):
            with zipfile.ZipFile(self.out / name) as zf:
                member = "Payload/Fixture.app/Fixture"
                data = zf.read(member)
                self.assertEqual(read_member_range(zf, member, 4, 12), data[4:16])
                self.assertEqual(read_member_range(zf, member, len(data)-8, 8), data[-8:])


    def test_large_fat_slice_headers_beyond_prefix_are_readable(self):
        for name in ("fat-large-offset-stored.ipa", "fat-large-offset-deflate.ipa"):
            with zipfile.ZipFile(self.out / name) as zf:
                member = "Payload/Fixture.app/Fixture"
                info = zf.getinfo(member)
                blob = zf.read(member)
                arches = read_fat_table(blob)
                self.assertTrue(any(a[2] > 131080 for a in arches))
                for cpu, subtype, off, size, align in arches:
                    header = read_member_range(zf, member, off, min(32, size))
                    magic, inner_cpu = struct.unpack("<Ii", header[:8])
                    self.assertEqual(magic, 0xFEEDFACF)
                    self.assertEqual(inner_cpu & 0xffffffff, cpu)

    def test_zip_range_rejects_out_of_bounds(self):
        with zipfile.ZipFile(self.out / "thin-deflate.ipa") as zf:
            member = "Payload/Fixture.app/Fixture"
            with self.assertRaises(ValueError):
                read_member_range(zf, member, 999, 8)


if __name__ == "__main__":
    unittest.main(verbosity=2)
