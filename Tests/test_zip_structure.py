#!/usr/bin/env python3
"""Reference ZIP-structure regression tests for AppleSigner 1.28.0.

This Python suite exercises adversarial ZIP fixtures and a small independent
reference validator. It does not execute the Objective-C IPAInspector.
"""
import pathlib
import struct
import tempfile
import unittest
import zipfile

SIG_EOCD = b"PK\x05\x06"
SIG_CENTRAL = b"PK\x01\x02"
SIG_LOCAL = b"PK\x03\x04"


def find_eocd(data):
    start = max(0, len(data) - 65557)
    for pos in range(len(data) - 22, start - 1, -1):
        if data[pos:pos+4] == SIG_EOCD:
            comment_len = struct.unpack_from("<H", data, pos+20)[0]
            if pos + 22 + comment_len == len(data):
                return pos
    raise ValueError("valid EOCD not found")


def audit_zip(data):
    eocd = find_eocd(data)
    disk, cd_disk, disk_count, total_count, cd_size, cd_off, _ = struct.unpack_from(
        "<HHHHIIH", data, eocd + 4
    )
    if disk or cd_disk or disk_count != total_count:
        raise ValueError("multi-disk")
    if total_count == 0xffff or cd_size == 0xffffffff or cd_off == 0xffffffff:
        raise ValueError("ZIP64")
    if cd_off + cd_size > eocd:
        raise ValueError("central bounds")
    cur = cd_off
    names = set()
    for _ in range(total_count):
        if cur + 46 > cd_off + cd_size or data[cur:cur+4] != SIG_CENTRAL:
            raise ValueError("central record")
        flags, method = struct.unpack_from("<HH", data, cur+8)
        crc, csize, usize = struct.unpack_from("<III", data, cur+16)
        nl, el, cl = struct.unpack_from("<HHH", data, cur+28)
        local_off = struct.unpack_from("<I", data, cur+42)[0]
        end = cur + 46 + nl + el + cl
        if end > cd_off + cd_size:
            raise ValueError("central record bounds")
        if csize == 0xffffffff or usize == 0xffffffff or local_off == 0xffffffff:
            raise ValueError("ZIP64 entry")
        name = bytes(data[cur+46:cur+46+nl])
        if name.startswith(b"Payload/") and not name.endswith(b"/"):
            if name in names:
                raise ValueError("duplicate payload")
            names.add(name)
            if local_off + 30 > cd_off or data[local_off:local_off+4] != SIG_LOCAL:
                raise ValueError("local header")
            local_flags, local_method = struct.unpack_from("<HH", data, local_off+6)
            local_nl, local_el = struct.unpack_from("<HH", data, local_off+26)
            data_start = local_off + 30 + local_nl + local_el
            if local_flags != flags or local_method != method:
                raise ValueError("local mismatch")
            if local_nl != nl or data[local_off+30:local_off+30+local_nl] != name:
                raise ValueError("local filename mismatch")
            if data_start > cd_off or csize > cd_off - data_start:
                raise ValueError("payload bounds")
        cur = end
    if cur != cd_off + cd_size:
        raise ValueError("central size mismatch")
    return True


def make_zip(comment=b""):
    tmp = tempfile.NamedTemporaryFile(suffix=".zip", delete=False)
    tmp.close()
    with zipfile.ZipFile(tmp.name, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("Payload/Demo.app/Info.plist", b"plist-data")
        zf.writestr("Payload/Demo.app/Demo", b"\xcf\xfa\xed\xfe" + b"\x00" * 200)
        zf.comment = comment
    return pathlib.Path(tmp.name)


class ZIPStructureTests(unittest.TestCase):
    def setUp(self):
        self.path = make_zip(b"safe-comment")
        self.data = bytearray(self.path.read_bytes())

    def tearDown(self):
        self.path.unlink(missing_ok=True)

    def test_valid_zip_with_comment(self):
        self.assertTrue(audit_zip(self.data))

    def test_false_eocd_signature_inside_comment_is_ignored(self):
        self.path.unlink(missing_ok=True)
        self.path = make_zip(b"noise-PK\x05\x06" + b"\x00" * 18)
        self.assertTrue(audit_zip(self.path.read_bytes()))

    def test_eocd_entry_count_mismatch_rejected(self):
        pos = find_eocd(self.data)
        struct.pack_into("<H", self.data, pos+10, 99)
        with self.assertRaises(ValueError):
            audit_zip(self.data)

    def test_zip64_sentinel_rejected(self):
        pos = find_eocd(self.data)
        struct.pack_into("<I", self.data, pos+16, 0xffffffff)
        with self.assertRaises(ValueError):
            audit_zip(self.data)

    def test_central_directory_truncation_rejected(self):
        pos = find_eocd(self.data)
        struct.pack_into("<I", self.data, pos+12, 3)
        with self.assertRaises(ValueError):
            audit_zip(self.data)

    def test_local_header_corruption_rejected(self):
        # Corrupt the local header signature at the first member's offset.
        cd = self.data.find(SIG_CENTRAL)
        local_off = struct.unpack_from("<I", self.data, cd+42)[0]
        self.data[local_off:local_off+4] = b"NOPE"
        with self.assertRaises(ValueError):
            audit_zip(self.data)

    def test_duplicate_payload_path_rejected(self):
        self.path.unlink(missing_ok=True)
        tmp = make_zip()
        with zipfile.ZipFile(tmp, "a", compression=zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("Payload/Demo.app/Info.plist", b"second-plist")
        self.path = tmp
        with self.assertRaises(ValueError):
            audit_zip(self.path.read_bytes())


if __name__ == "__main__":
    unittest.main(verbosity=2)
