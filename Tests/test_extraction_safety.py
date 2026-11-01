#!/usr/bin/env python3
"""Independent regression tests for IPA extraction safety policy.

These tests model the intended policy; they do not execute IPAExtractor.m.
"""
import pathlib
import struct
import tempfile
import unittest
import zipfile
import stat
import unicodedata

MAX_ENTRIES = 20_000
MAX_ENTRY = 256 * 1024 * 1024
MAX_TOTAL = 1024 * 1024 * 1024
MAX_RATIO = 200


def safe_path(name):
    if not name or name.startswith(("/", "\\")) or "\\" in name or ":" in name or "\x00" in name:
        raise ValueError("unsafe path")
    is_dir = name.endswith("/")
    trimmed = name[:-1] if is_dir else name
    parts = trimmed.split("/")
    if not trimmed or any(not p or p in (".", "..") for p in parts):
        raise ValueError("unsafe path")
    normalized = "/".join(parts)
    key = unicodedata.normalize("NFC", normalized).casefold()
    return normalized, key, is_dir


def enforce_limits(entries):
    if len(entries) > MAX_ENTRIES:
        raise ValueError("too many entries")
    total = 0
    for name, compressed, uncompressed, file_type in entries:
        safe_path(name)
        if file_type in (stat.S_IFLNK, stat.S_IFCHR, stat.S_IFBLK, stat.S_IFIFO, stat.S_IFSOCK):
            raise ValueError("special file")
        if uncompressed > MAX_ENTRY or total > MAX_TOTAL - uncompressed:
            raise ValueError("expanded size")
        if compressed == 0 and uncompressed > 0:
            raise ValueError("zero compressed size")
        if compressed > 0 and uncompressed > compressed * MAX_RATIO:
            raise ValueError("compression ratio")
        total += uncompressed
    return total


class ExtractionSafetyTests(unittest.TestCase):
    def test_normal_payload_paths_allowed(self):
        self.assertEqual(safe_path("Payload/Demo.app/Info.plist")[0],
                         "Payload/Demo.app/Info.plist")
        self.assertTrue(safe_path("Payload/")[2])

    def test_parent_traversal_rejected(self):
        for name in ("../escape", "Payload/../../escape", "Payload/./x"):
            with self.subTest(name=name), self.assertRaises(ValueError):
                safe_path(name)

    def test_absolute_and_windows_paths_rejected(self):
        for name in ("/tmp/escape", "\\\\server\\share", "C:/escape", "Payload\\evil"):
            with self.subTest(name=name), self.assertRaises(ValueError):
                safe_path(name)

    def test_empty_and_ambiguous_components_rejected(self):
        for name in ("", "/", "Payload//x", "Payload/"):
            if name == "Payload/":
                continue
            with self.subTest(name=name), self.assertRaises(ValueError):
                safe_path(name)

    def test_case_and_unicode_normalization_collisions_detectable(self):
        a = safe_path("Payload/Demo.app/File")[1]
        b = safe_path("payload/demo.app/file")[1]
        self.assertEqual(a, b)
        c = safe_path("Payload/Cafe\u0301")[1]
        d = safe_path("Payload/Café")[1]
        self.assertEqual(c, d)

    def test_symlink_and_special_files_rejected(self):
        for kind in (stat.S_IFLNK, stat.S_IFCHR, stat.S_IFBLK, stat.S_IFIFO, stat.S_IFSOCK):
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                enforce_limits([("Payload/x", 10, 10, kind)])

    def test_entry_and_total_size_limits(self):
        with self.assertRaises(ValueError):
            enforce_limits([("Payload/x", 1, MAX_ENTRY + 1, stat.S_IFREG)])
        with self.assertRaises(ValueError):
            enforce_limits([
                ("Payload/a", MAX_ENTRY, MAX_ENTRY, stat.S_IFREG),
                ("Payload/b", MAX_ENTRY, MAX_ENTRY, stat.S_IFREG),
                ("Payload/c", MAX_ENTRY, MAX_ENTRY, stat.S_IFREG),
                ("Payload/d", MAX_ENTRY, MAX_ENTRY, stat.S_IFREG),
                ("Payload/e", MAX_ENTRY, MAX_ENTRY, stat.S_IFREG),
            ])

    def test_compression_bomb_ratio_rejected(self):
        with self.assertRaises(ValueError):
            enforce_limits([("Payload/x", 1, 201, stat.S_IFREG)])

    def test_zero_compressed_nonempty_rejected(self):
        with self.assertRaises(ValueError):
            enforce_limits([("Payload/x", 0, 1, stat.S_IFREG)])

    def test_regular_stored_entry_allowed(self):
        self.assertEqual(enforce_limits([
            ("Payload/Demo.app/Info.plist", 100, 100, stat.S_IFREG)
        ]), 100)


if __name__ == "__main__":
    unittest.main(verbosity=2)
