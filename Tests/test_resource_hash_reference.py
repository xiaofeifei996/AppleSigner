"""Independent Python reference cases; these do not execute SignatureAudit.m."""
import hashlib
import tempfile
from pathlib import Path


def safe_relative_path(value):
    if not isinstance(value, str) or not value or len(value) > 4096:
        return False
    if value.startswith("/") or "\\" in value or "\x00" in value:
        return False
    parts = value.split("/")
    return all(part not in ("", ".", "..") and ":" not in part for part in parts)


def test_sha1_legacy_files_digest_matches():
    payload = b"resource fixture"
    expected = hashlib.sha1(payload).digest()
    assert hashlib.sha1(payload).digest() == expected


def test_sha256_files2_digest_matches_and_detects_mutation():
    payload = b"resource fixture"
    expected = hashlib.sha256(payload).digest()
    assert hashlib.sha256(payload).digest() == expected
    assert hashlib.sha256(payload + b"!").digest() != expected


def test_unsafe_resource_paths_are_rejected():
    for value in ("../outside", "/absolute", "a//b", "a/./b", "a\\b", "a\x00b", "C:/x"):
        assert not safe_relative_path(value), value
    assert safe_relative_path("Payload/App.app/Info.plist")


def test_hash_algorithm_length_is_unambiguous():
    assert len(hashlib.sha1(b"x").digest()) == 20
    assert len(hashlib.sha256(b"x").digest()) == 32
