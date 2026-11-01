#!/usr/bin/env python3
"""Remove duplicate Mach-O LC_RPATH entries and re-sign the RootHide app."""
import collections
import pathlib
import re
import subprocess
import sys

binary = pathlib.Path(sys.argv[1])
entitlements = pathlib.Path(sys.argv[2])
if not binary.is_file():
    raise SystemExit(f"AppleSigner executable not found: {binary}")
if not entitlements.is_file():
    raise SystemExit(f"Entitlements file not found: {entitlements}")

def rpaths():
    output = subprocess.check_output(["otool", "-l", str(binary)], text=True)
    found = []
    lines = output.splitlines()
    for index, line in enumerate(lines):
        if line.strip() == "cmd LC_RPATH":
            for candidate in lines[index + 1:index + 5]:
                match = re.match(r"\s*path (.+?) \(offset \d+\)", candidate)
                if match:
                    found.append(match.group(1))
                    break
    return found

before = rpaths()
counts = collections.Counter(before)
duplicates = {path: count for path, count in counts.items() if count > 1}
for path, count in duplicates.items():
    for _ in range(count - 1):
        subprocess.run(["install_name_tool", "-delete_rpath", path, str(binary)], check=True)
    print(f"Removed {count - 1} duplicate LC_RPATH entry/entries: {path}")

after = rpaths()
remaining = [path for path, count in collections.Counter(after).items() if count > 1]
if remaining:
    raise SystemExit("Duplicate LC_RPATH entries remain: " + ", ".join(remaining))
required = "@loader_path/.jbroot/Library/Frameworks"
if after.count(required) != 1:
    raise SystemExit(f"Expected exactly one {required!r}, found {after.count(required)}")

# install_name_tool invalidates the existing signature, so sign after normalization.
subprocess.run(["ldid", "-S" + str(entitlements), str(binary)], check=True)
print("Final LC_RPATH list:")
for path in after:
    print("  " + path)
print("RootHide app executable re-signed successfully.")
