#!/bin/sh
set -eu
command -v openssl >/dev/null 2>&1 || { echo "错误：未找到 openssl" >&2; exit 127; }
[ -f detached-test.p7s ] || { echo "错误：缺少 detached-test.p7s" >&2; exit 2; }
[ -f test-content.bin ] || { echo "错误：缺少 test-content.bin" >&2; exit 2; }
tmp="${TMPDIR:-/tmp}/applesigner-verified-$$.bin"
trap 'rm -f "$tmp"' EXIT HUP INT TERM
openssl cms -verify -binary -inform DER \
  -in detached-test.p7s -content test-content.bin \
  -noverify -out "$tmp"
cmp test-content.bin "$tmp"
echo "OpenSSL CMS 互操作验证通过（未验证证书链信任）"
