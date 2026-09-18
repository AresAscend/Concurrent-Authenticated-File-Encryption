#!/bin/sh
set -eu

project_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
binary="$project_root/encrypt_decrypt"
work_dir=$(mktemp -d /private/tmp/cafe-test.XXXXXX)
trap 'rm -rf "$work_dir"' EXIT

mkdir -p "$work_dir/input" "$work_dir/tampered" "$work_dir/single"
printf 'Encryption integration test\n' > "$work_dir/input/note.txt"
dd if=/dev/urandom of="$work_dir/input/blob.bin" bs=1024 count=128 2>/dev/null
printf 'Single file integration test\n' > "$work_dir/single/one.txt"
chmod 600 "$work_dir/input/blob.bin"

original_note=$(shasum -a 256 "$work_dir/input/note.txt" | awk '{print $1}')
original_blob=$(shasum -a 256 "$work_dir/input/blob.bin" | awk '{print $1}')

CAFE_PASSPHRASE='integration-passphrase' "$binary" encrypt "$work_dir/input"
test -f "$work_dir/input/note.txt.cafe"
test -f "$work_dir/input/blob.bin.cafe"
test "$(stat -f %Lp "$work_dir/input/blob.bin.cafe")" = "600"
test "$(shasum -a 256 "$work_dir/input/note.txt" | awk '{print $1}')" = "$original_note"
test "$(shasum -a 256 "$work_dir/input/blob.bin" | awk '{print $1}')" = "$original_blob"

CAFE_PASSPHRASE='integration-passphrase' "$binary" decrypt "$work_dir/input"
test "$(shasum -a 256 "$work_dir/input/note.txt.decrypted" | awk '{print $1}')" = "$original_note"
test "$(shasum -a 256 "$work_dir/input/blob.bin.decrypted" | awk '{print $1}')" = "$original_blob"
test "$(stat -f %Lp "$work_dir/input/blob.bin.decrypted")" = "600"

CAFE_PASSPHRASE='integration-passphrase' "$binary" encrypt "$work_dir/single/one.txt"
CAFE_PASSPHRASE='integration-passphrase' "$binary" decrypt "$work_dir/single/one.txt.cafe"
cmp "$work_dir/single/one.txt" "$work_dir/single/one.txt.decrypted"

printf 'source data\n' > "$work_dir/single/existing.txt"
printf 'must not be replaced\n' > "$work_dir/single/existing.txt.cafe"
if CAFE_PASSPHRASE='integration-passphrase' "$binary" encrypt "$work_dir/single/existing.txt"; then
    echo "Expected an existing output file to be rejected" >&2
    exit 1
fi
test "$(cat "$work_dir/single/existing.txt.cafe")" = 'must not be replaced'
test ! -e "$work_dir/single/existing.txt.cafe.tmp"

touch "$work_dir/input/stray.tmp"
CAFE_PASSPHRASE='integration-passphrase' "$binary" encrypt "$work_dir/input/stray.tmp"
CAFE_PASSPHRASE='integration-passphrase' "$binary" encrypt "$work_dir/input/note.txt.decrypted"

cp "$work_dir/input/note.txt.cafe" "$work_dir/tampered/note.txt.cafe"
printf X | dd of="$work_dir/tampered/note.txt.cafe" bs=1 seek=30 conv=notrunc 2>/dev/null
if CAFE_PASSPHRASE='integration-passphrase' "$binary" decrypt "$work_dir/tampered"; then
    echo "Expected tampered ciphertext to be rejected" >&2
    exit 1
fi
test ! -e "$work_dir/tampered/note.txt.decrypted"
test ! -e "$work_dir/tampered/note.txt.decrypted.tmp"
test ! -e "$work_dir/tampered/note.txt.decrypted.verify.tmp"

mkdir "$work_dir/wrong-passphrase"
cp "$work_dir/input/blob.bin.cafe" "$work_dir/wrong-passphrase/blob.bin.cafe"
if CAFE_PASSPHRASE='wrong-passphrase' "$binary" decrypt "$work_dir/wrong-passphrase"; then
    echo "Expected incorrect passphrase to be rejected" >&2
    exit 1
fi
test ! -e "$work_dir/wrong-passphrase/blob.bin.decrypted"
test ! -e "$work_dir/wrong-passphrase/blob.bin.decrypted.tmp"
test ! -e "$work_dir/wrong-passphrase/blob.bin.decrypted.verify.tmp"

echo "Integration checks passed."
