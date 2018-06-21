#!/bin/sh

set -eu

echo "#define LARGEST_TMPFS_VERSION \"$(cat "$1")\"" > "$2"
echo "#define LARGEST_TMPFS_SYSTEM \"$(uname)\"" >> "$2"
