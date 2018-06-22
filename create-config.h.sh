#!/bin/sh

set -eu

VERSION_FILE=$1
OUT_FILE=$2
{
    echo "#ifndef LARGEST_TMPFS_CONFIG_H"
    echo "#define LARGEST_TMPFS_CONFIG_H"
    echo
    echo "#define LARGEST_TMPFS_VERSION \"$(cat "$VERSION_FILE")\"" || exit 1
    echo "#define LARGEST_TMPFS_SYSTEM \"$(uname)\""
    echo
    echo "#endif"
} > "$OUT_FILE"
