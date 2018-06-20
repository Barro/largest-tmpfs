#!/bin/sh

set -xeu

WORKDIR=$(mktemp -d)
cleanup() {
    rm -rf "$WORKDIR"
}
trap cleanup EXIT

check_run_result() {
    if test "$TRAVIS_OS_NAME" = "osx"; then
        "$@" || return 0
        echo >&2 "Command $* unexpectedly succeeded!"
        return 1
    else
        "$@" && return 0
        echo >&2 "Command $* unexpectedly failed!"
        return 1
    fi
}

meson build-meson
ninja -C build-meson
check_run_result build-meson/largest-ramfs

bazel build :all
check_run_result bazel-bin/largest-ramfs

mkdir -p build-cmake
( cd build-cmake && cmake -GNinja .. )
ninja -C build-cmake
check_run_result build-cmake/largest-ramfs
