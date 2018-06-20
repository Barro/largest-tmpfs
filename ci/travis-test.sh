#!/bin/sh

set -xeu

WORKDIR=$(mktemp -d)
cleanup() {
    rm -rf "$WORKDIR"
}
trap cleanup EXIT

check_run_result() {
    # OS X is way harder to support than Linux or BSD, as there is no
    # comparable file system to tmpfs in there. Would require to
    # figure out how to read block device types until a ram:// type is
    # encountered or not without diskutil.
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
check_run_result build-meson/largest-tmpfs

bazel build :all
check_run_result bazel-bin/largest-tmpfs

mkdir -p build-cmake
( cd build-cmake && cmake -GNinja .. )
ninja -C build-cmake
check_run_result build-cmake/largest-tmpfs
