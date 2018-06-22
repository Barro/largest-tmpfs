#!/bin/sh

set -xeu

WORKDIR=$(mktemp -d)
cleanup() {
    rm -rf "$WORKDIR"
}
trap cleanup EXIT

test_installation()
{
    largest-tmpfs --version || return 1
    echo "#include <largest-tmpfs.h>" > "$WORKDIR"/header.c
    echo "void test_lib(void) { largest_tmpfs_get(1024); }" >> "$WORKDIR"/header.c
    flags=$(pkg-config --cflags --libs liblargest-tmpfs) || return 1
    cc -shared -c $flags "$WORKDIR"/header.c || return 1
}

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

create_asan_bazelrc() {
    {
        echo build --strip=never
        echo build --copt -fsanitize=address
        echo build --copt -O1
        echo build --copt -fno-omit-frame-pointer
        echo build --linkopt -fsanitize=address
    } > "$1"
}

meson build-meson
ninja -C build-meson
check_run_result build-meson/largest-tmpfs
sudo ninja -C build-meson install
test_installation
sudo ninja -C build-meson uninstall
if test_installation; then
    echo >&2 "Meson uninstallation failed!"
    exit 1
fi

bazel test ...:all
check_run_result bazel-bin/largest-tmpfs
bazel test --run_under='valgrind --quiet --error-exitcode=1 --leak-check=full --track-origins=yes' ...:all
create_asan_bazelrc .bazelrc.asan
bazel --bazelrc=.bazelrc.asan test ...:all

mkdir -p build-cmake
( cd build-cmake && cmake -GNinja .. )
ninja -C build-cmake
check_run_result build-cmake/largest-tmpfs
sudo ninja -C build-cmake install
test_installation
# No uninstallation support in CMake...
