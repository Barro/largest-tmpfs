/**
 * Copyright 2018 Jussi Judin
 *
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation
 * files (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use, copy,
 * modify, merge, publish, distribute, sublicense, and/or sell copies
 * of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include "largest-tmpfs.c"

static struct tmpfs_candidate tmpfs_candidate_new(void)
{
    struct tmpfs_candidate result = {0};
    result.required_fs_free = 1024 * 1024;
    return result;
}

static void fuzz_one(const char* path)
{
    struct tmpfs_candidate largest_candidate;
    largest_candidate = tmpfs_candidate_new();
    iterate_proc_mounts(path, &largest_candidate);
    largest_candidate = tmpfs_candidate_new();
    iterate_getmntent(path, &largest_candidate);
    largest_candidate = tmpfs_candidate_new();
    iterate_getvfsent(path, &largest_candidate);
}

int main(int argc, char* argv[])
{
    if (argc < 2) {
        fprintf(stderr, "Usage: %s filename\n", argv[0]);
        return EXIT_FAILURE;
    }
    {
        FILE* input = fopen(argv[1], "r");
        if (input == NULL) {
            fprintf(
                stderr, "Could not open the given filename: %s\n", argv[1]);
            return EXIT_FAILURE;
        }
        fclose(input);
    }

#ifdef __AFL_HAVE_MANUAL_CONTROL
    fuzz_one("/dev/null");
    fuzz_one("/etc/fstab");
    fuzz_one("/etc/mtab");
    fuzz_one("/etc/mnttab");
    fuzz_one("/proc/mounts");
    fuzz_one("/proc/self/mounts");
#  ifndef __AFL_LOOP
    __AFL_INIT();
#  endif /* __AFL_LOOP */
#endif /*__AFL_HAVE_MANUAL_CONTROL */

    {
        bool iterating = true;
#ifdef __AFL_LOOP
        while (__AFL_LOOP(40000)) {
#else /* __AFL_LOOP */
        while (iterating) {
            iterating = false;
#endif /* __AFL_LOOP */

            fuzz_one(argv[1]);
        }
    }

    return EXIT_SUCCESS;
}
