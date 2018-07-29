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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "largest-tmpfs.h"

#ifdef HAVE_CONFIG_H
#  include "config.h"
#else /* HAVE_CONFIG_H */
#  define LARGEST_TMPFS_VERSION "devbuild"
#  define LARGEST_TMPFS_SYSTEM "unknown"
#endif /* HAVE_CONFIG_H */

static void print_usage(const char* program_name, FILE* out)
{
    fprintf(out, "USAGE: %s [OPTION]\n", program_name);
    fputs("\n", out);
    fputs("OPTIONS:\n", out);
    fputs("  -h, --help  Show this help and exit\n", out);
    fputs("  --version   Show version information\n", out);
    fputs("\n", out);
    fputs(
"Prints the path to a memory based file system with the most free space when\n"
"no arguments are given. Does not print anything and returns with non-zero\n"
"value if there is no such file system available.\n", out);
}

int main(int argc, char* argv[])
{
    if (argc > 1) {
        if (strcmp(argv[1], "--version") == 0) {
            puts("largest-tmpfs " LARGEST_TMPFS_VERSION " " LARGEST_TMPFS_SYSTEM);
            return EXIT_SUCCESS;
        } else if (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0) {
            print_usage(argv[0], stdout);
            return EXIT_SUCCESS;
        } else {
            fprintf(stderr, "Unknown argument: %s\n", argv[1]);
            print_usage(argv[0], stderr);
            return EXIT_FAILURE;
        }
    }
    const char* tmpfs_path = largest_tmpfs_get(1024 * 1024);
    if (tmpfs_path == NULL) {
        return EXIT_FAILURE;
    }
    puts(tmpfs_path);
    return EXIT_SUCCESS;
}
