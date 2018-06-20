#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "largest-tmpfs.h"

#ifndef LARGEST_TMPFS_VERSION
#define LARGEST_TMPFS_VERSION devbuild
#endif /* LARGEST_TMPFS_VERSION */

#define STR_MACRO_VALUE(value) STR_MACRO_VALUE_(value)
#define STR_MACRO_VALUE_(value) #value

int main(int argc, char* argv[])
{
    if (argc > 1) {
        if (strcmp(argv[1], "--version") == 0) {
            puts("largest-tmpfs " STR_MACRO_VALUE(LARGEST_TMPFS_VERSION));
            return EXIT_SUCCESS;
        }
    }
    const char* tmpfs_path = largest_tmpfs_get(1024 * 1024);
    if (tmpfs_path == NULL) {
        return EXIT_FAILURE;
    }
    puts(tmpfs_path);
    return EXIT_SUCCESS;
}
