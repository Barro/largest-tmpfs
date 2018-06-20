#include <stdio.h>
#include <stdlib.h>

#include "largest-ramfs.h"

int main()
{
    const char* ramfs_path = largest_ramfs_get(1024 * 1024);
    if (ramfs_path == NULL) {
        return EXIT_FAILURE;
    }
    puts(ramfs_path);
    return EXIT_SUCCESS;
}
