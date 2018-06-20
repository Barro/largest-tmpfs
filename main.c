#include <stdio.h>
#include <stdlib.h>

#include "largest-tmpfs.h"

int main()
{
    const char* tmpfs_path = largest_tmpfs_get(1024 * 1024);
    if (tmpfs_path == NULL) {
        return EXIT_FAILURE;
    }
    puts(tmpfs_path);
    return EXIT_SUCCESS;
}
