#ifndef _LARGEST_RAMFS_H_
#define _LARGEST_RAMFS_H_

#include <stdint.h>

/**
 * Returns the path to the largest writable in-memory file system
 *
 * If this can not find such writable file system or the file system,
 * this will return NULL. This will also return NULL when all of the
 * writable file systems have less free space than the minimum size in
 * bytes.
 *
 * This function will return a pointer to a memory that will be
 * invalidated by the next call. This function is not thread safe and
 * should preferably used only at program start-up.
 */
const char* largest_ramfs_get(const uint64_t minimum_free_bytes);

#endif /* _LARGEST_RAMFS_H_ */
