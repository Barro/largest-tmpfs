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

#ifndef LARGEST_RAMFS_H
#define LARGEST_RAMFS_H

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
const char* largest_tmpfs_get(const uint64_t minimum_free_bytes);

#endif /* LARGEST_RAMFS_H */
