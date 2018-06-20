/**
 * A program that determines the largest usable memory based file
 * system path.
 */

#define _GNU_SOURCE

#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#if defined(__linux__)
#  include <mntent.h>
#  include <sys/statfs.h>
/* Not all Linux distros have linux/magic.h include available where */
/* TMPFS_MAGIC is defined. */
#  define TMPFS_MAGIC 0x01021994
#elif defined(__FreeBSD__) || defined(__OpenBSD__)
#  include <sys/mount.h>
#  include <sys/statvfs.h>
#elif defined(__NetBSD__)
#  include <sys/statvfs.h>
#elif defined(__sun)
#  include <sys/mnttab.h>
#  include <sys/statvfs.h>
#  include <sys/vfstab.h>
#endif /* __linux__ */

#include "largest-ramfs.h"

struct ramfs_candidate
{
    uint64_t required_fs_free;
    uint64_t fs_free;
    char fs_path[512];
};

static bool try_create_directory(const char* path)
{
    const char* path_end;
    char* template_path_end;
    char* template_end;
    const char suffix[] = "/.ramfs.XXXXXX";
    char template[sizeof(((struct ramfs_candidate*)0)->fs_path) + sizeof(suffix)] = {0};

    /* Strip the last slash */
    path_end = path + strlen(path);
    while (path < path_end && *(path_end - 1) == '/') {
        path_end--;
    }
    assert(path <= path_end);
    if (path_end == path) {
        return false;
    }

    if (sizeof(template) < (path_end - path) + sizeof(suffix)) {
        return false;
    }

    memcpy(template, path, path_end - path);
    template_path_end = template + (path_end - path);
    memcpy(template_path_end, suffix, sizeof(suffix));
    template_end = template_path_end + sizeof(suffix) - 1;
    assert(template_end < template + sizeof(template));

    {
        char* result = mkdtemp(template);
        if (result == NULL) {
            return false;
        }
        rmdir(result);
    }
    return true;
}

static bool is_path_ramfs(const char* fs_path)
{
#if defined(__linux__)
    struct statfs stats = {0};
    if (statfs(fs_path, &stats) != 0) {
        return false;
    }
    if (stats.f_type == TMPFS_MAGIC) {
        return true;
    }
#elif defined(__FreeBSD__) || defined(__OpenBSD__)
    struct statfs stats = {0};
    if (statfs(fs_path, &stats) != 0) {
        return false;
    }
    if (strcmp(stats.f_fstypename, "tmpfs") == 0) {
        return true;
    }
#  ifdef __OpenBSD__
    if (strcmp(stats.f_fstypename, "mfs") == 0) {
        return true;
    }
#  endif /* __OpenBSD */
#elif defined(__NetBSD__)
    struct statvfs stats = {0};
    if (statvfs(fs_path, &stats) != 0) {
        return false;
    }
    if (strcmp(stats.f_fstypename, "tmpfs") == 0) {
        return true;
    }
#elif defined(__sun)
    struct statvfs stats = {0};
    if (statvfs(fs_path, &stats) != 0) {
        return false;
    }
    if (strcmp(stats.f_basetype, "tmpfs") == 0) {
        return true;
    }
#endif
    return false;
}

static uint64_t get_fs_size(const char* fs_path)
{
#if defined(__linux__)
    struct statfs stats = {0};
    statfs(fs_path, &stats);
    return (uint64_t)stats.f_bavail * (uint64_t)stats.f_frsize;
#elif defined(__FreeBSD__) || defined(__NetBSD__) || defined(__OpenBSD__)
    struct statvfs stats = {0};
    statvfs(fs_path, &stats);
    return (uint64_t)stats.f_bavail * (uint64_t)stats.f_frsize;
#elif defined(__sun)
    struct statvfs stats = {0};
    statvfs(fs_path, &stats);
    return (uint64_t)stats.f_bavail * (uint64_t)stats.f_frsize;
#else
    return 0;
#endif
}

static uint64_t read_ramfs_free(const char* fs_path)
{
    if (!is_path_ramfs(fs_path)) {
        return 0;
    }
    return get_fs_size(fs_path);
}

static bool assign_if_freer_fs_path(
    const char* fs_path, struct ramfs_candidate* largest_candidate)
{
    uint64_t fs_free = read_ramfs_free(fs_path);
    if (fs_free < largest_candidate->required_fs_free) {
        return false;
    }
    if (fs_free <= largest_candidate->fs_free) {
        return false;
    }
    if (!try_create_directory(fs_path)) {
        return false;
    }
    {
        size_t fs_path_len = strlen(fs_path);
        if (sizeof(largest_candidate->fs_path) <= fs_path_len) {
            return false;
        }
        largest_candidate->fs_free = fs_free;
        memcpy(largest_candidate->fs_path, fs_path, fs_path_len);
        largest_candidate->fs_path[fs_path_len] = '\0';
    }
    return true;
}

static void iterate_proc_mounts(
    const char* proc_mounts, struct ramfs_candidate* largest_candidate)
{
    char mount_line[512] = "";

    /* Try to figure out other ramfs locations based on device
       mountpoints. This is Linux specific thing: */
    FILE* mounts_fp = fopen(proc_mounts, "r");
    if (mounts_fp == NULL) {
        return;
    }

    while (fgets(mount_line, sizeof(mount_line), mounts_fp) != NULL) {
        char* path_end;
        char* fs_path = strchr(mount_line, ' ');
        if (fs_path == NULL) {
            continue;
        }
        fs_path++;
        path_end = strchr(fs_path, ' ');
        if (path_end == NULL) {
            continue;
        }
        *path_end = '\0';
        assign_if_freer_fs_path(fs_path, largest_candidate);
    }

    fclose(mounts_fp);
}

static void iterate_getfsstat(struct ramfs_candidate* largest_candidate)
{
#if defined(__FreeBSD__) || defined(__OpenBSD__)
    int i;
    int mounted_fs = getfsstat(NULL, 0, MNT_NOWAIT);
    int allocated_fs = mounted_fs + 1;
    struct statfs* fs_list = calloc(allocated_fs, sizeof(struct statfs));
    if (fs_list == NULL) {
        return;
    }
#  if defined(__FreeBSD__) || defined(__OpenBSD__)
    int returned_fs = getfsstat(fs_list, sizeof(struct statfs) * allocated_fs, MNT_NOWAIT);
    const struct statfs* current_fs = fs_list;
#  elif defined(__NetBSD__)
    int returned_fs = getvfsstat(fs_list, sizeof(struct statvfs) * allocated_fs, MNT_NOWAIT);
    const struct statvfs* current_fs = fs_list;
#  endif
    if (returned_fs == -1) {
        free(fs_list);
        return;
    }
    for (i = 0; i < returned_fs; i++, current_fs++) {
        assign_if_freer_fs_path(current_fs->f_mntonname, largest_candidate);
    }
    free(fs_list);
#else
    (void)largest_candidate;
#endif
}

static void iterate_getmntent(const char* path, struct ramfs_candidate* largest_candidate)
{
#if defined(__linux__)
    struct mntent* mountpoint = NULL;
    FILE* mnttab = setmntent(path, "r");
    if (mnttab == NULL) {
        return;
    }
    while ((mountpoint = getmntent(mnttab)) != NULL) {
        assign_if_freer_fs_path(mountpoint->mnt_dir, largest_candidate);
    }
    endmntent(mnttab);
#elif defined(__sun)
    struct mnttab mountpoint = {0};
    struct mnttab ramfs_mountpoint = { .mnt_fstype = "tmpfs" };
    FILE* mnttab = fopen(path, "r");
    if (mnttab == NULL) {
        return;
    }
    while (getmntany(mnttab, &mountpoint, &ramfs_mountpoint) == 0
           && mountpoint.mnt_mountp != NULL) {
        assign_if_freer_fs_path(mountpoint.mnt_mountp, largest_candidate);
    }
    fclose(mnttab);
#else
    (void)path;
    (void)largest_candidate;
#endif
}

static void iterate_getvfsent(
    const char* path, struct ramfs_candidate* largest_candidate)
{
#if defined(__sun)
    struct vfstab mountpoint = {0};
    struct vfstab ramfs_mountpoint = { .vfs_fstype = "tmpfs" };
    FILE* vfstab = fopen(path, "r");
    if (vfstab == NULL) {
        return;
    }
    while (getvfsany(vfstab, &mountpoint, &ramfs_mountpoint) == 0
           && mountpoint.vfs_mountp != NULL) {
        assign_if_freer_fs_path(mountpoint.vfs_mountp, largest_candidate);
    }
    fclose(vfstab);
#else
    (void)path;
    (void)largest_candidate;
#endif
}

const char* largest_ramfs_get(uint64_t minimum_free_bytes)
{
    size_t i;
    struct ramfs_candidate largest_candidate = {0};
    /* First let's guess couple of locations in case we are inside a */
    /* container or other faked file system without /proc/ access but */
    /* possibly with some ramfs accesses: */
    const char* const ramfs_guesses[] = {
        "/var/shm",
        "/dev/shm",
        "/run/shm",
        "/tmp"
    };
    assert(minimum_free_bytes > 0);
    largest_candidate.required_fs_free = minimum_free_bytes;

    for (i = 0; i < sizeof(ramfs_guesses) / sizeof(*ramfs_guesses); i++) {
        const char* fs_path = ramfs_guesses[i];
        assign_if_freer_fs_path(fs_path, &largest_candidate);
    }

    /* NetBSD and Linux */
    iterate_proc_mounts("/proc/mounts", &largest_candidate);
    /* Just Linux */
    iterate_proc_mounts("/proc/self/mounts", &largest_candidate);

    iterate_getfsstat(&largest_candidate);

    /* Linux */
    iterate_getmntent("/etc/mtab", &largest_candidate);
    iterate_getmntent("/etc/fstab", &largest_candidate);
    /* SunOS */
    iterate_getmntent("/etc/mnttab", &largest_candidate);

    iterate_getvfsent("/etc/vfstab", &largest_candidate);

    if (largest_candidate.fs_free == 0) {
        return NULL;
    }

    {
        size_t fs_path_len = strlen(largest_candidate.fs_path);
        static char* result = NULL;
        if (result != NULL) {
            free(result);
        }
        result = calloc(1, fs_path_len + 1);
        if (result == NULL) {
            return NULL;
        }
        memcpy(result, largest_candidate.fs_path, fs_path_len);
        return result;
    }
}
