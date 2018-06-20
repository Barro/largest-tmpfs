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
