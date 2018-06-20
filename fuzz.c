#include "largest-ramfs.c"

#define AFL_PERSISTENT_ITERATIONS 40000

static struct ramfs_candidate ramfs_candidate_new(void)
{
    struct ramfs_candidate result = {
        .required_fs_free = 1024 * 1024
    };
    return result;
}

static void fuzz_one(const char* path)
{
    struct ramfs_candidate largest_candidate;
    largest_candidate = ramfs_candidate_new();
    iterate_proc_mounts(path, &largest_candidate);
    largest_candidate = ramfs_candidate_new();
    iterate_getmntent(path, &largest_candidate);
    largest_candidate = ramfs_candidate_new();
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
    __AFL_INIT();
#endif // #ifdef __AFL_HAVE_MANUAL_CONTROL

#ifdef __AFL_LOOP
    fuzz_one("/dev/null");
    while (__AFL_LOOP(AFL_PERSISTENT_ITERATIONS)) {
#else // #ifdef __AFL_LOOP
    bool iterating = true;
    while (iterating) {
        iterating = false;
#endif // #ifdef __AFL_LOOP

        fuzz_one(argv[1]);
    }

    return EXIT_SUCCESS;
}
