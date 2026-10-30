// Host-test-only substitute for libandroid. Does not emulate legacy ashmem.
#pragma once
#include <sys/stat.h>
#include <cstddef>
static inline size_t ASharedMemory_getSize(int fd) {
    struct stat st {};
    return fstat(fd, &st) == 0 && st.st_size > 0 ? static_cast<size_t>(st.st_size) : 0;
}
