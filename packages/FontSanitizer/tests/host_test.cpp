#include "../jni/Sanitize.h"
#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>
#include <iostream>
#include <vector>
int main(int argc, char** argv) {
    if (argc != 3) return 2;
    int fd = open(argv[1], O_RDONLY | O_CLOEXEC);
    if (fd < 0) return 3;
    // Exercise the production shared-memory transport, not a data-file FD.
    int memory = memfd_create("font-test-input", MFD_CLOEXEC | MFD_ALLOW_SEALING);
    if (memory < 0) return 6;
    char buffer[8192];
    ssize_t count;
    while ((count = read(fd, buffer, sizeof(buffer))) > 0) {
        if (write(memory, buffer, count) != count) return 7;
    }
    close(fd);
    if (count < 0 || fcntl(memory, F_ADD_SEALS,
            F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL) != 0) return 8;
    fd = memory;
    std::vector<uint8_t> out;
    bool accepted = fontsanitizer::SanitizeFd(fd, &out);
    close(fd);
    if (accepted) {
        int result = open(argv[2], O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
        if (result < 0) return 4;
        size_t n = 0;
        while (n < out.size()) {
            ssize_t wrote = write(result, out.data() + n, out.size() - n);
            if (wrote <= 0) return 5;
            n += wrote;
        }
        close(result);
    }
    return accepted ? 0 : 1;
}
