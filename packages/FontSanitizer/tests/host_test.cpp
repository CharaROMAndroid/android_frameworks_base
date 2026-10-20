#include "../jni/Sanitize.h"
#include <fcntl.h>
#include <unistd.h>
#include <iostream>
#include <vector>
int main(int argc, char** argv) {
    if (argc != 3) return 2;
    int fd = open(argv[1], O_RDONLY | O_CLOEXEC);
    if (fd < 0) return 3;
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
