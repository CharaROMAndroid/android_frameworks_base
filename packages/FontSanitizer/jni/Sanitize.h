#pragma once
#include <cstdint>
#include <cstddef>
#include <vector>
namespace fontsanitizer {
constexpr size_t kMaxBytes = 32u * 1024u * 1024u;
bool SanitizeFd(int fd, std::vector<uint8_t>* output);
}
