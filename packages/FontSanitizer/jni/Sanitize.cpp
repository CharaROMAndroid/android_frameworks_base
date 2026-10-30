#include <cstddef>
#include "Sanitize.h"
#include <cerrno>
#include <cstring>
#include <android/sharedmem.h>
#include <sys/mman.h>
#include <unistd.h>
#include "opentype-sanitiser.h"
#include "ots-memory-stream.h"

namespace fontsanitizer {
namespace {
uint32_t U32(const uint8_t* p) {
    return (uint32_t(p[0]) << 24) | (uint32_t(p[1]) << 16)
            | (uint32_t(p[2]) << 8) | p[3];
}
class UnhintedContext final : public ots::OTSContext {
 public:
    ots::TableAction GetTableAction(uint32_t tag) override {
        // Hint execution and hint-dependent device metrics are never exported.
        switch (tag) {
            case 0x6670676d: // fpgm
            case 0x70726570: // prep
            case 0x63766172: // cvar (variation deltas for the removed cvt)
            case 0x63767420: // cvt
            case 0x68646d78: // hdmx
            case 0x4c545348: // LTSH
            case 0x56444d58: // VDMX
                return ots::TABLE_ACTION_DROP;
            default:
                return ots::TABLE_ACTION_DEFAULT;
        }
    }
};
bool CheckDirectory(const std::vector<uint8_t>& bytes) {
    // Intentionally no TTC, WOFF, or WOFF2 decompression.
    if (bytes.size() < 12 || (U32(bytes.data()) != 0x00010000
            && U32(bytes.data()) != 0x4f54544f)) return false;
    size_t count = (size_t(bytes[4]) << 8) | bytes[5];
    if (count == 0 || count > 128 || 12 + count * 16 > bytes.size()) return false;
    size_t total = 0;
    for (size_t i = 0; i < count; ++i) {
        const uint8_t* table = bytes.data() + 12 + i * 16;
        size_t offset = U32(table + 8), length = U32(table + 12);
        if (offset > bytes.size() || length > bytes.size() - offset
                || length > kMaxBytes - total) return false;
        total += length;
    }
    return true;
}
}
bool SanitizeFd(int fd, std::vector<uint8_t>* output) {
    output->clear();
    // SharedMemory uses ashmem on older kernels and memfd on newer ones. An ashmem
    // descriptor is a character device, so S_ISREG/pread is not a valid transport contract.
    // Query through the shared-memory API and map read-only, never open a caller's path.
    const size_t size = ASharedMemory_getSize(fd);
    if (size < 12 || size > kMaxBytes) return false;
    const void* mapping = mmap(nullptr, size, PROT_READ, MAP_SHARED, fd, 0);
    if (mapping == MAP_FAILED) return false;
    // No pointers into caller-controlled mappings reach OTS.
    std::vector<uint8_t> snapshot(size);
    memcpy(snapshot.data(), mapping, size);
    munmap(const_cast<void*>(mapping), size);
    if (!CheckDirectory(snapshot)) return false;
    UnhintedContext context;
    ots::ExpandingMemoryStream stream(4096, kMaxBytes);
    if (!context.Process(&stream, snapshot.data(), snapshot.size())) return false;
    const off_t length = stream.Tell();
    if (length <= 0 || uint64_t(length) > kMaxBytes) return false;
    const auto* start = static_cast<const uint8_t*>(stream.get());
    output->assign(start, start + length);
    return true;
}
}
