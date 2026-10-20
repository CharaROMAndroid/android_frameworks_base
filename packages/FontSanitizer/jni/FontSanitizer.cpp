#include <jni.h>
#include <cstddef>
#include "Sanitize.h"
#include <sys/resource.h>
#include <time.h>
#include <limits>
#include <vector>

extern "C" JNIEXPORT jbyteArray JNICALL
Java_com_android_fontsanitizer_FontSanitizerService_nativeSanitize(
        JNIEnv* env, jclass, jint fd) {
    // RLIMIT_CPU is process-lifetime, not a per-request stopwatch. Advance
    // the soft ceiling from consumed process CPU for each serialized request.
    timespec used {};
    rlimit oldLimit {};
    if (clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &used) != 0
            || getrlimit(RLIMIT_CPU, &oldLimit) != 0) return nullptr;
    rlim_t ceiling = static_cast<rlim_t>(used.tv_sec) + 3;
    if (oldLimit.rlim_max != RLIM_INFINITY && ceiling > oldLimit.rlim_max) return nullptr;
    rlimit limit {ceiling, oldLimit.rlim_max};
    if (setrlimit(RLIMIT_CPU, &limit) != 0) return nullptr;
    std::vector<uint8_t> output;
    if (!fontsanitizer::SanitizeFd(fd, &output) || output.empty()
            || output.size() > fontsanitizer::kMaxBytes) return nullptr;
    jbyteArray result = env->NewByteArray(static_cast<jsize>(output.size()));
    if (result != nullptr) {
        env->SetByteArrayRegion(result, 0, static_cast<jsize>(output.size()),
                reinterpret_cast<const jbyte*>(output.data()));
    }
    return result;
}
