FontSanitizer integration

Add FontSanitizer to PRODUCT_PACKAGES. The framework owns the shared hidden AIDL
and binds the explicit com.android.fontsanitizer/.FontSanitizerService component.
Only system UID may invoke sanitize, in addition to manifest UPDATE_FONTS binding
permission. No permissions are requested by this app.

The worker accepts regular file descriptors, copies at most 32 MiB into private
native storage, and accepts only raw sfnt TrueType/OpenType. TTC, WOFF and WOFF2
are rejected before OTS. The directory is limited to 128 tables, whose aggregate
declared input size is at most 32 MiB. Default OTS table handling validates
supported tables and drops unknown tables, never a passthrough override.
Rewritten output is at most 32 MiB and transferred in exact-sized SharedMemory
with write protection applied after unmapping the writable mapping.

A separate Java scheduler kills the isolated process after ten seconds. Each job
advances the process CPU soft limit from already consumed CPU time plus three
seconds; this is not an incorrectly reused lifetime three-second limit. Native
input/output bounds are not a hard total-process RAM cap. RLIMIT_AS is deliberately
not applied because ART reserves large virtual address ranges. Allocation failure,
native crash, worker death and timeout must all fail closed in the framework.
A compromised native parser remains untrusted; OTS is risk reduction, not a proof
that every accepted font is harmless. The framework must authenticate the result
against its own pending request and must not accept caller-provided receipts.

OTS source is pinned in third_party/ots/UPSTREAM, with its license.
There is no assumed AOSP OTS module. WOFF2 decoder sources are vendored and pinned
as a private libfontsanitizer_woff2dec module because an upstream libwoff2dec module
could not be verified. Its otherwise-unused decoder symbols are needed by the
unmodified OTS translation unit. It links the verified AOSP libbrotli static
module from external/brotli/Android.bp and libz. No decompression path is reachable
through this wrapper. Keep both pinned trees maintained for upstream security
updates.

Host verification used GCC 13 with AddressSanitizer and UndefinedBehaviorSanitizer,
real OTS and the pinned decoder sources, zlib and system Brotli. Sixteen valid
TTF/OTF fonts were accepted; fifteen upstream malformed TTFs and seven boundary/
format cases were rejected, with no sanitizer findings. The JNI translation unit
also passed g++ -Wall -Werror -fsyntax-only against OpenJDK 21 JNI headers.
The worker Java and generated shared AIDL also compile against Robolectric's
Android 17 framework jar with javac 21. This is not a platform build.
These checks do not compile Soong, APK packaging, Binder, SELinux,
on-device CPU/watchdog behavior or integration with the platform font parser.
A full product build and device tests remain required before shipping.

The service, parent client, and actual generated shared AIDL were also compiled
together against font-hardening/android-17.jar with javac -Xlint:all (excluding
deprecation/options warnings), with no diagnostics. Manifest assertions verified
direct boot and isolation, no sharedUserId, and no requested permissions.
All sixteen rewritten valid fonts were accepted on a second sanitizer pass and
produced byte-identical output, exercising the preview-then-server-resanitize path.

TrueType hint stripping

The worker drops fpgm, prep, cvt, cvar, hdmx, LTSH and VDMX. The pinned
OTS glyf implementation is locally modified to validate but remove simple and
composite glyph instructions, zero simple instructionLength and clear composite
WE_HAVE_INSTRUCTIONS flags. It rebuilds loca, zeros maxp interpreter resources,
sets maxZones to one and clears head flags 2/3/4. OTS recomputes table checksums
and checkSumAdjustment. CFF/CFF2 charstring hints retain upstream validation.
The receipt policy is v2-unhinted; previous sanitized receipts no longer verify.

Host ASAN/UBSAN tests retain all 38 corpus outcomes. Additional real hinted
LiberationSans fixtures exercise 1,484 simple and 849 composite instruction
programs, outline preservation, malformed discarded hint tables, poisoned
instruction bytes, complete table/font checksums, repeat sanitation and
FreeType rasterization. See tests/dehint_test.py for a reproducible host test.
This closes the retained TrueType bytecode path, not all native renderer risk.
No full product build or device verification has been run.
