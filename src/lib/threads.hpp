#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace dmpstat {

// One thread from MINIDUMP_THREAD_LIST_STREAM, augmented with the optional
// name from MINIDUMP_THREAD_NAME_LIST_STREAM (Win10+ minidumps).
struct ThreadInfo {
    uint32_t     thread_id   = 0;
    std::wstring name;          // empty if no name list / no entry for tid
    uint64_t     teb          = 0;
    uint64_t     stack_start  = 0;  // VA of captured stack memory start
    uint64_t     stack_size   = 0;  // bytes captured (may be a fraction of
                                    // the full reservation)
};

// Read the thread list (and names, if present) from the minidump mapped at
// `dump_base`. Returns std::nullopt only if MINIDUMP_THREAD_LIST is missing.
// `name` is populated only for threads whose tid appears in the names stream.
std::optional<std::vector<ThreadInfo>> readThreads(void* dump_base);

} // namespace dmpstat
