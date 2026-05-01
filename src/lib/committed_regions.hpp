#pragma once

#include <cstdint>
#include <optional>
#include <vector>

#include "dump_memory.hpp"
#include "dump_memory_region.hpp"

namespace dmpstat {

// Result of intersecting a minidump's MemoryInfoListStream against a virtual
// address range. Use this to enumerate the committed pages that fall inside a
// virtual reservation (e.g. the cppgc cage, V8's pointer-compression cage,
// V8's code range, the V8 sandbox/trusted ranges).
struct CommittedRegionsInRange {
    // Committed regions (MEM_COMMIT|MEM_PRIVATE) clipped to the requested
    // [base, base+size) window, sorted by base. Each entry's `data` /
    // `captured_bytes` reflect what's actually present in the dump file.
    std::vector<DumpMemoryRegion> regions;

    // Sum of `regions[i].size` across the entire vector. Equals the in-range
    // committed (clipped) byte total regardless of how much was captured.
    uint64_t committed_bytes = 0;

    // Sum of MEM_COMMIT|MEM_PRIVATE bytes across the *entire* process (not
    // clipped to the range). Useful as a "share of process commit"
    // denominator for whichever range the caller is studying.
    uint64_t total_private_commit = 0;
};

// Walk MemoryInfoListStream from `dump_base` (a pointer into a mapped
// minidump file). For every MEM_COMMIT|MEM_PRIVATE region, intersect it with
// [base, base+size) and emit a clipped DumpMemoryRegion populated from the
// reader's captured bytes. Returns std::nullopt if the dump is missing
// MemoryInfoListStream or if the entry size doesn't match
// MINIDUMP_MEMORY_INFO. Diagnostics go to std::wcerr.
//
// The caller owns `[base, base+size)` semantics: the function does no
// alignment or wrap checking. Callers should ensure base+size doesn't
// overflow.
std::optional<CommittedRegionsInRange>
readCommittedRegionsInRange(const RandomAccessReader& reader,
                            void* dump_base,
                            uint64_t base,
                            uint64_t size,
                            bool verbose,
                            const wchar_t* log_label);

} // namespace dmpstat
