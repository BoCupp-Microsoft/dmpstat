#pragma once

#include <cstdint>
#include <unordered_map>
#include <vector>

#include "dump_memory_region.hpp"
#include "progress.hpp"

struct PointerValueInfo {
    uint64_t value;
    uint64_t count;
    uint64_t low_address;   // lowest VA at which this value was found
    uint64_t high_address;  // highest VA at which this value was found
};

// Scans 8-byte-aligned qwords across a vector of DumpMemoryRegion entries and
// counts each value that looks like a valid 64-bit user-mode pointer. The
// regions can be the full set produced by DumpMemoryReader (as in valcount)
// or any filtered subset (e.g. just the regions inside the Oilpan cage).
class PointerCounter {
public:
    PointerCounter(const std::vector<dmpstat::DumpMemoryRegion>& regions,
                   ProgressReporter& progress);
    std::vector<PointerValueInfo> getSortedPointersWithCounts() const;

private:
    struct Entry {
        uint64_t count;
        uint64_t low_address;
        uint64_t high_address;
    };
    std::unordered_map<uint64_t, Entry> value_counts_;
};
