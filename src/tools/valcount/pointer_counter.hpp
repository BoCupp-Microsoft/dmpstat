#pragma once

#include <unordered_map>
#include <vector>
#include "mapped_view.hpp"
#include "progress.hpp"

struct PointerValueInfo {
    uint64_t value;
    uint64_t count;
    uint64_t low_address;   // lowest dump-VA at which this value was found
    uint64_t high_address;  // highest dump-VA at which this value was found
};

class PointerCounter {
public:
    PointerCounter(const MappedView& mapped_view, ProgressReporter& progress);
    std::vector<PointerValueInfo> getSortedPointersWithCounts() const;

private:
    struct Entry {
        uint64_t count;
        uint64_t low_address;
        uint64_t high_address;
    };
    std::unordered_map<uint64_t, Entry> value_counts_;
};