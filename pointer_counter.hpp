#pragma once

#include <unordered_map>
#include "mapped_view.hpp"

class PointerCounter {
public:
    PointerCounter(const MappedView& mapped_view);
    std::vector<std::pair<uint64_t, uint64_t>> getSortedPointersWithCounts() const;

private:
    std::unordered_map<uint64_t, uint64_t> value_counts_;
};