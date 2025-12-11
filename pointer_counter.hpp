#pragma once

#include <unordered_map>
#include "mapped_file.hpp"

class PointerCounter {
public:
    PointerCounter(const MappedFile& mapped_file);
    std::vector<std::pair<uint64_t, uint64_t>> getSortedPointersWithCounts() const;

private:
    std::unordered_map<uint64_t, uint64_t> value_counts_;
};