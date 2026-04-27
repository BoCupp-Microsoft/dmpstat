#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "dump_memory.hpp"
#include "dump_memory_region.hpp"

class SymbolResolver;

namespace dmpstat {

// Symbol-anchored description of the cppgc / Oilpan caged heap and the set of
// committed regions inside it. Constructed via OilpanHeap::discover() which
// resolves both globals (g_heap_base_, g_age_table_size_), reads them from
// the dump, and walks MemoryInfoListStream collecting the cage-intersecting
// MEM_COMMIT|MEM_PRIVATE regions as DumpMemoryRegion entries. Tools then feed
// `regions()` into summary/scanning routines (e.g. PointerCounter).
class OilpanHeap {
public:
    // Locate the cage and gather its committed regions. Returns std::nullopt
    // on any failure (with a diagnostic written to std::wcerr).
    static std::optional<OilpanHeap> discover(const SymbolResolver& sr,
                                              const RandomAccessReader& reader,
                                              void* dump_base,
                                              bool verbose);

    // Cage descriptor.
    uint64_t cage_base()                 const { return cage_base_; }
    uint64_t cage_reserved_size()        const { return cage_reserved_size_; }
    uint64_t age_table_size_raw()        const { return age_table_size_raw_; }
    const std::wstring& base_symbol_name() const { return base_symbol_name_; }
    const std::wstring& size_symbol_name() const { return size_symbol_name_; }

    // Card size (bytes) used to derive the reserved cage size from the
    // age-table-size global. Mirrors V8's kCardSizeInBytes.
    static constexpr uint64_t kCageCardSizeBytes = 4096;

    // Committed regions intersecting the cage, in ascending VA order.
    const std::vector<DumpMemoryRegion>& regions() const { return regions_; }

    // Sum of the cage-intersected committed bytes (regions()[i].size, clipped
    // to the cage range during discovery).
    uint64_t committed_bytes() const { return committed_bytes_; }

    // Sum of MEM_COMMIT|MEM_PRIVATE bytes in the whole process (from the same
    // MemoryInfoListStream walk). Useful as denominator in summaries.
    uint64_t total_private_commit() const { return total_private_commit_; }

private:
    OilpanHeap() = default;

    uint64_t cage_base_           = 0;
    uint64_t cage_reserved_size_  = 0;
    uint64_t age_table_size_raw_  = 0;
    std::wstring base_symbol_name_;
    std::wstring size_symbol_name_;
    std::vector<DumpMemoryRegion> regions_;
    uint64_t committed_bytes_       = 0;
    uint64_t total_private_commit_  = 0;
};

} // namespace dmpstat

