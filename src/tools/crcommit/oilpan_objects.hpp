#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

#include "dump_memory.hpp"
#include "oilpan_heap.hpp"
#include "progress.hpp"

class SymbolResolver;

namespace dmpstat {

// Aggregate counts/bytes for one cppgc class, keyed by GCInfoIndex.
struct OilpanClassEntry {
    uint32_t     gc_info_index = 0;
    uint64_t     count         = 0;
    uint64_t     bytes         = 0;     // sum of header+object bytes
    std::wstring class_name;            // "<unresolved>" if name lookup failed
};

// Result of the page classification + header walk.
struct OilpanObjectStats {
    // Page-level counts.
    uint64_t normal_page_count = 0;
    uint64_t normal_page_bytes = 0;     // 128 KiB * normal_page_count
    uint64_t large_page_count = 0;
    uint64_t large_page_bytes = 0;      // sum of system-page-rounded sizes
    uint64_t distinct_heap_count = 0;   // unique HeapBase pointer values

    // Per-allocation accounting (sum of header+object bytes).
    uint64_t live_count = 0;
    uint64_t live_bytes = 0;
    uint64_t free_count = 0;
    uint64_t free_bytes = 0;
    uint64_t lab_unaccounted_bytes = 0; // tail of normal pages where walk bailed

    // Sum of sub-allocations (live + free).
    uint64_t allocation_count() const { return live_count + free_count; }

    // GCInfoIndex -> aggregate. After class names are resolved this map is
    // updated in place via OilpanObjectStats::resolveClassNames().
    std::unordered_map<uint32_t, OilpanClassEntry> by_gc_info;
};

// Run the page classification + HeapObjectHeader walk over the cage's
// committed regions. Returns std::nullopt if struct layout could not be
// resolved from the PDB. On success, by_gc_info has class_name == empty;
// call resolveClassNames() to populate it via the GCInfoTable.
std::optional<OilpanObjectStats>
walkOilpanObjects(const OilpanHeap& heap,
                  const RandomAccessReader& reader,
                  const SymbolResolver& sr,
                  ProgressReporter& progress);

// Resolve gc_info_index -> class name by walking the
// cppgc::internal::GlobalGCInfoTable singleton's GCInfo array, looking up
// each entry's `trace` callback symbol (TraceTrait<X>::Trace) and extracting
// X. Class names that cannot be decoded are left blank.
void resolveClassNames(OilpanObjectStats& stats,
                       const RandomAccessReader& reader,
                       const SymbolResolver& sr);

} // namespace dmpstat
