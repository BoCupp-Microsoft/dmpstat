#pragma once

#include <cstdint>
#include <string_view>
#include <vector>

#include "dump_memory_region.hpp"
#include "progress.hpp"

namespace dmpstat {

// Aggregate counts of printable byte runs found by scanPrintableStrings().
struct StringScanStats {
    uint64_t ascii_count = 0;
    uint64_t ascii_bytes = 0;
    uint64_t utf16_count = 0;
    uint64_t utf16_bytes = 0;
};

// Heuristic printable-string scan over a vector of captured regions. Counts
// runs of:
//   * printable ASCII bytes (0x20..0x7E) of length >= min_chars
//   * "wide ASCII" UTF-16LE characters (printable ASCII low byte, 0x00 high
//     byte) of length >= min_chars
//
// The two passes don't double-count: a UTF-16 char's 0x00 high byte breaks
// the ASCII run. Operates on `captured_bytes` only; regions with no captured
// data are skipped.
//
// `progress_label` is shown as the per-region progress prefix
// (e.g. "Scanning Oilpan strings"); pass empty to disable per-region updates.
StringScanStats
scanPrintableStrings(const std::vector<DumpMemoryRegion>& regions,
                     ProgressReporter& progress,
                     std::wstring_view progress_label,
                     size_t min_chars);

} // namespace dmpstat
