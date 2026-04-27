#include "pointer_counter.hpp"

#include <algorithm>
#include <cstring>
#include <cwchar>

// Helper: validate if a value could be a valid user-mode pointer on x64
// Windows. User space lives in [0x10000, 0x7FFEFFFF0000].
static bool IsValidUserModePointer(uint64_t value) {
    if (value < 0x10000) return false;
    if (value <= 0x7FFEFFFF0000ULL) return true;
    return false;
}

PointerCounter::PointerCounter(
    const std::vector<dmpstat::DumpMemoryRegion>& regions,
    ProgressReporter& progress) {

    // Total captured bytes -- denominator for the progress percentage.
    uint64_t total_bytes = 0;
    for (const auto& r : regions) total_bytes += r.captured_bytes;

    uint64_t bytes_processed = 0;
    const size_t region_count = regions.size();

    for (size_t i = 0; i < region_count; ++i) {
        const auto& r = regions[i];
        if (r.data == nullptr || r.captured_bytes < sizeof(uint64_t)) {
            bytes_processed += r.captured_bytes;
            continue;
        }

        // Round captured size down to an 8-byte boundary; we count
        // 8-byte-aligned qwords.
        const uint64_t aligned_size = r.captured_bytes & ~uint64_t{7};

        for (uint64_t offset = 0; offset < aligned_size; offset += sizeof(uint64_t)) {
            uint64_t value;
            std::memcpy(&value, r.data + offset, sizeof(uint64_t));

            if (IsValidUserModePointer(value)) {
                const uint64_t found_at = r.base + offset;
                auto [it, inserted] = value_counts_.try_emplace(
                    value, Entry{1, found_at, found_at});
                if (!inserted) {
                    auto& entry = it->second;
                    entry.count++;
                    if (found_at < entry.low_address)  entry.low_address  = found_at;
                    if (found_at > entry.high_address) entry.high_address = found_at;
                }
            }

            // Throttled status update every ~8 MiB of slot scans (actual
            // write is additionally time-throttled inside ProgressReporter).
            if ((offset & ((1ULL << 23) - 1)) == 0) {
                double pct = total_bytes == 0
                    ? 0.0
                    : (static_cast<double>(bytes_processed + offset) / total_bytes) * 100.0;
                wchar_t buf[128];
                swprintf_s(buf, L"Scanning memory range %llu/%llu (%.1f%%)",
                    static_cast<unsigned long long>(i + 1),
                    static_cast<unsigned long long>(region_count),
                    pct);
                progress.update(buf);
            }
        }

        bytes_processed += r.captured_bytes;
    }
}

std::vector<PointerValueInfo> PointerCounter::getSortedPointersWithCounts() const {
    std::vector<PointerValueInfo> sorted_values;
    sorted_values.reserve(value_counts_.size());
    for (const auto& [value, entry] : value_counts_) {
        sorted_values.push_back({value, entry.count, entry.low_address, entry.high_address});
    }
    std::sort(sorted_values.begin(), sorted_values.end(),
        [](const PointerValueInfo& a, const PointerValueInfo& b) {
            return a.count > b.count;
        });
    return sorted_values;
}
