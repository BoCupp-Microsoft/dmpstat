#include <windows.h>
#include <algorithm>
#include <dbghelp.h>
#include "pointer_counter.hpp"

// Helper function to validate if a value could be a valid user-mode pointer
bool IsValidUserModePointer(UINT64 value) {
    // On 64-bit Windows, valid user-mode pointers are:
    // - Between 0x00010000 and 0x7FFEFFFF0000 (user space)
    // - Must be properly aligned (we handle this by only processing 8-byte aligned values in the caller)
    
    if (value < 0x10000) {
        return false;
    }
    
    if (value <= 0x7FFEFFFF0000ULL) {
        // Valid pointer path
        return true;
    }
    
    return false;
}

PointerCounter::PointerCounter(const MappedView& mapped_view, ProgressReporter& progress) {
    // Read memory list stream
    void* stream = nullptr;
    ULONG stream_size = 0;

    THROW_IF_WIN32_BOOL_FALSE(MiniDumpReadDumpStream(mapped_view.get(), Memory64ListStream, nullptr, &stream, &stream_size));

    auto memory_list = static_cast<PMINIDUMP_MEMORY64_LIST>(stream);
    const ULONG64 range_count = memory_list->NumberOfMemoryRanges;

    // Precompute total bytes so we can report overall percent complete.
    ULONG64 total_bytes = 0;
    for (ULONG64 i = 0; i < range_count; i++) {
        total_bytes += memory_list->MemoryRanges[i].DataSize;
    }

    ULONG64 bytes_processed = 0;
    RVA64 current_rva = memory_list->BaseRva;

    for (ULONG64 i = 0; i < range_count; i++) {
        const MINIDUMP_MEMORY_DESCRIPTOR64& memory_desc = memory_list->MemoryRanges[i];

        // Get pointer to memory data in dump file
        BYTE* memory_data = static_cast<BYTE*>(mapped_view.get()) + current_rva;

        // Process 64-bit values at 8-byte aligned boundaries
        ULONG64 aligned_size = memory_desc.DataSize & ~7ULL; // Round down to 8-byte boundary

        for (ULONG64 offset = 0; offset < aligned_size; offset += sizeof(UINT64)) {
            UINT64 value = *reinterpret_cast<UINT64*>(memory_data + offset);

            // Only count values that could be valid user-mode pointers
            if (IsValidUserModePointer(value)) {
                const uint64_t found_at = memory_desc.StartOfMemoryRange + offset;
                auto [it, inserted] = value_counts_.try_emplace(value, Entry{1, found_at, found_at});
                if (!inserted) {
                    auto& entry = it->second;
                    entry.count++;
                    if (found_at < entry.low_address) entry.low_address = found_at;
                    if (found_at > entry.high_address) entry.high_address = found_at;
                }
            }

            // Throttled status update every ~1M values (actual write is
            // additionally time-throttled inside ProgressReporter).
            if ((offset & ((1ULL << 23) - 1)) == 0) {
                double pct = total_bytes == 0
                    ? 0.0
                    : (static_cast<double>(bytes_processed + offset) / total_bytes) * 100.0;
                wchar_t buf[128];
                swprintf_s(buf, L"Scanning memory range %llu/%llu (%.1f%%)",
                    static_cast<unsigned long long>(i + 1),
                    static_cast<unsigned long long>(range_count),
                    pct);
                progress.update(buf);
            }
        }

        bytes_processed += memory_desc.DataSize;
        current_rva += memory_desc.DataSize;
    }
}

std::vector<PointerValueInfo> PointerCounter::getSortedPointersWithCounts() const {
    std::vector<PointerValueInfo> sorted_values;
    sorted_values.reserve(value_counts_.size());
    for (const auto& [value, entry] : value_counts_) {
        sorted_values.push_back({value, entry.count, entry.low_address, entry.high_address});
    }

    // Sort by count (descending)
    std::sort(sorted_values.begin(), sorted_values.end(),
        [](const PointerValueInfo& a, const PointerValueInfo& b) { return a.count > b.count; });

    return sorted_values;
}