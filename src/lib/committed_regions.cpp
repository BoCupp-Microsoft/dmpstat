#include "committed_regions.hpp"

#include <windows.h>
#include <dbghelp.h>

#include <algorithm>
#include <iostream>

namespace dmpstat {

std::optional<CommittedRegionsInRange>
readCommittedRegionsInRange(const RandomAccessReader& reader,
                            void* dump_base,
                            uint64_t base,
                            uint64_t size,
                            bool verbose,
                            const wchar_t* log_label) {
    void* stream = nullptr;
    ULONG stream_size = 0;
    if (!MiniDumpReadDumpStream(dump_base, MemoryInfoListStream, nullptr,
                                &stream, &stream_size)
        || stream == nullptr) {
        std::wcerr << L"Error: dump does not contain a MemoryInfoListStream."
                   << std::endl;
        return std::nullopt;
    }
    auto* header = static_cast<MINIDUMP_MEMORY_INFO_LIST*>(stream);
    if (header->SizeOfEntry < sizeof(MINIDUMP_MEMORY_INFO)) {
        std::wcerr << L"Error: unexpected MINIDUMP_MEMORY_INFO entry size: "
                   << header->SizeOfEntry << std::endl;
        return std::nullopt;
    }

    CommittedRegionsInRange out;
    const uint64_t range_end = base + size;
    const BYTE* entries_base =
        static_cast<const BYTE*>(stream) + header->SizeOfHeader;

    for (ULONG64 i = 0; i < header->NumberOfEntries; ++i) {
        const auto* info = reinterpret_cast<const MINIDUMP_MEMORY_INFO*>(
            entries_base + i * header->SizeOfEntry);
        if (info->State != MEM_COMMIT) continue;
        if (info->Type  != MEM_PRIVATE) continue;

        out.total_private_commit += info->RegionSize;

        const uint64_t r_start = info->BaseAddress;
        const uint64_t r_end   = r_start + info->RegionSize;
        const uint64_t lo = std::max(r_start, base);
        const uint64_t hi = std::min(r_end,   range_end);
        if (lo >= hi) continue;

        DumpMemoryRegion region{};
        region.base = lo;
        region.size = hi - lo;
        const auto span = reader.captured_at(lo);
        region.data = span.data;
        region.captured_bytes = std::min<uint64_t>(region.size, span.size);

        if (verbose) {
            std::wcerr << L"[" << (log_label ? log_label : L"range")
                       << L"]  region 0x" << std::hex << region.base
                       << L"..0x" << (region.base + region.size) << std::dec
                       << L" size=" << region.size
                       << L" captured=" << region.captured_bytes << std::endl;
        }

        out.committed_bytes += region.size;
        out.regions.push_back(region);
    }

    std::sort(out.regions.begin(), out.regions.end(),
              [](const DumpMemoryRegion& a, const DumpMemoryRegion& b) {
                  return a.base < b.base;
              });

    return out;
}

} // namespace dmpstat
