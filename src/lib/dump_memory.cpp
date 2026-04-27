#include "dump_memory.hpp"

#include <algorithm>
#include <windows.h>
#include <dbghelp.h>

DumpMemoryReader::DumpMemoryReader(const MappedView& mapped_view) {
    buildRegions(mapped_view);
}

void DumpMemoryReader::buildRegions(const MappedView& mapped_view) {
    void* stream = nullptr;
    ULONG stream_size = 0;
    if (MiniDumpReadDumpStream(mapped_view.get(), Memory64ListStream,
                               nullptr, &stream, &stream_size) && stream) {
        auto* list = static_cast<MINIDUMP_MEMORY64_LIST*>(stream);
        uint64_t offset = list->BaseRva;
        regions_.reserve(static_cast<size_t>(list->NumberOfMemoryRanges));
        for (ULONG64 i = 0; i < list->NumberOfMemoryRanges; ++i) {
            const auto& d = list->MemoryRanges[i];
            const uint8_t* data = static_cast<const uint8_t*>(mapped_view.get())
                                  + offset;
            regions_.push_back({d.StartOfMemoryRange, d.DataSize, data, d.DataSize});
            offset += d.DataSize;
        }
    }
    stream = nullptr; stream_size = 0;
    if (MiniDumpReadDumpStream(mapped_view.get(), MemoryListStream,
                               nullptr, &stream, &stream_size) && stream) {
        auto* list = static_cast<MINIDUMP_MEMORY_LIST*>(stream);
        for (ULONG i = 0; i < list->NumberOfMemoryRanges; ++i) {
            const auto& d = list->MemoryRanges[i];
            const uint8_t* data = static_cast<const uint8_t*>(mapped_view.get())
                                  + d.Memory.Rva;
            regions_.push_back({d.StartOfMemoryRange, d.Memory.DataSize,
                                data, d.Memory.DataSize});
        }
    }
    std::sort(regions_.begin(), regions_.end(),
              [](const dmpstat::DumpMemoryRegion& a,
                 const dmpstat::DumpMemoryRegion& b) { return a.base < b.base; });
}

RandomAccessReader::RandomAccessReader(
    const std::vector<dmpstat::DumpMemoryRegion>& regions)
    : regions_(regions) {}

size_t RandomAccessReader::read(uint64_t addr, void* buf, size_t bytes) const {
    if (regions_.empty() || bytes == 0) return 0;
    auto it = std::upper_bound(regions_.begin(), regions_.end(), addr,
        [](uint64_t v, const dmpstat::DumpMemoryRegion& r) { return v < r.base; });
    if (it == regions_.begin()) return 0;
    --it;
    if (it->data == nullptr || it->captured_bytes == 0) return 0;
    if (addr >= it->base + it->captured_bytes) return 0;
    uint64_t local_off = addr - it->base;
    uint64_t avail = it->captured_bytes - local_off;
    size_t to_copy = static_cast<size_t>(std::min<uint64_t>(bytes, avail));
    std::memcpy(buf, it->data + local_off, to_copy);
    return to_copy;
}

bool RandomAccessReader::contains(uint64_t addr, size_t bytes) const {
    if (bytes == 0) return true;
    if (regions_.empty()) return false;
    auto it = std::upper_bound(regions_.begin(), regions_.end(), addr,
        [](uint64_t v, const dmpstat::DumpMemoryRegion& r) { return v < r.base; });
    if (it == regions_.begin()) return false;
    --it;
    if (it->data == nullptr) return false;
    if (addr < it->base) return false;
    uint64_t local_off = addr - it->base;
    return (it->captured_bytes - local_off) >= bytes;
}

RandomAccessReader::CapturedSpan
RandomAccessReader::captured_at(uint64_t addr) const {
    if (regions_.empty()) return {};
    auto it = std::upper_bound(regions_.begin(), regions_.end(), addr,
        [](uint64_t v, const dmpstat::DumpMemoryRegion& r) { return v < r.base; });
    if (it == regions_.begin()) return {};
    --it;
    if (it->data == nullptr || it->captured_bytes == 0) return {};
    if (addr >= it->base + it->captured_bytes) return {};
    uint64_t local_off = addr - it->base;
    size_t avail = static_cast<size_t>(it->captured_bytes - local_off);
    return {it->data + local_off, avail};
}
