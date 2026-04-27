#include "dump_memory.hpp"

#include <algorithm>
#include <dbghelp.h>

DumpMemoryReader::DumpMemoryReader(const MappedView& mapped_view)
    : mapped_view_(mapped_view) {
    buildIndex();
}

void DumpMemoryReader::buildIndex() {
    void* stream = nullptr;
    ULONG stream_size = 0;
    if (MiniDumpReadDumpStream(mapped_view_.get(), Memory64ListStream,
                               nullptr, &stream, &stream_size) && stream) {
        auto* list = static_cast<MINIDUMP_MEMORY64_LIST*>(stream);
        uint64_t offset = list->BaseRva;
        ranges_.reserve(static_cast<size_t>(list->NumberOfMemoryRanges));
        for (ULONG64 i = 0; i < list->NumberOfMemoryRanges; ++i) {
            const auto& d = list->MemoryRanges[i];
            ranges_.push_back({d.StartOfMemoryRange, d.DataSize, offset});
            offset += d.DataSize;
        }
    }
    stream = nullptr; stream_size = 0;
    if (MiniDumpReadDumpStream(mapped_view_.get(), MemoryListStream,
                               nullptr, &stream, &stream_size) && stream) {
        auto* list = static_cast<MINIDUMP_MEMORY_LIST*>(stream);
        for (ULONG i = 0; i < list->NumberOfMemoryRanges; ++i) {
            const auto& d = list->MemoryRanges[i];
            ranges_.push_back({d.StartOfMemoryRange, d.Memory.DataSize, d.Memory.Rva});
        }
    }
    std::sort(ranges_.begin(), ranges_.end(),
              [](const MemRange& a, const MemRange& b) { return a.va < b.va; });
}

size_t DumpMemoryReader::read(uint64_t addr, void* buf, size_t bytes) const {
    if (ranges_.empty() || bytes == 0) return 0;
    auto it = std::upper_bound(ranges_.begin(), ranges_.end(), addr,
        [](uint64_t v, const MemRange& r) { return v < r.va; });
    if (it == ranges_.begin()) return 0;
    --it;
    if (addr >= it->va + it->size) return 0;
    uint64_t local_off = addr - it->va;
    uint64_t avail = it->size - local_off;
    size_t to_copy = static_cast<size_t>(std::min<uint64_t>(bytes, avail));
    const BYTE* src = static_cast<const BYTE*>(mapped_view_.get()) + it->fileRva + local_off;
    std::memcpy(buf, src, to_copy);
    return to_copy;
}

bool DumpMemoryReader::contains(uint64_t addr, size_t bytes) const {
    if (bytes == 0) return true;
    if (ranges_.empty()) return false;
    auto it = std::upper_bound(ranges_.begin(), ranges_.end(), addr,
        [](uint64_t v, const MemRange& r) { return v < r.va; });
    if (it == ranges_.begin()) return false;
    --it;
    if (addr < it->va) return false;
    uint64_t local_off = addr - it->va;
    return (it->size - local_off) >= bytes;
}
