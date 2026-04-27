#pragma once

#include <cstdint>
#include <cstring>
#include <optional>
#include <vector>
#include <windows.h>
#include "mapped_view.hpp"

// Random-access reader for the captured memory in a Windows minidump.
// Indexes both Memory64ListStream (full-memory dumps) and MemoryListStream
// (smaller dumps), letting callers fetch arbitrary byte ranges by
// virtual address.
class DumpMemoryReader {
public:
    explicit DumpMemoryReader(const MappedView& mapped_view);

    // Copy up to `bytes` bytes starting at virtual address `addr` into `buf`.
    // Returns the number of bytes actually copied (0 when the address is
    // entirely outside any captured range, or when `bytes` is 0).
    // A short read at the tail of a captured range is allowed.
    size_t read(uint64_t addr, void* buf, size_t bytes) const;

    // Typed convenience: returns std::nullopt if the full sizeof(T) bytes are
    // not all available at `addr`.
    template <typename T>
    std::optional<T> read(uint64_t addr) const {
        T value{};
        if (read(addr, &value, sizeof(T)) != sizeof(T)) return std::nullopt;
        return value;
    }

    // Returns true if `bytes` starting at `addr` are fully present in the dump.
    bool contains(uint64_t addr, size_t bytes) const;

    // A contiguous run of captured bytes from the mapped dump file. `data` is
    // a pointer into the file mapping; `size` is how many valid bytes follow.
    // When the requested address is not covered, `data == nullptr` and
    // `size == 0`.
    struct CapturedSpan {
        const uint8_t* data = nullptr;
        size_t         size = 0;
    };

    // Return the largest contiguous captured span that begins at `addr`.
    // Useful for letting scanners walk the bytes of a region directly without
    // going through `read()` per slot.
    CapturedSpan captured_at(uint64_t addr) const;

private:
    struct MemRange {
        uint64_t va;       // virtual address in the captured process
        uint64_t size;     // size in bytes
        uint64_t fileRva;  // offset into the mapped dump file
    };

    void buildIndex();

    const MappedView& mapped_view_;
    std::vector<MemRange> ranges_; // sorted by va
};
