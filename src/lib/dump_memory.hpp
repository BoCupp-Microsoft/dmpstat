#pragma once

#include <cstdint>
#include <cstring>
#include <optional>
#include <vector>

#include "dump_memory_region.hpp"
#include "mapped_view.hpp"

// DumpMemoryReader: walks the captured-memory streams of a Windows minidump
// (Memory64ListStream + MemoryListStream) and produces a sorted vector of
// DumpMemoryRegion entries pointing into the mapped dump file. Owns the
// vector; consumers (RandomAccessReader, PointerCounter, ...) borrow it.
class DumpMemoryReader {
public:
    explicit DumpMemoryReader(const MappedView& mapped_view);

    // Captured regions, sorted by base (ascending). Each region's `size`
    // equals its `captured_bytes` because these come from streams that only
    // describe captured bytes.
    const std::vector<dmpstat::DumpMemoryRegion>& regions() const { return regions_; }

private:
    void buildRegions(const MappedView& mapped_view);

    std::vector<dmpstat::DumpMemoryRegion> regions_;
};

// RandomAccessReader: virtual-address random reads over a vector of
// DumpMemoryRegion entries (must be sorted by `base`). The vector is borrowed
// by const reference and must outlive the reader. Typical wiring is
//
//     DumpMemoryReader  dump_memory(mapped_view);
//     RandomAccessReader reader(dump_memory.regions());
//
// but the reader works equally well over any filtered subset (e.g. just the
// regions that intersect the Oilpan cage).
class RandomAccessReader {
public:
    explicit RandomAccessReader(const std::vector<dmpstat::DumpMemoryRegion>& regions);

    // Copy up to `bytes` bytes starting at virtual address `addr` into `buf`.
    // Returns the number of bytes actually copied (0 when the address is
    // outside any captured run, or when `bytes` is 0). Short reads at the
    // tail of a region are allowed.
    size_t read(uint64_t addr, void* buf, size_t bytes) const;

    // Typed convenience: returns std::nullopt unless the full sizeof(T) bytes
    // are available at `addr`.
    template <typename T>
    std::optional<T> read(uint64_t addr) const {
        T value{};
        if (read(addr, &value, sizeof(T)) != sizeof(T)) return std::nullopt;
        return value;
    }

    // Returns true if `bytes` starting at `addr` are fully present.
    bool contains(uint64_t addr, size_t bytes) const;

    // A contiguous run of captured bytes from the mapped dump file. `data`
    // points into the file mapping; `size` is how many valid bytes follow.
    // {nullptr, 0} when the requested address is not covered.
    struct CapturedSpan {
        const uint8_t* data = nullptr;
        size_t         size = 0;
    };

    // Return the captured bytes starting at `addr`, plus the count remaining
    // before the end of the region that contains `addr`. Adjacent regions
    // are not merged.
    CapturedSpan captured_at(uint64_t addr) const;

private:
    const std::vector<dmpstat::DumpMemoryRegion>& regions_;
};
