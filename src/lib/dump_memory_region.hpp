#pragma once

#include <cstdint>

namespace dmpstat {

// A virtual-address range whose bytes (or a prefix of them) are present in
// the dump file mapping. `data` points into the mapped dump and exposes the
// bytes that are actually captured; `captured_bytes` is how many valid bytes
// follow `data` and is <= `size`. `size` is the full extent of the region as
// described by whatever stream produced it (e.g. Memory64ListStream gives
// `size == captured_bytes`; MemoryInfoListStream may give a committed `size`
// that exceeds `captured_bytes` when the dump trimmed the region).
//
// A vector of DumpMemoryRegion is the common currency between dump-traversal
// code (DumpMemoryReader) and consumers (RandomAccessReader, PointerCounter,
// scanners). Vectors passed to RandomAccessReader must be sorted by `base`.
struct DumpMemoryRegion {
    uint64_t       base            = 0;        // virtual address
    uint64_t       size            = 0;        // described bytes
    const uint8_t* data            = nullptr;  // mapped-file pointer or nullptr
    uint64_t       captured_bytes  = 0;        // <= size
};

} // namespace dmpstat
