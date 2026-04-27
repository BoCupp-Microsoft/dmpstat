#pragma once

#include <cstdint>

namespace dmpstat {

// A virtual-address range whose bytes (or a prefix of them) are captured in
// the dump file mapping. `data` points into the mapped dump and exposes the
// bytes that are actually present; `captured_bytes` is how many valid bytes
// follow `data` and is <= `size`. `size` is the full extent of the region as
// described by whatever stream it came from (e.g. MemoryInfoListStream); it
// may exceed `captured_bytes` when the dump trimmed the tail of the region.
//
// Designed to be the common currency between dump-traversal code and
// scanners: a scanner takes a span of CapturedMemoryRegion and walks the
// `data .. data + captured_bytes` byte range of each, treating the
// corresponding VA range `base .. base + size` as the originating extent.
struct CapturedMemoryRegion {
    uint64_t       base            = 0;        // virtual address
    uint64_t       size            = 0;        // committed/described bytes
    const uint8_t* data            = nullptr;  // mapped-file pointer or nullptr
    uint64_t       captured_bytes  = 0;        // <= size
};

} // namespace dmpstat
