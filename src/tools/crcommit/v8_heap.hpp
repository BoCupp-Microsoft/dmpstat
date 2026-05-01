#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "dump_memory.hpp"
#include "dump_memory_region.hpp"

class SymbolResolver;

namespace dmpstat {

// Symbol-anchored description of the V8 IsolateGroup, its pointer-compression
// cage, and (for V8-A) the bare list of Isolate* pointers reachable from the
// IsolateGroup (main + shared-space).
//
// Layout discovery is driven entirely from PDB field offsets so we don't bake
// in V8 build flags (sandbox / multi-cage) or version-specific layouts.
//
// Phase V8-A: cage + committed region capture + main/shared isolate addresses.
// Phase V8-B (next) will add per-isolate Heap walking via this same struct.
class V8Heap {
public:
    // Locate the V8 IsolateGroup, its pointer-compression cage, and capture
    // the committed regions inside that cage. Returns std::nullopt with a
    // diagnostic to std::wcerr if any required symbol/field is missing.
    static std::optional<V8Heap> discover(const SymbolResolver& sr,
                                          const RandomAccessReader& reader,
                                          void* dump_base,
                                          bool verbose);

    // VA of the IsolateGroup instance (the value of
    // v8::internal::IsolateGroup::default_isolate_group_).
    uint64_t isolate_group_address() const { return isolate_group_address_; }

    // Pointer-compression cage descriptor.
    uint64_t cage_base()           const { return cage_base_; }
    uint64_t cage_reserved_size()  const { return cage_reserved_size_; }
    uint64_t cage_struct_address() const { return cage_struct_address_; }

    // Isolates reachable directly from the IsolateGroup. Either may be 0.
    // (`shared_space_isolate_` is informational; it also appears in
    // `isolates()` if it has been added to the group's set.)
    uint64_t main_isolate()         const { return main_isolate_; }
    uint64_t shared_space_isolate() const { return shared_space_isolate_; }

    // All isolates live in the IsolateGroup's `absl::flat_hash_set<Isolate*>`,
    // recovered by walking the set's control bytes until kSentinel and
    // emitting one slot per "full" entry. Each entry is augmented with the
    // OS thread that appears to own it (highest stack-pointer-occurrence
    // count) and that thread's name from MINIDUMP_THREAD_NAMES_STREAM.
    struct IsolateInfo {
        uint64_t     address      = 0;
        uint32_t     thread_id    = 0;   // OS thread id from Isolate::thread_id_
        std::wstring thread_name;        // empty if thread has no name
    };
    const std::vector<IsolateInfo>& isolates() const { return isolates_; }

    // Committed regions intersecting the cage, in ascending VA order.
    const std::vector<DumpMemoryRegion>& regions() const { return regions_; }

    uint64_t committed_bytes()      const { return committed_bytes_; }
    uint64_t total_private_commit() const { return total_private_commit_; }

private:
    V8Heap() = default;

    uint64_t isolate_group_address_  = 0;
    uint64_t cage_base_              = 0;
    uint64_t cage_reserved_size_     = 0;
    uint64_t cage_struct_address_    = 0;
    uint64_t main_isolate_           = 0;
    uint64_t shared_space_isolate_   = 0;
    std::vector<IsolateInfo>      isolates_;
    std::vector<DumpMemoryRegion> regions_;
    uint64_t committed_bytes_        = 0;
    uint64_t total_private_commit_   = 0;
};

} // namespace dmpstat
