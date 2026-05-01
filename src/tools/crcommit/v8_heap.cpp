#include "v8_heap.hpp"

#include <algorithm>
#include <iostream>
#include <unordered_map>
#include <unordered_set>

#include "committed_regions.hpp"
#include "read_global.hpp"
#include "symbol_resolver.hpp"
#include "threads.hpp"

namespace dmpstat {

namespace {

// Read a pointer-typed field at `struct_address + offset(struct_qname, field)`.
// Returns std::nullopt and logs to wcerr if the field can't be located or its
// bytes are not captured. The struct VA itself is assumed valid.
std::optional<uint64_t> readPointerField(const SymbolResolver& sr,
                                         const RandomAccessReader& reader,
                                         uint64_t struct_address,
                                         const std::wstring& struct_qname,
                                         const std::wstring& field,
                                         const wchar_t* domain_label) {
    const auto off = sr.fieldOffset(struct_qname, field);
    if (!off) {
        std::wcerr << L"Error: " << domain_label << L" PDB does not expose "
                   << struct_qname << L"::" << field
                   << L" (field offset lookup failed)." << std::endl;
        return std::nullopt;
    }
    const uint64_t va = struct_address + *off;
    const auto value = reader.read<uint64_t>(va);
    if (!value) {
        std::wcerr << L"Error: " << domain_label << L" "
                   << struct_qname << L"::" << field
                   << L" at VA 0x" << std::hex << va << std::dec
                   << L" but those bytes are not captured in the dump."
                   << std::endl;
        return std::nullopt;
    }
    return value;
}

// Read a size_t-typed field. On x64 size_t is 8 bytes -- same shape as the
// pointer reader above; kept separate for readability at call sites.
std::optional<uint64_t> readSizeField(const SymbolResolver& sr,
                                      const RandomAccessReader& reader,
                                      uint64_t struct_address,
                                      const std::wstring& struct_qname,
                                      const std::wstring& field,
                                      const wchar_t* domain_label) {
    return readPointerField(sr, reader, struct_address, struct_qname, field,
                            domain_label);
}

} // namespace

std::optional<V8Heap> V8Heap::discover(const SymbolResolver& sr,
                                       const RandomAccessReader& reader,
                                       void* dump_base,
                                       bool verbose) {
    V8Heap h{};

    // 1. Resolve the IsolateGroup pointer global. Its value is the VA of the
    //    process-wide IsolateGroup instance.
    const std::wstring kGroupGlobal =
        L"v8::internal::IsolateGroup::default_isolate_group_";
    const auto group_addr_opt = readGlobal<uint64_t>(sr, reader, kGroupGlobal,
                                                     L"[v8]");
    if (!group_addr_opt) {
        std::wcerr << L"  PDBs for the V8-hosting module may be missing or "
                      L"stripped, or this dump is from a process that did not "
                      L"initialize V8." << std::endl;
        return std::nullopt;
    }
    if (*group_addr_opt == 0) {
        std::wcerr << L"V8 IsolateGroup pointer is null -- V8 not initialized "
                      L"in this process." << std::endl;
        return std::nullopt;
    }
    h.isolate_group_address_ = *group_addr_opt;
    if (verbose) {
        std::wcerr << L"[v8] IsolateGroup @ 0x" << std::hex
                   << h.isolate_group_address_ << std::dec << std::endl;
    }

    const std::wstring kGroupType = L"v8::internal::IsolateGroup";

    // 2. pointer_compression_cage_ -> VirtualMemoryCage*
    const auto cage_struct = readPointerField(sr, reader,
                                              h.isolate_group_address_,
                                              kGroupType,
                                              L"pointer_compression_cage_",
                                              L"[v8]");
    if (!cage_struct) return std::nullopt;
    if (*cage_struct == 0) {
        std::wcerr << L"V8 pointer_compression_cage_ is null." << std::endl;
        return std::nullopt;
    }
    h.cage_struct_address_ = *cage_struct;
    if (verbose) {
        std::wcerr << L"[v8] VirtualMemoryCage @ 0x" << std::hex
                   << h.cage_struct_address_ << std::dec << std::endl;
    }

    // 3. VirtualMemoryCage::base_ / size_
    const std::wstring kCageType = L"v8::internal::VirtualMemoryCage";
    const auto cage_base = readPointerField(sr, reader, h.cage_struct_address_,
                                            kCageType, L"base_", L"[v8]");
    if (!cage_base) return std::nullopt;
    const auto cage_size = readSizeField(sr, reader, h.cage_struct_address_,
                                         kCageType, L"size_", L"[v8]");
    if (!cage_size) return std::nullopt;
    if (*cage_base == 0 || *cage_size == 0) {
        std::wcerr << L"V8 pointer-compression cage is not reserved (base=0x"
                   << std::hex << *cage_base << L" size=0x" << *cage_size
                   << std::dec << L")." << std::endl;
        return std::nullopt;
    }
    h.cage_base_         = *cage_base;
    h.cage_reserved_size_ = *cage_size;

    // 4. main_isolate_ / shared_space_isolate_ (best-effort; missing offsets
    //    are not fatal -- we still want the cage descriptor).
    auto read_isolate_field = [&](const std::wstring& field) -> uint64_t {
        const auto off = sr.fieldOffset(kGroupType, field);
        if (!off) {
            if (verbose) {
                std::wcerr << L"[v8] field offset missing: " << kGroupType
                           << L"::" << field << std::endl;
            }
            return 0;
        }
        const auto v = reader.read<uint64_t>(h.isolate_group_address_ + *off);
        return v ? *v : 0;
    };
    h.main_isolate_         = read_isolate_field(L"main_isolate_");
    h.shared_space_isolate_ = read_isolate_field(L"shared_space_isolate_");

    // 5. Walk the absl::flat_hash_set<Isolate*> at IsolateGroup::isolates_.
    //
    // absl raw_hash_set encodes the table as a contiguous {ctrl[], slots[]}
    // allocation. Empirically (verified via verbose dump on a Chromium PDB)
    // the relevant pointers live at fixed offsets within the set object:
    //   isolates_ + 0x10  -> ctrl_t* (start of control bytes)
    //   isolates_ + 0x18  -> Isolate** (start of slot array, capacity entries)
    //
    // Control byte semantics:
    //   0x80          kEmpty
    //   0xfe          kDeleted
    //   0xff          kSentinel    (terminates the array; stop here)
    //   0x00..0x7f    full slot    (low 7 bits = hash; corresponding slot
    //                                holds a live Isolate*)
    //
    // We cap iteration at kMaxCapacity to avoid runaway reads if the layout
    // assumption is wrong on some build, and we validate each candidate
    // Isolate* lies within the pointer-compression cage.
    {
        constexpr uint64_t kIsolatesCtrlOffset  = 0x10;
        constexpr uint64_t kIsolatesSlotsOffset = 0x18;
        constexpr uint64_t kMaxCapacity         = 64 * 1024;

        const auto isolates_off = sr.fieldOffset(kGroupType, L"isolates_");
        if (!isolates_off) {
            std::wcerr << L"Warning: [v8] could not find IsolateGroup::isolates_; "
                          L"only main/shared isolates will be listed." << std::endl;
        } else {
            const uint64_t set_va = h.isolate_group_address_ + *isolates_off;
            const auto ctrl_va  = reader.read<uint64_t>(set_va + kIsolatesCtrlOffset);
            const auto slots_va = reader.read<uint64_t>(set_va + kIsolatesSlotsOffset);
            if (!ctrl_va || !slots_va || *ctrl_va == 0 || *slots_va == 0) {
                if (verbose) {
                    std::wcerr << L"[v8] isolates_ ctrl/slots unreadable; "
                                  L"falling back to main/shared." << std::endl;
                }
            } else {
                if (verbose) {
                    std::wcerr << L"[v8] isolates_ ctrl=0x" << std::hex << *ctrl_va
                               << L" slots=0x" << *slots_va << std::dec << std::endl;
                }
                const bool kVerbose = verbose;
                bool stopped_at_sentinel = false;
                for (uint64_t i = 0; i < kMaxCapacity; ++i) {
                    const auto ctrl = reader.read<uint8_t>(*ctrl_va + i);
                    if (!ctrl) break;          // ran out of captured memory
                    if (*ctrl == 0xff) { stopped_at_sentinel = true; break; }
                    if (*ctrl & 0x80) continue; // empty (0x80) or deleted (0xfe)
                    const auto slot = reader.read<uint64_t>(*slots_va + i * 8);
                    if (!slot || *slot == 0) continue;
                    // Sanity: the Isolate object's first qword should be
                    // captured in the dump. Isolates live in normal C++ heap
                    // allocations, not inside the cage.
                    if (!reader.read<uint64_t>(*slot)) {
                        if (kVerbose) {
                            std::wcerr << L"[v8] discarding isolate candidate "
                                          L"with uncaptured bytes: 0x"
                                       << std::hex << *slot << std::dec
                                       << std::endl;
                        }
                        continue;
                    }
                    h.isolates_.push_back({*slot, 0, {}});
                }
                if (!stopped_at_sentinel && verbose) {
                    std::wcerr << L"[v8] hit kMaxCapacity (" << kMaxCapacity
                               << L") walking isolates_ without finding "
                                  L"kSentinel; result may be incomplete."
                               << std::endl;
                }
            }
        }

        // Fallback: ensure at minimum main_isolate_ is in the list.
        if (h.isolates_.empty() && h.main_isolate_ != 0) {
            h.isolates_.push_back({h.main_isolate_, 0, {}});
        }
        std::sort(h.isolates_.begin(), h.isolates_.end(),
                  [](const IsolateInfo& a, const IsolateInfo& b) {
                      return a.address < b.address;
                  });
        h.isolates_.erase(
            std::unique(h.isolates_.begin(), h.isolates_.end(),
                        [](const IsolateInfo& a, const IsolateInfo& b) {
                            return a.address == b.address;
                        }),
            h.isolates_.end());
    }

    // 6. Associate each isolate with its OS thread by finding the static-TLS
    //    location V8 uses for `g_current_isolate_`.
    //
    //    Naive approach (scan every block, claim first match) fails because
    //    Chromium keeps a process-wide list of all isolates inside one
    //    thread's TLS (e.g. on the Compositor thread), so a single thread
    //    can appear to "own" every isolate.
    //
    //    Robust approach: V8's g_current_isolate_ is a single thread_local
    //    variable, so it lives at a fixed (TLS slot index, offset within
    //    the static block) across every thread that has touched V8. We
    //    detect that location by scoring each (slot, offset) candidate:
    //       - +1 for each distinct thread whose value there is a known
    //         isolate address
    //       - reject any (slot, offset) where two threads point at the
    //         *same* isolate (g_current_isolate_ is per-thread, never
    //         shared)
    //    The (slot, offset) with the highest score is V8's TLS variable.
    //    Then a single re-scan reads one value per thread to assign tids.
    auto threads_opt = readThreads(dump_base);

    constexpr uint64_t kTebTlsArrayOffset = 0x58;   // ThreadLocalStoragePointer
    constexpr size_t   kMaxTlsSlots       = 256;
    constexpr size_t   kTlsBlockProbe     = 16384;  // bytes per block

    if (threads_opt && !threads_opt->empty() && !h.isolates_.empty()) {
        std::unordered_set<uint64_t> iso_set;
        for (const auto& iso : h.isolates_) iso_set.insert(iso.address);

        // Per-thread TLS array bases, captured once per thread.
        struct ThreadTls { const ThreadInfo* t; uint64_t tls_array; };
        std::vector<ThreadTls> tls_threads;
        for (const auto& t : *threads_opt) {
            if (t.teb == 0) continue;
            const auto a = reader.read<uint64_t>(t.teb + kTebTlsArrayOffset);
            if (!a || *a == 0) continue;
            tls_threads.push_back({&t, *a});
        }

        // candidate -> (set of distinct isolate ptrs, count of distinct
        //               threads, marked_invalid_due_to_collision).
        struct Candidate {
            std::unordered_set<uint64_t> isolates_seen;
            size_t threads = 0;
            bool   invalid = false;
        };
        // Key: (slot << 32) | offset_in_block. offset is small (<16K) so this
        // packs cleanly into 64 bits.
        std::unordered_map<uint64_t, Candidate> candidates;

        for (const auto& tt : tls_threads) {
            // Per-thread map: candidate -> isolate_ptr at that location.
            std::unordered_map<uint64_t, uint64_t> seen_here;
            for (size_t i = 0; i < kMaxTlsSlots; ++i) {
                const auto block = reader.read<uint64_t>(tt.tls_array + i * 8);
                if (!block || *block == 0) continue;
                for (size_t off = 0; off + 8 <= kTlsBlockProbe; off += 8) {
                    const auto v = reader.read<uint64_t>(*block + off);
                    if (!v || iso_set.find(*v) == iso_set.end()) continue;
                    const uint64_t key = (uint64_t(i) << 32) | uint32_t(off);
                    seen_here[key] = *v;
                }
            }
            for (const auto& [key, iso_ptr] : seen_here) {
                auto& c = candidates[key];
                if (c.invalid) continue;
                if (!c.isolates_seen.insert(iso_ptr).second) {
                    // Two threads' TLS at this (slot, offset) point at the
                    // same isolate -> not g_current_isolate_.
                    c.invalid = true;
                    continue;
                }
                ++c.threads;
            }
        }

        // Pick the highest-scoring valid candidate.
        uint64_t best_key   = 0;
        size_t   best_score = 0;
        for (const auto& [key, c] : candidates) {
            if (c.invalid) continue;
            if (c.threads > best_score) {
                best_score = c.threads;
                best_key   = key;
            }
        }

        if (best_score == 0) {
            if (verbose) {
                std::wcerr << L"[v8] could not locate g_current_isolate_ TLS "
                              L"slot." << std::endl;
            }
        } else {
            const size_t best_slot   = size_t(best_key >> 32);
            const size_t best_offset = size_t(uint32_t(best_key));
            if (verbose) {
                std::wcerr << L"[v8] g_current_isolate_ at TLS slot "
                           << best_slot << L" +0x" << std::hex << best_offset
                           << std::dec << L" (matched " << best_score
                           << L" threads)" << std::endl;
            }

            std::unordered_map<uint64_t, IsolateInfo*> by_addr;
            for (auto& iso : h.isolates_) by_addr[iso.address] = &iso;

            for (const auto& tt : tls_threads) {
                const auto block = reader.read<uint64_t>(
                    tt.tls_array + best_slot * 8);
                if (!block || *block == 0) continue;
                const auto v = reader.read<uint64_t>(*block + best_offset);
                if (!v) continue;
                auto it = by_addr.find(*v);
                if (it == by_addr.end()) continue;
                auto* iso = it->second;
                iso->thread_id   = tt.t->thread_id;
                iso->thread_name = tt.t->name;
            }
        }
    } else if (verbose) {
        std::wcerr << L"[v8] thread list unavailable; isolates will not be "
                      L"labeled with thread info." << std::endl;
    }

    // 7. Capture committed regions in the cage range.
    auto cr = readCommittedRegionsInRange(reader, dump_base,
                                          h.cage_base_, h.cage_reserved_size_,
                                          verbose, L"v8");
    if (!cr) return std::nullopt;
    h.regions_              = std::move(cr->regions);
    h.committed_bytes_      = cr->committed_bytes;
    h.total_private_commit_ = cr->total_private_commit;

    return h;
}

} // namespace dmpstat
