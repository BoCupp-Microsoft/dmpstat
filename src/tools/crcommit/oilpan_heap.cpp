#include "oilpan_heap.hpp"

#include <windows.h>
#include <dbghelp.h>

#include <algorithm>
#include <iostream>
#include <iomanip>

#include "symbol_resolver.hpp"

namespace dmpstat {

namespace {

// Documented v8 cage reservations.
constexpr uint64_t kCageDefaultReservation = static_cast<uint64_t>(4) * 1024 * 1024 * 1024;
constexpr uint64_t kCageMaxLargerCage      = static_cast<uint64_t>(16) * 1024 * 1024 * 1024;

struct ResolvedGlobal {
    std::wstring name;
    uint64_t     address = 0;
};

// Resolve a cppgc global by trying its fully-qualified name first, then a
// broader wildcard mask.
std::optional<ResolvedGlobal> resolveCppgcGlobal(const SymbolResolver& sr,
                                                 const std::wstring& exact_name,
                                                 const std::wstring& wildcard_mask,
                                                 bool verbose) {
    if (auto va = sr.findGlobal(exact_name); va) {
        if (verbose) {
            std::wcerr << L"[oilpan] resolved " << exact_name
                       << L" @ 0x" << std::hex << *va << std::dec << std::endl;
        }
        return ResolvedGlobal{exact_name, *va};
    }
    if (verbose) {
        std::wcerr << L"[oilpan] exact symbol lookup failed: " << exact_name
                   << L"; trying wildcard: " << wildcard_mask << std::endl;
    }
    auto hits = sr.findGlobalsMatching(wildcard_mask, /*max_results=*/8);
    if (hits.empty()) return std::nullopt;
    if (verbose) {
        std::wcerr << L"[oilpan] wildcard '" << wildcard_mask
                   << L"' matched " << hits.size() << L" symbol(s); using first:" << std::endl;
        for (const auto& h : hits) {
            std::wcerr << L"    " << h.name << L"  @ 0x"
                       << std::hex << h.address << std::dec << std::endl;
        }
    }
    return ResolvedGlobal{hits.front().name, hits.front().address};
}

} // namespace

std::optional<OilpanHeap> OilpanHeap::discover(const SymbolResolver& sr,
                                               const DumpMemoryReader& dm,
                                               void* dump_base,
                                               bool verbose) {
    OilpanHeap h{};

    // 1. Resolve symbols.
    const auto base_global = resolveCppgcGlobal(
        sr,
        L"cppgc::internal::CagedHeapBase::g_heap_base_",
        L"*CagedHeapBase*g_heap_base*",
        verbose);
    if (!base_global) {
        std::wcerr << L"Error: could not locate symbol "
                      L"'cppgc::internal::CagedHeapBase::g_heap_base_'.\n"
                      L"  PDBs for the v8/cppgc-hosting module may be missing or stripped.\n"
                      L"  Check --sympath / _NT_SYMBOL_PATH and rerun with -v for details."
                   << std::endl;
        return std::nullopt;
    }

    const auto size_global = resolveCppgcGlobal(
        sr,
        L"cppgc::internal::CagedHeapBase::g_age_table_size_",
        L"*CagedHeapBase*g_age_table_size*",
        verbose);
    if (!size_global) {
        std::wcerr << L"Error: could not locate symbol "
                      L"'cppgc::internal::CagedHeapBase::g_age_table_size_'."
                   << std::endl;
        return std::nullopt;
    }

    // 2. Read both 8-byte values from the dump.
    const auto cage_base = dm.read<uint64_t>(base_global->address);
    if (!cage_base) {
        std::wcerr << L"Error: cage base symbol resolved to VA 0x"
                   << std::hex << base_global->address << std::dec
                   << L" but those bytes are not captured in the dump." << std::endl;
        return std::nullopt;
    }
    const auto age_table_size = dm.read<uint64_t>(size_global->address);
    if (!age_table_size) {
        std::wcerr << L"Error: age-table-size symbol resolved to VA 0x"
                   << std::hex << size_global->address << std::dec
                   << L" but those bytes are not captured in the dump." << std::endl;
        return std::nullopt;
    }
    if (*cage_base == 0) {
        std::wcerr << L"Oilpan cage base is zero -- cppgc not initialized in this process."
                   << std::endl;
        return std::nullopt;
    }
    if (*age_table_size == 0) {
        std::wcerr << L"Oilpan age-table size is zero -- cppgc partially initialized."
                   << std::endl;
        return std::nullopt;
    }

    h.cage_base_          = *cage_base;
    h.age_table_size_raw_ = *age_table_size;
    h.cage_reserved_size_ = *age_table_size * kCageCardSizeBytes;
    h.base_symbol_name_   = base_global->name;
    h.size_symbol_name_   = size_global->name;

    // Sanity checks: known reservations and natural alignment.
    if (h.cage_reserved_size_ != kCageDefaultReservation
        && h.cage_reserved_size_ != kCageMaxLargerCage) {
        std::wcerr << L"Warning: derived cage reserved size ("
                   << h.cage_reserved_size_
                   << L" B) does not match a known build-flag combination "
                      L"(4 GiB / 16 GiB). Continuing with the derived value."
                   << std::endl;
    }
    if ((h.cage_base_ & (h.cage_reserved_size_ - 1)) != 0) {
        std::wcerr << L"Warning: cage base 0x" << std::hex << h.cage_base_ << std::dec
                   << L" is not aligned to derived cage reserved size; "
                      L"readings may be wrong." << std::endl;
    }

    // 3. Walk MemoryInfoListStream and collect cage-intersecting committed
    //    private regions.
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

    // cage_reserved_size_ is power-of-two and at most 16 GiB, and cage_base_
    // is aligned to it, so cage_end cannot wrap.
    const uint64_t cage_end = h.cage_base_ + h.cage_reserved_size_;
    const BYTE* base = static_cast<const BYTE*>(stream) + header->SizeOfHeader;

    for (ULONG64 i = 0; i < header->NumberOfEntries; ++i) {
        const auto* info = reinterpret_cast<const MINIDUMP_MEMORY_INFO*>(
            base + i * header->SizeOfEntry);

        if (info->State != MEM_COMMIT) continue;
        if (info->Type  != MEM_PRIVATE) continue;

        h.total_private_commit_ += info->RegionSize;

        const uint64_t r_start = info->BaseAddress;
        const uint64_t r_end   = r_start + info->RegionSize;
        const uint64_t lo = std::max(r_start, h.cage_base_);
        const uint64_t hi = std::min(r_end,   cage_end);
        if (lo >= hi) continue;

        OilpanRegion region{};
        region.base = lo;
        region.size = hi - lo;

        const auto span = dm.captured_at(lo);
        region.data = span.data;
        region.captured_bytes = std::min<uint64_t>(region.size, span.size);

        if (verbose) {
            std::wcerr << L"[oilpan]  region 0x" << std::hex << region.base
                       << L"..0x" << (region.base + region.size) << std::dec
                       << L" size=" << region.size
                       << L" captured=" << region.captured_bytes << std::endl;
        }

        h.committed_bytes_ += region.size;
        h.regions_.push_back(region);
    }

    std::sort(h.regions_.begin(), h.regions_.end(),
              [](const OilpanRegion& a, const OilpanRegion& b) {
                  return a.base < b.base;
              });

    return h;
}

} // namespace dmpstat
