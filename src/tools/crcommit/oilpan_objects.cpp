#include "oilpan_objects.hpp"

#include <algorithm>
#include <iostream>
#include <iomanip>
#include <unordered_set>

#include "symbol_resolver.hpp"

namespace dmpstat {
namespace {

// cppgc constants (stable across Chromium versions; assert via the PDB where
// possible).
constexpr uint64_t kPageSize             = 128 * 1024;     // kPageSize
constexpr uint64_t kAllocationGranularity = 8;             // sizeof(HeapObjectHeader)
constexpr uint16_t kFreeListGCInfoIndex  = 0;
constexpr uint32_t kMaxGCInfoIndex       = 1u << 14;       // 16384

// Encoded HeapObjectHeader layout:
//   [0..3]  uint32_t next_unfinalized_  (cage-relative; ignored)
//   [4..5]  uint16_t encoded_high_      gc_info_index (low 14 bits)
//   [6..7]  uint16_t encoded_low_       size_in_units (bits 1..15) | mark (bit 0)
struct DecodedHeader {
    uint32_t gc_info_index;
    uint64_t size_bytes;       // 0 when this header is a large-object sentinel
    bool     valid;
};

DecodedHeader decodeHeader(const uint8_t* p) {
    DecodedHeader d{0, 0, false};
    uint16_t encoded_high, encoded_low;
    std::memcpy(&encoded_high, p + 4, 2);
    std::memcpy(&encoded_low,  p + 6, 2);
    d.gc_info_index = static_cast<uint32_t>(encoded_high & 0x3FFF);
    d.size_bytes    = static_cast<uint64_t>(encoded_low >> 1) * kAllocationGranularity;
    d.valid         = true;
    return d;
}

// Page-layout offsets discovered from the PDB. We don't hardcode them because
// CPPGC_YOUNG_GENERATION conditionally adds a unique_ptr<SlotSet> field, and
// future struct changes are easier to absorb if the offsets are queried.
struct PageLayout {
    uint64_t sizeof_normal_page = 0;
    uint64_t sizeof_large_page  = 0;
    uint64_t off_basepage_type  = 0;
    uint64_t off_largepage_payload_size = 0;

    bool ok() const {
        // Page-header sizes are non-zero by construction; type_ is at a small
        // positive offset (after at least the heap-handle pointer).
        return sizeof_normal_page > 0 && sizeof_large_page > 0
            && off_basepage_type > 0 && off_largepage_payload_size > 0;
    }
};

std::optional<PageLayout> discoverPageLayout(const SymbolResolver& sr) {
    PageLayout L;
    L.sizeof_normal_page = sr.typeSize(L"cppgc::internal::NormalPage");
    L.sizeof_large_page  = sr.typeSize(L"cppgc::internal::LargePage");
    if (auto o = sr.fieldOffset(L"cppgc::internal::BasePage", L"type_")) {
        L.off_basepage_type = *o;
    }
    if (auto o = sr.fieldOffset(L"cppgc::internal::LargePage", L"payload_size_")) {
        L.off_largepage_payload_size = *o;
    }
    if (!L.ok()) return std::nullopt;
    return L;
}

// Frequency analysis: at every captured 128 KiB-aligned address inside the
// cage, read the first qword. Most non-page slots see "data noise" qwords that
// don't repeat. cppgc HeapBase pointers, however, repeat once per page that
// belongs to the same cppgc Heap, so they cluster at the top of the histogram.
// Returns the set of values that appear more than `min_repeats` times - these
// are accepted as HeapBase pointer candidates.
std::unordered_set<uint64_t>
discoverHeapHandles(const OilpanHeap& heap, const RandomAccessReader& reader) {
    std::unordered_map<uint64_t, uint32_t> hist;
    const uint64_t cage_lo = heap.cage_base();
    const uint64_t cage_hi = heap.cage_base() + heap.cage_reserved_size();
    const uint64_t first_aligned =
        (cage_lo + kPageSize - 1) & ~(kPageSize - 1);
    for (uint64_t addr = first_aligned; addr + 8 <= cage_hi; addr += kPageSize) {
        if (auto v = reader.read<uint64_t>(addr)) {
            // A HeapBase* is a process-VA pointer outside the cage (HeapBase
            // lives on the C++ heap, not in the cppgc cage). Skip values that
            // would imply an in-cage handle (impossible) or null.
            if (*v == 0) continue;
            if (*v >= cage_lo && *v < cage_hi) continue;
            ++hist[*v];
        }
    }
    // Threshold: a real cppgc Heap has many normal pages; "noise" qwords at a
    // 128 KiB boundary almost never repeat. Even a very small heap has >= 4
    // normal pages in steady state, and we only need a couple of hits to keep
    // false positives out.
    constexpr uint32_t kMinRepeats = 3;
    std::unordered_set<uint64_t> out;
    for (auto& [val, n] : hist) if (n >= kMinRepeats) out.insert(val);
    return out;
}

// Walk one normal page's HeapObjectHeader stream. Stops at the first
// invalid/overrun header (treated as the LAB tail) and adds the trailing
// bytes to `unaccounted`.
void walkNormalPage(uint64_t page_base,
                    const RandomAccessReader& reader,
                    const PageLayout& L,
                    OilpanObjectStats& stats) {
    const uint64_t payload_start = page_base
        + ((L.sizeof_normal_page + kAllocationGranularity - 1)
           & ~(kAllocationGranularity - 1));
    const uint64_t payload_end = page_base + kPageSize;
    uint64_t cursor = payload_start;
    while (cursor + 8 <= payload_end) {
        uint8_t buf[8];
        if (reader.read(cursor, buf, 8) != 8) break;
        DecodedHeader h = decodeHeader(buf);
        if (!h.valid || h.size_bytes == 0) break;       // sentinel / LAB
        if (h.gc_info_index >= kMaxGCInfoIndex) break;  // corrupt / LAB
        if (cursor + h.size_bytes > payload_end) break; // overrun / LAB
        if (h.gc_info_index == kFreeListGCInfoIndex) {
            ++stats.free_count;
            stats.free_bytes += h.size_bytes;
        } else {
            ++stats.live_count;
            stats.live_bytes += h.size_bytes;
            auto& e = stats.by_gc_info[h.gc_info_index];
            e.gc_info_index = h.gc_info_index;
            ++e.count;
            e.bytes += h.size_bytes;
        }
        cursor += h.size_bytes;
    }
    stats.lab_unaccounted_bytes += (payload_end - cursor);
}

// Walk a large page: it's a single object whose total size lives in the
// LargePage struct. We attribute the full system-page-rounded span to the
// large-page accounting, but only payload_size_ + sizeof(HeapObjectHeader) to
// the live/by_gc_info bucket - matching how cppgc's accounting splits them.
void walkLargePage(uint64_t page_base,
                   uint64_t total_span,
                   const RandomAccessReader& reader,
                   const PageLayout& L,
                   OilpanObjectStats& stats) {
    stats.large_page_bytes += total_span;
    ++stats.large_page_count;

    auto payload_size = reader.read<uint64_t>(page_base + L.off_largepage_payload_size);
    if (!payload_size || *payload_size == 0) return;

    // First HeapObjectHeader sits at base + RoundUp(sizeof(LargePage), 8)
    // (cppgc rounds the page header up to alignment before the user object).
    const uint64_t header_addr = page_base
        + ((L.sizeof_large_page + kAllocationGranularity - 1)
           & ~(kAllocationGranularity - 1));
    uint8_t buf[8];
    if (reader.read(header_addr, buf, 8) != 8) return;
    DecodedHeader h = decodeHeader(buf);
    if (!h.valid) return;
    if (h.gc_info_index == kFreeListGCInfoIndex) return; // impossible but defensive
    ++stats.live_count;
    const uint64_t bytes = *payload_size + 8;            // payload + header
    stats.live_bytes += bytes;
    auto& e = stats.by_gc_info[h.gc_info_index];
    e.gc_info_index = h.gc_info_index;
    ++e.count;
    e.bytes += bytes;
}

// Determine page kind by reading BasePage::type_ (uint8_t enum: 0=Normal,
// 1=Large). Returns {is_large, total_span}. total_span is the captured byte
// count for the page (kPageSize for normal, system-page-rounded for large).
struct PageKind { bool is_large; uint64_t total_span; };

std::optional<PageKind> classifyPage(uint64_t page_base,
                                     const RandomAccessReader& reader,
                                     const PageLayout& L) {
    auto type_byte = reader.read<uint8_t>(page_base + L.off_basepage_type);
    if (!type_byte) return std::nullopt;
    if (*type_byte == 0) return PageKind{false, kPageSize};
    if (*type_byte == 1) {
        // Large-page total span: payload_size_ + sizeof(LargePage), rounded
        // up to the system page (4 KiB). cppgc rounds at allocation time.
        auto payload_size = reader.read<uint64_t>(
            page_base + L.off_largepage_payload_size);
        if (!payload_size) return std::nullopt;
        constexpr uint64_t kSystemPage = 4096;
        const uint64_t raw = L.sizeof_large_page + *payload_size;
        const uint64_t rounded = (raw + kSystemPage - 1) & ~(kSystemPage - 1);
        return PageKind{true, rounded};
    }
    return std::nullopt;
}

} // namespace

std::optional<OilpanObjectStats>
walkOilpanObjects(const OilpanHeap& heap,
                  const RandomAccessReader& reader,
                  const SymbolResolver& sr,
                  ProgressReporter& progress) {
    progress.update(L"Resolving cppgc page layout from PDB");
    auto layout = discoverPageLayout(sr);
    progress.clear();
    if (!layout) {
        // Re-resolve with the same calls just to get individual values for
        // the diagnostic; cheap because findType has its own caching paths.
        const uint64_t snp = sr.typeSize(L"cppgc::internal::NormalPage");
        const uint64_t slp = sr.typeSize(L"cppgc::internal::LargePage");
        const auto bpt = sr.fieldOffset(L"cppgc::internal::BasePage", L"type_");
        const auto lpps = sr.fieldOffset(L"cppgc::internal::LargePage", L"payload_size_");
        std::wcerr << std::endl
                   << L"Could not resolve cppgc page-layout offsets from PDB:" << std::endl
                   << L"  sizeof(NormalPage)                  = " << snp << std::endl
                   << L"  sizeof(LargePage)                   = " << slp << std::endl
                   << L"  offsetof(BasePage::type_)           = " << (bpt ? *bpt : 0) << std::endl
                   << L"  offsetof(LargePage::payload_size_)  = " << (lpps ? *lpps : 0) << std::endl;

        // Diagnostic probes: try a few alternative spellings to figure out
        // whether (a) the type is present under a different name or (b) the
        // type has been stripped from the PDB entirely.
        auto probe = [&](const std::wstring& name) {
            const uint64_t sz = sr.typeSize(name);
            std::wcerr << L"  probe sizeof(" << name << L") = " << sz << std::endl;
        };
        probe(L"cppgc::internal::BasePage");
        probe(L"cppgc::internal::NormalPage");
        probe(L"cppgc::internal::LargePage");
        probe(L"cppgc::internal::BasePageHandle");

        auto enumProbe = [&](const std::wstring& mask) {
            auto names = sr.enumerateTypeNames(mask, 16);
            std::wcerr << L"  types matching '" << mask << L"' (" << names.size()
                       << L"):" << std::endl;
            for (const auto& n : names) std::wcerr << L"    " << n << std::endl;
        };
        enumProbe(L"*NormalPage");
        enumProbe(L"*BasePage");
        return std::nullopt;
    }

    progress.update(L"Discovering cppgc Heap handles");
    auto handles = discoverHeapHandles(heap, reader);
    progress.clear();

    OilpanObjectStats stats;
    stats.distinct_heap_count = handles.size();

    const uint64_t cage_lo = heap.cage_base();
    const uint64_t cage_hi = heap.cage_base() + heap.cage_reserved_size();
    const uint64_t first_aligned =
        (cage_lo + kPageSize - 1) & ~(kPageSize - 1);
    const uint64_t total_slots =
        (cage_hi - first_aligned) / kPageSize;
    uint64_t scanned = 0;
    for (uint64_t addr = first_aligned; addr + 8 <= cage_hi;
         addr += kPageSize, ++scanned) {
        if ((scanned & 0xFF) == 0) {
            wchar_t buf[96];
            swprintf_s(buf, L"Walking cppgc pages %llu/%llu",
                       static_cast<unsigned long long>(scanned),
                       static_cast<unsigned long long>(total_slots));
            progress.update(buf);
        }
        auto first_qword = reader.read<uint64_t>(addr);
        if (!first_qword) continue;
        if (handles.find(*first_qword) == handles.end()) continue;
        auto kind = classifyPage(addr, reader, *layout);
        if (!kind) continue;
        if (kind->is_large) {
            walkLargePage(addr, kind->total_span, reader, *layout, stats);
        } else {
            ++stats.normal_page_count;
            stats.normal_page_bytes += kPageSize;
            walkNormalPage(addr, reader, *layout, stats);
        }
    }
    progress.clear();
    return stats;
}

namespace {

// Strip `enum`, `class`, `struct`, `union` keywords that MSVC's name
// undecorator inserts inside template arg lists. Same logic used for vftable
// names; duplicated here to keep this module self-contained.
std::wstring stripElaboratedTypeKeywords(const std::wstring& s) {
    static const wchar_t* const kKeywords[] = {
        L"enum ", L"class ", L"struct ", L"union "};
    std::wstring out;
    out.reserve(s.size());
    auto isIdentChar = [](wchar_t c) {
        return (c >= L'a' && c <= L'z') || (c >= L'A' && c <= L'Z')
            || (c >= L'0' && c <= L'9') || c == L'_';
    };
    size_t i = 0;
    while (i < s.size()) {
        bool stripped = false;
        for (const wchar_t* kw : kKeywords) {
            const size_t kw_len = wcslen(kw);
            if (i + kw_len > s.size()) continue;
            if (wcsncmp(s.c_str() + i, kw, kw_len) != 0) continue;
            if (i > 0 && isIdentChar(s[i - 1])) continue;
            i += kw_len;
            stripped = true;
            break;
        }
        if (!stripped) out.push_back(s[i++]);
    }
    return out;
}

// Extract `X` from a symbol of the form
// "cppgc::internal::TraceTrait<X>::Trace". Returns empty string on miss.
std::wstring extractTraceTraitArg(const std::wstring& sym) {
    static const std::wstring kPrefix = L"cppgc::internal::TraceTrait<";
    static const std::wstring kSuffix = L">::Trace";
    if (sym.size() < kPrefix.size() + kSuffix.size()) return {};
    if (sym.compare(0, kPrefix.size(), kPrefix) != 0) return {};
    // The trailing >::Trace is the last occurrence; take everything between.
    size_t end = sym.rfind(kSuffix);
    if (end == std::wstring::npos || end <= kPrefix.size()) return {};
    return sym.substr(kPrefix.size(), end - kPrefix.size());
}

} // namespace

void resolveClassNames(OilpanObjectStats& stats,
                       const RandomAccessReader& reader,
                       const SymbolResolver& sr) {
    if (stats.by_gc_info.empty()) return;

    auto global_table_addr = sr.findGlobal(
        L"cppgc::internal::GlobalGCInfoTable::global_table_");
    if (!global_table_addr) {
        if (sr.verbose()) {
            std::wcerr << L"GlobalGCInfoTable::global_table_ not found" << std::endl;
        }
        return;
    }
    auto table_ptr = reader.read<uint64_t>(*global_table_addr);
    if (!table_ptr || *table_ptr == 0) return;

    auto off_table = sr.fieldOffset(L"cppgc::internal::GCInfoTable", L"table_");
    auto off_index = sr.fieldOffset(L"cppgc::internal::GCInfoTable", L"current_index_");
    auto sizeof_gcinfo = sr.typeSize(L"cppgc::internal::GCInfo");
    auto off_trace = sr.fieldOffset(L"cppgc::internal::GCInfo", L"trace");
    if (!off_table || !off_index || sizeof_gcinfo == 0 || !off_trace) {
        if (sr.verbose()) {
            std::wcerr << L"GCInfoTable layout incomplete: "
                       << L"off_table=" << (off_table ? *off_table : 0)
                       << L" off_index=" << (off_index ? *off_index : 0)
                       << L" sizeof(GCInfo)=" << sizeof_gcinfo
                       << L" off_trace=" << (off_trace ? *off_trace : 0)
                       << std::endl;
        }
        return;
    }

    auto array_ptr = reader.read<uint64_t>(*table_ptr + *off_table);
    auto current_index = reader.read<uint16_t>(*table_ptr + *off_index);
    if (!array_ptr || !current_index || *array_ptr == 0) return;

    // Resolve only indices we actually saw - dramatically cheaper than
    // walking every entry of a 16K-slot table.
    for (auto& [idx, entry] : stats.by_gc_info) {
        if (idx == 0 || idx >= *current_index) continue;
        const uint64_t entry_addr = *array_ptr + idx * sizeof_gcinfo;
        auto trace_fn = reader.read<uint64_t>(entry_addr + *off_trace);
        if (!trace_fn || *trace_fn == 0) continue;
        auto sym = sr.resolveFunction(*trace_fn);
        if (!sym) continue;
        std::wstring arg = extractTraceTraitArg(sym->symbol_name);
        if (arg.empty()) continue;
        entry.class_name = stripElaboratedTypeKeywords(arg);
    }
}

} // namespace dmpstat
