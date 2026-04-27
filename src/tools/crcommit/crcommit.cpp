// crcommit: Chromium-aware private-commit analyzer for Windows minidumps.
//
// Phase 1: walk MemoryInfoListStream, classify each COMMIT/PRIVATE region
// into an allocator family using purely heuristic rules (no symbols
// required), and print a per-family rollup. Region-level breakdown is
// available via --regions.
//
// The allocator-family tagger here intentionally errs on the side of
// "Unknown" when signals are weak; later phases (symbol-anchored
// cross-checks, slot/page enumeration, object identification) will
// upgrade these classifications.

#include <windows.h>
#include <dbghelp.h>
#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <map>
#include <sstream>
#include <string>
#include <vector>
#include <CLI/CLI.hpp>
#include <wil/result.h>
#include "mapped_view.hpp"
#include "dump_memory.hpp"
#include "symbol_resolver.hpp"
#include "progress.hpp"
#include "wide_string_utils.hpp"

namespace {

using dmpstat::Utf8ToWide;
using dmpstat::WideToUtf8;

// ---------- Pretty-printers ----------

std::wstring FormatSize(uint64_t bytes) {
    const wchar_t* units[] = { L"B", L"KB", L"MB", L"GB", L"TB" };
    double v = static_cast<double>(bytes);
    int u = 0;
    while (v >= 1024.0 && u + 1 < static_cast<int>(_countof(units))) {
        v /= 1024.0; ++u;
    }
    wchar_t buf[32];
    if (u == 0) {
        swprintf_s(buf, L"%llu %s",
            static_cast<unsigned long long>(bytes), units[u]);
    } else {
        swprintf_s(buf, L"%.2f %s", v, units[u]);
    }
    return buf;
}

std::wstring FormatHexAddr(uint64_t a) {
    wchar_t buf[32];
    swprintf_s(buf, L"0x%016llX", static_cast<unsigned long long>(a));
    return buf;
}

const wchar_t* StateName(DWORD s) {
    switch (s) {
        case MEM_COMMIT:  return L"COMMIT";
        case MEM_RESERVE: return L"RESERVE";
        case MEM_FREE:    return L"FREE";
        default:          return L"?";
    }
}
const wchar_t* TypeName(DWORD t) {
    switch (t) {
        case MEM_IMAGE:   return L"IMAGE";
        case MEM_MAPPED:  return L"MAPPED";
        case MEM_PRIVATE: return L"PRIVATE";
        case 0:           return L"-";
        default:          return L"?";
    }
}

// ---------- Module list (for IMAGE attribution & future symbol anchors) ----------

std::wstring ReadMinidumpString(const void* dump_base, RVA rva) {
    if (rva == 0) return {};
    const BYTE* p = static_cast<const BYTE*>(dump_base) + rva;
    ULONG32 length_bytes = 0;
    std::memcpy(&length_bytes, p, sizeof(length_bytes));
    const wchar_t* chars = reinterpret_cast<const wchar_t*>(p + sizeof(ULONG32));
    return std::wstring(chars, length_bytes / sizeof(wchar_t));
}

struct ModuleEntry {
    uint64_t base;
    uint64_t end;          // exclusive
    std::wstring name;
};

std::vector<ModuleEntry> LoadModuleList(const void* dump_base) {
    std::vector<ModuleEntry> modules;
    void* stream = nullptr; ULONG stream_size = 0;
    if (!MiniDumpReadDumpStream(const_cast<void*>(dump_base), ModuleListStream,
                                nullptr, &stream, &stream_size) || stream == nullptr) {
        return modules;
    }
    auto* list = static_cast<MINIDUMP_MODULE_LIST*>(stream);
    modules.reserve(list->NumberOfModules);
    for (ULONG32 i = 0; i < list->NumberOfModules; ++i) {
        const auto& m = list->Modules[i];
        modules.push_back({m.BaseOfImage,
                           m.BaseOfImage + m.SizeOfImage,
                           ReadMinidumpString(dump_base, m.ModuleNameRva)});
    }
    std::sort(modules.begin(), modules.end(),
              [](const ModuleEntry& a, const ModuleEntry& b) { return a.base < b.base; });
    return modules;
}

// Lower-case basename without path or extension.
std::wstring ModuleBaseName(const std::wstring& full) {
    size_t slash = full.find_last_of(L"\\/");
    std::wstring tail = (slash == std::wstring::npos) ? full : full.substr(slash + 1);
    size_t dot = tail.find_last_of(L'.');
    if (dot != std::wstring::npos) tail.resize(dot);
    std::transform(tail.begin(), tail.end(), tail.begin(),
                   [](wchar_t c) { return static_cast<wchar_t>(towlower(c)); });
    return tail;
}

// Renderer-process modules whose presence indicates a Chromium-derived process.
bool IsChromiumLikeModule(const std::wstring& base_lower) {
    static const std::array<const wchar_t*, 8> kChromiumModules{{
        L"chrome", L"chrome_child", L"chrome_elf",
        L"msedge", L"msedgewebview2",
        L"v8", L"blink",
        L"content_shell",
    }};
    for (auto* m : kChromiumModules) if (base_lower == m) return true;
    return false;
}

// ---------- Thread-stack ranges (from ThreadListStream) ----------

struct StackRange {
    uint64_t start;
    uint64_t end; // exclusive
    DWORD thread_id;
};

std::vector<StackRange> LoadStackRanges(const void* dump_base) {
    std::vector<StackRange> stacks;
    void* stream = nullptr; ULONG stream_size = 0;
    if (!MiniDumpReadDumpStream(const_cast<void*>(dump_base), ThreadListStream,
                                nullptr, &stream, &stream_size) || !stream) {
        return stacks;
    }
    auto* list = static_cast<MINIDUMP_THREAD_LIST*>(stream);
    stacks.reserve(list->NumberOfThreads);
    for (ULONG32 i = 0; i < list->NumberOfThreads; ++i) {
        const auto& t = list->Threads[i];
        stacks.push_back({t.Stack.StartOfMemoryRange,
                          t.Stack.StartOfMemoryRange + t.Stack.Memory.DataSize,
                          t.ThreadId});
    }
    return stacks;
}

bool RangeIntersectsAnyStack(uint64_t start, uint64_t end,
                             const std::vector<StackRange>& stacks) {
    for (const auto& s : stacks) {
        if (start < s.end && s.start < end) return true;
    }
    return false;
}

// ---------- Allocator family classification ----------

enum class Family {
    ThreadStack,
    PartitionAlloc,
    V8Heap,
    Oilpan,
    WinHeap,                 // TODO p2: anchor via PEB->ProcessHeaps.
    PlainVirtualAlloc,       // Looks like a plain VirtualAlloc reservation.
    Unknown,
};

const wchar_t* FamilyName(Family f) {
    switch (f) {
        case Family::ThreadStack:       return L"ThreadStack";
        case Family::PartitionAlloc:    return L"PartitionAlloc";
        case Family::V8Heap:            return L"V8 Heap";
        case Family::Oilpan:            return L"Oilpan/cppgc";
        case Family::WinHeap:           return L"WinHeap";
        case Family::PlainVirtualAlloc: return L"VirtualAlloc";
        case Family::Unknown:           return L"Unknown";
    }
    return L"?";
}

// PartitionAlloc super-pages are 2 MiB-aligned reservations whose layout is:
//   [guard page (4 KiB)] [metadata page (4 KiB)] [payload pages...] [guard page]
// A super-page reserves exactly 2 MiB; PartitionAlloc may reserve a contiguous
// run of N super-pages for a single root, so the per-AllocationBase reserved
// span is a multiple of 2 MiB. Committed payload pages within appear as
// separate COMMIT/PRIVATE/RW- MEMORY_BASIC_INFORMATION entries that all share
// the super-page-run AllocationBase.
constexpr uint64_t kPartitionAllocSuperPageSize = 2ull * 1024 * 1024;
constexpr uint64_t kPartitionAllocPageSize = 4096;
constexpr uint64_t kPartitionAllocPayloadOffset = 2 * kPartitionAllocPageSize;

// V8 reserves an entire "cage" (a few GB to tens of GB) at a 4 GiB-aligned
// base, then commits 256 KiB MemoryChunks inside. Every commit within a cage
// shares the cage's AllocationBase. Cages we recognize:
//   - kPtrComprCageReservationSize = 4 GiB (main pointer-compression cage).
//   - Trusted space / external code cage (~4 GiB each).
//   - Sandbox (default reserves up to 32 GiB - 1 TiB sparsely).
constexpr uint64_t kV8CageMinSpan      = 1ull * 1024 * 1024 * 1024; // 1 GiB
constexpr uint64_t kV8CageBaseAlignment = 4ull * 1024 * 1024 * 1024; // 4 GiB

// Oilpan/cppgc heap pages are 128 KiB; cage base alignment & reservation
// scheme matches V8's pattern but with a smaller cage. We rely on
// symbol anchoring (Phase 2) for definitive Oilpan detection; this constant
// is documented for the Phase 3 walker.
constexpr uint64_t kOilpanPageSize = 128ull * 1024;

// Per-AllocationBase aggregate built in a single pre-pass. Used by the
// classifier to decide whether a commit lives inside a V8 cage, a
// PartitionAlloc super-page run, or something else.
struct AllocCluster {
    uint64_t reserved_span = 0;  // max (BaseAddress+RegionSize - AllocationBase)
    uint64_t commit_bytes = 0;
    uint64_t region_count = 0;
};

std::map<uint64_t, AllocCluster> BuildAllocClusters(
        const BYTE* mi_base, const MINIDUMP_MEMORY_INFO_LIST* mi_header) {
    std::map<uint64_t, AllocCluster> by_base;
    for (ULONG64 i = 0; i < mi_header->NumberOfEntries; ++i) {
        const auto* info = reinterpret_cast<const MINIDUMP_MEMORY_INFO*>(
            mi_base + i * mi_header->SizeOfEntry);
        if (info->Type != MEM_PRIVATE) continue;
        if (info->AllocationBase == 0) continue;
        auto& a = by_base[info->AllocationBase];
        const uint64_t hi = info->BaseAddress + info->RegionSize - info->AllocationBase;
        if (hi > a.reserved_span) a.reserved_span = hi;
        if (info->State == MEM_COMMIT) {
            a.commit_bytes += info->RegionSize;
            a.region_count += 1;
        }
    }
    return by_base;
}

bool IsV8Cage(uint64_t base, const AllocCluster& c) {
    if ((base & (kV8CageBaseAlignment - 1)) != 0) return false;
    if (c.reserved_span < kV8CageMinSpan) return false;
    return true;
}

bool IsPartitionAllocSuperPageRun(uint64_t base, const AllocCluster& c) {
    if ((base & (kPartitionAllocSuperPageSize - 1)) != 0) return false;
    // Reserved span must be a positive multiple of 2 MiB.
    if (c.reserved_span == 0) return false;
    if ((c.reserved_span & (kPartitionAllocSuperPageSize - 1)) != 0) return false;
    return true;
}

Family ClassifyRegion(const MINIDUMP_MEMORY_INFO& info,
                      const std::vector<StackRange>& stacks,
                      const std::map<uint64_t, AllocCluster>& clusters) {
    if (info.State != MEM_COMMIT) return Family::Unknown;

    if (info.Type == MEM_PRIVATE) {
        const uint64_t end = info.BaseAddress + info.RegionSize;
        if (RangeIntersectsAnyStack(info.BaseAddress, end, stacks)) {
            return Family::ThreadStack;
        }
    }
    if (info.Type != MEM_PRIVATE) return Family::Unknown;
    if (info.AllocationBase == 0)   return Family::PlainVirtualAlloc;

    auto it = clusters.find(info.AllocationBase);
    if (it == clusters.end()) return Family::PlainVirtualAlloc;
    const auto& c = it->second;

    if (IsV8Cage(info.AllocationBase, c)) {
        // A region inside a V8 cage that lies in the first 2 KiB of the cage
        // (i.e., the cage's read-only roots/isolate header) is still V8 by
        // ownership; treat the whole cage as V8 in this phase.
        return Family::V8Heap;
    }
    if (IsPartitionAllocSuperPageRun(info.AllocationBase, c)) {
        // Distinguish payload commits from the metadata page if we can; both
        // are PartitionAlloc-owned, so we keep them in the same family.
        return Family::PartitionAlloc;
    }
    return Family::PlainVirtualAlloc;
}

// ---------- Cluster lookup utility ----------

// Sorted view of clusters for fast "which cluster contains VA" lookups.
struct ClusterIndex {
    struct Entry { uint64_t base; uint64_t span; };
    std::vector<Entry> entries; // sorted by base

    static ClusterIndex Build(const std::map<uint64_t, AllocCluster>& clusters) {
        ClusterIndex idx;
        idx.entries.reserve(clusters.size());
        for (auto& [b, c] : clusters) idx.entries.push_back({b, c.reserved_span});
        return idx;
    }

    // Returns the AllocationBase of the cluster containing `va`, or 0.
    uint64_t Find(uint64_t va) const {
        auto it = std::upper_bound(entries.begin(), entries.end(), va,
            [](uint64_t v, const Entry& e) { return v < e.base; });
        if (it == entries.begin()) return 0;
        --it;
        if (va >= it->base && va < it->base + it->span) return it->base;
        return 0;
    }
};

// ---------- Symbol-anchored cluster identification ----------

// Curated list of DbgHelp wildcard masks that, in current Chromium PDBs,
// tend to match globals whose value is (or contains) a heap-root pointer.
// Masks are tried in order; we don't require any to succeed and don't fail
// if a particular pattern matches nothing.
//
// Each entry is (mask, hint) where `hint` is a short label printed
// alongside any anchored cluster (e.g. "PartitionAlloc root", "V8 cage").
struct SymbolProbe {
    const wchar_t* mask;
    const wchar_t* hint;
};

static const SymbolProbe kSymbolProbes[] = {
    // PartitionAlloc roots. WTF::Partitions hosts the typed partitions used
    // by Blink (FastMallocPartition, ArrayBufferPartition, BufferPartition,
    // LayoutPartition); the PartitionAllocator template owns a PartitionRoot.
    { L"*Partitions::*Partition*",                L"PartitionAlloc root (Blink)" },
    { L"*partition_alloc::*g_root*",              L"PartitionAlloc g_root" },
    { L"*PartitionAllocator*allocator_*",         L"PartitionAllocator" },
    // V8 cages and isolate roots.
    { L"*v8::internal::IsolateGroup::*",          L"V8 IsolateGroup" },
    { L"*PointerCompressionCage*base*",           L"V8 cage base" },
    { L"*Sandbox*base_*",                         L"V8 sandbox base" },
    { L"*v8::internal::Isolate::isolate_root*",   L"V8 Isolate root" },
    // Oilpan / cppgc.
    { L"*blink::ThreadState::*main_thread*",      L"Oilpan main thread" },
    { L"*cppgc::internal::ProcessHeap*",          L"cppgc ProcessHeap" },
    // Skia, ICU, base allocator references can also point at large reservations.
    { L"*base::allocator::*",                     L"base::allocator" },
};

struct AnchorMatch {
    uint64_t cluster_base;     // AllocationBase of the cluster
    uint64_t global_va;        // VA of the global symbol
    uint64_t pointer_value;    // value read at *global_va
    std::wstring symbol_name;
    const wchar_t* hint;
};

std::vector<AnchorMatch> ProbeSymbolAnchors(
        const SymbolResolver& sr,
        const DumpMemoryReader& dump,
        const ClusterIndex& cluster_index) {
    std::vector<AnchorMatch> matches;
    for (const auto& probe : kSymbolProbes) {
        // Cap per-probe results to keep noise down for very broad masks.
        auto hits = sr.findGlobalsMatching(probe.mask, /*max_results=*/2000);
        for (const auto& h : hits) {
            // Read 8 bytes at the global; if it looks like a pointer that
            // lands inside a known cluster, record it as an anchor.
            auto val = dump.read<uint64_t>(h.address);
            if (!val) continue;
            uint64_t ptr = *val;
            if (ptr < 0x10000) continue; // ignore null/small ints
            uint64_t base = cluster_index.Find(ptr);
            if (base == 0) continue;
            matches.push_back({base, h.address, ptr, h.name, probe.hint});
        }
    }
    return matches;
}

void PrintAnchors(const std::vector<AnchorMatch>& matches,
                  const std::map<uint64_t, AllocCluster>& clusters) {
    if (matches.empty()) {
        std::wcout << L"\nSymbol-anchored cluster identification: no matches "
                      L"(symbols may be unavailable, or PDB lacks the probed names).\n";
        return;
    }
    // Group by cluster base.
    std::map<uint64_t, std::vector<const AnchorMatch*>> by_cluster;
    for (const auto& m : matches) by_cluster[m.cluster_base].push_back(&m);

    std::wcout << L"\nSymbol-anchored cluster identification (" << matches.size()
               << L" hits across " << by_cluster.size() << L" clusters)\n";
    std::wcout << L"---------------------------------------------------------------\n";
    for (auto& [base, hits] : by_cluster) {
        auto cit = clusters.find(base);
        uint64_t span = (cit != clusters.end()) ? cit->second.reserved_span : 0;
        uint64_t cb   = (cit != clusters.end()) ? cit->second.commit_bytes  : 0;
        std::wcout << L"Cluster " << FormatHexAddr(base)
                   << L"  reserved=" << FormatSize(span)
                   << L"  committed=" << FormatSize(cb)
                   << L"\n";
        for (const auto* m : hits) {
            std::wcout << L"  [" << m->hint << L"] "
                       << m->symbol_name
                       << L"  (global @" << FormatHexAddr(m->global_va)
                       << L" -> " << FormatHexAddr(m->pointer_value) << L")\n";
        }
    }
    std::wcout << L"---------------------------------------------------------------\n";
}

void PrintFamilyRollup(const std::map<Family, std::pair<uint64_t, uint64_t>>& roll,
                       uint64_t total) {
    // Sort by bytes desc.
    std::vector<std::tuple<Family, uint64_t, uint64_t>> rows;
    rows.reserve(roll.size());
    for (auto& [f, br] : roll) rows.emplace_back(f, br.first, br.second);
    std::sort(rows.begin(), rows.end(),
        [](const auto& a, const auto& b) { return std::get<1>(a) > std::get<1>(b); });

    std::wcout << L"\nAllocator family rollup (private commit only)\n";
    std::wcout << L"---------------------------------------------------------------\n";
    std::wcout << std::left << std::setw(22) << L"Family"
               << std::right << std::setw(18) << L"Bytes"
               << std::setw(12) << L"Regions"
               << std::setw(10) << L"% Total"
               << L"\n";
    std::wcout << L"---------------------------------------------------------------\n";
    for (auto& [f, bytes, count] : rows) {
        double pct = total ? (100.0 * static_cast<double>(bytes) /
                              static_cast<double>(total)) : 0.0;
        std::wcout << std::left << std::setw(22) << FamilyName(f)
                   << std::right << std::setw(18) << FormatSize(bytes)
                   << std::setw(12) << count
                   << std::setw(9) << std::fixed << std::setprecision(1) << pct << L"%"
                   << L"\n";
    }
    std::wcout << L"---------------------------------------------------------------\n";
    std::wcout << std::left << std::setw(22) << L"Total"
               << std::right << std::setw(18) << FormatSize(total)
               << L"\n";
    std::wcout.unsetf(std::ios::fixed);
}

void PrintRegions(const std::vector<std::pair<MINIDUMP_MEMORY_INFO, Family>>& tagged) {
    std::wcout << L"\nPer-region detail (private commit only, sorted by family then size)\n";
    std::wcout << L"Start              | End (excl.)        | Size              | Family               | AllocBase\n";
    std::wcout << L"-------------------|--------------------|-------------------|----------------------|--------------------\n";

    auto sorted = tagged;
    std::sort(sorted.begin(), sorted.end(),
        [](const auto& a, const auto& b) {
            if (a.second != b.second) return a.second < b.second;
            return a.first.RegionSize > b.first.RegionSize;
        });

    for (auto& [info, fam] : sorted) {
        std::wcout << FormatHexAddr(info.BaseAddress)
                   << L" | " << FormatHexAddr(info.BaseAddress + info.RegionSize)
                   << L" | " << std::right << std::setw(17) << FormatSize(info.RegionSize)
                   << L" | " << std::left << std::setw(20) << FamilyName(fam)
                   << L" | " << FormatHexAddr(info.AllocationBase)
                   << L"\n";
    }
}

} // namespace

int wmain(int argc, wchar_t** argv) {
    std::vector<std::string> args_utf8;
    args_utf8.reserve(argc);
    for (int i = 0; i < argc; ++i) args_utf8.emplace_back(WideToUtf8(argv[i]));

    CLI::App app{"Chromium-aware private-commit analyzer (Phase 1: heuristic region tagging)"};
    app.set_version_flag("--version", std::string("0.1.0"));

    std::string dump_file_utf8;
    bool show_regions = false;
    bool include_stacks = false;
    bool debug_allocs = false;
    bool use_symbols = false;
    std::string sympath_utf8;
    std::vector<std::string> probe_patterns;
    bool verbose = false;

    app.add_option("dump_file", dump_file_utf8, "Dump file to analyze")
        ->required()
        ->check(CLI::ExistingFile);
    app.add_flag("--regions", show_regions,
        "Print per-region detail in addition to the family rollup");
    app.add_flag("--include-stacks", include_stacks,
        "Include thread-stack regions in the rollup (off by default)");
    app.add_flag("--debug-allocs", debug_allocs,
        "Print top AllocationBase clusters (diagnostic)");
    app.add_flag("--symbols", use_symbols,
        "Load PDB symbols and run symbol-anchored cluster identification "
        "(slow: triggers symbol downloads)");
    app.add_option("-s,--sympath", sympath_utf8,
        "Symbol path for symbol-anchored cluster identification "
        "(implies --symbols; defaults to _NT_SYMBOL_PATH or C:\\Symbols)");
    app.add_flag("-v,--verbose", verbose, "Print DbgHelp diagnostic messages");
    app.add_option("--probe", probe_patterns,
        "DbgHelp wildcard mask(s) to enumerate (diagnostic; implies --symbols). "
        "May be repeated.");

    std::vector<char*> argv_utf8;
    argv_utf8.reserve(args_utf8.size());
    for (auto& s : args_utf8) argv_utf8.push_back(s.data());

    try {
        app.parse(static_cast<int>(argv_utf8.size()), argv_utf8.data());
    } catch (const CLI::ParseError& e) {
        return app.exit(e);
    }

    const std::wstring dumpFilePath = Utf8ToWide(dump_file_utf8);
    MappedView mapped_view(dumpFilePath);

    // MemoryInfoListStream is required: it carries State/Type/Protect.
    void* mi_stream = nullptr; ULONG mi_size = 0;
    if (!MiniDumpReadDumpStream(mapped_view.get(), MemoryInfoListStream,
                                nullptr, &mi_stream, &mi_size) || !mi_stream) {
        std::wcerr << L"Error: dump does not contain a MemoryInfoListStream.\n";
        return 1;
    }
    auto* mi_header = static_cast<MINIDUMP_MEMORY_INFO_LIST*>(mi_stream);
    if (mi_header->SizeOfEntry < sizeof(MINIDUMP_MEMORY_INFO)) {
        std::wcerr << L"Error: unexpected MINIDUMP_MEMORY_INFO entry size.\n";
        return 1;
    }
    const BYTE* mi_base = static_cast<const BYTE*>(mi_stream) + mi_header->SizeOfHeader;

    // Side data we'll need throughout (and increasingly in later phases).
    const auto modules = LoadModuleList(mapped_view.get());
    const auto stacks  = LoadStackRanges(mapped_view.get());
    DumpMemoryReader dump_mem(mapped_view); // built now so its index is warm.

    const auto clusters = BuildAllocClusters(mi_base, mi_header);

    // Quick sanity check: warn (don't abort) if we don't see any Chromium
    // module. The classifier runs unconditionally; the rollup may still be
    // useful for non-Chromium dumps.
    bool looks_chromium = false;
    for (const auto& m : modules) {
        if (IsChromiumLikeModule(ModuleBaseName(m.name))) { looks_chromium = true; break; }
    }
    if (!looks_chromium) {
        std::wcerr << L"Note: no Chromium-derived module detected in this dump; "
                      L"PartitionAlloc/V8/Oilpan tagging may not apply.\n";
    }

    std::map<Family, std::pair<uint64_t, uint64_t>> rollup; // family -> (bytes, count)
    std::vector<std::pair<MINIDUMP_MEMORY_INFO, Family>> tagged;
    if (show_regions) tagged.reserve(static_cast<size_t>(mi_header->NumberOfEntries));

    uint64_t total_bytes = 0;

    for (ULONG64 i = 0; i < mi_header->NumberOfEntries; ++i) {
        const auto* info = reinterpret_cast<const MINIDUMP_MEMORY_INFO*>(
            mi_base + i * mi_header->SizeOfEntry);
        if (info->State != MEM_COMMIT) continue;
        if (info->Type != MEM_PRIVATE) continue;

        Family fam = ClassifyRegion(*info, stacks, clusters);
        if (fam == Family::ThreadStack && !include_stacks) continue;

        auto& cell = rollup[fam];
        cell.first  += info->RegionSize;
        cell.second += 1;
        total_bytes += info->RegionSize;
        if (show_regions) tagged.emplace_back(*info, fam);
    }

    PrintFamilyRollup(rollup, total_bytes);
    if (show_regions) PrintRegions(tagged);

    // Symbol-anchored cross-check (Phase 2). Loads PDBs (slow on first run);
    // gated on --symbols / --sympath.
    const bool want_symbols = use_symbols || !sympath_utf8.empty() || !probe_patterns.empty();
    if (want_symbols) {
        std::wstring sympath;
        if (!sympath_utf8.empty()) {
            sympath = Utf8ToWide(sympath_utf8);
        } else {
            wchar_t* env = nullptr;
            size_t env_size = 0;
            if (_wdupenv_s(&env, &env_size, L"_NT_SYMBOL_PATH") == 0 &&
                env != nullptr && wcslen(env) > 0) {
                sympath = env;
                free(env);
            } else {
                sympath = L"C:\\Symbols";
                if (env) free(env);
            }
        }
        ProgressReporter progress;
        SymbolResolver sr(mapped_view, sympath, progress, verbose);
        progress.clear();
        const auto cluster_idx = ClusterIndex::Build(clusters);
        const auto anchors = ProbeSymbolAnchors(sr, dump_mem, cluster_idx);
        PrintAnchors(anchors, clusters);

        for (const auto& pat_utf8 : probe_patterns) {
            std::wstring pat = Utf8ToWide(pat_utf8);
            auto hits = sr.findGlobalsMatching(pat, /*max_results=*/200);
            std::wcout << L"\nProbe '" << pat << L"': " << hits.size() << L" hits";
            if (hits.size() == 200) std::wcout << L" (capped)";
            std::wcout << L"\n";
            int shown = 0;
            for (const auto& h : hits) {
                if (shown++ >= 25) { std::wcout << L"  ... (" << (hits.size() - 25)
                                                << L" more)\n"; break; }
                auto val = dump_mem.read<uint64_t>(h.address);
                std::wcout << L"  " << FormatHexAddr(h.address)
                           << L"  size=" << std::setw(8) << h.size
                           << L"  value=" << (val ? FormatHexAddr(*val) : std::wstring(L"<no-mem>          "))
                           << L"  " << h.name << L"\n";
            }
        }
    }

    if (debug_allocs) {
        // Re-walk and aggregate by AllocationBase to inspect what the
        // address-space layout actually looks like. Helps validate
        // heuristic alignment thresholds.
        struct AllocAgg { uint64_t bytes = 0; uint64_t regions = 0;
                          uint64_t span = 0; DWORD protect_seen = 0; };
        std::map<uint64_t, AllocAgg> by_base;
        for (ULONG64 i = 0; i < mi_header->NumberOfEntries; ++i) {
            const auto* info = reinterpret_cast<const MINIDUMP_MEMORY_INFO*>(
                mi_base + i * mi_header->SizeOfEntry);
            if (info->Type != MEM_PRIVATE) continue;
            if (info->AllocationBase == 0) continue;
            auto& a = by_base[info->AllocationBase];
            a.bytes += (info->State == MEM_COMMIT) ? info->RegionSize : 0;
            a.regions += 1;
            uint64_t hi = info->BaseAddress + info->RegionSize - info->AllocationBase;
            if (hi > a.span) a.span = hi;
            if (info->State == MEM_COMMIT) a.protect_seen |= info->Protect;
        }
        std::vector<std::pair<uint64_t, AllocAgg>> rows(by_base.begin(), by_base.end());
        std::sort(rows.begin(), rows.end(),
            [](const auto& a, const auto& b) { return a.second.bytes > b.second.bytes; });
        std::wcout << L"\nTop AllocationBase clusters (private):\n";
        std::wcout << L"AllocBase           | Aligned   | Committed         | Reserved Span     | Regions\n";
        std::wcout << L"--------------------|-----------|-------------------|-------------------|---------\n";
        int shown = 0;
        for (auto& [base, a] : rows) {
            if (shown++ >= 25) break;
            const wchar_t* align =
                (base & (1ull << 30) - 1) == 0 ? L"1GB" :
                (base & (256ull * 1024 * 1024 - 1)) == 0 ? L"256MB" :
                (base & (16ull * 1024 * 1024 - 1)) == 0 ? L"16MB" :
                (base & (2ull  * 1024 * 1024 - 1)) == 0 ? L"2MB" :
                (base & (1ull  * 1024 * 1024 - 1)) == 0 ? L"1MB" :
                (base & (256ull * 1024 - 1)) == 0 ? L"256KB" :
                (base & (64ull  * 1024 - 1)) == 0 ? L"64KB" :
                L"<64K";
            std::wcout << FormatHexAddr(base) << L" | "
                       << std::left << std::setw(9) << align
                       << L" | " << std::right << std::setw(17) << FormatSize(a.bytes)
                       << L" | " << std::right << std::setw(17) << FormatSize(a.span)
                       << L" | " << std::right << std::setw(7) << a.regions
                       << L"\n";
        }
        std::wcout << L"(showing top " << std::min<size_t>(25, rows.size())
                   << L" of " << rows.size() << L" private allocations)\n";
    }
    return 0;
}
