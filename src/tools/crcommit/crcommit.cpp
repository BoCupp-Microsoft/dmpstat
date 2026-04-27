// crcommit -- Chromium-aware private-commit analyzer for Windows dumps.
//
// Phase 1 (Oilpan only, --summary only):
//   1. Resolve cppgc::internal::CagedHeapBase::g_heap_base_ from symbols.
//   2. Resolve cppgc::internal::CagedHeapBase::g_age_table_size_.
//   3. Read both 8-byte values from the dump's captured memory.
//   4. Compute cage_size = age_table_size * 4096 (kCardSizeInBytes).
//   5. Walk MemoryInfoListStream; sum committed bytes whose extents fall
//      inside [cage_base, cage_base + cage_size).
//
// Rationale for this approach is documented in
//   docs/oilpan-heap-layout.md
//
// What this tool deliberately does NOT do yet:
//   - per-space / per-page enumeration via HeapBase walks
//   - HeapObjectHeader / GCInfoIndex decoding (type names)
//   - any heuristic region tagging -- everything is symbol-anchored
//
// Later phases will extend the binary; today's CLI surface is intentionally
// minimal so the cage discovery path is clearly the first thing exercised.

#include <windows.h>
#include <dbghelp.h>

#include <algorithm>
#include <cstdint>
#include <cstdlib>
#include <iomanip>
#include <iostream>
#include <optional>
#include <sstream>
#include <string>
#include <vector>

#include <CLI/CLI.hpp>
#include <wil/result.h>

#include "dump_memory.hpp"
#include "mapped_view.hpp"
#include "progress.hpp"
#include "symbol_resolver.hpp"
#include "wide_string_utils.hpp"

namespace {

using dmpstat::Utf8ToWide;
using dmpstat::WideToUtf8;

// Constants from V8's include/cppgc/internal/api-constants.h.
// kCardSizeInBytes = kCagedHeapDefaultReservationSize / 1 MiB.
constexpr uint64_t kCageCardSizeBytes      = 4096;
constexpr uint64_t kCageDefaultReservation = static_cast<uint64_t>(4) * 1024 * 1024 * 1024;
constexpr uint64_t kCageMaxLargerCage      = static_cast<uint64_t>(16) * 1024 * 1024 * 1024;

// Pretty-print bytes as "X.YY MiB" / "X.YY GiB". Mirrors the segments tool's
// formatting style at the same scale.
std::wstring formatBytes(uint64_t bytes) {
    constexpr uint64_t kKiB = 1024;
    constexpr uint64_t kMiB = kKiB * 1024;
    constexpr uint64_t kGiB = kMiB * 1024;

    std::wostringstream s;
    s.setf(std::ios::fixed);
    s << std::setprecision(2);
    if (bytes >= kGiB) {
        s << (static_cast<double>(bytes) / kGiB) << L" GiB";
    } else if (bytes >= kMiB) {
        s << (static_cast<double>(bytes) / kMiB) << L" MiB";
    } else if (bytes >= kKiB) {
        s << (static_cast<double>(bytes) / kKiB) << L" KiB";
    } else {
        s << bytes << L" B";
    }
    return s.str();
}

// Resolve a cppgc global by trying its fully-qualified name first, then a
// broader wildcard mask. Returns the symbol info, or std::nullopt.
struct ResolvedGlobal {
    std::wstring name;     // the name DbgHelp ultimately matched
    uint64_t     address;
};

std::optional<ResolvedGlobal> resolveCppgcGlobal(const SymbolResolver& sr,
                                                 const std::wstring& exact_name,
                                                 const std::wstring& wildcard_mask,
                                                 bool verbose) {
    if (auto va = sr.findGlobal(exact_name); va) {
        if (verbose) {
            std::wcerr << L"[crcommit] resolved " << exact_name
                       << L" @ 0x" << std::hex << *va << std::dec << std::endl;
        }
        return ResolvedGlobal{exact_name, *va};
    }
    if (verbose) {
        std::wcerr << L"[crcommit] exact symbol lookup failed: " << exact_name
                   << L"; trying wildcard: " << wildcard_mask << std::endl;
    }
    auto hits = sr.findGlobalsMatching(wildcard_mask, /*max_results=*/8);
    if (hits.empty()) return std::nullopt;
    if (verbose) {
        std::wcerr << L"[crcommit] wildcard '" << wildcard_mask
                   << L"' matched " << hits.size() << L" symbol(s); using first:" << std::endl;
        for (const auto& h : hits) {
            std::wcerr << L"    " << h.name << L"  @ 0x"
                       << std::hex << h.address << std::dec << std::endl;
        }
    }
    return ResolvedGlobal{hits.front().name, hits.front().address};
}

struct CageInfo {
    uint64_t base;             // cage_base (g_heap_base_)
    uint64_t reserved_size;    // age_table_size * kCardSizeInBytes
    std::wstring base_symbol_name;
    std::wstring size_symbol_name;
    uint64_t age_table_size_raw;
};

// Locate and read the cppgc cage descriptors. Returns std::nullopt on any
// failure with a diagnostic written to std::wcerr.
std::optional<CageInfo> discoverCage(const SymbolResolver& sr,
                                     const DumpMemoryReader& dm,
                                     bool verbose) {
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

    const uint64_t cage_reserved_size = *age_table_size * kCageCardSizeBytes;

    // Sanity: reserved size should be one of the documented values. Warn but
    // continue if it isn't -- a future build flavour may pick something else.
    if (cage_reserved_size != kCageDefaultReservation
        && cage_reserved_size != kCageMaxLargerCage) {
        std::wcerr << L"Warning: derived cage reserved size ("
                   << formatBytes(cage_reserved_size)
                   << L") does not match a known build-flag combination (4 GiB / 16 GiB).\n"
                      L"  Continuing with the derived value." << std::endl;
    }
    // Sanity: cage base should be naturally aligned to its reserved size.
    if ((*cage_base & (cage_reserved_size - 1)) != 0) {
        std::wcerr << L"Warning: cage base 0x" << std::hex << *cage_base << std::dec
                   << L" is not aligned to derived cage reserved size "
                   << formatBytes(cage_reserved_size)
                   << L"; readings may be wrong." << std::endl;
    }

    return CageInfo{
        *cage_base,
        cage_reserved_size,
        base_global->name,
        size_global->name,
        *age_table_size,
    };
}

// Sum the committed bytes of MemoryInfoListStream entries that intersect
// [cage_base, cage_base + cage_size).
struct OilpanRollup {
    uint64_t bytes_in_cage = 0;
    uint64_t regions       = 0;
    uint64_t total_private_commit = 0;  // for context in the summary line
};

std::optional<OilpanRollup> rollupOilpanRegions(void* dump_base,
                                                const CageInfo& cage,
                                                bool verbose) {
    void* stream = nullptr;
    ULONG stream_size = 0;
    if (!MiniDumpReadDumpStream(dump_base, MemoryInfoListStream, nullptr,
                                &stream, &stream_size)
        || stream == nullptr) {
        std::wcerr << L"Error: dump does not contain a MemoryInfoListStream." << std::endl;
        return std::nullopt;
    }

    auto* header = static_cast<MINIDUMP_MEMORY_INFO_LIST*>(stream);
    if (header->SizeOfEntry < sizeof(MINIDUMP_MEMORY_INFO)) {
        std::wcerr << L"Error: unexpected MINIDUMP_MEMORY_INFO entry size: "
                   << header->SizeOfEntry << std::endl;
        return std::nullopt;
    }

    // Reserved size is power-of-two and at most 16 GiB; cage_base is aligned
    // to it, so cage_base + reserved_size cannot overflow on a 64-bit address
    // space.
    const uint64_t cage_end = cage.base + cage.reserved_size;
    const BYTE* base = static_cast<const BYTE*>(stream) + header->SizeOfHeader;

    OilpanRollup roll{};
    for (ULONG64 i = 0; i < header->NumberOfEntries; ++i) {
        const auto* info = reinterpret_cast<const MINIDUMP_MEMORY_INFO*>(
            base + i * header->SizeOfEntry);

        if (info->State != MEM_COMMIT) continue;
        if (info->Type != MEM_PRIVATE) continue;  // Oilpan is private commit.

        const uint64_t r_start = info->BaseAddress;
        const uint64_t r_end   = r_start + info->RegionSize;

        roll.total_private_commit += info->RegionSize;

        const uint64_t lo = std::max(r_start, cage.base);
        const uint64_t hi = std::min(r_end,   cage_end);
        if (lo >= hi) continue;

        const uint64_t intersect = hi - lo;
        roll.bytes_in_cage += intersect;
        roll.regions       += 1;

        if (verbose) {
            std::wcerr << L"[crcommit]  oilpan region 0x" << std::hex << r_start
                       << L"..0x" << r_end << std::dec
                       << L" (" << formatBytes(info->RegionSize) << L")";
            if (intersect != info->RegionSize) {
                std::wcerr << L" intersect=" << formatBytes(intersect);
            }
            std::wcerr << std::endl;
        }
    }
    return roll;
}

void printSummary(const CageInfo& cage, const OilpanRollup& roll) {
    std::wcout << L"Oilpan (cppgc) cage" << std::endl;
    std::wcout << L"  base:           0x" << std::hex << std::setw(16) << std::setfill(L'0')
               << cage.base << std::dec << std::setfill(L' ') << std::endl;
    std::wcout << L"  reserved size:  " << formatBytes(cage.reserved_size)
               << L"  (g_age_table_size_ = " << cage.age_table_size_raw
               << L" cards x " << kCageCardSizeBytes << L" B)" << std::endl;
    std::wcout << L"  base symbol:    " << cage.base_symbol_name << std::endl;
    std::wcout << L"  size symbol:    " << cage.size_symbol_name << std::endl;
    std::wcout << std::endl;
    std::wcout << L"Oilpan committed memory in this dump" << std::endl;
    std::wcout << L"  bytes:          " << formatBytes(roll.bytes_in_cage)
               << L"  (" << roll.bytes_in_cage << L" B)" << std::endl;
    std::wcout << L"  regions:        " << roll.regions << std::endl;
    if (roll.total_private_commit > 0) {
        const double pct = 100.0 * static_cast<double>(roll.bytes_in_cage)
                                  / static_cast<double>(roll.total_private_commit);
        std::wcout << L"  share of priv:  " << std::fixed << std::setprecision(2)
                   << pct << L"%  of " << formatBytes(roll.total_private_commit)
                   << L" private commit" << std::endl;
    }
}

} // namespace

int wmain(int argc, wchar_t** argv) {
    std::vector<std::string> args_utf8;
    args_utf8.reserve(argc);
    for (int i = 0; i < argc; ++i) {
        args_utf8.emplace_back(WideToUtf8(argv[i]));
    }

    CLI::App app{"Chromium-aware private-commit analyzer (Windows minidumps)"};
    app.set_version_flag("--version", std::string("0.1.0"));

    std::string dump_file_utf8;
    std::string sympath_utf8;
    bool summary = false;
    bool verbose = false;

    app.add_option("dump_file", dump_file_utf8, "Dump file to analyze")
        ->required()
        ->check(CLI::ExistingFile);
    app.add_option("-s,--sympath", sympath_utf8,
        "Symbol search path (overrides _NT_SYMBOL_PATH).");
    app.add_flag("--summary", summary,
        "Print a one-block summary of Oilpan committed memory.");
    app.add_flag("-v,--verbose", verbose,
        "Print symbol-resolution and region-walk diagnostics to stderr.");

    std::vector<char*> argv_utf8;
    argv_utf8.reserve(args_utf8.size());
    for (auto& s : args_utf8) argv_utf8.push_back(s.data());

    try {
        app.parse(static_cast<int>(argv_utf8.size()), argv_utf8.data());
    } catch (const CLI::ParseError& e) {
        return app.exit(e);
    }

    if (!summary) {
        std::wcerr << L"crcommit currently only supports --summary. "
                      L"Pass --summary to run." << std::endl;
        return 2;
    }

    const std::wstring dump_path = Utf8ToWide(dump_file_utf8);

    std::wstring sympath;
    if (!sympath_utf8.empty()) {
        sympath = Utf8ToWide(sympath_utf8);
    } else {
        wchar_t* env = nullptr;
        size_t   env_len = 0;
        _wdupenv_s(&env, &env_len, L"_NT_SYMBOL_PATH");
        if (env) {
            sympath = env;
            free(env);
        }
    }

    MappedView mapped_view(dump_path);
    DumpMemoryReader dump_memory(mapped_view);

    ProgressReporter progress;
    SymbolResolver symbol_resolver(mapped_view, sympath, progress, verbose);
    progress.clear();

    const auto cage = discoverCage(symbol_resolver, dump_memory, verbose);
    if (!cage) return 1;

    const auto roll = rollupOilpanRegions(mapped_view.get(), *cage, verbose);
    if (!roll) return 1;

    printSummary(*cage, *roll);
    return 0;
}
