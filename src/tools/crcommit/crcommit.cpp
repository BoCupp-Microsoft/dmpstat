// crcommit -- Chromium-aware private-commit analyzer for Windows dumps.
//
// Phase 1 (Oilpan only, --summary only):
//   1. Construct an OilpanHeap from the dump (cage discovery + region walk).
//   2. Print the cage descriptor and committed-byte rollup.
//
// All Oilpan-specific logic lives in src/lib/oilpan_heap.{hpp,cpp} so future
// extractors (v-table scan, header decode, ...) can be added as free
// functions over an OilpanHeap without bloating this driver.

#include <windows.h>

#include <cstdint>
#include <cstdlib>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

#include <CLI/CLI.hpp>
#include <wil/result.h>

#include "dump_memory.hpp"
#include "mapped_view.hpp"
#include "oilpan_heap.hpp"
#include "progress.hpp"
#include "symbol_resolver.hpp"
#include "wide_string_utils.hpp"

namespace {

using dmpstat::OilpanHeap;
using dmpstat::Utf8ToWide;
using dmpstat::WideToUtf8;

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

void printSummary(const OilpanHeap& heap) {
    std::wcout << L"Oilpan (cppgc) cage" << std::endl;
    std::wcout << L"  base:           0x" << std::hex << std::setw(16) << std::setfill(L'0')
               << heap.cage_base() << std::dec << std::setfill(L' ') << std::endl;
    std::wcout << L"  reserved size:  " << formatBytes(heap.cage_reserved_size())
               << L"  (g_age_table_size_ = " << heap.age_table_size_raw()
               << L" cards x " << OilpanHeap::kCageCardSizeBytes << L" B)" << std::endl;
    std::wcout << L"  base symbol:    " << heap.base_symbol_name() << std::endl;
    std::wcout << L"  size symbol:    " << heap.size_symbol_name() << std::endl;
    std::wcout << std::endl;
    std::wcout << L"Oilpan committed memory in this dump" << std::endl;
    std::wcout << L"  bytes:          " << formatBytes(heap.committed_bytes())
               << L"  (" << heap.committed_bytes() << L" B)" << std::endl;
    std::wcout << L"  regions:        " << heap.regions().size() << std::endl;
    if (heap.total_private_commit() > 0) {
        const double pct = 100.0 * static_cast<double>(heap.committed_bytes())
                                  / static_cast<double>(heap.total_private_commit());
        std::wcout << L"  share of priv:  " << std::fixed << std::setprecision(2)
                   << pct << L"%  of " << formatBytes(heap.total_private_commit())
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
    RandomAccessReader reader(dump_memory.regions());

    ProgressReporter progress;
    SymbolResolver symbol_resolver(mapped_view, sympath, progress, verbose);
    progress.clear();

    const auto heap = OilpanHeap::discover(symbol_resolver, reader,
                                           mapped_view.get(), verbose);
    if (!heap) return 1;

    printSummary(*heap);
    return 0;
}
