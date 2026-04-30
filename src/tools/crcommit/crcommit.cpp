// crcommit -- Chromium-aware private-commit analyzer for Windows dumps.
//
// Default mode prints the cage descriptor, committed-byte rollup, and a
// breakdown of the top-N v-tables found inside the cage (count, total bytes
// occupied, type size). `--summary` suppresses the v-table breakdown.
//
// All Oilpan-specific logic lives in src/tools/crcommit/oilpan_heap.{hpp,cpp}.

#include <windows.h>

#include <algorithm>
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
#include "oilpan_objects.hpp"
#include "pointer_counter.hpp"
#include "progress.hpp"
#include "symbol_resolver.hpp"
#include "wide_string_utils.hpp"

namespace {

using dmpstat::OilpanHeap;
using dmpstat::OilpanObjectStats;
using dmpstat::OilpanClassEntry;
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

// Aggregate statistics for printable byte sequences found inside the cage.
struct StringStats {
    uint64_t ascii_count    = 0;
    uint64_t ascii_bytes    = 0;
    uint64_t utf16_count    = 0;
    uint64_t utf16_bytes    = 0;
};

// Heuristic string scan over the Oilpan cage. We don't need symbols here -
// we just look for runs of printable bytes (ASCII / UTF-16LE) of at least
// `min_chars` characters. UTF-16 strings escape the ASCII pass because each
// printable char is followed by 0x00 (not in the printable set), so the two
// counts don't overlap on real string data.
StringStats scanStrings(const OilpanHeap& heap,
                        ProgressReporter& progress,
                        size_t min_chars) {
    auto isPrintableAscii = [](uint8_t b) {
        return b >= 0x20 && b <= 0x7E;
    };

    StringStats stats{};
    const auto& regions = heap.regions();
    for (size_t r = 0; r < regions.size(); ++r) {
        const auto& reg = regions[r];
        if (!reg.data || reg.captured_bytes == 0) continue;

        wchar_t buf[96];
        swprintf_s(buf, L"Scanning strings %zu/%zu", r + 1, regions.size());
        progress.update(buf);

        const uint8_t* p = reg.data;
        const uint64_t n = reg.captured_bytes;

        // ASCII pass.
        uint64_t i = 0;
        while (i < n) {
            if (isPrintableAscii(p[i])) {
                uint64_t j = i;
                while (j < n && isPrintableAscii(p[j])) ++j;
                const uint64_t run = j - i;
                if (run >= min_chars) {
                    ++stats.ascii_count;
                    stats.ascii_bytes += run;
                }
                i = j;
            } else {
                ++i;
            }
        }

        // UTF-16LE pass over even-aligned 2-byte units. A "char" is a pair
        // (lo, 0x00) where lo is printable ASCII; this reliably catches the
        // common case (blink/WTF stores Latin-1/BMP strings two bytes wide)
        // without false-matching other binary content.
        i = 0;
        while (i + 1 < n) {
            if (p[i + 1] == 0 && isPrintableAscii(p[i])) {
                uint64_t j = i;
                while (j + 1 < n && p[j + 1] == 0 && isPrintableAscii(p[j])) {
                    j += 2;
                }
                const uint64_t chars = (j - i) / 2;
                if (chars >= min_chars) {
                    ++stats.utf16_count;
                    stats.utf16_bytes += chars * 2;
                }
                i = j;
            } else {
                i += 2;
            }
        }
    }
    progress.clear();
    return stats;
}

void printStrings(const StringStats& s,
                  size_t min_chars,
                  uint64_t heap_committed_bytes) {
    const uint64_t total_bytes = s.ascii_bytes + s.utf16_bytes;
    const uint64_t total_count = s.ascii_count + s.utf16_count;
    std::wcout << std::endl;
    std::wcout << L"Oilpan strings (printable runs, min length=" << min_chars
               << L")" << std::endl;
    auto row = [](const wchar_t* label, uint64_t count, uint64_t bytes) {
        std::wostringstream line;
        line << L"  " << std::left << std::setw(10) << label
             << std::right << std::setw(10) << count << L" strings  "
             << std::setw(11) << formatBytes(bytes);
        std::wcout << line.str() << std::endl;
    };
    row(L"ASCII:",    s.ascii_count, s.ascii_bytes);
    row(L"UTF-16LE:", s.utf16_count, s.utf16_bytes);
    std::wostringstream line;
    line << L"  " << std::left << std::setw(10) << L"Total:"
         << std::right << std::setw(10) << total_count << L" strings  "
         << std::setw(11) << formatBytes(total_bytes);
    if (heap_committed_bytes > 0) {
        const double pct = 100.0 * static_cast<double>(total_bytes)
                                  / static_cast<double>(heap_committed_bytes);
        line << L"  (" << std::fixed << std::setprecision(2) << pct
             << L"% of " << formatBytes(heap_committed_bytes)
             << L" Oilpan committed)";
    }
    std::wcout << line.str() << std::endl;
}

// One v-table found inside the cage, with its aggregate footprint.
struct VtableEntry {
    uint64_t     vtable_address = 0;
    std::wstring module_name;
    std::wstring class_name;
    uint64_t     count     = 0;  // number of pointers to this vtable found
    uint64_t     type_size = 0;  // bytes per instance per the PDB
    // Number of sibling v-tables collapsed into this row. >1 indicates the
    // class has multiple polymorphic bases and MSVC emitted one vftable per
    // base sub-object; each instance still occupies type_size bytes once.
    uint32_t     vtable_count = 1;
};

// Collapse rows that share (module, class). Each instance of a class with
// multiple polymorphic bases stores one vptr per base sub-object, so the
// pointer scan reports the same instance count under several adjacent vtable
// addresses. Summing those rows would double-count the heap footprint, so we
// keep one canonical row per class: the lowest-address vtable, with
// count = max sibling count (they normally tie) and a vtable_count tag for
// visibility.
std::vector<VtableEntry> collapseSiblingVtables(
        const std::vector<VtableEntry>& in) {
    struct Key { std::wstring m; std::wstring c; };
    auto key_lt = [](const VtableEntry& a, const VtableEntry& b) {
        if (a.module_name != b.module_name) return a.module_name < b.module_name;
        if (a.class_name  != b.class_name)  return a.class_name  < b.class_name;
        return a.vtable_address < b.vtable_address;
    };
    std::vector<VtableEntry> sorted = in;
    std::stable_sort(sorted.begin(), sorted.end(), key_lt);

    std::vector<VtableEntry> out;
    out.reserve(sorted.size());
    for (const auto& e : sorted) {
        if (!out.empty()
            && out.back().module_name == e.module_name
            && out.back().class_name  == e.class_name
            && !e.class_name.empty()) {
            // Same class as previous: merge. Count should match across
            // siblings; take max defensively. type_size is identical.
            auto& dst = out.back();
            if (e.count > dst.count) dst.count = e.count;
            if (dst.vtable_address == 0
                || (e.vtable_address != 0 && e.vtable_address < dst.vtable_address)) {
                dst.vtable_address = e.vtable_address;
            }
            ++dst.vtable_count;
        } else {
            out.push_back(e);
        }
    }
    return out;
}

enum class VtableSort { Size, Count };

// Scan all 8-byte-aligned slots in the heap's regions, count pointer-like
// values, then keep only those that resolve exactly to `Class::`vftable'`.
// Every distinct candidate is consulted (the size cache makes repeats cheap)
// so callers can compute aggregate footprints across the full set, not just
// the rows they intend to display.
std::vector<VtableEntry> collectVtables(const OilpanHeap& heap,
                                        const SymbolResolver& sr,
                                        ProgressReporter& progress) {
    PointerCounter counter(heap.regions(), progress);
    progress.clear();

    auto sorted = counter.getSortedPointersWithCounts();

    // V-tables live inside loaded modules' .rdata. Pre-filter candidate
    // pointer values to those that fall inside a loaded module image; this
    // typically removes ~99% of "data noise" (heap objects, stack frames,
    // misaligned data) before dbghelp gets involved, which dominates the
    // runtime of this step. Doing this filter up-front (rather than inside
    // the loop) lets the progress denominator reflect the real workload.
    std::vector<PointerValueInfo> filtered;
    filtered.reserve(sorted.size() / 64);
    for (const auto& v : sorted) {
        if (sr.isAddressInLoadedModule(v.value)) filtered.push_back(v);
    }

    std::vector<VtableEntry> vtables;
    vtables.reserve(64);
    uint64_t i = 0;
    const uint64_t total = filtered.size();
    for (const auto& v : filtered) {
        ++i;
        wchar_t buf[96];
        swprintf_s(buf, L"Resolving v-tables %llu/%llu",
                   static_cast<unsigned long long>(i),
                   static_cast<unsigned long long>(total));
        progress.update(buf);
        auto info = sr.resolveVtable(v.value);
        if (!info) continue;
        vtables.push_back({info->vtable_address,
                           std::move(info->module_name),
                           std::move(info->class_name),
                           v.count,
                           info->type_size});
    }
    progress.clear();
    return vtables;
}

void printVtables(const std::vector<VtableEntry>& vtables_in,
                  size_t top,
                  VtableSort sort,
                  uint64_t heap_committed_bytes,
                  const SymbolResolver& sr) {
    std::vector<VtableEntry> vtables = collapseSiblingVtables(vtables_in);
    if (sort == VtableSort::Size) {
        std::stable_sort(vtables.begin(), vtables.end(),
            [](const VtableEntry& a, const VtableEntry& b) {
                return a.count * a.type_size > b.count * b.type_size;
            });
    } else {
        std::stable_sort(vtables.begin(), vtables.end(),
            [](const VtableEntry& a, const VtableEntry& b) {
                return a.count > b.count;
            });
    }

    uint64_t total_bytes = 0;
    for (const auto& e : vtables) total_bytes += e.count * e.type_size;

    const size_t shown = std::min(top, vtables.size());
    std::wcout << std::endl;
    std::wcout << L"Oilpan v-tables (top " << shown
               << L" of " << vtables.size()
               << L", sorted by " << (sort == VtableSort::Size ? L"size" : L"count")
               << L")" << std::endl;
    if (heap_committed_bytes > 0) {
        const double pct = 100.0 * static_cast<double>(total_bytes)
                                  / static_cast<double>(heap_committed_bytes);
        std::wcout << L"  accounted:    " << formatBytes(total_bytes)
                   << L"  (" << std::fixed << std::setprecision(2) << pct
                   << L"% of " << formatBytes(heap_committed_bytes)
                   << L" Oilpan committed)" << std::endl;
    } else {
        std::wcout << L"  accounted:    " << formatBytes(total_bytes) << std::endl;
    }

    // Always report how many distinct (module, class) keys we couldn't get
    // sizeof() for - those rows render as 0 B and silently shrink "accounted",
    // which would otherwise make the heap attribution look smaller than it
    // really is.
    const auto stats = sr.vtable_resolution_stats();
    const uint64_t total_keys = stats.resolved + stats.unresolved;
    std::wcout << L"  type info:    "
               << stats.resolved << L" resolved, "
               << stats.unresolved << L" unresolved";
    if (total_keys > 0) {
        const double pct = 100.0 * static_cast<double>(stats.unresolved)
                                  / static_cast<double>(total_keys);
        std::wcout << L"  (" << std::fixed << std::setprecision(2) << pct
                   << L"% missing sizeof)";
    }
    std::wcout << std::endl;
    if (sr.verbose() && !sr.unresolved_vtable_classes().empty()) {
        std::vector<std::wstring> names(sr.unresolved_vtable_classes().begin(),
                                        sr.unresolved_vtable_classes().end());
        std::sort(names.begin(), names.end());
        std::wcout << L"  unresolved classes:" << std::endl;
        for (const auto& n : names) {
            std::wcout << L"    " << n << std::endl;
        }
    }
    std::wcout << L"  Count       Bytes        Type size  Vt  V-table address     Class" << std::endl;
    std::wcout << L"  ----------  -----------  ---------  --  ------------------  -----------------------------------"
               << std::endl;
    for (size_t i = 0; i < shown; ++i) {
        const auto& e = vtables[i];
        const uint64_t bytes = e.count * e.type_size;
        std::wostringstream line;
        line << L"  " << std::left << std::setw(10) << e.count
             << L"  " << std::setw(11) << formatBytes(bytes)
             << L"  " << std::setw(9)  << e.type_size
             << L"  " << std::setw(2)  << e.vtable_count
             << L"  0x" << std::right << std::hex << std::setw(16)
             << std::setfill(L'0') << e.vtable_address
             << std::dec << std::setfill(L' ') << std::left
             << L"  ";
        if (!e.module_name.empty()) {
            line << e.module_name << L"!";
        }
        line << e.class_name;
        std::wcout << line.str() << std::endl;
    }
}

void printOilpanPages(const OilpanObjectStats& s, uint64_t committed_bytes) {
    auto pct = [committed_bytes](uint64_t v) {
        if (committed_bytes == 0) return 0.0;
        return 100.0 * static_cast<double>(v) / static_cast<double>(committed_bytes);
    };
    std::wcout << std::endl;
    std::wcout << L"Oilpan pages" << std::endl;
    std::wcout << L"  Normal pages: " << s.normal_page_count
               << L"  (" << formatBytes(s.normal_page_bytes)
               << L", " << std::fixed << std::setprecision(2)
               << pct(s.normal_page_bytes) << L"% of committed)" << std::endl;
    std::wcout << L"  Large pages:  " << s.large_page_count
               << L"  (" << formatBytes(s.large_page_bytes)
               << L", " << std::fixed << std::setprecision(2)
               << pct(s.large_page_bytes) << L"% of committed)" << std::endl;
    std::wcout << L"  Distinct cppgc Heaps: " << s.distinct_heap_count << std::endl;

    std::wcout << std::endl;
    std::wcout << L"Oilpan objects" << std::endl;
    std::wcout << L"  Live:        " << std::setw(8) << s.live_count
               << L"  " << formatBytes(s.live_bytes)
               << L"  (" << std::fixed << std::setprecision(2)
               << pct(s.live_bytes) << L"% of committed)" << std::endl;
    std::wcout << L"  Free-list:   " << std::setw(8) << s.free_count
               << L"  " << formatBytes(s.free_bytes)
               << L"  (" << std::fixed << std::setprecision(2)
               << pct(s.free_bytes) << L"% of committed)" << std::endl;
    std::wcout << L"  Total subs:  " << std::setw(8) << s.allocation_count() << std::endl;
    std::wcout << L"  Unaccounted (LAB tail / page header / rounding): "
               << formatBytes(s.lab_unaccounted_bytes
                              + (committed_bytes
                                 > s.live_bytes + s.free_bytes
                                       + s.lab_unaccounted_bytes
                                 ? committed_bytes
                                       - s.live_bytes - s.free_bytes
                                       - s.lab_unaccounted_bytes
                                 : 0))
               << std::endl;
}

void printOilpanClasses(const OilpanObjectStats& stats,
                        size_t top,
                        VtableSort sort,
                        uint64_t committed_bytes) {
    std::vector<OilpanClassEntry> rows;
    rows.reserve(stats.by_gc_info.size());
    for (auto& [_, e] : stats.by_gc_info) rows.push_back(e);
    if (sort == VtableSort::Size) {
        std::stable_sort(rows.begin(), rows.end(),
            [](const OilpanClassEntry& a, const OilpanClassEntry& b) {
                return a.bytes > b.bytes;
            });
    } else {
        std::stable_sort(rows.begin(), rows.end(),
            [](const OilpanClassEntry& a, const OilpanClassEntry& b) {
                return a.count > b.count;
            });
    }

    uint64_t total_bytes = 0;
    uint64_t resolved_bytes = 0;
    for (auto& e : rows) {
        total_bytes += e.bytes;
        if (!e.class_name.empty()) resolved_bytes += e.bytes;
    }

    const size_t shown = std::min(top, rows.size());
    std::wcout << std::endl;
    std::wcout << L"Oilpan classes (top " << shown << L" of " << rows.size()
               << L", sorted by " << (sort == VtableSort::Size ? L"size" : L"count")
               << L")" << std::endl;
    if (committed_bytes > 0) {
        std::wcout << L"  accounted:    " << formatBytes(total_bytes)
                   << L"  (" << std::fixed << std::setprecision(2)
                   << 100.0 * static_cast<double>(total_bytes)
                            / static_cast<double>(committed_bytes)
                   << L"% of " << formatBytes(committed_bytes)
                   << L" Oilpan committed)" << std::endl;
        if (total_bytes > 0) {
            std::wcout << L"  named:        " << formatBytes(resolved_bytes)
                       << L"  (" << std::fixed << std::setprecision(2)
                       << 100.0 * static_cast<double>(resolved_bytes)
                                / static_cast<double>(total_bytes)
                       << L"% resolved via GCInfoTable)" << std::endl;
        }
    }
    std::wcout << L"  Count       Bytes        Idx     Class" << std::endl;
    std::wcout << L"  ----------  -----------  ------  ----------------------------------------"
               << std::endl;
    for (size_t i = 0; i < shown; ++i) {
        const auto& e = rows[i];
        std::wostringstream line;
        line << L"  " << std::left << std::setw(10) << e.count
             << L"  " << std::setw(11) << formatBytes(e.bytes)
             << L"  " << std::setw(6) << e.gc_info_index
             << L"  ";
        if (e.class_name.empty()) {
            line << L"<unresolved>";
        } else {
            line << e.class_name;
        }
        std::wcout << line.str() << std::endl;
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
    std::string sort_utf8 = "size";
    bool     summary = false;
    bool     no_strings = false;
    bool     no_pages = false;
    bool     no_classes = false;
    bool     verbose = false;
    uint64_t top     = 25;
    uint64_t min_string_length = 8;

    app.add_option("dump_file", dump_file_utf8, "Dump file to analyze")
        ->required()
        ->check(CLI::ExistingFile);
    app.add_option("-s,--sympath", sympath_utf8,
        "Symbol search path (overrides _NT_SYMBOL_PATH).");
    app.add_flag("--summary", summary,
        "Print only the cage descriptor and committed-byte rollup; "
        "skip the v-table breakdown.");
    app.add_option("--top", top,
        "Maximum number of v-table rows to print (default 25).")
        ->capture_default_str();
    app.add_option("--sort", sort_utf8,
        "Sort the v-table table by 'size' (count*type_size) or 'count'.")
        ->check(CLI::IsMember({"size", "count"}))
        ->capture_default_str();
    app.add_flag("--no-strings", no_strings,
        "Skip the printable-string scan over Oilpan committed memory.");
    app.add_flag("--no-pages", no_pages,
        "Skip the cppgc page classification + HeapObjectHeader walk.");
    app.add_flag("--no-classes", no_classes,
        "Skip GCInfoIndex -> class name resolution (still walks objects).");
    app.add_option("--min-string-length", min_string_length,
        "Minimum character count for a printable run to count as a string.")
        ->capture_default_str();
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

    if (!summary) {
        if (!no_strings) {
            const auto strings = scanStrings(*heap, progress,
                                             static_cast<size_t>(min_string_length));
            printStrings(strings, static_cast<size_t>(min_string_length),
                         heap->committed_bytes());
        }
        const VtableSort sort = (sort_utf8 == "count") ? VtableSort::Count
                                                       : VtableSort::Size;
        if (!no_pages) {
            auto stats = dmpstat::walkOilpanObjects(*heap, reader,
                                                    symbol_resolver, progress);
            if (stats) {
                if (!no_classes) {
                    progress.update(L"Resolving cppgc class names");
                    dmpstat::resolveClassNames(*stats, reader, symbol_resolver);
                    progress.clear();
                }
                printOilpanPages(*stats, heap->committed_bytes());
                printOilpanClasses(*stats, static_cast<size_t>(top), sort,
                                   heap->committed_bytes());
            }
        }
        const auto vtables = collectVtables(*heap, symbol_resolver, progress);
        printVtables(vtables, static_cast<size_t>(top), sort,
                     heap->committed_bytes(), symbol_resolver);
    }
    return 0;
}
