#include <windows.h>
#include <dbghelp.h>
#include <algorithm>
#include <charconv>
#include <iomanip>
#include <iostream>
#include <limits>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>
#include <CLI/CLI.hpp>
#include <wil/result.h>
#include <wil/win32_helpers.h>
#include "mapped_view.hpp"
#include "progress.hpp"
#include "symbol_resolver.hpp"

namespace {

std::wstring Utf8ToWide(const std::string& s) {
    if (s.empty()) return {};
    int needed = MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), nullptr, 0);
    std::wstring result(needed, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), result.data(), needed);
    return result;
}

std::string WideToUtf8(const std::wstring& s) {
    if (s.empty()) return {};
    int needed = WideCharToMultiByte(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), nullptr, 0, nullptr, nullptr);
    std::string result(needed, '\0');
    WideCharToMultiByte(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), result.data(), needed, nullptr, nullptr);
    return result;
}

// Parse a 64-bit unsigned integer from a string. Accepts decimal or
// `0x`/`0X`-prefixed hex.
uint64_t ParseUInt64(const std::string& text) {
    std::string s = text;
    int base = 10;
    size_t pos = 0;
    if (s.size() >= 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) {
        base = 16;
        pos = 2;
    }
    if (pos >= s.size()) {
        throw std::invalid_argument("empty numeric value: '" + text + "'");
    }
    uint64_t value = 0;
    auto first = s.data() + pos;
    auto last = s.data() + s.size();
    auto [ptr, ec] = std::from_chars(first, last, value, base);
    if (ec != std::errc{} || ptr != last) {
        throw std::invalid_argument("invalid numeric value: '" + text + "'");
    }
    return value;
}

// CLI11 validator/transform that parses dec/hex into a uint64 stored as string,
// then we re-parse on use. Simpler: bind to std::string and convert later.

void PrintMatch(uint64_t match_address,
                uint64_t target_value,
                const MINIDUMP_MEMORY_DESCRIPTOR64& memory_desc,
                const BYTE* memory_data,
                uint64_t context,
                const SymbolResolver* symbols) {
    // Compute the byte offset of the match within this memory range.
    const uint64_t match_offset = match_address - memory_desc.StartOfMemoryRange;

    // Determine how many context entries are available before/after, clamped
    // by the bounds of the current memory range. Context outside the range is
    // silently truncated.
    const uint64_t aligned_size = memory_desc.DataSize & ~7ULL;

    uint64_t before = context;
    if (match_offset / sizeof(uint64_t) < before) {
        before = match_offset / sizeof(uint64_t);
    }

    uint64_t after = context;
    const uint64_t bytes_after = aligned_size > match_offset + sizeof(uint64_t)
        ? aligned_size - (match_offset + sizeof(uint64_t))
        : 0;
    const uint64_t entries_after = bytes_after / sizeof(uint64_t);
    if (entries_after < after) {
        after = entries_after;
    }

    auto resolve = [&](uint64_t v) -> std::wstring {
        if (!symbols) return {};
        std::wstring s = symbols->resolveSymbol(v);
        if (s == L"<unknown>") return {};
        return s;
    };

    std::wstring value_sym = resolve(target_value);
    std::wcout << L"Match at 0x"
               << std::hex << std::uppercase << std::setw(16) << std::setfill(L'0')
               << match_address
               << L" (value 0x"
               << std::setw(16) << std::setfill(L'0') << target_value << L")"
               << std::dec << std::setfill(L' ');
    if (!value_sym.empty()) {
        std::wcout << L"  " << value_sym;
    }
    std::wcout << std::endl;

    if (before == 0 && after == 0) {
        return;
    }

    const uint64_t first_offset = match_offset - before * sizeof(uint64_t);
    const uint64_t last_offset = match_offset + after * sizeof(uint64_t);
    for (uint64_t off = first_offset; off <= last_offset; off += sizeof(uint64_t)) {
        const uint64_t addr = memory_desc.StartOfMemoryRange + off;
        const uint64_t value = *reinterpret_cast<const uint64_t*>(memory_data + off);
        const wchar_t marker = (off == match_offset) ? L'>' : L' ';
        std::wcout << L"  " << marker << L" 0x"
                   << std::hex << std::uppercase << std::setw(16) << std::setfill(L'0')
                   << addr
                   << L" : 0x"
                   << std::setw(16) << std::setfill(L'0') << value
                   << std::dec << std::setfill(L' ');
        std::wstring sym = resolve(value);
        if (!sym.empty()) {
            std::wcout << L"  " << sym;
        }
        std::wcout << std::endl;
    }
}

} // namespace

int wmain(int argc, wchar_t** argv) {
    // Convert wide argv to UTF-8 for CLI11.
    std::vector<std::string> args_utf8;
    args_utf8.reserve(argc);
    for (int i = 0; i < argc; ++i) {
        args_utf8.emplace_back(WideToUtf8(argv[i]));
    }

    CLI::App app{"Locate occurrences of a 64-bit value within a Windows dump file"};
    app.set_version_flag("--version", std::string("1.0.0"));

    std::string dump_file_utf8;
    std::string value_str;
    std::string start_str;
    std::string end_str;
    uint64_t skip = 0;
    uint64_t max_results = 0; // 0 = unlimited
    uint64_t context = 0;
    std::string sympath_utf8;
    bool verbose = false;

    app.add_option("dump_file", dump_file_utf8, "Dump file to search")
        ->required()
        ->check(CLI::ExistingFile);
    app.add_option("value", value_str, "64-bit value to find (decimal or 0x-prefixed hex)")
        ->required();
    app.add_option("--start", start_str,
        "Lowest address (inclusive) to search (decimal or 0x-prefixed hex)");
    app.add_option("--end", end_str,
        "Highest address (inclusive) to search (decimal or 0x-prefixed hex)");
    app.add_option("--skip", skip,
        "Number of leading matches to skip before printing")
        ->capture_default_str();
    app.add_option("--max", max_results,
        "Maximum number of matches to print (0 = unlimited)")
        ->capture_default_str();
    app.add_option("--context", context,
        "Pointer-sized values of surrounding context to print on each side")
        ->capture_default_str();
    app.add_option("-s,--sympath", sympath_utf8,
        "Symbol path passed verbatim to DbgHelp (enables symbolication of "
        "the matched value and its context). Defaults to _NT_SYMBOL_PATH if set.");
    app.add_flag("-v,--verbose", verbose,
        "Emit DbgHelp diagnostics during symbol loading");

    std::vector<char*> argv_utf8;
    argv_utf8.reserve(args_utf8.size());
    for (auto& s : args_utf8) argv_utf8.push_back(s.data());

    try {
        app.parse(static_cast<int>(argv_utf8.size()), argv_utf8.data());
    } catch (const CLI::ParseError& e) {
        return app.exit(e);
    }

    uint64_t target_value = 0;
    uint64_t start_addr = 0;
    uint64_t end_addr = std::numeric_limits<uint64_t>::max();
    try {
        target_value = ParseUInt64(value_str);
        if (!start_str.empty()) start_addr = ParseUInt64(start_str);
        if (!end_str.empty()) end_addr = ParseUInt64(end_str);
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }

    if (start_addr > end_addr) {
        std::cerr << "Error: --start must be <= --end." << std::endl;
        return 1;
    }

    const std::wstring dumpFilePath = Utf8ToWide(dump_file_utf8);
    MappedView mapped_view(dumpFilePath);

    ProgressReporter progress;

    // Optionally build a SymbolResolver. We only construct one if the user
    // either passed --sympath or has _NT_SYMBOL_PATH set; otherwise we skip
    // symbolication entirely (avoids loading every module's PDB needlessly).
    std::wstring sympath;
    if (!sympath_utf8.empty()) {
        sympath = Utf8ToWide(sympath_utf8);
    } else {
        wchar_t* env_sympath = nullptr;
        size_t env_size = 0;
        if (_wdupenv_s(&env_sympath, &env_size, L"_NT_SYMBOL_PATH") == 0 && env_sympath != nullptr && wcslen(env_sympath) > 0) {
            sympath = env_sympath;
        }
        if (env_sympath) free(env_sympath);
    }

    std::unique_ptr<SymbolResolver> symbols;
    if (!sympath.empty()) {
        symbols = std::make_unique<SymbolResolver>(mapped_view, sympath, progress, verbose);
        progress.clear();
    }

    void* stream = nullptr;
    ULONG stream_size = 0;
    THROW_IF_WIN32_BOOL_FALSE(MiniDumpReadDumpStream(
        mapped_view.get(), Memory64ListStream, nullptr, &stream, &stream_size));

    auto memory_list = static_cast<PMINIDUMP_MEMORY64_LIST>(stream);
    const ULONG64 range_count = memory_list->NumberOfMemoryRanges;

    ULONG64 total_bytes = 0;
    for (ULONG64 i = 0; i < range_count; i++) {
        total_bytes += memory_list->MemoryRanges[i].DataSize;
    }

    ULONG64 bytes_processed = 0;
    RVA64 current_rva = memory_list->BaseRva;
    uint64_t matches_seen = 0;
    uint64_t matches_printed = 0;

    for (ULONG64 i = 0; i < range_count; i++) {
        const MINIDUMP_MEMORY_DESCRIPTOR64& memory_desc = memory_list->MemoryRanges[i];
        BYTE* memory_data = static_cast<BYTE*>(mapped_view.get()) + current_rva;

        const uint64_t range_start = memory_desc.StartOfMemoryRange;
        const uint64_t range_end = range_start + memory_desc.DataSize; // exclusive

        // Skip ranges that don't intersect [start_addr, end_addr].
        if (range_end <= start_addr || range_start > end_addr) {
            bytes_processed += memory_desc.DataSize;
            current_rva += memory_desc.DataSize;
            continue;
        }

        const uint64_t aligned_size = memory_desc.DataSize & ~7ULL;

        // Compute scan bounds (offsets) intersected with the requested address window.
        uint64_t scan_begin_offset = 0;
        if (start_addr > range_start) {
            // Round up to the next 8-byte boundary within the range.
            const uint64_t delta = start_addr - range_start;
            scan_begin_offset = (delta + 7ULL) & ~7ULL;
        }

        uint64_t scan_end_offset = aligned_size; // exclusive
        if (end_addr < range_end - 1) {
            // Last byte to include is at offset (end_addr - range_start). The
            // last 8-byte slot whose starting address is <= end_addr ends at
            // offset slot_off + 8.
            if (end_addr >= range_start) {
                const uint64_t slot_off = (end_addr - range_start) & ~7ULL;
                scan_end_offset = std::min<uint64_t>(slot_off + sizeof(uint64_t), aligned_size);
            } else {
                scan_end_offset = 0;
            }
        }

        for (uint64_t offset = scan_begin_offset; offset + sizeof(uint64_t) <= scan_end_offset; offset += sizeof(uint64_t)) {
            const uint64_t value = *reinterpret_cast<const uint64_t*>(memory_data + offset);
            if (value == target_value) {
                if (matches_seen >= skip) {
                    progress.clear();
                    PrintMatch(range_start + offset, target_value, memory_desc, memory_data, context, symbols.get());
                    matches_printed++;
                    if (max_results != 0 && matches_printed >= max_results) {
                        return 0;
                    }
                }
                matches_seen++;
            }

            if ((offset & ((1ULL << 23) - 1)) == 0) {
                double pct = total_bytes == 0
                    ? 0.0
                    : (static_cast<double>(bytes_processed + offset) / total_bytes) * 100.0;
                wchar_t buf[160];
                swprintf_s(buf, L"Scanning memory range %llu/%llu (%.1f%%) - matches: %llu, printed: %llu",
                    static_cast<unsigned long long>(i + 1),
                    static_cast<unsigned long long>(range_count),
                    pct,
                    static_cast<unsigned long long>(matches_seen),
                    static_cast<unsigned long long>(matches_printed));
                progress.update(buf);
            }
        }

        bytes_processed += memory_desc.DataSize;
        current_rva += memory_desc.DataSize;
    }

    progress.clear();
    if (matches_printed == 0) {
        std::wcout << L"No matches printed (matches found: " << matches_seen
                   << L", skipped: " << std::min<uint64_t>(matches_seen, skip) << L")" << std::endl;
    }
    return 0;
}
