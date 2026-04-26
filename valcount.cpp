#include <iomanip>
#include <iostream>
#include <string>
#include <CLI/CLI.hpp>
#include <wil/result.h>
#include <wil/win32_helpers.h>
#include "mapped_view.hpp"
#include "pointer_counter.hpp"
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

} // namespace

void printTopValues(const PointerCounter& pointer_counter, const SymbolResolver& symbol_resolver, int top_count) {
    auto sorted_pointers = pointer_counter.getSortedPointersWithCounts();
    
    std::wcout << L"\n=== TOP " << top_count << L" MOST FREQUENT VALUES WITH SYMBOLS ===" << std::endl;
    std::wcout << L"Value (Hex)        | Count     | Percentage | Low Address        | High Address       | Symbol" << std::endl;
    std::wcout << L"-------------------|-----------|------------|--------------------|--------------------|----------------------------------------" << std::endl;
    
    uint64_t total_count = 0;
    for (const auto& info : sorted_pointers) {
        total_count += info.count;
    }
    
    int displayed = 0;
    for (const auto& info : sorted_pointers) {
        if (displayed >= top_count) break;
        
        double percentage = (static_cast<double>(info.count) / total_count) * 100.0;
        std::wstring symbol_name = symbol_resolver.resolveSymbol(info.value);
        
        // Truncate very long symbol names for better display
        if (symbol_name.length() > 40) {
            symbol_name = symbol_name.substr(0, 37) + L"...";
        }
        
        std::wcout << L"0x" << std::hex << std::uppercase << std::setw(16) << std::setfill(L'0') 
                    << info.value << L" | " 
                    << std::dec << std::setfill(L' ') << std::setw(9) << info.count << L" | "
                    << std::fixed << std::setprecision(2) << std::setw(6) << percentage << L"% | "
                    << L"0x" << std::hex << std::uppercase << std::setw(16) << std::setfill(L'0')
                    << info.low_address << L" | "
                    << L"0x" << std::setw(16) << std::setfill(L'0')
                    << info.high_address << L" | "
                    << std::dec << std::setfill(L' ')
                    << symbol_name << std::endl;
        
        displayed++;
    }
}

int wmain(int argc, wchar_t** argv) {
    // Convert wide argv to UTF-8 for CLI11.
    std::vector<std::string> args_utf8;
    args_utf8.reserve(argc);
    for (int i = 0; i < argc; ++i) {
        args_utf8.emplace_back(WideToUtf8(argv[i]));
    }

    CLI::App app{"Windows dump-file pointer frequency analyzer"};
    app.set_version_flag("--version", std::string("1.0.0"));

    std::string dump_file_utf8;
    int top_count = 100;
    std::string sympath_utf8;

    app.add_option("dump_file", dump_file_utf8, "Dump file to process")
        ->required()
        ->check(CLI::ExistingFile);
    app.add_option("-t,--top", top_count, "Show top N most frequent values")
        ->capture_default_str()
        ->check(CLI::PositiveNumber);
    app.add_option("-s,--sympath", sympath_utf8,
        "Symbol path for symbol resolution (defaults to _NT_SYMBOL_PATH or C:\\Symbols)");

    // Build a vector<const char*> for CLI11; it expects argv-style (program name first is fine).
    std::vector<char*> argv_utf8;
    argv_utf8.reserve(args_utf8.size());
    for (auto& s : args_utf8) argv_utf8.push_back(s.data());

    try {
        app.parse(static_cast<int>(argv_utf8.size()), argv_utf8.data());
    } catch (const CLI::ParseError& e) {
        return app.exit(e);
    }

    std::wstring dumpFilePath = Utf8ToWide(dump_file_utf8);

    // Determine symbol path: command line -> environment variable -> default
    std::wstring sympath;
    if (!sympath_utf8.empty()) {
        sympath = Utf8ToWide(sympath_utf8);
    } else {
        wchar_t* env_sympath = nullptr;
        size_t env_size = 0;
        if (_wdupenv_s(&env_sympath, &env_size, L"_NT_SYMBOL_PATH") == 0 && env_sympath != nullptr && wcslen(env_sympath) > 0) {
            sympath = env_sympath;
            free(env_sympath);
        } else {
            sympath = L"C:\\Symbols";
            if (env_sympath) free(env_sympath);
        }
    }

    MappedView mapped_view(dumpFilePath);

    wil::unique_handle process_handle{GetCurrentProcess()};
    wil::unique_handle process_handle_dup;
    THROW_IF_WIN32_BOOL_FALSE(DuplicateHandle(
        process_handle.get(),
        process_handle.get(),
        process_handle.get(),
        process_handle_dup.put(),
        0,
        FALSE,
        DUPLICATE_SAME_ACCESS
    ));

    ProgressReporter progress;
    SymbolResolver symbol_resolver(mapped_view, process_handle_dup, progress);
    PointerCounter pointer_counter(mapped_view, progress);
    progress.clear();

    printTopValues(pointer_counter, symbol_resolver, top_count);
}
