#include <iomanip>
#include <iostream>
#include <wil/result.h>
#include <wil/win32_helpers.h>
#include "command_line.hpp"
#include "mapped_file.hpp"
#include "pointer_counter.hpp"
#include "symbol_resolver.hpp"

void printUsage(const wchar_t* program_name) {
    std::wcout << L"Usage: " << program_name << L" [options]" << std::endl;
    std::wcout << L"Options:" << std::endl;
    std::wcout << L"  -d <dump_file>  Dump file to process" << std::endl;
    std::wcout << L"  -t <count>      Show top N most frequent values (default: 100)" << std::endl;
    std::wcout << L"  -s <sympath>    Symbol path for symbol resolution" << std::endl;
    std::wcout << L"  -h              Show this help message" << std::endl;
    std::wcout << L"" << std::endl;
    std::wcout << L"Example: " << program_name << L" -d memory.dmp -t 1000 -s C:\\Symbols" << std::endl;
}

void printTopValues(const PointerCounter& pointer_counter, const SymbolResolver& symbol_resolver, int top_count) {
    auto sorted_pointers = pointer_counter.getSortedPointersWithCounts();
    
    std::wcout << L"\n=== TOP " << top_count << L" MOST FREQUENT VALUES WITH SYMBOLS ===" << std::endl;
    std::wcout << L"Value (Hex)        | Count     | Percentage | Symbol" << std::endl;
    std::wcout << L"-------------------|-----------|------------|----------------------------------------" << std::endl;
    
    uint64_t total_count = 0;
    for (const auto& pair : sorted_pointers) {
        total_count += pair.second;
    }
    
    int displayed = 0;
    for (const auto& pair : sorted_pointers) {
        if (displayed >= top_count) break;
        
        double percentage = (static_cast<double>(pair.second) / total_count) * 100.0;
        std::wstring symbol_name = symbol_resolver.resolveSymbol(pair.first);
        
        // Truncate very long symbol names for better display
        if (symbol_name.length() > 40) {
            symbol_name = symbol_name.substr(0, 37) + L"...";
        }
        
        std::wcout << L"0x" << std::hex << std::uppercase << std::setw(16) << std::setfill(L'0') 
                    << pair.first << L" | " 
                    << std::dec << std::setw(9) << pair.second << L" | "
                    << std::fixed << std::setprecision(2) << std::setw(6) << percentage << L"% | "
                    << symbol_name << std::endl;
        
        displayed++;
    }
}

int wmain(int argc, wchar_t** argv) {
    CommandLine cmd(argc, argv);

    if (cmd.hasFlag(L"-h")) {
        printUsage(argv[0]);
        return 0;
    }

    auto& dumpFilePath = cmd.get(L"-d");
    if (dumpFilePath.empty()) {
        std::wcerr << L"Error: No dump file specified." << std::endl;
        printUsage(argv[0]);
        return 1;
    }

    int top_count = 100;
    if (!cmd.get(L"-t").empty()) {
        auto& top_count_str = cmd.get(L"-t");
        try {
            top_count = std::stoi(top_count_str);
        }
        catch (std::invalid_argument const&) {
            std::wcerr << L"Error: Invalid top count value: " << top_count_str << std::endl;
            printUsage(argv[0]);
        }
        catch (std::out_of_range const&) {
            std::wcerr << L"Error: Top count value too large: " << top_count_str << std::endl;
            printUsage(argv[0]);
        }
    }

    // Determine symbol path: command line -> environment variable -> default
    std::wstring sympath;
    if (!cmd.get(L"-s").empty()) {
        sympath = cmd.get(L"-s");
        std::wcout << L"Using command line symbol path: " << sympath << std::endl;
    } else {
        // Try to get from _NT_SYMBOL_PATH environment variable
        wchar_t* env_sympath = nullptr;
        size_t env_size = 0;
        if (_wdupenv_s(&env_sympath, &env_size, L"_NT_SYMBOL_PATH") == 0 && env_sympath != nullptr && wcslen(env_sympath) > 0) {
            sympath = env_sympath;
            std::wcout << L"Using _NT_SYMBOL_PATH environment variable: " << sympath << std::endl;
            free(env_sympath);
        } else {
            // Default to C:\Symbols (system drive)
            sympath = L"C:\\Symbols";
            std::wcout << L"Using default symbol path: " << sympath << std::endl;
            if (env_sympath) free(env_sympath);
        }
    }

    MappedFile mapped_file(dumpFilePath);
    
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
    SymbolResolver symbol_resolver(mapped_file, process_handle_dup);
    // Uncomment for quick testing of symbol resolution
    //std::wcout << L"Symbol resolve test: " << symbol_resolver.resolveSymbol(0x00007FFAAB738708) << std::endl;
    PointerCounter pointer_counter(mapped_file);
    printTopValues(pointer_counter, symbol_resolver, top_count);
}
