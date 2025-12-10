#include <windows.h>
#include <dbghelp.h>
#include <iostream>
#include <unordered_map>
#include <vector>
#include <string>
#include <iomanip>
#include <fstream>
#include <algorithm>

#pragma comment(lib, "dbghelp.lib")

class DumpAnalyzer {
private:
    HANDLE hProcess;
    std::unordered_map<UINT64, ULONG> valueCount;
    PVOID pDumpFileData;
    bool symbolsInitialized;
    
    // Helper function to validate if a value could be a valid user-mode pointer
    bool IsValidUserModePointer(UINT64 value) const {
        // Null pointer is not valid
        if (value == 0) {
            return false;
        }
        
        // On 64-bit Windows, valid user-mode pointers are typically:
        // - Between 0x00010000 and 0x7FFEFFFF0000 (user space)
        // - Must be properly aligned (we're already processing 8-byte aligned values)
        
        // Values below 64KB (0x10000) are typically invalid in user mode
        if (value < 0x10000) {
            return false;
        }
        
        // Check if it's in valid user-mode range (up to 0x7FFEFFFF0000)
        // Exclude kernel-mode space since these are user-mode dumps
        if (value <= 0x7FFEFFFF0000ULL) {
            return true;
        }
        
        // Values above user-mode space are not valid user-mode pointer values
        return false;
    }
    
    // Function to resolve address to symbol name
    std::wstring ResolveSymbol(UINT64 address) const {
        if (!hProcess || !symbolsInitialized) {
            return L"<no symbols>";
        }
        
        // Buffer for symbol information
        BYTE symbolBuffer[sizeof(SYMBOL_INFOW) + MAX_SYM_NAME * sizeof(WCHAR)];
        PSYMBOL_INFOW pSymbol = reinterpret_cast<PSYMBOL_INFOW>(symbolBuffer);
        
        pSymbol->SizeOfStruct = sizeof(SYMBOL_INFOW);
        pSymbol->MaxNameLen = MAX_SYM_NAME;
        
        DWORD64 displacement = 0;
        
        if (SymFromAddrW(hProcess, address, &displacement, pSymbol)) {
            if (displacement == 0) {
                return std::wstring(pSymbol->Name);
            } else {
                return std::wstring(pSymbol->Name) + L"+" + std::to_wstring(displacement);
            }
        }
        
        // Try to get module information if symbol lookup failed
        IMAGEHLP_MODULEW64 moduleInfo = { 0 };
        moduleInfo.SizeOfStruct = sizeof(IMAGEHLP_MODULEW64);
        
        if (SymGetModuleInfoW64(hProcess, address, &moduleInfo)) {
            DWORD64 moduleBase = moduleInfo.BaseOfImage;
            DWORD64 offset = address - moduleBase;
            
            // Extract just the module name without path
            std::wstring moduleName = moduleInfo.ModuleName;
            return moduleName + L"+0x" + std::to_wstring(offset);
        }
        
        return L"<unknown>";
    }
    
    // Function to load symbols from the dump file
    bool LoadSymbolsFromDump(PVOID pDumpFile) {
        std::wcout << L"Loading symbols from dump file..." << std::endl;
        
        // Read module list stream
        PVOID pModuleStream = nullptr;
        ULONG moduleStreamSize = 0;
        
        if (!MiniDumpReadDumpStream(pDumpFile, ModuleListStream, nullptr, &pModuleStream, &moduleStreamSize)) {
            std::wcout << L"Warning: ModuleListStream not found. Symbol resolution may be limited." << std::endl;
            symbolsInitialized = false;
            return false;
        }
        
        PMINIDUMP_MODULE_LIST pModuleList = static_cast<PMINIDUMP_MODULE_LIST>(pModuleStream);
        std::wcout << L"Found " << pModuleList->NumberOfModules << L" modules in dump." << std::endl;
        
        // Load each module for symbol resolution
        for (ULONG i = 0; i < pModuleList->NumberOfModules; i++) {
            const MINIDUMP_MODULE& module = pModuleList->Modules[i];
            
            // Get module name
            PMINIDUMP_STRING pModuleName = reinterpret_cast<PMINIDUMP_STRING>(
                static_cast<BYTE*>(pDumpFile) + module.ModuleNameRva);
            
            std::wstring moduleName(pModuleName->Buffer, pModuleName->Length / sizeof(WCHAR));
            
            // Load symbols for this module
            std::wcout << L"Loading symbols for module: " << moduleName << "... ";
            DWORD64 baseAddress = SymLoadModuleExW(
                hProcess,
                nullptr,
                moduleName.c_str(),
                nullptr,
                module.BaseOfImage,
                module.SizeOfImage,
                nullptr,
                0
            );
            
            if (baseAddress != 0) {
                std::wcout << L"success." << std::endl;
                std::wcout << L" (Base: 0x" << std::hex << module.BaseOfImage << L")" << std::dec << std::endl;
            }
            else {
                std::wcout << L"failed. Error: " << GetSymLoadError() << std::endl;
            }
        }
        
        symbolsInitialized = true;
        return true;
    }

public:
    DumpAnalyzer() : hProcess(nullptr), pDumpFileData(nullptr), symbolsInitialized(false) {}
    
    ~DumpAnalyzer() {
        if (hProcess) {
            CloseHandle(hProcess);
        }
    }
    
    bool LoadDumpFile(const std::wstring& dumpPath) {
        std::wcout << L"Loading dump file: " << dumpPath << std::endl;
        
        // Open the dump file
        HANDLE hFile = CreateFileW(
            dumpPath.c_str(),
            GENERIC_READ,
            FILE_SHARE_READ,
            nullptr,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            nullptr
        );
        
        if (hFile == INVALID_HANDLE_VALUE) {
            std::wcerr << L"Failed to open dump file. Error: " << GetLastError() << std::endl;
            return false;
        }
        
        // Get file size
        LARGE_INTEGER fileSize;
        if (!GetFileSizeEx(hFile, &fileSize)) {
            std::wcerr << L"Failed to get file size. Error: " << GetLastError() << std::endl;
            CloseHandle(hFile);
            return false;
        }
        
        std::wcout << L"File size: " << fileSize.QuadPart << L" bytes" << std::endl;
        
        // Create file mapping
        HANDLE hMapping = CreateFileMappingW(hFile, nullptr, PAGE_READONLY, 0, 0, nullptr);
        if (!hMapping) {
            std::wcerr << L"Failed to create file mapping. Error: " << GetLastError() << std::endl;
            CloseHandle(hFile);
            return false;
        }
        
        // Map view of file
        PVOID pMappedFile = MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0);
        if (!pMappedFile) {
            std::wcerr << L"Failed to map view of file. Error: " << GetLastError() << std::endl;
            CloseHandle(hMapping);
            CloseHandle(hFile);
            return false;
        }
        
        DWORD options;
        // We are choosing to ignore _NT_SYMBOL_PATH for now
        options = SYMOPT_CASE_INSENSITIVE | SYMOPT_UNDNAME | SYMOPT_DEFERRED_LOADS |
                SYMOPT_NO_UNQUALIFIED_LOADS | SYMOPT_NO_IMAGE_SEARCH |
                SYMOPT_FAVOR_COMPRESSED | SYMOPT_DISABLE_SYMSRV_AUTODETECT |
                SYMOPT_EXACT_SYMBOLS | SYMOPT_IGNORE_CVREC | SYMOPT_NO_PROMPTS |
                SYMOPT_LOAD_LINES | 
                //SYMOPT_OMAP_FIND_NEAREST |
                SYMOPT_INCLUDE_32BIT_MODULES | SYMOPT_FAIL_CRITICAL_ERRORS |
                SYMOPT_AUTO_PUBLICS;
        SymSetOptions(options);
        // Initialize symbol handler for current process
        hProcess = (HANDLE)0x1234; //GetCurrentProcess();
        //char *symbolPath = "srv*C:\\Symbols*https://symweb.azurefd.net";
        char *symbolPath = "C:\\Symbols";
        if (!SymInitialize(hProcess, symbolPath, FALSE)) {
            std::wcerr << L"Failed to initialize symbol handler. Error: " << GetLastError() << std::endl;
            UnmapViewOfFile(pMappedFile);
            CloseHandle(hMapping);
            CloseHandle(hFile);
            return false;
        }
        
        // Process the dump file using dbghelp APIs
        bool result = ProcessDumpWithDbgHelp(pMappedFile);
        
        // Cleanup
        UnmapViewOfFile(pMappedFile);
        CloseHandle(hMapping);
        CloseHandle(hFile);
        
        return result;
    }
    
private:
    bool ProcessDumpWithDbgHelp(PVOID pDumpFile) {
        std::wcout << L"Processing dump file using dbghelp APIs..." << std::endl;
        
        // Store dump file data for symbol loading
        pDumpFileData = pDumpFile;
        
        // Load symbols from the dump
        LoadSymbolsFromDump(pDumpFile);

        // Read memory list stream
        PVOID pStream = nullptr;
        ULONG streamSize = 0;
        
        if (!MiniDumpReadDumpStream(pDumpFile, Memory64ListStream, nullptr, &pStream, &streamSize)) {
            std::wcout << L"Memory64ListStream not found..." << std::endl;
            return false;
        }
        
        return ProcessMemory64ListStream(pDumpFile, static_cast<PMINIDUMP_MEMORY64_LIST>(pStream));
    }
    
    bool ProcessMemory64ListStream(PVOID pDumpFile, PMINIDUMP_MEMORY64_LIST pMemory64List) {
        std::wcout << L"Processing Memory64ListStream with " << pMemory64List->NumberOfMemoryRanges 
                  << L" memory ranges..." << std::endl;
        
        ULONG64 totalProcessedValues = 0;
        RVA64 currentRva = pMemory64List->BaseRva;
        
        for (ULONG64 i = 0; i < pMemory64List->NumberOfMemoryRanges; i++) {
            const MINIDUMP_MEMORY_DESCRIPTOR64& memDesc = pMemory64List->MemoryRanges[i];
            
            std::wcout << L"Processing memory range " << (i + 1) << L"/" << pMemory64List->NumberOfMemoryRanges
                      << L" - Base: 0x" << std::hex << memDesc.StartOfMemoryRange
                      << L" Size: 0x" << memDesc.DataSize << std::dec << std::endl;
            
            // Get pointer to memory data in dump file
            BYTE* pMemoryData = static_cast<BYTE*>(pDumpFile) + currentRva;
            
            // Process 64-bit values at 8-byte aligned boundaries
            ULONG64 alignedSize = memDesc.DataSize & ~7; // Round down to 8-byte boundary
            
            for (ULONG64 offset = 0; offset < alignedSize; offset += sizeof(UINT64)) {
                UINT64 value = *reinterpret_cast<UINT64*>(pMemoryData + offset);
                
                // Only count values that could be valid user-mode pointers
                if (IsValidUserModePointer(value)) {
                    valueCount[value]++;
                }
                totalProcessedValues++;
                
                if (totalProcessedValues % 1000000 == 0) {
                    std::wcout << L"Processed " << totalProcessedValues << L" values..." << std::endl;
                }
            }
            
            currentRva += memDesc.DataSize;
        }
        
        std::wcout << L"Processing complete." << std::endl;
        std::wcout << L"Total 64-bit values processed: " << totalProcessedValues << std::endl;
        std::wcout << L"Distinct values found: " << valueCount.size() << std::endl;
        
        return true;
    }
    
public:
    void PrintStatistics() const {
        if (valueCount.empty()) {
            std::wcout << L"No values found." << std::endl;
            return;
        }
        
        ULONG totalCount = 0;
        for (const auto& pair : valueCount) {
            totalCount += pair.second;
        }
        
        std::wcout << L"\n=== STATISTICS ===" << std::endl;
        std::wcout << L"Total 64-bit values: " << totalCount << std::endl;
        std::wcout << L"Distinct values: " << valueCount.size() << std::endl;
        std::wcout << L"Average occurrences per distinct value: " 
                  << std::fixed << std::setprecision(2) 
                  << static_cast<double>(totalCount) / valueCount.size() << std::endl;
    }
    
    void PrintTopValues(int count = 10) const {
        if (valueCount.empty()) {
            return;
        }
        
        // Create vector of pairs for sorting
        std::vector<std::pair<UINT64, ULONG>> sortedValues(valueCount.begin(), valueCount.end());
        
        // Sort by count (descending)
        std::sort(sortedValues.begin(), sortedValues.end(),
            [](const auto& a, const auto& b) { return a.second > b.second; });
        
        std::wcout << L"\n=== TOP " << count << L" MOST FREQUENT VALUES WITH SYMBOLS ===" << std::endl;
        std::wcout << L"Value (Hex)          | Count     | Percentage | Symbol" << std::endl;
        std::wcout << L"---------------------|-----------|------------|----------------------------------------" << std::endl;
        
        ULONG totalCount = 0;
        for (const auto& pair : valueCount) {
            totalCount += pair.second;
        }
        
        int displayed = 0;
        for (const auto& pair : sortedValues) {
            if (displayed >= count) break;
            
            double percentage = (static_cast<double>(pair.second) / totalCount) * 100.0;
            std::wstring symbolName = ResolveSymbol(pair.first);
            
            // Truncate very long symbol names for better display
            if (symbolName.length() > 40) {
                symbolName = symbolName.substr(0, 37) + L"...";
            }
            
            std::wcout << L"0x" << std::hex << std::uppercase << std::setw(16) << std::setfill(L'0') 
                      << pair.first << L" | " 
                      << std::dec << std::setw(9) << pair.second << L" | "
                      << std::fixed << std::setprecision(2) << std::setw(6) << percentage << L"% | "
                      << symbolName << std::endl;
            
            displayed++;
        }
        
        if (symbolsInitialized) {
            std::wcout << L"\nNote: Symbol resolution enabled. Module symbols loaded from dump file." << std::endl;
        } else {
            std::wcout << L"\nNote: Symbol resolution disabled. No module information found in dump file." << std::endl;
        }
    }
    
    void SaveResults(const std::wstring& outputPath) const {
        std::wcout << L"Saving results to: " << outputPath << std::endl;
        
        std::wofstream outFile(outputPath);
        if (!outFile.is_open()) {
            std::wcerr << L"Failed to open output file: " << outputPath << std::endl;
            return;
        }
        
        // Write header with symbol information
        outFile << L"Value (Hex),Count,Symbol" << std::endl;
        
        // Create sorted list for consistent output
        std::vector<std::pair<UINT64, ULONG>> sortedValues(valueCount.begin(), valueCount.end());
        std::sort(sortedValues.begin(), sortedValues.end(),
            [](const auto& a, const auto& b) { return a.second > b.second; });
        
        // Write all values with symbols
        for (const auto& pair : sortedValues) {
            std::wstring symbolName = ResolveSymbol(pair.first);
            
            // Escape commas in symbol names for CSV format
            std::wstring escapedSymbol = symbolName;
            size_t pos = 0;
            while ((pos = escapedSymbol.find(L",", pos)) != std::wstring::npos) {
                escapedSymbol.replace(pos, 1, L";");
                pos += 1;
            }
            
            outFile << L"0x" << std::hex << std::uppercase << pair.first 
                   << L"," << std::dec << pair.second 
                   << L"," << escapedSymbol << std::endl;
        }
        
        outFile.close();
        std::wcout << L"Results saved successfully with symbol information." << std::endl;
    }
};

void PrintUsage(const wchar_t* programName) {
    std::wcout << L"Usage: " << programName << L" <dump_file.dmp> [options]" << std::endl;
    std::wcout << L"Options:" << std::endl;
    std::wcout << L"  -o <output_file>  Save results to CSV file" << std::endl;
    std::wcout << L"  -t <count>        Show top N most frequent values (default: 10)" << std::endl;
    std::wcout << L"  -h                Show this help message" << std::endl;
    std::wcout << L"" << std::endl;
    std::wcout << L"Example: " << programName << L" memory.dmp -o results.csv -t 20" << std::endl;
}

int wmain(int argc, wchar_t* argv[]) {
    if (argc < 2) {
        PrintUsage(argv[0]);
        return 1;
    }
    
    std::wstring dumpFile;
    std::wstring outputFile;
    int topCount = 10;
    
    // Parse command line arguments
    for (int i = 1; i < argc; i++) {
        if (wcscmp(argv[i], L"-h") == 0) {
            PrintUsage(argv[0]);
            return 0;
        }
        else if (wcscmp(argv[i], L"-o") == 0) {
            if (i + 1 < argc) {
                outputFile = argv[++i];
            }
        }
        else if (wcscmp(argv[i], L"-t") == 0) {
            if (i + 1 < argc) {
                topCount = _wtoi(argv[++i]);
            }
        }
        else if (dumpFile.empty()) {
            dumpFile = argv[i];
        }
    }
    
    if (dumpFile.empty()) {
        std::wcerr << L"Error: No dump file specified." << std::endl;
        PrintUsage(argv[0]);
        return 1;
    }
    
    std::wcout << L"Windows Dump File Analyzer" << std::endl;
    std::wcout << L"===========================" << std::endl;
    
    DumpAnalyzer analyzer;
    
    if (!analyzer.LoadDumpFile(dumpFile)) {
        std::wcerr << L"Failed to analyze dump file." << std::endl;
        return 1;
    }
    
    // Print statistics
    analyzer.PrintStatistics();
    analyzer.PrintTopValues(topCount);
    
    // Save results if requested
    if (!outputFile.empty()) {
        analyzer.SaveResults(outputFile);
    }
    
    return 0;
}
