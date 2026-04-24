#include <windows.h>
#include <dbghelp.h>
#include <iostream>
#include "symbol_resolver.hpp"

void InitializeSymbols(const wil::unique_handle& process_handle) {
    DWORD options = SYMOPT_CASE_INSENSITIVE | SYMOPT_UNDNAME | SYMOPT_DEFERRED_LOADS |
        SYMOPT_NO_UNQUALIFIED_LOADS | SYMOPT_NO_IMAGE_SEARCH |
        SYMOPT_FAVOR_COMPRESSED | SYMOPT_DISABLE_SYMSRV_AUTODETECT |
        SYMOPT_EXACT_SYMBOLS | SYMOPT_IGNORE_CVREC | SYMOPT_NO_PROMPTS |
        SYMOPT_LOAD_LINES | 
        SYMOPT_INCLUDE_32BIT_MODULES | SYMOPT_FAIL_CRITICAL_ERRORS |
        SYMOPT_AUTO_PUBLICS;
    SymSetOptions(options);
    
    const char *symbol_path = "C:\\Symbols";
    THROW_LAST_ERROR_IF(!SymInitialize(process_handle.get(), nullptr, FALSE));
}

void LoadModules(const MappedView& mapped_view, const wil::unique_handle& process_handle) {
    std::wcout << L"Loading symbols from dump file..." << std::endl;
    
    // Read module list stream
    void* module_stream = nullptr;
    ULONG module_stream_size = 0;
    
    THROW_IF_WIN32_BOOL_FALSE(MiniDumpReadDumpStream(
        mapped_view.get(), 
        ModuleListStream, 
        nullptr, 
        &module_stream, 
        &module_stream_size
    ));

    PMINIDUMP_MODULE_LIST module_list = static_cast<PMINIDUMP_MODULE_LIST>(module_stream);
    std::wcout << L"Found " << module_list->NumberOfModules << L" modules in dump." << std::endl;
    
    // Load each module for symbol resolution
    for (ULONG i = 0; i < module_list->NumberOfModules; i++) {
        const MINIDUMP_MODULE& module = module_list->Modules[i];
        
        // Get module name
        PMINIDUMP_STRING module_name_dmp_str = reinterpret_cast<PMINIDUMP_STRING>(
            static_cast<BYTE*>(mapped_view.get()) + module.ModuleNameRva);
        
        std::wstring module_name(module_name_dmp_str->Buffer, module_name_dmp_str->Length / sizeof(wchar_t));
        
        // Extract UUID from CvRecord if available
        std::wstring uuid_str = L"<no UUID>";
        if (module.CvRecord.DataSize >= sizeof(DWORD) + 16) { // DWORD signature + 16 bytes for GUID
            BYTE* cv_data = static_cast<BYTE*>(mapped_view.get()) + module.CvRecord.Rva;
            DWORD signature = *reinterpret_cast<DWORD*>(cv_data);
            
            // Check for RSDS signature (0x53445352) which contains GUID
            if (signature == 0x53445352) {
                GUID* guid = reinterpret_cast<GUID*>(cv_data + sizeof(DWORD));
                wchar_t guid_buffer[64];
                swprintf_s(guid_buffer, L"{%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}",
                    guid->Data1, guid->Data2, guid->Data3,
                    guid->Data4[0], guid->Data4[1], guid->Data4[2], guid->Data4[3],
                    guid->Data4[4], guid->Data4[5], guid->Data4[6], guid->Data4[7]);
                uuid_str = guid_buffer;
            }
        }
        
        // Load symbols for this module
        std::wcout << L"Loading symbols for module: " << module_name << L" (UUID: " << uuid_str << L")... ";
        DWORD64 baseAddress = SymLoadModuleExW(
            process_handle.get(),
            nullptr,
            // next argument should be the pdb path
            module_name.c_str(),
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
            DWORD lastError = GetLastError();
            std::wcout << L"failed. Error: 0x" << std::hex << lastError << std::dec << std::endl;
        }
    }
}

SymbolResolver::SymbolResolver(const MappedView& mapped_view, const wil::unique_handle& process_handle)
    : mapped_view_(mapped_view), process_handle_(process_handle) {
    InitializeSymbols(process_handle_);
    LoadModules(mapped_view_, process_handle_);
}

std::wstring SymbolResolver::resolveSymbol(uint64_t address) const {
    // Buffer for symbol information
    BYTE symbol_buffer[sizeof(SYMBOL_INFOW) + MAX_SYM_NAME * sizeof(WCHAR)];
    PSYMBOL_INFOW symbol_info = reinterpret_cast<PSYMBOL_INFOW>(symbol_buffer);
    
    symbol_info->SizeOfStruct = sizeof(SYMBOL_INFOW);
    symbol_info->MaxNameLen = MAX_SYM_NAME;
    
    DWORD64 displacement = 0;    
    if (SymFromAddrW(process_handle_.get(), address, &displacement, symbol_info)) {
        if (displacement == 0) {
            return std::wstring(symbol_info->Name);
        } else {
            return std::wstring(symbol_info->Name) + L"+" + std::to_wstring(displacement);
        }
    }
        
    // Try to get module information if symbol lookup failed
    IMAGEHLP_MODULEW64 module_info = { 0 };
    module_info.SizeOfStruct = sizeof(IMAGEHLP_MODULEW64);
    
    if (SymGetModuleInfoW64(process_handle_.get(), address, &module_info)) {
        DWORD64 module_base = module_info.BaseOfImage;
        DWORD64 offset = address - module_base;
        
        // Extract just the module name without path
        std::wstring module_name = module_info.ModuleName;
        return module_name + L"+0x" + std::to_wstring(offset);
    }
    
    return L"<unknown>";
}
