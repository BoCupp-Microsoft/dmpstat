#include <windows.h>
#include <dbghelp.h>
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

    THROW_LAST_ERROR_IF(!SymInitialize(process_handle.get(), nullptr, FALSE));
}

void LoadModules(const MappedView& mapped_view, const wil::unique_handle& process_handle, ProgressReporter& progress) {
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

    // Load each module for symbol resolution
    for (ULONG i = 0; i < module_list->NumberOfModules; i++) {
        const MINIDUMP_MODULE& module = module_list->Modules[i];

        // Get module name
        PMINIDUMP_STRING module_name_dmp_str = reinterpret_cast<PMINIDUMP_STRING>(
            static_cast<BYTE*>(mapped_view.get()) + module.ModuleNameRva);

        std::wstring module_name(module_name_dmp_str->Buffer, module_name_dmp_str->Length / sizeof(wchar_t));

        wchar_t status[512];
        swprintf_s(status, L"Loading symbols %u/%u: %s",
            i + 1, module_list->NumberOfModules, module_name.c_str());
        progress.update(status);

        // Load symbols for this module. Failures are silently ignored; the
        // results table will fall back to module+offset or <unknown>.
        (void)SymLoadModuleExW(
            process_handle.get(),
            nullptr,
            module_name.c_str(),
            nullptr,
            module.BaseOfImage,
            module.SizeOfImage,
            nullptr,
            0
        );
    }
}

SymbolResolver::SymbolResolver(const MappedView& mapped_view, const wil::unique_handle& process_handle, ProgressReporter& progress)
    : mapped_view_(mapped_view), process_handle_(process_handle) {
    InitializeSymbols(process_handle_);
    LoadModules(mapped_view_, process_handle_, progress);
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
