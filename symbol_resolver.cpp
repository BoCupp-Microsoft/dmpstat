#include <windows.h>
#include <dbghelp.h>
#include <algorithm>
#include <cstring>
#include <iostream>
#include "symbol_resolver.hpp"

namespace {

BOOL CALLBACK SymUnifiedCallback(HANDLE /*hProcess*/, ULONG ActionCode, ULONG64 CallbackData, ULONG64 UserContext) {
    auto* self = reinterpret_cast<SymbolResolver*>(static_cast<uintptr_t>(UserContext));
    switch (ActionCode) {
    case CBA_DEBUG_INFO:
        if (self && self->verbose() && CallbackData) {
            const wchar_t* msg = reinterpret_cast<const wchar_t*>(CallbackData);
            std::wcerr << L"[dbghelp] " << msg;
        }
        return TRUE;
    case CBA_READ_MEMORY: {
        if (!self || !CallbackData) return FALSE;
        auto* req = reinterpret_cast<PIMAGEHLP_CBA_READ_MEMORY>(CallbackData);
        DWORD got = self->readDumpMemory(req->addr, req->buf, req->bytes);
        if (got == 0) return FALSE;
        if (req->bytesread) *req->bytesread = got;
        return TRUE;
    }
    default:
        return FALSE;
    }
}

} // namespace

void InitializeSymbols(HANDLE sym_handle, const std::wstring& sympath, bool verbose) {
    DWORD options = SYMOPT_CASE_INSENSITIVE | SYMOPT_UNDNAME |
        SYMOPT_NO_UNQUALIFIED_LOADS |
        SYMOPT_FAVOR_COMPRESSED |
        SYMOPT_NO_PROMPTS |
        SYMOPT_LOAD_LINES |
        SYMOPT_INCLUDE_32BIT_MODULES | SYMOPT_FAIL_CRITICAL_ERRORS |
        SYMOPT_EXACT_SYMBOLS |
        SYMOPT_AUTO_PUBLICS;
    if (verbose) {
        options |= SYMOPT_DEBUG;
    }
    SymSetOptions(options);

    THROW_LAST_ERROR_IF(!SymInitializeW(
        sym_handle,
        sympath.empty() ? nullptr : sympath.c_str(),
        FALSE));
}

void LoadModules(const MappedView& mapped_view, HANDLE sym_handle, ProgressReporter& progress, bool verbose) {
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

        // Hand DbgHelp the dump's CodeView record so it can match the right
        // PDB without needing the original on-disk binary. The CvRecord is a
        // RVA into the dump file pointing at a CV_INFO_PDB70-style record.
        MODLOAD_DATA cv_data{};
        MODLOAD_DATA* mod_data_ptr = nullptr;
        if (module.CvRecord.Rva != 0 && module.CvRecord.DataSize != 0) {
            cv_data.ssize = sizeof(MODLOAD_DATA);
            cv_data.ssig = DBHHEADER_CVMISC;
            cv_data.data = static_cast<BYTE*>(mapped_view.get()) + module.CvRecord.Rva;
            cv_data.size = module.CvRecord.DataSize;
            cv_data.flags = 0;
            mod_data_ptr = &cv_data;
        }

        // Load symbols for this module. Failures are silently ignored; the
        // results table will fall back to module+offset or <unknown>.
        SetLastError(0);
        DWORD64 loaded = SymLoadModuleExW(
            sym_handle,
            nullptr,
            module_name.c_str(),
            nullptr,
            module.BaseOfImage,
            module.SizeOfImage,
            mod_data_ptr,
            0
        );
        if (verbose) {
            DWORD err = GetLastError();
            if (loaded == 0 && err != ERROR_SUCCESS) {
                std::wcerr << L"[loader] SymLoadModuleExW failed for " << module_name
                           << L" (base=0x" << std::hex << module.BaseOfImage
                           << L" size=0x" << module.SizeOfImage
                           << L" cvSize=" << std::dec << module.CvRecord.DataSize
                           << L"): err=" << err << std::endl;
            } else if (loaded == 0) {
                std::wcerr << L"[loader] SymLoadModuleExW: already loaded: " << module_name << std::endl;
            } else {
                IMAGEHLP_MODULEW64 mi{};
                mi.SizeOfStruct = sizeof(mi);
                std::wstring pdb_name = L"<?>";
                std::wstring sym_type = L"?";
                if (SymGetModuleInfoW64(sym_handle, loaded, &mi)) {
                    pdb_name = mi.LoadedPdbName[0] ? mi.LoadedPdbName : L"<none>";
                    switch (mi.SymType) {
                        case SymNone: sym_type = L"None"; break;
                        case SymExport: sym_type = L"Export"; break;
                        case SymPdb: sym_type = L"Pdb"; break;
                        case SymDeferred: sym_type = L"Deferred"; break;
                        case SymSym: sym_type = L"Sym"; break;
                        case SymDia: sym_type = L"Dia"; break;
                        case SymVirtual: sym_type = L"Virtual"; break;
                        default: sym_type = std::to_wstring(static_cast<int>(mi.SymType)); break;
                    }
                }
                std::wcerr << L"[loader] Loaded " << module_name
                           << L" type=" << sym_type
                           << L" pdb=" << pdb_name << std::endl;
            }
        }
    }
}

SymbolResolver::SymbolResolver(const MappedView& mapped_view, const std::wstring& sympath, ProgressReporter& progress, bool verbose)
    : mapped_view_(mapped_view),
      // Use an arbitrary unique non-process pseudo-handle so DbgHelp treats
      // this as a fresh symbol context. Passing GetCurrentProcess() (or a
      // duplicate of it) causes DbgHelp to attempt to load PDBs into our
      // own process's module list, which AVs whenever a dump module's
      // address range overlaps a real module already mapped into us.
      sym_handle_(reinterpret_cast<HANDLE>(static_cast<uintptr_t>(0xDEC0DE01))),
      verbose_(verbose) {
    buildMemoryIndex();
    InitializeSymbols(sym_handle_, sympath, verbose);
    // Register the unified callback BEFORE loading any modules, so DbgHelp
    // serves its memory reads from the dump (CBA_READ_MEMORY) instead of
    // attempting ReadProcessMemory on our fake handle.
    SymRegisterCallbackW64(sym_handle_,
        reinterpret_cast<PSYMBOL_REGISTERED_CALLBACK64>(SymUnifiedCallback),
        static_cast<ULONG64>(reinterpret_cast<uintptr_t>(this)));
    if (verbose) {
        wchar_t resolved[2048] = {};
        if (SymGetSearchPathW(sym_handle_, resolved, ARRAYSIZE(resolved))) {
            std::wcerr << L"[dbghelp] Search path: " << resolved << std::endl;
        }
    }
    LoadModules(mapped_view_, sym_handle_, progress, verbose);
}

SymbolResolver::~SymbolResolver() {
    SymCleanup(sym_handle_);
}

void SymbolResolver::buildMemoryIndex() {
    // Index Memory64ListStream (typical for full-memory dumps).
    void* stream = nullptr;
    ULONG stream_size = 0;
    if (MiniDumpReadDumpStream(mapped_view_.get(), Memory64ListStream, nullptr, &stream, &stream_size) && stream) {
        auto* list = static_cast<MINIDUMP_MEMORY64_LIST*>(stream);
        uint64_t offset = list->BaseRva;
        memory_ranges_.reserve(static_cast<size_t>(list->NumberOfMemoryRanges));
        for (ULONG64 i = 0; i < list->NumberOfMemoryRanges; ++i) {
            const auto& d = list->MemoryRanges[i];
            memory_ranges_.push_back({d.StartOfMemoryRange, d.DataSize, offset});
            offset += d.DataSize;
        }
    }
    // Also index MemoryListStream (32-bit RVAs, smaller dumps).
    stream = nullptr; stream_size = 0;
    if (MiniDumpReadDumpStream(mapped_view_.get(), MemoryListStream, nullptr, &stream, &stream_size) && stream) {
        auto* list = static_cast<MINIDUMP_MEMORY_LIST*>(stream);
        for (ULONG i = 0; i < list->NumberOfMemoryRanges; ++i) {
            const auto& d = list->MemoryRanges[i];
            memory_ranges_.push_back({d.StartOfMemoryRange, d.Memory.DataSize, d.Memory.Rva});
        }
    }
    std::sort(memory_ranges_.begin(), memory_ranges_.end(),
              [](const MemRange& a, const MemRange& b) { return a.va < b.va; });
}

DWORD SymbolResolver::readDumpMemory(uint64_t addr, void* buf, DWORD bytes) const {
    if (memory_ranges_.empty() || bytes == 0) return 0;
    // Binary search for the last range whose va <= addr.
    auto it = std::upper_bound(memory_ranges_.begin(), memory_ranges_.end(), addr,
        [](uint64_t v, const MemRange& r) { return v < r.va; });
    if (it == memory_ranges_.begin()) return 0;
    --it;
    if (addr >= it->va + it->size) return 0;
    uint64_t local_off = addr - it->va;
    uint64_t avail = it->size - local_off;
    DWORD to_copy = static_cast<DWORD>(std::min<uint64_t>(bytes, avail));
    const BYTE* src = static_cast<const BYTE*>(mapped_view_.get()) + it->fileRva + local_off;
    std::memcpy(buf, src, to_copy);
    return to_copy;
}

std::wstring SymbolResolver::resolveSymbol(uint64_t address) const {
    // Buffer for symbol information
    BYTE symbol_buffer[sizeof(SYMBOL_INFOW) + MAX_SYM_NAME * sizeof(WCHAR)];
    PSYMBOL_INFOW symbol_info = reinterpret_cast<PSYMBOL_INFOW>(symbol_buffer);

    symbol_info->SizeOfStruct = sizeof(SYMBOL_INFOW);
    symbol_info->MaxNameLen = MAX_SYM_NAME;

    DWORD64 displacement = 0;
    if (SymFromAddrW(sym_handle_, address, &displacement, symbol_info)) {
        if (displacement == 0) {
            return std::wstring(symbol_info->Name);
        } else {
            return std::wstring(symbol_info->Name) + L"+" + std::to_wstring(displacement);
        }
    }

    // Try to get module information if symbol lookup failed
    IMAGEHLP_MODULEW64 module_info = { 0 };
    module_info.SizeOfStruct = sizeof(IMAGEHLP_MODULEW64);

    if (SymGetModuleInfoW64(sym_handle_, address, &module_info)) {
        DWORD64 module_base = module_info.BaseOfImage;
        DWORD64 offset = address - module_base;

        // Extract just the module name without path
        std::wstring module_name = module_info.ModuleName;
        return module_name + L"+0x" + std::to_wstring(offset);
    }

    return L"<unknown>";
}
