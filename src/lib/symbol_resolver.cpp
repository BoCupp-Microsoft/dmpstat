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

void LoadModules(const MappedView& mapped_view, HANDLE sym_handle, ProgressReporter& progress, bool verbose,
                 std::vector<SymbolResolver::ModuleRange>* out_module_ranges = nullptr) {
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

        if (out_module_ranges) {
            out_module_ranges->push_back({module.BaseOfImage, module.SizeOfImage});
        }

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
    if (out_module_ranges) {
        std::sort(out_module_ranges->begin(), out_module_ranges->end(),
                  [](const SymbolResolver::ModuleRange& a,
                     const SymbolResolver::ModuleRange& b) {
                      return a.base < b.base;
                  });
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
    LoadModules(mapped_view_, sym_handle_, progress, verbose, &module_ranges_);
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

namespace {
// MSVC's symbol-name undecorator emits elaborated-type-specifiers (enum,
// class, struct, union) inside template argument lists, e.g. the vftable
// symbol decodes as `Foo<enum Bar>::`vftable'`. The same type is stored in
// the PDB type stream under its canonical name `Foo<Bar>` (no keyword), so
// SymGetTypeFromNameW fails when handed the keyword form. Strip standalone
// occurrences of those keywords so that the name matches the type record.
std::wstring stripElaboratedTypeKeywords(std::wstring s) {
    static constexpr std::wstring_view kKeywords[] = {
        L"enum ", L"class ", L"struct ", L"union ",
    };
    auto isIdent = [](wchar_t c) {
        return iswalnum(c) || c == L'_';
    };
    for (auto kw : kKeywords) {
        size_t pos = 0;
        while ((pos = s.find(kw, pos)) != std::wstring::npos) {
            // Skip if the keyword is actually a suffix of an identifier
            // (e.g. "myenum ").
            if (pos > 0 && isIdent(s[pos - 1])) {
                pos += kw.size();
                continue;
            }
            s.erase(pos, kw.size());
        }
    }
    return s;
}
} // namespace

std::optional<SymbolResolver::VtableInfo>
SymbolResolver::resolveVtable(uint64_t address) const {
    BYTE symbol_buffer[sizeof(SYMBOL_INFOW) + MAX_SYM_NAME * sizeof(WCHAR)];
    PSYMBOL_INFOW symbol_info = reinterpret_cast<PSYMBOL_INFOW>(symbol_buffer);
    symbol_info->SizeOfStruct = sizeof(SYMBOL_INFOW);
    symbol_info->MaxNameLen = MAX_SYM_NAME;

    DWORD64 displacement = 0;
    if (!SymFromAddrW(sym_handle_, address, &displacement, symbol_info)) {
        return std::nullopt;
    }
    // Only count exact vtable starts.
    if (displacement != 0) return std::nullopt;

    std::wstring name(symbol_info->Name, symbol_info->NameLen);
    constexpr std::wstring_view kSuffix = L"::`vftable'";
    if (name.size() < kSuffix.size()) return std::nullopt;
    if (name.compare(name.size() - kSuffix.size(),
                     kSuffix.size(), kSuffix) != 0) return std::nullopt;

    VtableInfo info;
    info.vtable_address = symbol_info->Address;
    info.class_name = stripElaboratedTypeKeywords(
        name.substr(0, name.size() - kSuffix.size()));
    info.type_size  = 0;

    // Module name (e.g. "msedge") helps disambiguate when the same class is
    // statically linked into multiple binaries in the dump.
    IMAGEHLP_MODULEW64 mod{};
    mod.SizeOfStruct = sizeof(mod);
    bool has_type_info = false;
    if (SymGetModuleInfoW64(sym_handle_, symbol_info->ModBase, &mod)) {
        info.module_name = mod.ModuleName;
        has_type_info = mod.TypeInfo != FALSE;
    }

    // Cache lookup: classes commonly have multiple vftables in the same
    // module (incomplete COMDAT folding, MI subobjects, etc.) so we may
    // ask for the same (module, class) sizeof many times.
    const VtableSizeKey cache_key{symbol_info->ModBase, info.class_name};
    if (auto it = vtable_size_cache_.find(cache_key);
        it != vtable_size_cache_.end()) {
        info.type_size = it->second;
        return info;
    }

    // Preferred path: the vftable symbol's TypeIndex is an array-of-pointers
    // whose class parent is the owning class. TI_GET_LENGTH on that class
    // type gives sizeof(Class). One walk per hit, no name-based search.
    if (symbol_info->TypeIndex != 0) {
        DWORD class_ti = 0;
        if (SymGetTypeInfo(sym_handle_, symbol_info->ModBase,
                           symbol_info->TypeIndex,
                           TI_GET_CLASSPARENTID, &class_ti) && class_ti != 0) {
            ULONG64 len = 0;
            if (SymGetTypeInfo(sym_handle_, symbol_info->ModBase, class_ti,
                               TI_GET_LENGTH, &len)) {
                info.type_size = len;
            }
        }
    }

    // Fallback: look the class type up by name. SymGetTypeFromNameW handles
    // namespace-qualified names in modern dbghelp builds. We deliberately do
    // NOT fall back to SymEnumTypesByNameW: that path is O(types-in-module)
    // and on large PDBs (msedge) blocks for many seconds per miss, which
    // dominates wall-clock for the v-table phase.
    if (info.type_size == 0) {
        BYTE type_buf[sizeof(SYMBOL_INFOW) + MAX_SYM_NAME * sizeof(WCHAR)] = {};
        auto* type_info = reinterpret_cast<PSYMBOL_INFOW>(type_buf);
        type_info->SizeOfStruct = sizeof(SYMBOL_INFOW);
        type_info->MaxNameLen = MAX_SYM_NAME;
        if (SymGetTypeFromNameW(sym_handle_, symbol_info->ModBase,
                                info.class_name.c_str(), type_info)) {
            info.type_size = type_info->Size;
        }
    }
    if (info.type_size == 0) {
        std::wstring qualified = info.module_name.empty()
            ? info.class_name
            : info.module_name + L"!" + info.class_name;
        unresolved_vtable_classes_.insert(std::move(qualified));
        if (verbose_) {
            std::wcerr << L"[symres] no type info for '" << info.class_name
                       << L"' in " << info.module_name
                       << L" (TypeInfo=" << (has_type_info ? L"yes" : L"no")
                       << L", SymType=" << mod.SymType << L")"
                       << std::endl;
        }
    }
    vtable_size_cache_.emplace(cache_key, info.type_size);
    return info;
}

SymbolResolver::VtableResolutionStats
SymbolResolver::vtable_resolution_stats() const {
    VtableResolutionStats s{};
    for (const auto& [_, size] : vtable_size_cache_) {
        if (size == 0) ++s.unresolved; else ++s.resolved;
    }
    return s;
}

std::optional<uint64_t> SymbolResolver::findGlobal(const std::wstring& name) const {
    BYTE buf[sizeof(SYMBOL_INFOW) + MAX_SYM_NAME * sizeof(WCHAR)] = {};
    auto* info = reinterpret_cast<PSYMBOL_INFOW>(buf);
    info->SizeOfStruct = sizeof(SYMBOL_INFOW);
    info->MaxNameLen = MAX_SYM_NAME;
    if (!SymFromNameW(sym_handle_, name.c_str(), info)) return std::nullopt;
    if (info->Address == 0) return std::nullopt;
    return info->Address;
}

namespace {
struct EnumCtx {
    std::vector<SymbolResolver::GlobalHit>* out;
    size_t max_results;
};
BOOL CALLBACK SymEnumGlobalsCb(PSYMBOL_INFOW info, ULONG /*size*/, PVOID user) {
    auto* ctx = static_cast<EnumCtx*>(user);
    if (!info || info->Address == 0) return TRUE;
    ctx->out->push_back({std::wstring(info->Name, info->NameLen), info->Address, info->Size});
    if (ctx->max_results && ctx->out->size() >= ctx->max_results) return FALSE;
    return TRUE;
}
} // namespace

std::vector<SymbolResolver::GlobalHit>
SymbolResolver::findGlobalsMatching(const std::wstring& mask, size_t max_results) const {
    std::vector<GlobalHit> hits;
    EnumCtx ctx{&hits, max_results};
    // BaseOfDll = 0 means "search all loaded modules".
    SymEnumSymbolsW(sym_handle_, 0, mask.c_str(), SymEnumGlobalsCb, &ctx);
    return hits;
}

namespace {
struct FindTypeCtx {
    uint64_t mod_base;
    uint32_t type_index;
    uint64_t size;
    bool     found;
};
BOOL CALLBACK FindTypeCb(PSYMBOL_INFOW info, ULONG /*size*/, PVOID user) {
    auto* ctx = static_cast<FindTypeCtx*>(user);
    // SymEnumTypesByNameW already filtered by the qualified name we passed
    // as the mask. The Name it hands back is often just the unqualified leaf
    // (e.g. "NormalPage" for "cppgc::internal::NormalPage"), so don't try to
    // re-validate by string equality - any callback invocation IS the match.
    ctx->mod_base   = info->ModBase;
    ctx->type_index = info->TypeIndex;
    ctx->size       = info->Size;
    ctx->found      = true;
    return FALSE;
}

struct EnumModulesCtx {
    HANDLE sym_handle;
    const std::wstring* want;
    SymbolResolver::ResolvedType result;
    bool found;
};
BOOL CALLBACK EnumModulesCb(PCWSTR /*module_name*/, DWORD64 base, PVOID user) {
    auto* ctx = static_cast<EnumModulesCtx*>(user);
    BYTE buf[sizeof(SYMBOL_INFOW) + MAX_SYM_NAME * sizeof(WCHAR)] = {};
    auto* info = reinterpret_cast<PSYMBOL_INFOW>(buf);
    info->SizeOfStruct = sizeof(SYMBOL_INFOW);
    info->MaxNameLen = MAX_SYM_NAME;
    if (SymGetTypeFromNameW(ctx->sym_handle, base, ctx->want->c_str(), info)
        && info->TypeIndex != 0) {
        ctx->result = {info->ModBase, info->TypeIndex};
        ctx->found = true;
        return FALSE;
    }
    return TRUE;
}
} // namespace

std::optional<SymbolResolver::ResolvedType>
SymbolResolver::findType(const std::wstring& qualified_name) const {
    // Fast path: process-wide search.
    BYTE buf[sizeof(SYMBOL_INFOW) + MAX_SYM_NAME * sizeof(WCHAR)] = {};
    auto* info = reinterpret_cast<PSYMBOL_INFOW>(buf);
    info->SizeOfStruct = sizeof(SYMBOL_INFOW);
    info->MaxNameLen = MAX_SYM_NAME;
    if (SymGetTypeFromNameW(sym_handle_, 0, qualified_name.c_str(), info)
        && info->TypeIndex != 0) {
        return ResolvedType{info->ModBase, info->TypeIndex};
    }
    // dbghelp's BaseOfDll=0 path doesn't always find namespace-qualified C++
    // types (especially deeply nested ones in third-party modules). Fall back
    // to per-module SymGetTypeFromNameW; this succeeds where the global
    // search silently returns 0.
    EnumModulesCtx mod_ctx{sym_handle_, &qualified_name, {}, false};
    SymEnumerateModulesW64(sym_handle_, EnumModulesCb, &mod_ctx);
    if (mod_ctx.found) return mod_ctx.result;

    // Last-resort: enumerate types by name across all modules.
    FindTypeCtx ctx{0, 0, 0, false};
    SymEnumTypesByNameW(sym_handle_, 0, qualified_name.c_str(), FindTypeCb, &ctx);
    if (ctx.found) return ResolvedType{ctx.mod_base, ctx.type_index};
    return std::nullopt;
}

uint64_t SymbolResolver::typeSize(const std::wstring& qualified_name) const {
    auto t = findType(qualified_name);
    if (!t) return 0;
    ULONG64 len = 0;
    if (SymGetTypeInfo(sym_handle_, t->mod_base, t->type_index,
                       TI_GET_LENGTH, &len)) {
        return len;
    }
    return 0;
}

std::optional<uint64_t>
SymbolResolver::fieldOffset(const std::wstring& struct_qname,
                            const std::wstring& field) const {
    auto t = findType(struct_qname);
    if (!t) return std::nullopt;

    // Two-step TI_FINDCHILDREN: first ask for the count, then allocate and
    // fill the index array.
    DWORD child_count = 0;
    if (!SymGetTypeInfo(sym_handle_, t->mod_base, t->type_index,
                        TI_GET_CHILDRENCOUNT, &child_count)
        || child_count == 0) {
        return std::nullopt;
    }
    std::vector<BYTE> blob(sizeof(TI_FINDCHILDREN_PARAMS) +
                           sizeof(ULONG) * child_count);
    auto* params = reinterpret_cast<TI_FINDCHILDREN_PARAMS*>(blob.data());
    params->Count = child_count;
    params->Start = 0;
    if (!SymGetTypeInfo(sym_handle_, t->mod_base, t->type_index,
                        TI_FINDCHILDREN, params)) {
        return std::nullopt;
    }

    // Walk children looking for a data member matching `field`. We only honor
    // direct (non-base-class) members; base-class fields show up via their own
    // type's children, not as named children of the derived type. This matches
    // C++ static layout where each derived class introduces only its own
    // members at the offset reported by TI_GET_OFFSET (0 == start of the
    // derived sub-object).
    for (ULONG i = 0; i < child_count; ++i) {
        ULONG child_id = params->ChildId[i];
        WCHAR* name_ptr = nullptr;
        if (!SymGetTypeInfo(sym_handle_, t->mod_base, child_id,
                            TI_GET_SYMNAME, &name_ptr) || !name_ptr) {
            continue;
        }
        std::wstring name(name_ptr);
        LocalFree(name_ptr);
        if (name != field) continue;
        DWORD off = 0;
        if (SymGetTypeInfo(sym_handle_, t->mod_base, child_id,
                           TI_GET_OFFSET, &off)) {
            return static_cast<uint64_t>(off);
        }
    }
    return std::nullopt;
}

std::optional<SymbolResolver::FunctionSymbol>
SymbolResolver::resolveFunction(uint64_t address) const {
    BYTE buf[sizeof(SYMBOL_INFOW) + MAX_SYM_NAME * sizeof(WCHAR)] = {};
    auto* info = reinterpret_cast<PSYMBOL_INFOW>(buf);
    info->SizeOfStruct = sizeof(SYMBOL_INFOW);
    info->MaxNameLen = MAX_SYM_NAME;
    DWORD64 disp = 0;
    if (!SymFromAddrW(sym_handle_, address, &disp, info) || disp != 0) {
        return std::nullopt;
    }
    FunctionSymbol fs;
    fs.symbol_name.assign(info->Name, info->NameLen);
    IMAGEHLP_MODULEW64 mod{};
    mod.SizeOfStruct = sizeof(mod);
    if (SymGetModuleInfoW64(sym_handle_, info->ModBase, &mod)) {
        fs.module_name = mod.ModuleName;
    }
    return fs;
}

bool SymbolResolver::isAddressInLoadedModule(uint64_t address) const {
    if (module_ranges_.empty()) return false;
    auto it = std::upper_bound(module_ranges_.begin(), module_ranges_.end(),
                               address,
                               [](uint64_t v, const ModuleRange& r) {
                                   return v < r.base;
                               });
    if (it == module_ranges_.begin()) return false;
    --it;
    return address < it->base + it->size;
}

namespace {
struct EnumTypesCtx {
    std::vector<std::wstring>* out;
    size_t                     max_results;
};
BOOL CALLBACK EnumTypesCb(PSYMBOL_INFOW info, ULONG /*size*/, PVOID user) {
    auto* ctx = static_cast<EnumTypesCtx*>(user);
    ctx->out->emplace_back(info->Name, info->NameLen);
    if (ctx->max_results && ctx->out->size() >= ctx->max_results) return FALSE;
    return TRUE;
}
} // namespace

std::vector<std::wstring>
SymbolResolver::enumerateTypeNames(const std::wstring& mask,
                                   size_t max_results) const {
    std::vector<std::wstring> out;
    EnumTypesCtx ctx{&out, max_results};
    SymEnumTypesByNameW(sym_handle_, 0, mask.c_str(), EnumTypesCb, &ctx);
    return out;
}
