#pragma once

#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include <windows.h>
#include "mapped_view.hpp"
#include "progress.hpp"

class SymbolResolver {
public:
    SymbolResolver(const MappedView& mapped_view, const std::wstring& sympath, ProgressReporter& progress, bool verbose = false);
    ~SymbolResolver();

    SymbolResolver(const SymbolResolver&) = delete;
    SymbolResolver& operator=(const SymbolResolver&) = delete;

    std::wstring resolveSymbol(uint64_t address) const;

    // If `address` resolves exactly to a v-table symbol (`Class::\`vftable'`
    // pattern emitted by MSVC), return the vtable address (= the symbol's
    // address in the dump), the class name, and the byte size of the class's
    // type as recorded in the PDB. `type_size` is 0 if the type info could
    // not be retrieved. Returns std::nullopt for non-vtable symbols or if
    // symbol resolution fails.
    struct VtableInfo {
        uint64_t     vtable_address = 0; // address of the vftable symbol
        std::wstring module_name;        // e.g. "msedge"
        std::wstring class_name;         // e.g. "blink::HTMLDivElement"
        uint64_t     type_size = 0;
    };
    std::optional<VtableInfo> resolveVtable(uint64_t address) const;

    // Read up to `bytes` bytes from the dump's captured memory at virtual
    // address `addr`, into `buf`. Returns the number of bytes actually copied
    // (0 if the address is outside any captured range). Used by the DbgHelp
    // CBA_READ_MEMORY callback so DbgHelp reads from the dump rather than
    // ReadProcessMemory on our own (or a bogus) process.
    DWORD readDumpMemory(uint64_t addr, void* buf, DWORD bytes) const;

    // Look up a fully-qualified symbol name (e.g.
    // "v8::internal::Heap::isolate_") and return its virtual address if found.
    // The name may include DbgHelp wildcards (`*`, `?`); only the first match
    // is returned.
    std::optional<uint64_t> findGlobal(const std::wstring& name) const;

    // Enumerate all symbols matching `mask` (DbgHelp wildcard syntax). The
    // callback receives (name, address, size). Return false from the callback
    // to stop early.
    struct GlobalHit { std::wstring name; uint64_t address; uint64_t size; };
    std::vector<GlobalHit> findGlobalsMatching(const std::wstring& mask,
                                               size_t max_results = 0) const;

    bool verbose() const { return verbose_; }

    // PDB type introspection.
    //
    // findType: resolve a fully-qualified C++ type name (handles namespaces,
    // including elaborated-type-specifier keywords like `enum`/`class`) to a
    // (module base, type index) pair.
    struct ResolvedType { uint64_t mod_base = 0; uint32_t type_index = 0; };
    std::optional<ResolvedType> findType(const std::wstring& qualified_name) const;

    // Total byte size of `qualified_name` (sizeof in C++ terms). Returns 0 if
    // the type cannot be resolved.
    uint64_t typeSize(const std::wstring& qualified_name) const;

    // Offset (in bytes) of `field` inside `struct_qname`. Returns std::nullopt
    // if the type or field cannot be resolved. Walks members via dbghelp's
    // TI_FINDCHILDREN / TI_GET_OFFSET.
    std::optional<uint64_t> fieldOffset(const std::wstring& struct_qname,
                                        const std::wstring& field) const;

    // Symbolicate a function address; returns {module, demangled name} when
    // the address is exactly at a known symbol's start. nullopt otherwise.
    struct FunctionSymbol {
        std::wstring module_name;
        std::wstring symbol_name;
    };
    std::optional<FunctionSymbol> resolveFunction(uint64_t address) const;

    // Returns true if `address` lies inside any loaded module's image range
    // (BaseOfImage .. BaseOfImage + SizeOfImage). All v-table symbols sit in
    // a module's `.rdata`, so this is a cheap O(log N) pre-filter that
    // eliminates the vast majority of "data noise" pointer values before
    // dbghelp gets involved.
    bool isAddressInLoadedModule(uint64_t address) const;

    // V-table type-resolution stats. Counts are over distinct (module, class)
    // keys (not raw v-table address sites), matching the cache. Updated as
    // resolveVtable() runs; safe to read after collection.
    struct VtableResolutionStats {
        uint64_t resolved   = 0;
        uint64_t unresolved = 0;
    };
    VtableResolutionStats vtable_resolution_stats() const;

    // Distinct "module!class" names whose sizeof(class) could not be
    // resolved. Useful as a verbose diagnostic; the entries are stable across
    // calls to resolveVtable() (the cache dedupes).
    const std::unordered_set<std::wstring>& unresolved_vtable_classes() const {
        return unresolved_vtable_classes_;
    }

    // Diagnostic: enumerate types whose fully-qualified name matches `mask`
    // (DbgHelp wildcard syntax: `*` and `?`). Returns up to `max_results`
    // matches. Use sparingly: this calls SymEnumTypesByNameW which is O(types
    // in module) and slow on large PDBs. Intended for one-shot diagnostics
    // (e.g. when struct-layout discovery fails).
    std::vector<std::wstring> enumerateTypeNames(const std::wstring& mask,
                                                 size_t max_results = 50) const;

    // Sorted (by base) image range of a loaded module.
    struct ModuleRange { uint64_t base; uint64_t size; };

private:
    struct MemRange {
        uint64_t va;       // virtual address in the captured process
        uint64_t size;     // size in bytes
        uint64_t fileRva;  // offset into the mapped dump file
    };

    void buildMemoryIndex();

    // Sorted (by base) image ranges of all loaded modules. Used by
    // isAddressInLoadedModule() as a fast pre-filter for v-table candidates.
    std::vector<ModuleRange> module_ranges_;

    const MappedView& mapped_view_;
    HANDLE sym_handle_;
    bool verbose_;
    std::vector<MemRange> memory_ranges_; // sorted by va

    // Cache of (module base, class name) -> sizeof(class). Avoids repeating
    // expensive PDB type lookups when many vtables resolve to the same class
    // (e.g. duplicate vftables in the same module from incomplete COMDAT
    // folding). Mutable so resolveVtable() can stay const.
    struct VtableSizeKey {
        uint64_t     mod_base;
        std::wstring class_name;
        bool operator==(const VtableSizeKey& o) const {
            return mod_base == o.mod_base && class_name == o.class_name;
        }
    };
    struct VtableSizeKeyHash {
        size_t operator()(const VtableSizeKey& k) const noexcept {
            size_t h1 = std::hash<uint64_t>{}(k.mod_base);
            size_t h2 = std::hash<std::wstring>{}(k.class_name);
            return h1 ^ (h2 + 0x9e3779b97f4a7c15ULL + (h1 << 6) + (h1 >> 2));
        }
    };
    mutable std::unordered_map<VtableSizeKey, uint64_t, VtableSizeKeyHash>
        vtable_size_cache_;

    // "module!class" entries we've seen but couldn't resolve a sizeof for.
    // Built on first encounter (the cache dedupes), so this naturally lists
    // each problem class exactly once.
    mutable std::unordered_set<std::wstring> unresolved_vtable_classes_;
};