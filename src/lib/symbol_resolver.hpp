#pragma once

#include <cstdint>
#include <functional>
#include <optional>
#include <string>
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

private:
    struct MemRange {
        uint64_t va;       // virtual address in the captured process
        uint64_t size;     // size in bytes
        uint64_t fileRva;  // offset into the mapped dump file
    };

    void buildMemoryIndex();

    const MappedView& mapped_view_;
    HANDLE sym_handle_;
    bool verbose_;
    std::vector<MemRange> memory_ranges_; // sorted by va
};