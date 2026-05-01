#pragma once

#include <cstdint>
#include <iostream>
#include <optional>
#include <string>

#include "dump_memory.hpp"
#include "symbol_resolver.hpp"

namespace dmpstat {

// Read the typed value of a named global from the dump.
//
// Resolves `qualified_name` via SymbolResolver (exact match), then reads
// sizeof(T) bytes from the resulting VA via the reader. Returns std::nullopt
// (and logs a diagnostic to std::wcerr) if the symbol can't be found or its
// bytes aren't captured. `domain_label` is prepended to error lines, e.g.
// "[oilpan]" or "[v8]".
template <typename T>
std::optional<T> readGlobal(const SymbolResolver& sr,
                            const RandomAccessReader& reader,
                            const std::wstring& qualified_name,
                            const wchar_t* domain_label) {
    const auto va = sr.findGlobal(qualified_name);
    if (!va) {
        std::wcerr << L"Error: " << (domain_label ? domain_label : L"")
                   << L" could not locate symbol '" << qualified_name << L"'."
                   << std::endl;
        return std::nullopt;
    }
    const auto value = reader.read<T>(*va);
    if (!value) {
        std::wcerr << L"Error: " << (domain_label ? domain_label : L"")
                   << L" symbol '" << qualified_name << L"' resolved to VA 0x"
                   << std::hex << *va << std::dec
                   << L" but those bytes are not captured in the dump."
                   << std::endl;
        return std::nullopt;
    }
    return value;
}

} // namespace dmpstat
