#pragma once

#include <string>
#include <wil/resource.h>
#include "mapped_file.hpp"

class SymbolResolver {
public:
    SymbolResolver(const MappedFile& mapped_file, const wil::unique_handle& process_handle);

    std::wstring resolveSymbol(uint64_t address) const;

private:
    const MappedFile& mapped_file_;
    const wil::unique_handle& process_handle_;
};