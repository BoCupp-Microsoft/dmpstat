#pragma once

#include <string>
#include <wil/resource.h>
#include "mapped_view.hpp"

class SymbolResolver {
public:
    SymbolResolver(const MappedView& mapped_view, const wil::unique_handle& process_handle);

    std::wstring resolveSymbol(uint64_t address) const;

private:
    const MappedView& mapped_view_;
    const wil::unique_handle& process_handle_;
};