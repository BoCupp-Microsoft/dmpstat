#pragma once

#include <string>
#include <wil/resource.h>
#include "mapped_view.hpp"
#include "progress.hpp"

class SymbolResolver {
public:
    SymbolResolver(const MappedView& mapped_view, const wil::unique_handle& process_handle, ProgressReporter& progress);

    std::wstring resolveSymbol(uint64_t address) const;

private:
    const MappedView& mapped_view_;
    const wil::unique_handle& process_handle_;
};