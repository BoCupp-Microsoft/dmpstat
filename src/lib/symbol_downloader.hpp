#pragma once

#include <string>

class SymbolDownloader {
public:
    SymbolDownloader(TokenFetcher& token_fetcher, const std::wstring& symbol_path);
    std::wstring downloadSymbolForModuleIfNeeded(const std::wstring& module_name, const std::wstring& uuid);

private:
    TokenFetcher& token_fetcher_;
    std::wstring symbol_path_;
};