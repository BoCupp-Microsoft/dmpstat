#pragma once

#include <string>

class TokenFetcher {
public:
    std::wstring fetchToken(const std::wstring& resource);
}