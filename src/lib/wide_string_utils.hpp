#pragma once

#include <string>

namespace dmpstat {

std::wstring Utf8ToWide(const std::string& s);
std::string WideToUtf8(const std::wstring& s);

} // namespace dmpstat
