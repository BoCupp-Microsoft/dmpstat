#include "command_line.hpp"

CommandLine::CommandLine(int argc, wchar_t **argv) {
    for (int i=1; i < argc; ++i) {
        this->tokens.push_back(std::wstring(argv[i]));
    }
}

const std::wstring& CommandLine::get(const std::wstring &option) const {
    std::vector<std::wstring>::const_iterator itr;
    itr = std::find(this->tokens.begin(), this->tokens.end(), option);
    if (itr != this->tokens.end() && ++itr != this->tokens.end()){
        return *itr;
    }
    static const std::wstring empty_string(L"");
    return empty_string;
}

bool CommandLine::hasFlag(const std::wstring &option) const {
    return std::find(this->tokens.begin(), this->tokens.end(), option)
            != this->tokens.end();
}