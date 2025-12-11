#pragma once

#include <string>
#include <vector>

// https://stackoverflow.com/questions/865668/parsing-command-line-arguments-in-c
class CommandLine {
    public:
        CommandLine(int argc, wchar_t **argv);
        const std::wstring& get(const std::wstring &option) const;
        bool hasFlag(const std::wstring &option) const;

    private:
        std::vector <std::wstring> tokens;
};