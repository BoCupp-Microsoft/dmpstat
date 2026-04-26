#include <windows.h>
#include <dbghelp.h>
#include <algorithm>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <map>
#include <string>
#include <tuple>
#include <vector>
#include <CLI/CLI.hpp>
#include <wil/result.h>
#include "mapped_view.hpp"

namespace {

std::wstring Utf8ToWide(const std::string& s) {
    if (s.empty()) return {};
    int needed = MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), nullptr, 0);
    std::wstring result(needed, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), result.data(), needed);
    return result;
}

std::string WideToUtf8(const std::wstring& s) {
    if (s.empty()) return {};
    int needed = WideCharToMultiByte(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), nullptr, 0, nullptr, nullptr);
    std::string result(needed, '\0');
    WideCharToMultiByte(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), result.data(), needed, nullptr, nullptr);
    return result;
}

// Translate a Win32 page-protection constant to a short mnemonic. Only the
// access bits are decoded (PAGE_GUARD/PAGE_NOCACHE/PAGE_WRITECOMBINE etc.
// are appended as suffixes when present).
std::wstring ProtectToString(DWORD protect) {
    if (protect == 0) return L"-";
    DWORD access = protect & 0xFF;
    std::wstring s;
    switch (access) {
        case PAGE_NOACCESS:          s = L"---"; break;
        case PAGE_READONLY:          s = L"R--"; break;
        case PAGE_READWRITE:         s = L"RW-"; break;
        case PAGE_WRITECOPY:         s = L"RWC"; break;
        case PAGE_EXECUTE:           s = L"--X"; break;
        case PAGE_EXECUTE_READ:      s = L"R-X"; break;
        case PAGE_EXECUTE_READWRITE: s = L"RWX"; break;
        case PAGE_EXECUTE_WRITECOPY: s = L"RCX"; break;
        default: {
            wchar_t buf[16];
            swprintf_s(buf, L"0x%02X", access);
            s = buf;
            break;
        }
    }
    if (protect & PAGE_GUARD)         s += L"+G";
    if (protect & PAGE_NOCACHE)       s += L"+NC";
    if (protect & PAGE_WRITECOMBINE)  s += L"+WC";
    return s;
}

const wchar_t* StateToString(DWORD state) {
    switch (state) {
        case MEM_COMMIT:  return L"COMMIT";
        case MEM_RESERVE: return L"RESERVE";
        case MEM_FREE:    return L"FREE";
        default:          return L"?";
    }
}

const wchar_t* TypeToString(DWORD type) {
    switch (type) {
        case MEM_IMAGE:   return L"IMAGE";
        case MEM_MAPPED:  return L"MAPPED";
        case MEM_PRIVATE: return L"PRIVATE";
        case 0:           return L"-";
        default:          return L"?";
    }
}

// Read a MINIDUMP_STRING (ULONG32 length-in-bytes + UTF-16 buffer) at the
// given RVA within the mapped dump and return it as a wide string.
std::wstring ReadMinidumpString(const void* dump_base, RVA rva) {
    if (rva == 0) return {};
    const BYTE* p = static_cast<const BYTE*>(dump_base) + rva;
    ULONG32 length_bytes = 0;
    std::memcpy(&length_bytes, p, sizeof(length_bytes));
    const wchar_t* chars = reinterpret_cast<const wchar_t*>(p + sizeof(ULONG32));
    return std::wstring(chars, length_bytes / sizeof(wchar_t));
}

struct ModuleEntry {
    uint64_t base;
    uint64_t end; // exclusive
    std::wstring name;
};

// Build a sorted list of loaded PE modules from the dump's ModuleListStream.
std::vector<ModuleEntry> LoadModuleList(const void* dump_base) {
    std::vector<ModuleEntry> modules;
    void* stream = nullptr;
    ULONG stream_size = 0;
    if (!MiniDumpReadDumpStream(const_cast<void*>(dump_base), ModuleListStream,
                                nullptr, &stream, &stream_size) ||
        stream == nullptr) {
        return modules;
    }
    auto* list = static_cast<MINIDUMP_MODULE_LIST*>(stream);
    modules.reserve(list->NumberOfModules);
    for (ULONG32 i = 0; i < list->NumberOfModules; ++i) {
        const MINIDUMP_MODULE& m = list->Modules[i];
        ModuleEntry e;
        e.base = m.BaseOfImage;
        e.end = m.BaseOfImage + m.SizeOfImage;
        e.name = ReadMinidumpString(dump_base, m.ModuleNameRva);
        modules.push_back(std::move(e));
    }
    std::sort(modules.begin(), modules.end(),
              [](const ModuleEntry& a, const ModuleEntry& b) { return a.base < b.base; });
    return modules;
}

// Find the module whose image range contains the given address, if any.
const ModuleEntry* FindModuleAt(const std::vector<ModuleEntry>& modules, uint64_t addr) {
    auto it = std::upper_bound(modules.begin(), modules.end(), addr,
        [](uint64_t a, const ModuleEntry& m) { return a < m.base; });
    if (it == modules.begin()) return nullptr;
    --it;
    if (addr >= it->base && addr < it->end) return &*it;
    return nullptr;
}

// Format a byte size as a human-readable string with an SI-ish suffix.
std::wstring FormatSize(uint64_t bytes) {
    const wchar_t* units[] = { L"B", L"KB", L"MB", L"GB", L"TB" };
    double v = static_cast<double>(bytes);
    int u = 0;
    while (v >= 1024.0 && u + 1 < static_cast<int>(_countof(units))) {
        v /= 1024.0;
        ++u;
    }
    wchar_t buf[32];
    if (u == 0) {
        swprintf_s(buf, L"%llu %s",
            static_cast<unsigned long long>(bytes), units[u]);
    } else {
        swprintf_s(buf, L"%.2f %s", v, units[u]);
    }
    return buf;
}

} // namespace

int wmain(int argc, wchar_t** argv) {
    std::vector<std::string> args_utf8;
    args_utf8.reserve(argc);
    for (int i = 0; i < argc; ++i) {
        args_utf8.emplace_back(WideToUtf8(argv[i]));
    }

    CLI::App app{"List committed memory segments described by a Windows dump file"};
    app.set_version_flag("--version", std::string("1.0.0"));

    std::string dump_file_utf8;
    bool show_all = false;
    bool summary = false;

    app.add_option("dump_file", dump_file_utf8, "Dump file to inspect")
        ->required()
        ->check(CLI::ExistingFile);
    app.add_flag("-a,--all", show_all,
        "Show all regions (committed, reserved, free) instead of only committed");
    app.add_flag("--summary", summary,
        "Print only a summary aggregated by (State, Type, Protect, AllocProt)");

    std::vector<char*> argv_utf8;
    argv_utf8.reserve(args_utf8.size());
    for (auto& s : args_utf8) argv_utf8.push_back(s.data());

    try {
        app.parse(static_cast<int>(argv_utf8.size()), argv_utf8.data());
    } catch (const CLI::ParseError& e) {
        return app.exit(e);
    }

    const std::wstring dumpFilePath = Utf8ToWide(dump_file_utf8);
    MappedView mapped_view(dumpFilePath);

    void* stream = nullptr;
    ULONG stream_size = 0;
    if (!MiniDumpReadDumpStream(mapped_view.get(), MemoryInfoListStream, nullptr, &stream, &stream_size) || stream == nullptr) {
        std::wcerr << L"Error: dump does not contain a MemoryInfoListStream "
                      L"(no per-region protection/type info available)." << std::endl;
        return 1;
    }

    auto* header = static_cast<MINIDUMP_MEMORY_INFO_LIST*>(stream);
    if (header->SizeOfEntry < sizeof(MINIDUMP_MEMORY_INFO)) {
        std::wcerr << L"Error: unexpected MINIDUMP_MEMORY_INFO entry size: "
                   << header->SizeOfEntry << std::endl;
        return 1;
    }

    std::wcout
        << (summary ? L"" :
            L"Start Address      | End Address (excl.) | Size              | State    | Type     | Prot       | AllocProt  | Allocation Base    | Mapped File\n"
            L"-------------------|---------------------|-------------------|----------|----------|------------|------------|--------------------|-------------------\n");

    const BYTE* base = static_cast<const BYTE*>(stream) + header->SizeOfHeader;
    uint64_t total_committed = 0;
    uint64_t printed = 0;

    // Module list is used to resolve file names for IMAGE-mapped regions.
    const std::vector<ModuleEntry> modules =
        summary ? std::vector<ModuleEntry>{} : LoadModuleList(mapped_view.get());

    // Aggregation key: (State, Type, Protect, AllocationProtect).
    using SummaryKey = std::tuple<DWORD, DWORD, DWORD, DWORD>;
    struct SummaryRow { uint64_t bytes = 0; uint64_t count = 0; };
    std::map<SummaryKey, SummaryRow> summary_table;

    for (ULONG64 i = 0; i < header->NumberOfEntries; ++i) {
        const auto* info = reinterpret_cast<const MINIDUMP_MEMORY_INFO*>(base + i * header->SizeOfEntry);

        if (!show_all && info->State != MEM_COMMIT) {
            continue;
        }

        const uint64_t start = info->BaseAddress;
        const uint64_t end = start + info->RegionSize; // exclusive

        if (info->State == MEM_COMMIT) {
            total_committed += info->RegionSize;
        }

        if (summary) {
            SummaryKey key{info->State, info->Type, info->Protect, info->AllocationProtect};
            auto& row = summary_table[key];
            row.bytes += info->RegionSize;
            row.count += 1;
            ++printed;
            continue;
        }

        std::wstring mapped_file;
        if (info->Type == MEM_IMAGE) {
            const uint64_t lookup_addr =
                info->AllocationBase ? info->AllocationBase : start;
            if (const ModuleEntry* m = FindModuleAt(modules, lookup_addr)) {
                mapped_file = m->name;
            }
        }

        std::wcout << L"0x" << std::hex << std::uppercase
                   << std::right
                   << std::setw(16) << std::setfill(L'0') << start
                   << L" | 0x"
                   << std::setw(16) << std::setfill(L'0') << end
                   << L"   | "
                   << std::dec << std::setfill(L' ')
                   << std::setw(17) << std::right << FormatSize(info->RegionSize)
                   << L" | "
                   << std::setw(8) << std::left << StateToString(info->State)
                   << L" | "
                   << std::setw(8) << std::left << TypeToString(info->Type)
                   << L" | "
                   << std::setw(10) << std::left << ProtectToString(info->Protect)
                   << L" | "
                   << std::setw(10) << std::left << ProtectToString(info->AllocationProtect)
                   << L" | "
                   << L"0x" << std::hex << std::uppercase << std::right
                   << std::setw(16) << std::setfill(L'0') << info->AllocationBase
                   << std::dec << std::setfill(L' ')
                   << L" | " << mapped_file
                   << std::endl;
        ++printed;
    }

    if (summary) {
        // Sort summary rows by total bytes descending for readability.
        std::vector<std::pair<SummaryKey, SummaryRow>> rows(summary_table.begin(), summary_table.end());
        std::sort(rows.begin(), rows.end(),
            [](const auto& a, const auto& b) { return a.second.bytes > b.second.bytes; });

        std::wcout
            << L"State    | Type     | Prot       | AllocProt  | Regions    | Total Size       | Bytes\n"
            << L"---------|----------|------------|------------|------------|------------------|-------------------\n";

        uint64_t total_bytes = 0;
        uint64_t total_regions = 0;
        for (const auto& [key, row] : rows) {
            const auto [state, type, prot, alloc_prot] = key;
            std::wcout << std::setfill(L' ')
                       << std::setw(8) << std::left << StateToString(state) << L" | "
                       << std::setw(8) << std::left << TypeToString(type) << L" | "
                       << std::setw(10) << std::left << ProtectToString(prot) << L" | "
                       << std::setw(10) << std::left << ProtectToString(alloc_prot) << L" | "
                       << std::setw(10) << std::right << row.count << L" | "
                       << std::setw(16) << std::right << FormatSize(row.bytes) << L" | "
                       << row.bytes
                       << std::endl;
            total_bytes += row.bytes;
            total_regions += row.count;
        }

        std::wcout << std::endl
                   << L"Distinct combinations: " << rows.size()
                   << L"   Regions: " << total_regions
                   << L"   Total: " << FormatSize(total_bytes)
                   << L" (" << total_bytes << L" bytes)" << std::endl;
        return 0;
    }

    std::wcout << std::endl
               << L"Regions printed: " << printed
               << L"   Total committed: " << FormatSize(total_committed)
               << L" (" << total_committed << L" bytes)" << std::endl;

    return 0;
}
