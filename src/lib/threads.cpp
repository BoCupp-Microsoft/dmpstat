#include "threads.hpp"

#include <windows.h>
#include <dbghelp.h>

#include <iostream>
#include <unordered_map>

namespace dmpstat {

std::optional<std::vector<ThreadInfo>> readThreads(void* dump_base) {
    void* stream = nullptr;
    ULONG stream_size = 0;
    if (!MiniDumpReadDumpStream(dump_base, ThreadListStream, nullptr,
                                &stream, &stream_size)
        || stream == nullptr) {
        std::wcerr << L"Error: dump does not contain a ThreadListStream."
                   << std::endl;
        return std::nullopt;
    }
    auto* list = static_cast<MINIDUMP_THREAD_LIST*>(stream);

    std::vector<ThreadInfo> threads;
    threads.reserve(list->NumberOfThreads);
    for (ULONG i = 0; i < list->NumberOfThreads; ++i) {
        const auto& t = list->Threads[i];
        ThreadInfo info;
        info.thread_id  = t.ThreadId;
        info.teb        = t.Teb;
        info.stack_start = t.Stack.StartOfMemoryRange;
        info.stack_size  = t.Stack.Memory.DataSize;
        threads.push_back(info);
    }

    // Names stream is optional. Index the bytes-block ourselves: each entry
    // is { ULONG32 ThreadId; RVA64 RvaOfThreadName } and the name itself is
    // a MINIDUMP_STRING (ULONG32 Length in bytes, then UTF-16 chars).
    void* name_stream = nullptr;
    ULONG name_stream_size = 0;
    if (MiniDumpReadDumpStream(dump_base, ThreadNamesStream, nullptr,
                               &name_stream, &name_stream_size)
        && name_stream != nullptr) {
        auto* nl = static_cast<MINIDUMP_THREAD_NAME_LIST*>(name_stream);
        std::unordered_map<uint32_t, std::wstring> tid_to_name;
        for (ULONG i = 0; i < nl->NumberOfThreadNames; ++i) {
            const auto& te = nl->ThreadNames[i];
            if (te.RvaOfThreadName == 0) continue;
            auto* str = reinterpret_cast<MINIDUMP_STRING*>(
                static_cast<BYTE*>(dump_base) + te.RvaOfThreadName);
            // Length is in bytes; chars are UTF-16.
            const size_t chars = str->Length / sizeof(wchar_t);
            tid_to_name.emplace(te.ThreadId,
                                std::wstring(str->Buffer, chars));
        }
        for (auto& t : threads) {
            auto it = tid_to_name.find(t.thread_id);
            if (it != tid_to_name.end()) t.name = it->second;
        }
    }

    return threads;
}

} // namespace dmpstat
