#include <windows.h>
#include <iostream>
#include "progress.hpp"

namespace {
constexpr unsigned long long kMinUpdateIntervalMs = 100;
}

ProgressReporter::ProgressReporter() {
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    tty_ = (h != INVALID_HANDLE_VALUE) && (GetFileType(h) == FILE_TYPE_CHAR);
}

void ProgressReporter::update(const std::wstring& status, bool force) {
    if (!tty_) {
        return;
    }

    unsigned long long now = GetTickCount64();
    if (!force && last_write_tick_ != 0 &&
        (now - last_write_tick_) < kMinUpdateIntervalMs) {
        return;
    }
    last_write_tick_ = now;

    std::wcout << L'\r' << status;
    if (status.size() < last_len_) {
        std::wcout << std::wstring(last_len_ - status.size(), L' ');
    }
    std::wcout.flush();
    last_len_ = status.size();
}

void ProgressReporter::clear() {
    if (!tty_ || last_len_ == 0) {
        return;
    }
    std::wcout << L'\r' << std::wstring(last_len_, L' ') << L'\r';
    std::wcout.flush();
    last_len_ = 0;
    last_write_tick_ = 0;
}
