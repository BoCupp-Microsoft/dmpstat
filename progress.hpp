#pragma once

#include <string>

// Single-line in-place progress indicator.
//
// Writes status strings that overwrite the current console line using
// carriage return plus space padding. When stdout is not a TTY (e.g. the
// program is redirected to a file or pipe), all operations are no-ops so
// that logs stay clean. Calls are also time-throttled so that callers can
// invoke update() from hot loops without paying the cost of a console write
// for every call.
class ProgressReporter {
public:
    ProgressReporter();

    // Overwrite the current progress line with `status`. Throttled: if
    // `force` is false, writes at most once per ~100 ms.
    void update(const std::wstring& status, bool force = false);

    // Erase the current progress line so subsequent output starts clean.
    void clear();

private:
    bool tty_;
    size_t last_len_ = 0;
    unsigned long long last_write_tick_ = 0;
};
