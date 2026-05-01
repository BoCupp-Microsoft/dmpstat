#include "string_scanner.hpp"

#include <cstdio>

namespace dmpstat {

namespace {
inline bool isPrintableAscii(uint8_t b) {
    return b >= 0x20 && b <= 0x7E;
}
}

StringScanStats
scanPrintableStrings(const std::vector<DumpMemoryRegion>& regions,
                     ProgressReporter& progress,
                     std::wstring_view progress_label,
                     size_t min_chars) {
    StringScanStats stats{};
    for (size_t r = 0; r < regions.size(); ++r) {
        const auto& reg = regions[r];
        if (!reg.data || reg.captured_bytes == 0) continue;

        if (!progress_label.empty()) {
            wchar_t buf[160];
            swprintf_s(buf, L"%.*ls %zu/%zu",
                       static_cast<int>(progress_label.size()),
                       progress_label.data(),
                       r + 1, regions.size());
            progress.update(buf);
        }

        const uint8_t* p = reg.data;
        const uint64_t n = reg.captured_bytes;

        // ASCII pass.
        uint64_t i = 0;
        while (i < n) {
            if (isPrintableAscii(p[i])) {
                uint64_t j = i;
                while (j < n && isPrintableAscii(p[j])) ++j;
                const uint64_t run = j - i;
                if (run >= min_chars) {
                    ++stats.ascii_count;
                    stats.ascii_bytes += run;
                }
                i = j;
            } else {
                ++i;
            }
        }

        // UTF-16LE pass over even-aligned 2-byte units. A "char" is a pair
        // (lo, 0x00) where lo is printable ASCII; this reliably catches the
        // common case (Blink/WTF stores Latin-1/BMP strings two bytes wide)
        // without false-matching other binary content.
        i = 0;
        while (i + 1 < n) {
            if (p[i + 1] == 0 && isPrintableAscii(p[i])) {
                uint64_t j = i;
                while (j + 1 < n && p[j + 1] == 0 && isPrintableAscii(p[j])) {
                    j += 2;
                }
                const uint64_t chars = (j - i) / 2;
                if (chars >= min_chars) {
                    ++stats.utf16_count;
                    stats.utf16_bytes += chars * 2;
                }
                i = j;
            } else {
                i += 2;
            }
        }
    }
    if (!progress_label.empty()) {
        progress.clear();
    }
    return stats;
}

} // namespace dmpstat
