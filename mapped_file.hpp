#pragma once

#include <string>
#include <wil/resource.h>

class MappedFile {
public:
    MappedFile(const std::wstring& file_path);
    void* get() const;
private:
    wil::unique_hfile file_handle_;
    wil::unique_handle mapping_handle_;
    wil::unique_mapview_ptr<void> mapped_view_;
};
