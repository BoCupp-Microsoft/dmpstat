#include <iostream>
#include "mapped_file.hpp"

MappedFile::MappedFile(const std::wstring& file_path) {
    file_handle_.reset(CreateFileW(
        file_path.c_str(),
        GENERIC_READ,
        FILE_SHARE_READ,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr
    ));
    THROW_LAST_ERROR_IF(!file_handle_);
        
    mapping_handle_.reset(CreateFileMappingW(file_handle_.get(), nullptr, PAGE_READONLY, 0, 0, nullptr));
    THROW_LAST_ERROR_IF(!mapping_handle_);
        
    mapped_view_.reset(MapViewOfFile(mapping_handle_.get(), FILE_MAP_READ, 0, 0, 0));
    THROW_LAST_ERROR_IF(!mapped_view_);
}

void* MappedFile::get() const {
    return mapped_view_.get();
}