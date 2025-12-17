#include <windows.h>
#include <algorithm>
#include <dbghelp.h>
#include <iostream>
#include "pointer_counter.hpp"

// Helper function to validate if a value could be a valid user-mode pointer
bool IsValidUserModePointer(UINT64 value) {
    // On 64-bit Windows, valid user-mode pointers are:
    // - Between 0x00010000 and 0x7FFEFFFF0000 (user space)
    // - Must be properly aligned (we handle this by only processing 8-byte aligned values in the caller)
    
    if (value < 0x10000) {
        return false;
    }
    
    if (value <= 0x7FFEFFFF0000ULL) {
        // Valid pointer path
        return true;
    }
    
    return false;
}

PointerCounter::PointerCounter(const MappedFile& mapped_file) {
    // Read memory list stream
    void* stream = nullptr;
    ULONG stream_size = 0;
    
    THROW_IF_WIN32_BOOL_FALSE(MiniDumpReadDumpStream(mapped_file.get(), Memory64ListStream, nullptr, &stream, &stream_size));
    
    auto memory_list = static_cast<PMINIDUMP_MEMORY64_LIST>(stream);
    std::wcout << L"Processing Memory64ListStream with " << memory_list->NumberOfMemoryRanges 
        << L" memory ranges..." << std::endl;
        
    ULONG64 total_processed_values = 0;
    RVA64 current_rva = memory_list->BaseRva;
    
    for (ULONG64 i = 0; i < memory_list->NumberOfMemoryRanges; i++) {
        const MINIDUMP_MEMORY_DESCRIPTOR64& memory_desc = memory_list->MemoryRanges[i];
        
        std::wcout << L"Processing memory range " << (i + 1) << L"/" << memory_list->NumberOfMemoryRanges
                    << L" - Base: 0x" << std::hex << memory_desc.StartOfMemoryRange
                    << L" Size: 0x" << memory_desc.DataSize << std::dec << std::endl;
        
        // Get pointer to memory data in dump file
        BYTE* memory_data = static_cast<BYTE*>(mapped_file.get()) + current_rva;
        
        // Process 64-bit values at 8-byte aligned boundaries
        ULONG64 aligned_size = memory_desc.DataSize & ~7; // Round down to 8-byte boundary
        
        for (ULONG64 offset = 0; offset < aligned_size; offset += sizeof(UINT64)) {
            UINT64 value = *reinterpret_cast<UINT64*>(memory_data + offset);
            
            // Only count values that could be valid user-mode pointers
            if (IsValidUserModePointer(value)) {
                value_counts_[value]++;
            }
            total_processed_values++;
            
            if (total_processed_values % 1000000 == 0) {
                std::wcout << L"Processed " << total_processed_values << L" values..." << std::endl;
            }
        }
        
        current_rva += memory_desc.DataSize;
    }
    
    std::wcout << L"Processing complete." << std::endl;
    std::wcout << L"Total 64-bit values processed: " << total_processed_values << std::endl;
    std::wcout << L"Distinct values found: " << value_counts_.size() << std::endl;
}

std::vector<std::pair<uint64_t, uint64_t>> PointerCounter::getSortedPointersWithCounts() const {
    // Create vector of pairs for sorting
    std::vector<std::pair<uint64_t, uint64_t>> sorted_values(value_counts_.begin(), value_counts_.end());
    
    // Sort by count (descending)
    std::sort(sorted_values.begin(), sorted_values.end(),
        [](const auto& a, const auto& b) { return a.second > b.second; });
    
    return sorted_values;
}