# Windows Dump File Analyzer

A C++ program that reads Windows dump files (*.dmp) and counts distinct occurrences of every 64-bit pointer-aligned value using the Windows dbghelp library.

## Features

- **Proper Dump File Parsing**: Uses Windows dbghelp library APIs to correctly read dump file structures
- **Memory Stream Processing**: Handles both Memory64ListStream and MemoryListStream formats
- **64-bit Pointer Alignment**: Processes values at 8-byte aligned boundaries
- **Efficient Processing**: Memory-mapped file access with progress indicators for large files
- **Statistical Analysis**: Provides comprehensive statistics and top value reporting
- **CSV Export**: Save results to CSV format for further analysis
- **Fallback Processing**: Falls back to raw data processing if memory streams are not available

## Requirements

- Windows operating system
- Visual Studio 2019 or later (for MSVC compiler)
- CMake 3.15 or later
- Windows SDK with dbghelp.h

## Building

### Using CMake (Recommended)

```bash
# Create build directory
mkdir build
cd build

# Configure with CMake
cmake ..

# Build the project
cmake --build . --config Release

# The executable will be in build/bin/dmp_analyzer.exe
```

### Using Visual Studio Developer Command Prompt

```cmd
# Open Developer Command Prompt for Visual Studio
# Navigate to project directory
cd c:\src\dmpstat

# Build directly with CMake
cmake -B build -S .
cmake --build build --config Release
```

## Usage

```
dmp_analyzer.exe <dump_file.dmp> [options]

Options:
  -o <output_file>  Save results to CSV file
  -t <count>        Show top N most frequent values (default: 10)
  -h                Show help message

Examples:
  dmp_analyzer.exe memory.dmp
  dmp_analyzer.exe crash.dmp -o results.csv -t 20
  dmp_analyzer.exe user.dmp -t 50
```

## Output

The program provides three types of output:

### 1. Processing Information
- File size and loading status
- Memory range information from dump streams
- Progress indicators for large files

### 2. Statistics
- Total number of 64-bit values processed
- Number of distinct values found
- Average occurrences per distinct value

### 3. Top Values Report
- Most frequently occurring values
- Hexadecimal representation
- Occurrence count and percentage

### 4. CSV Export (Optional)
When using the `-o` option, results are saved in CSV format:
```csv
Value (Hex),Count
0x0000000000000000,1234567
0x00007FF123456789,98765
...
```

## How It Works

1. **File Loading**: Opens the dump file and creates a memory-mapped view
2. **Dump Stream Analysis**: Uses `MiniDumpReadDumpStream` to read memory streams:
   - First attempts Memory64ListStream (full memory dumps)
   - Falls back to MemoryListStream (selective memory dumps)
   - Falls back to raw processing if no streams are found
3. **Memory Processing**: Iterates through each memory range in 8-byte increments
4. **Value Counting**: Uses an unordered_map to efficiently count distinct 64-bit values
5. **Results Analysis**: Sorts and presents the most frequent values

## Technical Details

- **Alignment**: Processes only 8-byte aligned values (pointer alignment on 64-bit systems)
- **Endianness**: Assumes little-endian format (standard for x86/x64 Windows)
- **Memory Efficiency**: Uses memory mapping to handle large dump files without loading entirely into RAM
- **Progress Tracking**: Provides progress updates every 1 million values processed

## Supported Dump File Types

- Windows minidumps (.dmp files)
- Full memory dumps
- Kernel dumps
- User-mode process dumps
- Any dump file that follows the Windows minidump format

## Error Handling

The program handles various error conditions:
- File not found or access denied
- Invalid dump file format
- Memory allocation failures
- Missing memory streams (falls back to raw processing)

## Performance Considerations

- Large dump files (GB+) are processed efficiently using memory mapping
- Progress indicators help track processing of very large files
- Memory usage remains low regardless of dump file size
- Processing speed depends on file size and storage performance

## License

This project is provided as-is for educational and analysis purposes.
