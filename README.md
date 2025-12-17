# Windows Dump File Analyzer
A C++ program that reads Windows dump files (*.dmp) and counts pointer values using the Windows dbghelp library.
The top N values are printed and symbolicated (if possible).

The idea is to find objects with high counts using identifying symbols like vtables or other function pointers
for the sake of understanding where memory is being used in excess without knowing anything about the particulars
of the program being analyzed.

## Building

### Using CMake (Recommended)

```bash
# Create build directory
mkdir build
cd build

# Configure with CMake
cmake ..

# Build the project
cmake --build . --config Debug
```

## Usage

```
Usage: dmpstat.exe [options]
Options:
  -d <dump_file>  Dump file to process
  -t <count>      Show top N most frequent values (default: 100)
  -h              Show this help message
```
