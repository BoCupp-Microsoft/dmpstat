# Windows Dump File Analyzer
A C++ program that reads Windows dump files (*.dmp) and counts pointer values using the Windows dbghelp library.
The top N values are printed and symbolicated (if possible).

The idea is to find objects with high counts using identifying symbols like vtables or other function pointers
for the sake of understanding where memory is being used in excess without knowing anything about the particulars
of the program being analyzed.

## Building

Dependencies (currently just [WIL](https://github.com/microsoft/wil)) are
provided through a project-local [vcpkg](https://github.com/microsoft/vcpkg)
submodule, so no globally installed package manager is required.

### First-time setup

```bash
# Clone with submodules (or run `git submodule update --init --recursive` after a plain clone)
git clone --recurse-submodules <repo-url>

# Bootstrap the pinned vcpkg in the submodule (one-time per clone)
.\vcpkg\bootstrap-vcpkg.bat -disableMetrics
```

### Configure and build

```bash
cmake --preset default
cmake --build build
```

The resulting binary is written to `build\bin\dmpstat.exe`.

## Usage

```
Usage: dmpstat.exe [options]
Options:
  -d <dump_file>  Dump file to process
  -t <count>      Show top N most frequent values (default: 100)
  -h              Show this help message
```
