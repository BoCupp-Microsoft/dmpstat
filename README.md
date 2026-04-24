# Windows Dump File Tools
A collection of programs for inspecting Windows dump files (*.dmp).

## Tools

**valcount.exe**
The idea is to find objects with high counts using identifying symbols like vtables, function pointers, string pointers, etc,
for the sake of understanding where memory is being used in excess without needing to know really anything about the particulars
of the program being analyzed.

```
Usage: valcount.exe [options]
Options:
  -d <dump_file>  Dump file to process
  -t <count>      Show top N most frequent values (default: 100)
  -h              Show this help message
```

## Building

Dependencies (currently just [WIL](https://github.com/microsoft/wil)) are provided through a project-local [vcpkg](https://github.com/microsoft/vcpkg)
submodule.

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
