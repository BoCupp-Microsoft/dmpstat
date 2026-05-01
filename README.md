# Windows Dump File Tools
A collection of programs for inspecting Windows dump files (*.dmp).

## Tools

### `valcount.exe`

Find objects with high counts using identifying symbols (vtables, function
pointers, string pointers, etc.) to surface where memory is being used in
excess without needing prior knowledge of the program being analyzed.

```
Usage: valcount.exe [options] <dump_file>
  -t, --top <n>      Show top N most frequent values (default: 100)
  -s, --sympath ...  Symbol path (defaults to _NT_SYMBOL_PATH or C:\Symbols)
  -v, --verbose      Print DbgHelp diagnostic messages
```

### `valfind.exe`

Locate every occurrence of a specific 64-bit value in a dump's committed
memory. Useful follow-up to `valcount` (where does this hot value live?)
or for chasing references to a known address. With a symbol path the
match site and surrounding pointers are symbolicated.

```
Usage: valfind.exe [options] <dump_file> <value>
  --start <addr>     Lowest address (inclusive) to search
  --end <addr>       Highest address (inclusive) to search
  --skip <n>         Skip the first N matches before printing
  --max <n>          Stop after N matches printed (0 = unlimited)
  --context <n>      Print N pointer-sized words on each side of each match
  -s, --sympath ...  Symbol path passed verbatim to DbgHelp
  -v, --verbose      DbgHelp diagnostics during symbol loading
```

### `segments.exe`

List the committed memory segments described by a dump's
`MemoryInfoListStream`. Pair with `--all` to also see reserved and free
ranges, or `--summary` to roll up by `(State, Type, Protect, AllocProt)`
for a quick map of how a process has carved up its address space.

```
Usage: segments.exe [options] <dump_file>
  -a, --all     Show all regions (committed, reserved, free)
  --summary     Aggregate by (State, Type, Protect, AllocProt) only
```

### `crcommit.exe`

Chromium-aware private-commit analyzer for Windows minidumps. Finds the
Oilpan (cppgc) cage and the V8 pointer-compression cage, attributes
committed memory to each, walks Oilpan pages to count live vs. free-list
vs. LAB-tail bytes, resolves `GCInfoIndex` → class names via PDB, and
enumerates V8 isolates per process (Main / DedicatedWorker /
SharedWorker / ServiceWorker) by locating V8's `g_current_isolate_`
thread-local and matching it to OS thread ids. Requires Microsoft
private symbols for the V8-hosting module (e.g. `msedge.dll` /
`chrome.dll`).

```
Usage: crcommit.exe [options] <dump_file>
  -s, --sympath ...        Symbol search path (overrides _NT_SYMBOL_PATH)
  --summary                Cage + committed-byte rollup only
  --top <n>                Top-N v-table rows to print (default 25)
  --sort {size,count}      Sort v-table table by size (default) or count
  --oilpan {skip,only}     Skip Oilpan analysis, or run only Oilpan
  --v8 {skip,only}         Skip V8 analysis, or run only V8
  --no-strings             Skip printable-string scan over Oilpan memory
  --no-pages               Skip cppgc page classification / object walk
  --no-classes             Skip GCInfoIndex -> class name resolution
  --min-string-length <n>  Min printable run length to count (default 8)
  -v, --verbose            Symbol-resolution / region-walk diagnostics
```

See [`docs/architecture.md`](docs/architecture.md) for a code-layout
overview and [`docs/memory-investigation-playbook.md`](docs/memory-investigation-playbook.md)
for field notes on interpreting the output.

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
