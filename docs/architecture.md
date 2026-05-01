# crcommit architecture

This document describes how `crcommit` is structured today, what each layer is
responsible for, and where the seams should be when we add a parallel **V8
isolate** analysis alongside the existing **Oilpan (cppgc)** analysis.

The guiding principle: `crcommit.cpp` parses CLI arguments and renders output;
domain knowledge ("how cppgc lays out its cage", "how V8 lays out an isolate")
lives in dedicated classes/modules under `src/tools/crcommit/`; primitives that
are useful to *any* dump-analysis tool live in `src/lib/`.

---

## 1. Current layout

```
src/
  lib/                            # dump primitives, no domain knowledge
    mapped_view.{hpp,cpp}         # mmap a minidump file
    dump_memory_region.hpp        # POD: { base, size, data, captured_bytes }
    dump_memory.{hpp,cpp}         # DumpMemoryReader (Memory64ListStream walk)
                                  # RandomAccessReader (VA reads + captured_at)
    pointer_counter.{hpp,cpp}     # 8-byte aligned qword scan -> { value -> count }
    progress.{hpp,cpp}            # ProgressReporter (single-line stderr UI)
    symbol_resolver.{hpp,cpp}     # DbgHelp wrapper:
                                  #  - findGlobal/findGlobalsMatching
                                  #  - resolveSymbol/resolveFunction
                                  #  - resolveVtable (incl. type-size cache)
                                  #  - findType/typeSize/fieldOffset
                                  #  - probeType*/enumerateFields/enumerateTypeNames
                                  #  - module-range pre-filter
    wide_string_utils.{hpp,cpp}   # UTF-8/UTF-16 conversions

  tools/crcommit/                 # the tool
    crcommit.cpp                  # CLI parsing + orchestration + all printers
    oilpan_heap.{hpp,cpp}         # OilpanHeap::discover() -> cage descriptor
                                  #   + cage-intersected committed regions
                                  #   + total private commit
    oilpan_objects.{hpp,cpp}      # walkOilpanObjects(): page classification +
                                  #   HeapObjectHeader walk + per-class aggregation
                                  # resolveClassNames(): GCInfoTable -> names
```

`crcommit.cpp` (~600 lines today) currently contains, **in addition to**
argument parsing and orchestration:

- `printSummary` — cage descriptor / committed-bytes rollup
- `scanStrings` + `printStrings` — printable-run scan over committed regions
- `VtableEntry` + `collectVtables` + `collapseSiblingVtables` + `printVtables`
- `printOilpanPages`, `printOilpanClasses`

The "scan" and "collect" helpers are domain-agnostic; the "print" helpers are
where the table layout lives.

---

## 2. Where the seam should be for V8

V8 isolate analysis (see `docs/v8-heap-layout.md`) has a structurally similar
shape:

| Concept            | Oilpan today                          | V8 (to add)                               |
|--------------------|---------------------------------------|-------------------------------------------|
| Virtual reservation| cppgc cage (4 GiB)                    | pointer-compression cage (4 GiB), code range, sandbox/trusted ranges |
| Locate from PDB    | `g_heap_base_` / `g_age_table_size_`  | `IsolateGroup::default_isolate_group_`, `V8HeapCompressionScheme::base_`, `Isolate::isolate_root_` |
| Committed regions  | `MemoryInfoListStream` ∩ cage         | same, ∩ each V8 reservation               |
| Pages              | 128 KiB cppgc pages w/ BasePage hdr   | 256 KiB V8 pages w/ MutablePageMetadata   |
| Per-object id      | `HeapObjectHeader.gc_info_index`      | `HeapObject.map.instance_type` / `Map*`   |
| Class name source  | GCInfoTable → `TraceTrait<X>::Trace`  | Map's class name + InstanceType enum      |
| Strings            | printable-run scanner                 | same scanner is fine                      |
| V-tables           | MSVC vftable scan                     | not directly applicable to V8 internals   |

The natural plan is: **mirror the Oilpan files with V8 equivalents under the
same directory**, factor anything genuinely shared into `src/lib/`, and have
`crcommit.cpp` orchestrate both and render. That keeps the existing user
mental model: one tool, two domains, parallel structure.

### Proposed layout

```
src/tools/crcommit/
  crcommit.cpp              # CLI + orchestration + display only
  oilpan_heap.{hpp,cpp}     # OilpanHeap (cage discovery + region capture)
  oilpan_objects.{hpp,cpp}  # page/object walk + GCInfo class names
  v8_heap.{hpp,cpp}         # NEW: V8Heap (cage(s) + region capture)
  v8_isolate.{hpp,cpp}      # NEW: IsolateGroup/Isolate/Heap/Spaces enumeration
  v8_objects.{hpp,cpp}      # NEW: per-space page walk + Map-based aggregation
```

`crcommit.cpp` then becomes a thin sequence of:

1. Parse args.
2. Build the shared infrastructure (mapped view, readers, symbol resolver,
   progress reporter).
3. If Oilpan analysis is requested: `OilpanHeap::discover` →
   `walkOilpanObjects` → `resolveClassNames` → render.
4. If V8 analysis is requested: `V8Heap::discover` → enumerate isolates →
   `walkV8Objects` → render.
5. Run shared cross-cage scans (strings, vtables) once per cage.

Argument flags will likely grow a `--no-v8` / `--v8-only` parallel to the
existing `--no-pages` / `--no-classes` / `--no-strings`. Defaults remain "do
everything".

---

## 3. Refactoring opportunities (lib candidates)

These are pieces currently inside `crcommit.cpp` or `oilpan_*.cpp` that have
*no* Oilpan-specific knowledge and would be reused verbatim by V8 analysis.
Moving them now makes the V8 work cheaper and reduces `crcommit.cpp` clutter.

### 3.1 Cage-intersected region capture *(high value)*

`OilpanHeap::discover` walks `MemoryInfoListStream` and emits the
`MEM_COMMIT|MEM_PRIVATE` regions that intersect `[cage_base, cage_base+size)`,
plus a process-wide `total_private_commit` total. V8 needs the same operation
applied to each of its reservations (main cage, code range, possibly sandbox /
trusted ranges).

**Proposed:** `src/lib/committed_regions.{hpp,cpp}` exposing
```cpp
struct CommittedRegionsInRange {
  std::vector<DumpMemoryRegion> regions;   // clipped to [base, base+size)
  uint64_t                      committed_bytes;       // sum of clipped sizes
  uint64_t                      total_private_commit;  // process-wide
};
std::optional<CommittedRegionsInRange>
readCommittedRegionsInRange(const RandomAccessReader& reader,
                            void* dump_base,
                            uint64_t base, uint64_t size,
                            bool verbose);
```
`OilpanHeap` and `V8Heap` then both call this with their respective ranges.

### 3.2 `readGlobal<T>` helper *(small but everywhere)*

Both Oilpan and V8 follow the same pattern: resolve a fully-qualified symbol
to a VA, then `reader.read<T>(va)` to get the value. We do this 5+ times in
`oilpan_heap.cpp` already and will do it many more times for V8.

**Proposed:** add to `SymbolResolver` (or a free helper next to it):
```cpp
template <typename T>
std::optional<T> readGlobal(const RandomAccessReader& reader,
                            const std::wstring& qualified_name) const;
```
Returning the typed value (or `nullopt`) and emitting the standard error
messages on `findGlobal` failure / not-captured failure.

### 3.3 Printable-string scanner *(direct lift)*

`scanStrings` in `crcommit.cpp` is generic over `OilpanHeap` only because it
asks for `heap.regions()`. Make it take `const std::vector<DumpMemoryRegion>&`
and a label, and it works for any cage.

**Proposed:** `src/lib/string_scanner.{hpp,cpp}`:
```cpp
struct StringScanStats { uint64_t ascii_count, ascii_bytes, utf16_count, utf16_bytes; };
StringScanStats
scanPrintableStrings(const std::vector<DumpMemoryRegion>& regions,
                     ProgressReporter& progress,
                     std::wstring_view progress_label,
                     size_t min_chars);
```
The corresponding printer stays in `crcommit.cpp` (display concern).

### 3.4 V-table collection / collapse *(direct lift)*

`collectVtables` and `collapseSiblingVtables` in `crcommit.cpp` are
domain-agnostic once you accept regions + a `SymbolResolver`. V8 itself
doesn't ship vftables for its internal objects (V8 objects are tagged via
`Map*`, not vptrs), but Blink renderer dumps with the V8 cage scanned for
vtables would still be useful (e.g. embedder-owned wrappers in
`v8::Object::Wrappable` slots). At minimum it stops cluttering
`crcommit.cpp`.

**Proposed:** `src/lib/vtable_collector.{hpp,cpp}` with `VtableEntry`,
`collectVtables`, `collapseSiblingVtables`. The two `printVtables` overloads
(currently one) stay in `crcommit.cpp`.

### 3.5 Top-N / accounted aggregator *(small)*

Both `printVtables` and `printOilpanClasses` compute the same shape:
`total_bytes = sum(count*size); accounted% = total/heap_committed; top N
sorted by either size or count`. The future `printV8Classes` will too.

**Proposed:** a tiny helper next to the printers, e.g.
```cpp
template <typename Row>
struct TopNView {
    std::vector<Row> rows;        // already sorted; first `shown` are visible
    size_t           shown;
    uint64_t         total_bytes; // sum across ALL rows, not just shown
};
```
Worth doing once we have three call sites; not yet.

### 3.6 Page-layout discovery helper *(judgment call, defer)*

`discoverPageLayout` in `oilpan_objects.cpp` runs N `typeSize` /
`fieldOffset` lookups and returns a struct. V8 will do the same with many
more fields (Map, HeapObject, MemoryChunk, PageMetadata, NewSpace, ...).
The pattern is "fail-loudly batch", but each domain's struct is bespoke.
**Recommendation:** keep per-domain layout structs; do not over-abstract.

### 3.7 Heap-walker / object-iteration interface *(defer)*

`walkOilpanObjects` walks a page-tagged region and yields per-object stats.
V8 has the same shape (page → object iteration → aggregate). It would be
tempting to define an abstract `HeapWalker` interface, but the per-object
decoding is so domain-specific (HeapObjectHeader bit-layout vs Map*-tagged
header) that the only thing they would share is the outer aggregation loop.
**Recommendation:** keep them parallel; revisit if a third heap appears.

---

## 4. Suggested order of work

1. Land **3.1 (committed regions in range)** and **3.2 (`readGlobal<T>`)** as
   pure refactors. Reduces `oilpan_heap.cpp` and gives V8 work an immediate
   foundation.
2. Land **3.3 (string scanner)** and **3.4 (vtable collector)** as pure
   refactors. Slims `crcommit.cpp` and prepares it for V8 sections.
3. Add **`v8_heap.{hpp,cpp}`** — `V8Heap::discover` resolves the
   pointer-compression cage base from
   `v8::internal::IsolateGroup::default_isolate_group_` (or
   `V8HeapCompressionScheme::base_`), captures its committed regions via 3.1,
   and exposes the same surface as `OilpanHeap`. Wire `printSummary` to
   handle either kind.
4. Add **`v8_isolate.{hpp,cpp}`** — given the cage, walk to one or more
   `Isolate`s, enumerate `heap_->space_[...]` (NewSpace / OldSpace /
   LargeObjectSpace / CodeSpace / TrustedSpace / ReadOnlySpace / shared\_\*),
   and capture each space's page-list head + per-space byte counters.
5. Add **`v8_objects.{hpp,cpp}`** — per-space page walk; for each live object,
   read the `Map*` from word 0 of the body, follow it to read
   `instance_type` / `instance_size`, aggregate. Class names come from
   resolving the Map's address to its symbol (or from a static InstanceType
   enum table if the class name is too generic).
6. Wire it all into `crcommit.cpp` printers (`printV8Spaces`,
   `printV8Classes`, etc.) and a `--v8` / `--no-v8` flag pair. The cross-cage
   string and vtable scans run once per cage.

---

## 5. Out of scope for this refactor

- Off-cage V8 attribution (ArrayBuffer backing stores, WASM memories, zone
  arenas). These don't have a fixed virtual reservation we can intersect; they
  require walking heap objects to find their owner records. Worthwhile, but
  builds on top of step 5 above and is its own milestone.
- DbgHelp performance work beyond the existing module-range pre-filter and
  vtable-size cache.
- Multi-isolate enumeration policy (workers, service workers): start with the
  main isolate; design a list-based enumeration once we have it working.
