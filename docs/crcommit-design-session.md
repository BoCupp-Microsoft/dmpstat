# `crcommit` Design Session

A working journal of the design discussion and Phase 1/2 implementation
for `crcommit`, a Chromium-aware private-commit analyzer for Windows
minidumps in the `dmpstat` tool suite.

---

## 1. Motivation

`segments` already shows *where* private commit lives in the address
space of a captured Windows process. It can tell you that a renderer has
~868 MB of `COMMIT/PRIVATE/RW-/---` regions — but not what the bytes
actually represent. `crcommit` is the next step: bucket private commit
by allocator family, then by allocator-internal sub-bucket, then (where
possible) name individual objects down to their C++ class.

Target: Chromium **renderer** processes (Chrome stable + WebView2 — they
share allocator and heap layout). Reference source for layout details:
[`cs.chromium.org`](https://source.chromium.org/chromium). No local
checkout required for v1.

---

## 2. Identifying Object Types — Coverage Analysis

The user's framing question: **even with a dump, symbols, and knowledge
of allocator internals, we don't record exactly what type of object a
piece of memory is unless it has a vtable or some other identifying
characteristic. How much of Chromium can we cover with that
"object-tag" approach?**

The answer turns out to be: a lot, *if* we generalize "tag" beyond just
vtables.

### Tier 1 — Cheap & high-coverage tags (~60–75% of identifiable objects)

**1. C++ vtables.** Any class with a virtual function has a vtable
pointer in slot 0. Vtables live in `.rdata` of a known module, and
DbgHelp can resolve `vtable_va → "blink::HTMLDivElement::``vftable'"`.

- Blink DOM, layout, style, loaders, network: nearly 100% — Blink leans
  hard on virtual interfaces.
- Chromium content/, services/, components/: high — Mojo bindings,
  observers, KeyedServices are all virtual.
- `base::RefCounted` hierarchies: high.
- V8 / cppgc internals: low — V8 deliberately avoids virtual dispatch
  in hot paths.

This single tagger probably gives the biggest single payoff. Validate by
checking the vtable is at instance-aligned slot 0 of an object.

**2. V8 Map pointers.** Every V8 heap object has its `Map*` in slot 0
(compressed in pointer-compression builds, ±4 GB cage). Maps live in
`read_only_space` and have well-known instance types. Procedure:
- Find the cage/isolate (heuristics or symbol).
- Enumerate the Map → InstanceType table once.
- For every aligned slot in V8 pages, decompress the tagged pointer in
  slot 0; if it resolves to a known Map, the object's V8 type
  (`JS_OBJECT_TYPE`, `STRING_TYPE`, `FIXED_ARRAY_TYPE`, etc.) is named.

Covers **~100% of V8 heap objects** — Map-tagging is structural.

**3. cppgc/Oilpan `GCInfoIndex`.** Every Oilpan `HeapObjectHeader` has a
14-bit `GCInfoIndex` indexing a per-process `GCInfoTable` that stores
type-name strings (used by Blink heap-dump infra). Resolves type name
for **~100% of Oilpan-managed objects**.

### Tier 2 — Moderate coverage (~15–25% more)

**4. PartitionAlloc bucket size + tag bits.** Slots are just
`(size, alignment)` buckets, but:
- Bucket size alone is informative ("117 MB in 32-byte slots").
- *Caller-site* tags (typed partitions: `Partitions::ArrayBufferPartition()`,
  `BufferPartition()`, `LayoutPartition()`). The root identifies the
  partition; we walk roots from symbols.
- In-slot debug headers (BRP ref-count, freeslot bitmap) confirm
  partition affinity in non-official builds.

PartitionAlloc itself doesn't name objects, but bucket+root tagging
yields "this is a 64 MB Blink-layout-partition slot region of 32-byte
objects" — plenty actionable.

**5. WTF::AtomicString, base::FilePath, std::string SSO buffers.**
Strings have recognizable shapes (length prefix + ASCII or UTF-16 byte
distribution). A statistical scanner can flag "this 8 MB region is
dominated by short ASCII strings → likely AtomicString table."

**6. Sentinel values.** PartitionAlloc freelist pointers are
XOR-obfuscated with a per-partition constant (the obfuscation key
itself is identifiable), V8 uses `kFreeListNullPtr`, etc. These help
label *free* slots vs live slots within a slot span.

**7. Thread stacks.** TEB/stack-base info is in `ThreadListStream` —
trivially identifiable. Easy 5–15 MB win.

### Tier 3 — Hard or genuinely opaque (~15–25% unidentifiable)

**8. POD allocations with no vtable / no embedded tag.** `std::vector`
backing buffers, `SkBitmap` pixel storage, `media::AudioBus` samples,
decoded image bitmaps, network buffer pools, ICU dictionary data.
Recoverable only by walking back to the *owning* object that holds the
pointer (see "back-references" below).

**9. Thread-local arena allocations.** Reachable only via
`Teb->ThreadLocalStorage` and a module's TLS index. Doable but expensive.

**10. Mojo message buffers, IPC scratch.** Transient; often tagged by
allocator (e.g., `IpcPartition`) but not by message type.

### Refinements to the "object tag" idea

**Function-pointer tags (the user's idea, generalized).** Many tagless
structs hold a pointer to a static `*Traits` table — a `vtable`-equivalent
for non-virtual classes (e.g., Skia's `SkRefCntBase` derivatives,
`mojo::InterfacePtr` thunks, `base::OnceCallback`'s
`BindStateBase::polymorphic_invoke_`). Symbol resolution names the trait
which names the type. Significant subset of "tagless C++."

**Back-reference closure.** Once tier-1/2 names a *containing* object,
follow its non-null pointer fields and label what they point to as
`<Owner>::<field-name>` even if the pointee is opaque bytes. PDB type
info gives field offsets and types. This is how WinDbg `dt`/`dx` work.
- Chains naturally from any v-tabled root.
- Limited only by PDB completeness and pointer-compression decoding.
- This is where DIA SDK / `SymGetTypeInfo` pays off.

**Module-section attribution.** Even before object identification, every
pointer can be classified as "into module X's `.text`/`.rdata`/`.data`"
or "into private heap region Y." Cheap and informative for sanity-checking.

**Frequency / statistical fingerprints.** A region whose 8-byte slots,
interpreted as pointers, mostly resolve to vftables of class hierarchy
`H` is "a container of `H`s" with high confidence. Catches
`HeapVector<Member<Node>>`, `WTF::HashSet<Element*>`, etc. without
decoding the container header.

**Allocator-page metadata.** PartitionAlloc super-pages and V8
`MemoryChunk`s store live-byte count, freelist head, slot size, and
owning root/space pointer in their headers. Reading these is *free*
once the allocator is identified, and gives authoritative bytes-live
numbers without per-object scanning.

**Known singletons via symbols.** `g_main_thread_state`,
`v8::internal::Isolate::isolate_root_`, `partition_alloc::internal::PartitionRoot`
for each known partition (`fast_malloc`, `array_buffer`, `buffer`,
`layout`). Anchoring from these makes the whole walk deterministic
instead of heuristic.

### Coverage estimate

Combining all tiers and refinements:
- **~40–55% of bytes** named to a specific C++ class (vtables + V8 Maps
  + Oilpan GCInfo + back-references).
- **~25–35% of bytes** named to an allocator/partition/role
  ("ArrayBufferContents storage", "V8 LargeObjectSpace", "thread stack #N").
- **~10–20% of bytes** truly opaque (pixel buffers, decoded media,
  ICU data).

That's already enough to answer "where did 868 MB go" with actionable
specificity (e.g., "412 MB V8 heap, 38% FixedArrays in old space;
180 MB Blink Oilpan, 60% Nodes; 95 MB layout partition; 80 MB images").

---

## 3. Architecture (planned)

### Layered detector with explicit confidence tiers

1. **Region tagger** — classify every `COMMIT/PRIVATE` region by
   allocator family using page-header heuristics, cross-validated by
   symbol-anchored roots when available.
2. **Slot/page enumerator** — walk allocator metadata to enumerate
   live objects with authoritative byte counts.
3. **Object identifier** — chain of taggers per object: V8 Map →
   Oilpan GCInfoIndex → vtable in slot 0 → Traits/function-pointer tag
   → statistical fingerprint.
4. **Back-reference pass** — for objects whose type is known, label
   their non-null pointer fields via PDB type info, naming buffers like
   `Owner::field_name`.
5. **Aggregator + reporter** — group by `(allocator, type-name | role)`
   with bytes/count and per-region drill-down. Text + JSON first; HTML
   report later via the `segments_report.py` pipeline.

### Allocator families detected

- **PartitionAlloc** — 2 MiB-aligned super-pages with guard + metadata
  pages; multiple roots (FastMalloc, ArrayBuffer, Buffer, Layout, ...)
  anchored by symbols.
- **V8 heap** — 256 KiB-aligned `MemoryChunk`s within a per-isolate
  cage; objects identified by Map pointer in slot 0.
- **Oilpan / cppgc** — page-aligned arena pages; `HeapObjectHeader`
  carries a `GCInfoIndex` resolvable via per-process `GCInfoTable`.
- **WinHeap** — process heaps from `ProcessHeapsData` (when present in
  the dump) or NTDLL `_HEAP` walk.
- **Thread stacks** — derivable from `ThreadListStream`.
- **Plain VirtualAlloc** — anything left.

### Source tree layout (planned)

```
crcommit.cpp                  -- CLI11 entry point (mirrors segments.cpp)
mapped_view.{hpp,cpp}         -- existing
symbol_resolver.{hpp,cpp}     -- existing; extended with SymFromName + type-info wrappers
dump_memory.{hpp,cpp}         -- typed reads (read<T>(va), readPointer, readArray)
type_info.{hpp,cpp}           -- DIA/DbgHelp wrappers (SymGetTypeFromName, walk fields)
allocators/
  region_tagger.{hpp,cpp}     -- per-region heuristics + symbol anchors
  partition_alloc.{hpp,cpp}   -- super-page walker, root enumeration
  v8_heap.{hpp,cpp}           -- isolate/cage detection, Map cache, object enumeration
  oilpan.{hpp,cpp}            -- ThreadState walk, GCInfoTable, header decoding
  win_heap.{hpp,cpp}          -- process heap enumeration
identifiers/
  vtable.{hpp,cpp}            -- vtable-in-rdata recognizer
  traits.{hpp,cpp}            -- static-table recognizer
  fingerprint.{hpp,cpp}       -- string/buffer detectors
  backref.{hpp,cpp}           -- typed-field labeler
report/
  text_writer.{hpp,cpp}
  json_writer.{hpp,cpp}
```

Then a follow-on `crcommit_report.py` + `crcommit_report_template.html`
mirroring the segments pipeline.

### CLI surface (proposed)

```
crcommit <dump.dmp> [--sympath PATH] [--top N]
                    [--by allocator|type|module]
                    [--include-stacks] [--include-mapped]
                    [--json] [--verbose]
```

Default output: a sorted table grouped by `(allocator family,
identified type-or-role)` with bytes / region count / live-object count
where available. `--json` emits the same data structurally for the
Python reporter.

---

## 4. Phased delivery

### Phase 1 — Skeleton + region tagger ✅ DONE
- New `crcommit` target in CMakeLists.txt; `stage_dbgeng_redist`.
- `crcommit.cpp` boilerplate: CLI11, `MappedView`, optional
  `SymbolResolver`.
- Walk `MemoryInfoListStream`; for each `COMMIT/PRIVATE` region apply
  heuristic-only allocator tagging.
- Heuristics: cluster by `AllocationBase`, then test each cluster by
  base alignment + reserved-span shape.
- Output: per-allocator-family bytes & region count.
- Validation: ran on `1GBTeamsMainRenderer.DMP`; totals match
  `segments --summary`.

### Phase 2 — Symbol-anchored cross-check 🚧 IN PROGRESS
- Extend `SymbolResolver` with `findGlobal` and a thin type-info layer.
- For each allocator, anchor by symbol where possible:
  - PartitionAlloc roots (`partition_alloc::internal::PartitionRoot`
    instances; FastMalloc/Buffer/ArrayBuffer/Layout partitions).
  - V8 isolate via `v8::internal::Isolate::isolate_root_` /
    per-thread storage.
  - Oilpan via `blink::ThreadState::main_thread_state_`.
- Reconcile heuristic regions with anchored ones; resolve
  disagreements (heuristic wins on missing symbols, symbol wins on
  ambiguity).

### Phase 3 — Slot/page enumeration
- **PartitionAlloc** first (highest impact): walk super-page metadata
  → slot spans → buckets; report per-`(root, bucket-size)` bytes &
  live-slot counts.
- **V8** next: cage discovery, Map table cache, walk pages; report
  per-InstanceType bytes & counts.
- **Oilpan** last in this phase: read `GCInfoTable`, walk arena pages,
  decode `HeapObjectHeader`; report per-cppgc-type bytes & counts.

### Phase 4 — Object identification chain
- vtable identifier (any region; most useful on Oilpan/PartitionAlloc).
- Traits/function-pointer identifier.
- String/buffer fingerprint (cheap statistical detector).
- Wire all of them into a per-object pipeline that stops at the first
  confident hit and records the *tier* used.

### Phase 5 — Back-reference labeling
- For each identified object, walk its PDB-known fields; for each
  pointer field, label the pointee region as `Owner::field` if not
  already named at higher confidence.
- Single pass; skip opaque types and null/invalid pointers.

### Phase 6 — Reporting
- `--json` output schema design.
- `crcommit_report.py` + `crcommit_report_template.html` modeled on
  `segments_report.py`.
- Per-region drill-downs; sortable like the segments report.

### Risks & open questions

- **PDB completeness**: official Chrome/Edge PDBs *do* ship with type
  info for most C++ classes, but inlined templates may collapse types.
  Need to verify against `msedge.dll.pdb` early in Phase 2.
- **V8 pointer compression cage discovery**: cage base lives in the
  isolate; need either symbol or heuristic (256 GiB-aligned reservation).
  Defer to Phase 3.
- **PartitionAlloc layout drift**: layout has changed several times.
  v1 will hardcode for the current Chromium milestone; structural
  decoding via PDB types in v2 if needed.
- **MEMORY64 vs MEMORY**: which streams the dump contains varies by
  `MiniDumpWriteDump` flags; existing `SymbolResolver` already handles
  both.
- **Multi-isolate**: workers each have their own isolate. v1: enumerate
  every isolate found.
- **Performance**: full-dump scans of 1+ GB regions need to be
  I/O-friendly; reuse `MappedView` and avoid per-byte virtual calls.

### Out of scope for v1

- Browser process (different allocator mix; revisit once renderer is
  solid).
- GPU process.
- Live process attach (dump-only, like the rest of the suite).
- Cross-version PDB diffing / Chromium-version auto-detection.

---

## 5. Phase 1 implementation notes

### Files added

- **`dump_memory.{hpp,cpp}`** — random-access typed reader for the
  dump's captured memory. Indexes both `Memory64ListStream` and
  `MemoryListStream`. API:
  ```cpp
  size_t read(uint64_t addr, void* buf, size_t bytes) const;
  template <typename T> std::optional<T> read(uint64_t addr) const;
  bool contains(uint64_t addr, size_t bytes) const;
  ```
  Built so its index is warm before Phase 3 needs it.

- **`crcommit.cpp`** — CLI11 entry, region walker, cluster builder,
  heuristic tagger, text rollup. Flags so far: `--regions`,
  `--include-stacks`, `--debug-allocs`, `--symbols`, `--sympath`,
  `--probe`, `-v`.

### CMake addition

```cmake
add_executable(crcommit
    crcommit.cpp
    mapped_view.cpp
    mapped_view.hpp
    dump_memory.cpp
    dump_memory.hpp
    symbol_resolver.cpp
    symbol_resolver.hpp
    progress.cpp
    progress.hpp
)
target_compile_definitions(crcommit PRIVATE WIN32_LEAN_AND_MEAN UNICODE _UNICODE NOMINMAX)
target_link_libraries(crcommit PRIVATE dbghelp WIL::WIL CLI11::CLI11)
target_compile_options(crcommit PRIVATE /W4 /MP)
set_target_properties(crcommit PROPERTIES LINK_FLAGS "/SUBSYSTEM:CONSOLE")
stage_dbgeng_redist(crcommit)
```

### Heuristic classifier — key insight

The first cut tested per-region alignment (e.g., "is this 256 KiB
aligned?"). That misclassified ~99% of private commit because **V8
doesn't expose 256-KiB-aligned `AllocationBase`s** — it reserves an
entire 4–32 GiB **cage** at a 4 GiB-aligned base and commits chunks
within. Each commit shares the cage's `AllocationBase`.

The fix: a pre-pass aggregates by `AllocationBase` to build per-cluster
metadata (max reserved span, total committed, region count). The
classifier then tests the *cluster's* properties:

```cpp
bool IsV8Cage(uint64_t base, const AllocCluster& c) {
    if ((base & (kV8CageBaseAlignment - 1)) != 0) return false;     // 4 GiB-aligned
    if (c.reserved_span < kV8CageMinSpan) return false;             // ≥ 1 GiB
    return true;
}

bool IsPartitionAllocSuperPageRun(uint64_t base, const AllocCluster& c) {
    if ((base & (kPartitionAllocSuperPageSize - 1)) != 0) return false;  // 2 MiB-aligned
    if (c.reserved_span == 0) return false;
    if ((c.reserved_span & (kPartitionAllocSuperPageSize - 1)) != 0) return false;
    return true;
}
```

### Validation

Run on `1GBTeamsMainRenderer.DMP`:

```
Allocator family rollup (private commit only)
---------------------------------------------------------------
Family                             Bytes     Regions   % Total
---------------------------------------------------------------
V8 Heap                        867.85 MB        2929     93.2%
PartitionAlloc                  42.50 MB          65      4.6%
VirtualAlloc                    19.98 MB         525      2.1%
ThreadStack                      1.12 MB          31      0.1%
---------------------------------------------------------------
Total                          931.45 MB
```

Matches the `segments --summary` private-commit total (~935 MB, mostly
the `COMMIT/PRIVATE/RW-/---` row at 868 MB).

`--debug-allocs` confirms the layout: the top two clusters are
1 GiB-aligned with 4 GiB and 32 GiB reserved spans respectively
(V8 main cage and sandbox/trusted-space cage).

---

## 6. Phase 2 implementation notes (in progress)

### `SymbolResolver` extensions

Added (`symbol_resolver.{hpp,cpp}`):

```cpp
std::optional<uint64_t> findGlobal(const std::wstring& name) const;

struct GlobalHit { std::wstring name; uint64_t address; uint64_t size; };
std::vector<GlobalHit> findGlobalsMatching(const std::wstring& mask,
                                           size_t max_results = 0) const;
```

Implementation wraps `SymFromNameW` and `SymEnumSymbolsW` respectively.

### Symbol-anchored cluster identification

`crcommit` Phase 2 logic:
1. Build `ClusterIndex` (sorted vector of `(base, span)` for fast
   "which cluster contains VA `x`" lookup).
2. For each curated wildcard mask in `kSymbolProbes`, enumerate matching
   globals.
3. For each global, read its 8-byte value. If that value lands inside a
   known cluster, record an anchor `(cluster_base, global_va, ptr_value,
   symbol_name, hint)`.
4. Group anchors by cluster and print.

Curated probe list (current):

```cpp
{ L"*Partitions::*Partition*",                L"PartitionAlloc root (Blink)" },
{ L"*partition_alloc::*g_root*",              L"PartitionAlloc g_root" },
{ L"*PartitionAllocator*allocator_*",         L"PartitionAllocator" },
{ L"*v8::internal::IsolateGroup::*",          L"V8 IsolateGroup" },
{ L"*PointerCompressionCage*base*",           L"V8 cage base" },
{ L"*Sandbox*base_*",                         L"V8 sandbox base" },
{ L"*v8::internal::Isolate::isolate_root*",   L"V8 Isolate root" },
{ L"*blink::ThreadState::*main_thread*",      L"Oilpan main thread" },
{ L"*cppgc::internal::ProcessHeap*",          L"cppgc ProcessHeap" },
{ L"*base::allocator::*",                     L"base::allocator" },
```

### Current status / blocker

First run with the user's standard sympath
(`c:\users\pcupp\downloads\;srv*c:\symbols*https://symweb.azurefd.net;c:\users\pcupp\downloads\anaheim-win32-syms`)
returned **0 hits** for every probe — including very broad ones like
`*Isolate*`, `*PartitionRoot*`, `*ThreadState*`.

Hypotheses to investigate next session:
1. **PDBs not actually loading** for the Chromium DLLs in the dump.
   `-v` should show `[loader] Loaded ... type=Pdb pdb=...` lines for
   `msedgewebview2.dll.pdb` etc.; if they show `type=Export` or
   `type=None` we have no symbols to enumerate.
2. **Chromium PDBs are stripped public-only PDBs** in the WebView2
   distribution, with no symbol records that match wildcard
   enumeration (only `SymFromAddr` works on them).
3. **Symbol path issue** — symweb.azurefd.net may not have these
   particular PDBs; need to point at a local Chromium symbol drop.
4. **`SYMOPT_NO_UNQUALIFIED_LOADS`** is set in `InitializeSymbols` —
   this can suppress some enumeration. Worth trying without it for
   `crcommit` specifically.

The diagnostic `--probe PATTERN` flag is now built into the tool so we
can quickly test patterns interactively once we resolve the symbol
loading issue. Added a debug printout that includes value @ each global
for sanity checking.

### Next steps

1. Resolve the symbol-loading question with `-v` and a known-good
   pattern like `*RtlAllocateHeap*` (which should always match
   `ntdll.pdb`). If `ntdll` enumerates but Chromium DLLs don't, the
   PDBs are public-only / stripped.
2. If Chromium PDBs are stripped, fall back to alternative anchoring:
   - `SymFromAddr` on every entry in the Chromium DLLs' `.text`
     section to get demangled function names; identify allocator
     globals via reference patterns (e.g., functions named `*::root`
     that load from a static address).
   - Disassemble PartitionAlloc allocation entry points (e.g.,
     `partition_alloc::PartitionRoot::Alloc`) and recover the
     `g_root` global address from the code (RIP-relative load).
3. Once anchoring works on at least one allocator, plumb it back into
   the family rollup: anchored clusters get a more specific label
   (e.g., "V8 Heap (main isolate)", "PartitionAlloc (BufferPartition)")
   and are no longer dependent on heuristics.

---

## 7. Open design questions for future phases

These were discussed but deferred:

- **v1 deliverable scope**: bucket private commit by allocator vs
  decode individual objects with type info. (Decision: **layered v1
  covering both**, building incrementally per phase.)
- **Symbol introspection depth**: simple symbol-name lookups vs full
  DIA SDK type traversal. (Decision: **start with DbgHelp wrappers**;
  add DIA-style traversal in Phase 5 when back-reference labeling
  needs it.)
- **Output format**: text first; HTML follows the segments pipeline.
- **Source-tree reference**: user does not have a local checkout;
  `cs.chromium.org` is the reference of record.

---

## 8. Inventory of files touched

### New
- `crcommit.cpp`
- `dump_memory.hpp`, `dump_memory.cpp`
- `docs/crcommit-design-session.md` (this file)

### Modified
- `CMakeLists.txt` — added `crcommit` target
- `symbol_resolver.hpp` — added `findGlobal` and `findGlobalsMatching`
  declarations
- `symbol_resolver.cpp` — implementations of the two new methods
  using `SymFromNameW` and `SymEnumSymbolsW`
