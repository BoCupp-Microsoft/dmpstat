# V8 isolate heap layout

Reference for analyzing V8 memory consumption in Chromium minidumps. Companion
to [memory-investigation-playbook.md](memory-investigation-playbook.md). Same
mental model as the Oilpan (cppgc) analysis in `crcommit`: identify the virtual
reservations, enumerate per-page metadata, attribute committed bytes to
purposes.

V8 uses **isolates** (`v8::Isolate` ≈ a self-contained JS VM instance: heap, GC,
stacks, root tables). In Chromium each renderer process has one *main* isolate
plus one isolate per Worker / ServiceWorker thread. Almost everything below is
**per-isolate** unless flagged "shared" or "process-wide".

The memory falls into **two big buckets**: the GC-managed heap (lives inside
one or more virtual reservations called *cages*), and *off-cage* allocations
(zones, backing stores, external strings, etc.).

---

## 1. Virtual reservations (the "cages")

V8 makes a few large `VirtualAlloc` reservations up front. They show up in
`!address` as `MEM_RESERVE` regions; only the committed pages count against
private commit. Each is the V8 analogue of the cppgc cage.

| Reservation | Size (default) | Purpose | Symbol |
|---|---|---|---|
| **Main pointer-compression cage** | 4 GiB | Holds all "compressible" V8 heap objects (new/old/large/etc.) so a 32-bit "compressed pointer" plus a per-isolate base reaches every JS object. One per isolate by default; with `--shared-pointer-compression-cage` (Chromium's default) one per **process** shared by all isolates. | `v8::internal::IsolateGroup::default_isolate_group_` ; cage base accessible via `V8HeapCompressionScheme::base_` |
| **Code range / code cage** | 128 MiB (Win, configurable) | Executable code (JITted Builtins, Ignition handlers, Sparkplug/Maglev/TurboFan output, regexp). Separate so all code is within ±2 GiB for PC-relative jumps and to give it `PAGE_EXECUTE_READ` perms. Process-wide with the shared cage. | `v8::internal::CodeRange` |
| **Trusted space cage** (V8 sandbox build) | up to 1 TiB | "Trusted" objects (`BytecodeArray`, `Code` metadata, dispatch tables, anything an attacker corrupting the sandbox heap mustn't be able to forge). Lives **outside** the sandbox so a UAF inside the sandbox can't reach it. | `v8::internal::TrustedRange` |
| **Sandbox cage** (V8 sandbox build) | 1 TiB virtual | The whole pointer-compression cage relocated inside a 1 TiB sandbox; all "untrusted" pointer-compressed accesses are bounded to it. | `v8::internal::Sandbox::base_` |
| **External pointer table / trusted pointer table / code pointer table** | a few MiB | Indirection tables that turn small handles in heap objects into raw pointers / external addresses. Per-isolate (or shared). | `IsolateGroup::external_pointer_table_` etc. |
| **Embedded blob** (read-only) | ~5–10 MiB | Pre-built builtins compiled into the binary, mapped from the executable image. Shared, not on private commit. | `v8_Default_embedded_blob_*` |
| **Read-only space** | ~few MiB | Roots/maps/empty arrays etc. that never change. Mapped shared between isolates in a process. | `Heap::read_only_space_` |

The **inside-the-cage heap** is then carved into 256 KiB-ish *pages*
(`v8::internal::MemoryChunk` / `PageMetadata`), each tagged with a *space*.

---

## 2. The GC-managed spaces (inside the main cage)

Each space has its own allocator, GC strategy, and live/free accounting.
`v8::Isolate::GetHeapSpaceStatistics()` enumerates them.

| Space | Generation / GC | What's in it |
|---|---|---|
| **`new_space`** (a.k.a. young gen / nursery) — two semispaces | Scavenger (copying GC), high churn | Freshly allocated JS objects, short-lived arrays/strings |
| **`old_space`** | Mark-Sweep / Mark-Compact (full or incremental, often concurrent) | Survivors promoted from new_space; long-lived JS objects |
| **`large_object_space` (LO space)** | Mark-Sweep, never moved | Single objects ≥ ~512 KiB (long strings, big TypedArrays, big regexps) |
| **`new_large_object_space`** | Same | Newborn large objects |
| **`code_space`** (lives inside the **code cage**, not the main cage) | Mark-Sweep with code-specific compaction | `Code` (machine-code) objects |
| **`code_lo_space`** | Mark-Sweep | Oversized code objects |
| **`shared_space` / `shared_lo_space`** *(when shared-heap enabled)* | One per **process**, shared by isolates | `SharedArrayBuffer` slots, internalized strings shared across isolates, shared structs |
| **`trusted_space` / `trusted_lo_space`** *(sandbox build)* | Mark-Sweep | `BytecodeArray`, `InterpreterData`, `Script` metadata, dispatch tables, anything the sandbox mustn't forge |
| **`read_only_space`** | Never collected | Immutable roots, well-known maps/heap numbers, empty fixed arrays |

(Historic: *map_space* — folded into `old_space` in modern V8.)

Each page also carries **GC metadata** that adds non-trivial overhead and is
real committed memory:

- **Marking bitmap** (1 bit per 8-byte aligned slot ⇒ ~1.5% of page bytes)
- **Slot sets** (`OLD_TO_NEW`, `OLD_TO_OLD`, `OLD_TO_SHARED`, `OLD_TO_CODE`,
  `TRUSTED_TO_TRUSTED`, …) — remembered-set bitmaps used by write barriers
- **Typed slots / invalidated slots**
- **Free list**: linked lists of free chunks within the page
- **Page header** (`MutablePageMetadata` / `MemoryChunkLayout`) at the start of
  each page — owner space, flags, age marker, mutex, allocation watermarks,
  LAB, …
- **Linear Allocation Buffer (LAB) tail** — same concept as Oilpan: bump
  allocator's unused tail at the end of the current page

---

## 3. Off-cage / external memory

Stuff that V8 manages but doesn't (always) live in the cage. These hit
`malloc`/PartitionAlloc and show up as ordinary process commit.

| Category | Owner / API | Notes |
|---|---|---|
| **Zone arenas** (`v8::internal::Zone`, `AccountingAllocator`) | Bump-arena allocator scoped to a task | Used by parser, regex compiler, **TurboFan**, **Maglev** during compilation. TurboFan jobs can transiently allocate **tens of MiB**. Released wholesale on Zone destruction. |
| **ArrayBuffer / SharedArrayBuffer backing stores** | `v8::ArrayBuffer::Allocator` (in Chrome: `gin::ArrayBufferAllocator` → PartitionAlloc) | Big. User code can allocate arbitrary bytes here. Tracked as "external memory". The JS object is small and on-heap; the bytes are off-heap. |
| **External strings** (`ExternalString`) | Embedder-owned char buffer | The on-heap object holds only a pointer; text bytes are off-heap (e.g. V8 wraps Blink-owned `WTF::String` data without copying). |
| **WebAssembly memories** | `WasmMemoryObject`, allocated as huge `VirtualAlloc` with guard pages | Each `WebAssembly.Memory` is a separate reservation (usually 4–10 GiB reserved with small commit). |
| **WebAssembly module code** | `wasm::NativeModule` | Lives in its own per-module code space (executable), not in `code_space`. |
| **Ignition bytecode** | `BytecodeArray` (on heap, in `trusted_space` when sandbox is on) | Per compiled JS function; survives until the SFI is collected. Often a major contributor for big apps. |
| **Feedback vectors / IC state** | `FeedbackVector` (on-heap `old_space`) | Inline-cache state; grows with executed code. |
| **Compilation cache** | `CompilationCache` | Caches parsed/compiled scripts to skip re-parsing. |
| **Optimized-code metadata** | `DeoptimizationData`, source-position tables | Per optimized function. |
| **HandleScopes / persistent handles** | `HandleScopeImplementer` | Small but per-thread; matters for renderer with many handles. |
| **Stack(s)** | One JS stack per thread + native stack | Renderer's main thread + background-compile thread + GC helper threads. |
| **Inspector / DevTools state** | `V8InspectorImpl` | Only when DevTools is attached or Heap Profiler is on. |
| **CPU profiler / sampling buffers** | When `--prof` / `console.profile` is on | |

---

## 4. Per-isolate fixed structures

Mostly pointed at by `v8::internal::Isolate*`. Useful to enumerate one-shot
from a dump:

- **`Isolate` struct** itself (~100 KiB; thread roots, microtask queue,
  optimizing-compile dispatcher, deoptimizer, regexp stack, …)
- **Roots table** (`isolate->roots_table_`) — a fixed-size array of strong refs
  to ~1000 well-known on-heap objects
- **Builtins table** (offsets into the embedded blob)
- **Microtask queue** (per context)
- **NativeContexts** / Contexts — one per realm; in Chrome each frame's main
  world + isolated worlds
- **OptimizingCompileDispatcher** + Maglev/TurboFan job queues
- **GC scheduler / background thread state**
- **External-pointer / trusted-pointer / code-pointer tables** (see §1)

---

## 5. Where to look in a Chromium dump (analyst's checklist)

For the kind of analysis `crcommit` does for cppgc, the tractable handholds
are:

1. **Find the main cage base.** Look up
   `v8::internal::IsolateGroup::default_isolate_group_` then walk to
   `pointer_compression_cage_`, or use the static
   `V8HeapCompressionScheme::base_`. Cage size is fixed at 4 GiB. Page
   granularity is `kPageSize` (256 KiB on 64-bit normally; check
   `v8::internal::MemoryChunkLayout` from the PDB).
2. **Find the Isolate(s).** Walk `Isolate::isolate_root_` from cage base, or
   enumerate from the per-thread `v8::internal::Isolate::TryGetCurrent()` TLS.
   From there: `heap_->space_[kNewSpace..kReadOnlySpace]`.
3. **Walk pages per space.** Every space has a `memory_chunk_list_` of
   `PageMetadata`. Each page's header gives the space owner, `allocated_bytes`,
   `wasted_memory` (LAB tail), `live_bytes_at_last_gc`.
4. **Enumerate live objects** by scanning page payload guided by the marking
   bitmap + map pointers (every heap object's first word is a `Map*` whose
   `instance_type` and `instance_size` give you class identity and size — V8's
   analogue of cppgc's GCInfoTable). This is essentially what
   `--trace-gc-object-stats` produces.
5. **Code range** is its own reservation. Code pages have an
   `InstructionStream` + `Code` pair you can walk for "where did all the code
   go" tables (per-function size).
6. **Off-cage allocations** are harder — no central registry. Best you can do
   for ArrayBuffers is `Heap::array_buffer_sweeper_` (a list of all live
   `ArrayBufferExtension`s and their backing-store sizes). For WASM memories
   you'd walk `WasmMemoryObject`s on the heap and read the backing-store size
   out of each. For zones in flight, there's no easy enumerator — they're
   transient by design.
7. **Read-only and embedded blob** are mapped, not private — usually negligible
   for private-commit attribution, but useful to *exclude* so you don't confuse
   them with real growth.

---

## 6. TL;DR — likely categories to surface for a future `crv8`

In rough order of "most likely to be the culprit" in a real growth
investigation:

1. **Old-space live objects** broken down by `Map.instance_type` / class name
   (the V8 analogue of the cppgc class table).
2. **ArrayBuffer backing stores** (sum of
   `ArrayBufferExtension::accounting_length_`).
3. **WebAssembly memory + code**.
4. **`code_space` + WASM code** — JIT footprint.
5. **Bytecode** (`BytecodeArray` in `trusted_space`).
6. **External strings' off-heap byte total**.
7. **Free space inside pages** (LAB tail + free lists) — fragmentation.
8. **Per-page GC metadata** (slot sets/bitmaps).
9. **Zones** (transient; only visible if dumped mid-compilation).
