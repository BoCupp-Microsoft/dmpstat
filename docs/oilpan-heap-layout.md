# Oilpan / cppgc heap layout (for crcommit)

This document captures the facts about Oilpan / `cppgc` that `crcommit` relies on to identify which pages of a captured Chromium-renderer dump belong to the Oilpan garbage-collected heap. It is intentionally narrow: the goal is to enable **principled, symbol-anchored identification** of Oilpan committed memory from a dump, not to document cppgc as a whole.

All section references below are to the V8 source tree at `https://github.com/v8/v8/tree/main/`. Paths are relative to that root unless noted. Verified against `main` on 2026-04-26.

---

## 1. What "Oilpan" is in modern Chromium

Oilpan is the Blink-facing name for **`cppgc`**, the V8 tracing GC for C++ objects. The implementation lives in V8:

- Public API: `include/cppgc/`
- Engine:    `src/heap/cppgc/`

Blink wraps cppgc in `third_party/blink/renderer/platform/heap/` (`ThreadState`, `HeapAllocator`, `Member<T>`, etc.). A renderer process has at minimum the main thread's `cppgc::Heap`, plus one per worker thread.

Crucially for us, **all cppgc heaps in the process share a single process-wide reservation** when caged-heap mode is enabled (see §3), which gives us a single anchor to identify every Oilpan byte in the dump regardless of how many isolates / worker threads exist.

---

## 2. Page model

`src/heap/cppgc/globals.h`:

```cpp
constexpr size_t kPageSizeLog2 = 17;
constexpr size_t kPageSize = 1 << kPageSizeLog2;          // 128 KiB
constexpr size_t kPageOffsetMask = kPageSize - 1;
constexpr size_t kPageBaseMask = ~kPageOffsetMask;
constexpr size_t kLargeObjectSizeThreshold = kPageSize / 2;  // 64 KiB
```

Two page kinds:

- **Normal page**: fixed 128 KiB, base-aligned. Holds many objects; for any interior pointer, `addr & kPageBaseMask` gives the page header.
- **Large page**: one object per page, page-allocator-aligned, sized to the object plus a header. Used for objects whose size exceeds `kLargeObjectSizeThreshold` (64 KiB).

Both kinds begin with a `BasePageHandle` (then `BasePage`) at the page-aligned base. From `include/cppgc/internal/base-page-handle.h`:

```cpp
class BasePageHandle {
 public:
  static V8_INLINE BasePageHandle* FromPayload(void* payload) {
    return reinterpret_cast<BasePageHandle*>(
        reinterpret_cast<uintptr_t>(payload) & ~(api_constants::kPageSize - 1));
  }
  // ...
 protected:
  HeapHandle& heap_handle_;   // first field; pointer to the owning HeapBase
};
```

So **the very first 8 bytes of every cppgc page are a pointer to the owning `HeapBase`**. This is useful for cross-validation: if we suspect a region is Oilpan, the first qword of each 128 KiB-aligned page should point at one of the dump's `HeapBase` instances.

---

## 3. Caged heap

This is the central fact we exploit.

### 3.1 What "caged" means

When `CPPGC_CAGED_HEAP` is defined, the cppgc engine reserves **one large, naturally-aligned virtual range — the "cage"** — at process startup, and allocates *every* Oilpan page from inside that cage via a `v8::base::BoundedPageAllocator`. There is **one cage per process**, shared by every cppgc `Heap` (main thread, workers, isolates).

`CPPGC_CAGED_HEAP` is **on** for Chromium on 64-bit, including Windows. It is the configuration that ships in stable Chrome, Edge, and the WebView2 runtime.

### 3.2 Cage size

`include/cppgc/internal/api-constants.h`:

```cpp
constexpr size_t kCagedHeapDefaultReservationSize =
    static_cast<size_t>(4) * kGB;

#if defined(CPPGC_POINTER_COMPRESSION)
constexpr size_t kCagedHeapMaxReservationSize =
    size_t{1} << (31 + kPointerCompressionShift);
#else
constexpr size_t kCagedHeapMaxReservationSize =
    kCagedHeapDefaultReservationSize;
#endif

constexpr size_t kCagedHeapReservationAlignment = kCagedHeapMaxReservationSize;
```

with `kPointerCompressionShift` = 1 by default and 3 with `CPPGC_ENABLE_LARGER_CAGE`. Effective sizes:

| build flags | `kCagedHeapMaxReservationSize` |
|---|---|
| no `CPPGC_POINTER_COMPRESSION`               | 4 GiB  |
| `CPPGC_POINTER_COMPRESSION` (default)        | 4 GiB  |
| `CPPGC_POINTER_COMPRESSION` + larger cage    | 16 GiB |

Recovering the cage size from the dump without guessing build flags: the engine also exposes the on-cage "age table" size via `CagedHeapBase::g_age_table_size_`. From the AgeTable definition in `include/cppgc/internal/caged-heap-local-data.h`:

```cpp
static constexpr size_t kCardSizeInBytes =
    api_constants::kCagedHeapDefaultReservationSize / kRequiredSize;  // = 4096
static constexpr size_t CalculateAgeTableSizeForHeapSize(size_t heap_size) {
  return heap_size / kCardSizeInBytes;
}
```

so when `CPPGC_YOUNG_GENERATION` is enabled (which it is in Chromium),

```
cage_size_bytes = CagedHeapBase::g_age_table_size_ * 4096
```

This avoids any dependency on which Chromium build flavour produced the dump.

### 3.3 Cage base

`include/cppgc/internal/caged-heap.h`:

```cpp
class V8_EXPORT CagedHeapBase {
 public:
  V8_INLINE static bool IsWithinCage(const void* address) {
    CPPGC_DCHECK(g_heap_base_);
    return (reinterpret_cast<uintptr_t>(address) &
            ~(api_constants::kCagedHeapReservationAlignment - 1)) ==
           g_heap_base_;
  }
  V8_INLINE static uintptr_t GetBase() { return g_heap_base_; }
  V8_INLINE static size_t GetAgeTableSize() { return g_age_table_size_; }

 private:
  static uintptr_t g_heap_base_;
  static size_t    g_age_table_size_;
};
```

So **the cage base is a single 8-byte global** at symbol `cppgc::internal::CagedHeapBase::g_heap_base_`. The age-table size sits next to it at `cppgc::internal::CagedHeapBase::g_age_table_size_`.

Both are linked into whichever module embeds cppgc — for renderer processes that's `v8.dll` / `chrome_elf.dll` / `msedgewebview2.dll` depending on the build packaging.

### 3.4 Windows-specific quirk

`src/heap/cppgc/caged-heap.cc`:

```cpp
#if !defined(LEAK_SANITIZER) && !defined(V8_OS_WIN)
constexpr bool kUnmapSubregions = true;
#else
constexpr bool kUnmapSubregions = false;
#endif
```

In `CPPGC_POINTER_COMPRESSION` builds the engine over-reserves `2 × kCagedHeapMaxReservationSize` and selects the half whose "masked-out LSB" is set, so that compressed pointers always sign-extend with the high bit. On non-Windows it then frees the unused half; **on Windows the unused half stays reserved** (but uncommitted).

Consequence for `crcommit`: the *committed* Oilpan pages in the dump all live in `[g_heap_base_, g_heap_base_ + kCagedHeapMaxReservationSize)`, which is exactly the half we want. We do not need to reason about the over-reservation.

---

## 4. Identifying Oilpan committed memory in a dump

### 4.1 Algorithm

```
1.  Initialize SymbolResolver against the dump.
2.  global = findGlobal(L"cppgc::internal::CagedHeapBase::g_heap_base_")
            or fallback name matches.
3.  cage_base = read<uint64_t>(dump_memory, global.address)
    cage_size = read<uint64_t>(dump_memory,
                  findGlobal(L"cppgc::internal::CagedHeapBase::g_age_table_size_"))
                * 4096
4.  cage_end = cage_base + cage_size
5.  For each COMMIT/PRIVATE region R from MemoryInfoListStream:
        let R' = R ∩ [cage_base, cage_end)
        if R' is non-empty:
            attribute |R'| bytes to "Oilpan"
6.  Sum and report.
```

The intersection step matters because the cage VA range itself is *reserved*; only a subset is committed at any moment.

### 4.2 Optional cross-checks

For extra confidence (later phases, not required for `--summary`):

- **Page-header pointer**: for each 128 KiB-aligned page in the intersection, the first 8 bytes should point at a `HeapBase` instance. Roll up the distinct heap-handle values to count cppgc heaps in the process (= main thread + N workers).
- **AgeTable consistency**: the age table itself lives at the start of the cage as `CagedHeapLocalData`. Reading it should yield mostly `Age::kOld` / `kYoung` / `kMixed` byte values — useful as a sanity check on the cage base.

### 4.3 Failure modes to plan for

- **Symbol not found.** Public-only / stripped PDBs may not export internal cppgc statics. Mitigation: (a) try both undecorated and decorated forms; (b) probe with broad masks (`*CagedHeapBase*`) when the exact name fails; (c) fall back to scanning v8.dll's `.bss`/`.data` for a 4-GiB-aligned non-zero qword followed by a small (<10⁷) qword that, when multiplied by 4096, yields a power-of-two ≥ 4 GiB. This is *not* a region heuristic — it identifies the cage, not the pages.
- **Symbol resolves but value is 0.** Cage not yet initialized at dump time. We should report "Oilpan: cage not initialized" rather than silently classify zero bytes.
- **Multiple v8 modules** (e.g. v8.dll plus a side-loaded copy). Should not happen in renderers but we should detect duplicates and warn.

---

## 5. Out of scope for this iteration

The following are deliberately deferred to later phases — listed here so the doc reflects the full Oilpan picture as we'll eventually need it.

- **Per-heap / per-space / per-page enumeration** via `HeapBase → RawHeap → BaseSpace[] → BasePage` lists. Required for bytes-live-per-space reporting (Phase 3).
- **`HeapObjectHeader` decoding** (encoded `GCInfoIndex`, size, mark bit) and the `GCInfoTable` walk for type-name resolution (Phase 4 — the headline coverage win for Oilpan).
- **`BasePageHandle::heap_handle_` cross-tagging** of the cage to separate main-thread vs worker-thread bytes.
- **Non-caged builds** — would require walking `blink::ThreadState::main_thread_state_` and a per-thread / process heap registry. Not relevant for stable Chromium Win64 today.

---

## 6. Symbol names cheat-sheet

| What | Demangled name | Type |
|---|---|---|
| Cage base | `cppgc::internal::CagedHeapBase::g_heap_base_` | `uintptr_t` |
| Age table size | `cppgc::internal::CagedHeapBase::g_age_table_size_` | `size_t` |
| Cage singleton | `cppgc::internal::CagedHeap::instance_` | `CagedHeap*` |
| Page size constant | `cppgc::internal::kPageSize` | `size_t` (128 KiB) |
| Default reservation | `cppgc::internal::api_constants::kCagedHeapDefaultReservationSize` | `size_t` (4 GiB) |
