# Memory Investigation Playbook

Field notes for interpreting `crcommit` output and tracking down memory growth in
Chromium/Edge minidumps. Each entry is a short, repeatable tip — not a tutorial.

## Class meanings

### `v8::Object::Wrappable`

The cppgc-managed bridge V8 allocates for every C++ object exposed to JavaScript
(Blink `Node`, `Element`, `Event`, `DOMTimer`, `Resource`, etc.). It holds the
type tag and the back-pointer that ties a `v8::Object`'s internal field to its
C++ owner.

- One Wrappable per JS-visible C++ object → its `Count` is roughly the number
  of JS-exposed Blink objects in the renderer.
- Per-instance size is small (~96–100 B); it's an indirection record, not a
  payload.
- Almost always at or near the top of the Oilpan classes table because it is
  cross-cutting (not tied to one feature).
- Treat it as a **symptom, not a cause**: when it grows, the underlying leak
  shows up under the real DOM class names further down the table
  (`blink::HTMLImageElement`, `blink::DOMTimer`, `blink::Resource`, …).
- If Wrappable count grossly exceeds the sum of likely-wrappable named classes
  in the table, suspect a wrapper-side leak (JS reference keeping C++ alive).
- Confirm layout in windbg with `dt msedge!v8::Object::Wrappable`.

### `blink::Resource`

The cppgc-managed base class for every cached network resource in Blink.
Common concrete subclasses (visible in the v-tables table):

- `blink::ImageResource` — encoded/decoded image data
- `blink::ScriptResource` — JS files
- `blink::CSSStyleSheetResource` — stylesheets
- `blink::FontResource` — web fonts
- `blink::RawResource` — XHR/fetch responses, media segments, etc.

A `Resource` instance owns *metadata* (URL, MIME type, response headers, cache
policy, encoded/decoded byte counts, observers) and a handle to its backing
buffer. The **buffer itself lives outside Oilpan** (PartitionAlloc-managed
`SharedBuffer`/`SegmentedBuffer`), so the bytes attributed to `blink::Resource`
in the Oilpan classes table reflect bookkeeping only — actual resource content
cost is much higher.

- High `Count` ⇒ `MemoryCache` and `ResourceFetcher`-keepalive lists holding
  many cached items. Often dominated by long-lived images and scripts.
- Growing count across dumps suggests cache pressure or cache-key bloat.
- To break down by subtype, look at the v-tables table — `blink::ImageResource`,
  `blink::ScriptResource`, etc. each get their own row there.

## Allocation-shape concepts

### LAB tail

LAB = **Linear Allocation Buffer**. cppgc gives each thread/space a small
contiguous slab carved out of a NormalPage and bumps a pointer to allocate.
When the page is sealed (e.g., at the moment of the dump), the unused bytes
between the bump pointer and the page-payload end are the **LAB tail**.

`crcommit` reports them inside the `Unaccounted (LAB tail / page header /
rounding)` line of the Oilpan objects section.

- Detected per NormalPage: walk `HeapObjectHeader`s starting at
  `PayloadStart`; bail at the first zero-encoded header; everything from
  there to `PayloadEnd` is LAB tail.
- Treated as committed-but-neither-live-nor-free — wasted from an
  allocation-shape perspective.
- A few percent is normal. A large share suggests many partially-filled
  pages — a fragmentation signal worth investigating.

## V8 isolates

### Per-isolate OS thread (Win32 tid)

`v8::internal::Isolate` does not store a Win32 thread id anywhere — its
internal `thread_id_` field is V8's monotonic `ThreadId` counter, useful
only inside V8. To recover the OS tid that owns each isolate, locate
V8's `g_current_isolate_` `thread_local` variable and read it on every
captured thread.

- Each thread's TEB at `+0x58` holds `ThreadLocalStoragePointer`, an
  array of pointers to per-module static-TLS blocks.
- Score every (slot index, byte offset) candidate by the number of
  distinct threads whose value at that location is a known isolate
  pointer; invalidate any candidate where two threads point to the same
  isolate (a true `thread_local` is per-thread, never shared).
- The highest-scoring valid candidate is V8's `g_current_isolate_`.
  Reading one qword per thread there yields the OS tid that owns each
  isolate.
- Cross-reference the tid with `MINIDUMP_THREAD_NAMES_STREAM` to derive
  the isolate type from Chromium's standard thread-name prefixes:
  `CrRendererMain` → Main, `DedicatedWorker thread` → DedicatedWorker,
  `SharedWorker thread` → SharedWorker, `ServiceWorker thread` →
  ServiceWorker.
- A naive "first qword in any TLS block matching an isolate" scan is
  unreliable: Chromium keeps a process-wide registry of isolates inside
  one thread's TLS (often the Compositor thread), so a single thread
  can appear to own every isolate.

