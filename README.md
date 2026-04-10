# WebKit-UAF-ANGLE-OOB-Analysis (CVE-2025-43529, CVE-2025-14174)

Notes and PoC material for a WebKit/ANGLE chain on iOS 26.1. This repo is not a full exploit; it tracks the pieces that are verified and the parts that are still failing.

**Author:** [zeroxjf](https://x.com/zeroxjf)<br>
**Based on:** [jir4vv1t's CVE-2025-43529 exploit](https://github.com/jir4vv1t/CVE-2025-43529)<br>
**Status:** Work in progress — read64/write64 implemented, verification pending<br>
**Test Device:** iPhone 11 Pro Max, iOS 26.1<br>
**Last Updated:** April 2026

---

## Scope and credit

The CVE-2025-43529 UAF trigger, butterfly reclaim, and `addrof`/`fakeobj` primitives are based on **[jir4vv1t's work](https://github.com/jir4vv1t/CVE-2025-43529)**. My additions are the ANGLE OOB plumbing, PAC-focused analysis, and iOS 26.1 validation.

**Note:** AI assisted with probe analysis; findings were manually validated before publication.

---

## Overview

Two WebKit CVEs disclosed together and reported as in-the-wild use by Apple.

| CVE | Component | Type | Summary |
|-----|-----------|------|---------|
| CVE-2025-43529 | JavaScriptCore | Use-After-Free | DFG JIT missing write barrier leads to GC freeing live objects |
| CVE-2025-14174 | ANGLE (GPU) | Out-of-Bounds Write | Metal backend uses wrong height for staging buffer allocation |

---

## CVE-2025-43529: WebKit DFG Store Barrier UAF

### Root Cause

The bug is in JavaScriptCore's DFG JIT, specifically the **Store Barrier Insertion Phase** (`DFGStoreBarrierInsertionPhase.cpp`).

When a **Phi node escapes** but its **Upsilon inputs are not marked as escaped**, later stores miss a write barrier. That allows GC to free objects that are still reachable.

### Trigger Mechanism

```javascript
function triggerUAF(flag, k, allocCount) {
    let A = { p0: 0x41414141, p1: 1.1, p2: 2.2 };
    arr[arr_index] = A;  // A in old space

    let a = new Date(1111);
    a[0] = 1.1;  // Creates butterfly for Date

    // Force GC
    for (let j = 0; j < allocCount; ++j) {
        forGC.push(new ArrayBuffer(0x800000));
    }

    let b = { p0: 0x42424242, p1: 1.1 };

    // Phi node - the bug
    let f = b;
    if (flag) f = 1.1;

    A.p1 = f;  // Phi escapes, but 'b' NOT marked as escaped

    // Long loop = GC race window
    for (let i = 0; i < 1e6; ++i) { /* ... */ }

    b.p1 = a;  // NO WRITE BARRIER - 'a' freed while still reachable
}
```

### Exploitation sketch

The freed Date's butterfly can be reclaimed by spray arrays, creating a type confusion:

```javascript
// After reclaim:
boxed_arr[0] = obj;           // Store object reference
addr = ftoi(unboxed_arr[0]);  // Read as float64 = leaked address

unboxed_arr[0] = itof(addr);  // Write address as float64
fake = boxed_arr[0];          // Read as object = fakeobj
```

### Current results (iPhone 11 Pro Max, iOS 26.1)

- **addrof/fakeobj:** Verified in probe runs
- **Address leaking:** 20+ object addresses captured per run
- **Inline-storage read/write:** Verified against known inline slots (object-address-based)
- **Arbitrary R/W:** Not proven; backing-store scan proof fails in current runs
- **Primitive degradation:** read64/write64 work during Stage 1 but degrade before Stage 4 (see below)

### Primitive degradation problem

The key blocker for proving arbitrary R/W is **primitive degradation** between stages:

1. During Stage 1, the UAF reclaim succeeds and `boxed_arr`/`unboxed_arr` share a butterfly → inline storage read/write tests pass
2. Stages 2 and 3 allocate PBO buffers, textures, and corruption targets → these allocations trigger GC
3. GC collects the freed Date (or reallocates the shared butterfly memory) → the `boxed_arr`/`unboxed_arr` overlap breaks
4. Stage 4's `simpleRead64`/`simpleWrite64` use the now-broken overlap → all reads return NaN (`0x7ff8000000000000`)

**Mitigation approaches under investigation:**
- Run validation phases (JSCell dump, backing-store scan) within Stage 1's critical window before GC invalidation
- Complete StructureID harvest via `buildStablePrimitives()` while primitives are alive
- Explore Wasm memory backing store as a PAC-free, GC-stable read/write surface

---

## CVE-2025-14174: ANGLE Metal Backend OOB Write

### Root cause

In ANGLE's Metal backend (`TextureMtl.cpp`), staging buffer allocation uses `UNPACK_IMAGE_HEIGHT` instead of actual texture height when uploading via PBO.

### Trigger

```javascript
gl.pixelStorei(gl.UNPACK_IMAGE_HEIGHT, 16);  // Small value

// Staging buffer: 256 * 16 * 4 = 16KB
// Actual write:   256 * 256 * 4 = 256KB
// OOB: 240KB!

gl.texImage2D(gl.TEXTURE_2D, 0, gl.DEPTH_COMPONENT32F,
              256, 256, 0, gl.DEPTH_COMPONENT, gl.FLOAT, 0);
```

---

## The PAC problem

### What's blocking full exploitation

Two factors block full exploitation:

**1. Pointer Authentication (PAC)** — On arm64e (iPhone 11 Pro Max), PAC protects critical JSC pointers:

| Pointer | Protected | Result |
|---------|-----------|--------|
| TypedArray `m_vector` | Yes | Cannot fake TypedArray with arbitrary backing store |
| JSArray `butterfly` | Yes | Cannot fake JSArray with arbitrary butterfly |

When I try to create a fake TypedArray/JSArray with an arbitrary data pointer, PAC verification fails and crashes:

```
Exception: EXC_BAD_ACCESS
KERN_INVALID_ADDRESS at 0x0001fffffffffffc -> 0x0000007ffffffffc
(possible pointer authentication failure)
```

**2. Primitive degradation** — The UAF butterfly sharing is ephemeral. The inline-storage PAC bypass (read via `fakeobj(addr-0x10).slot0`) works during Stage 1's critical window, but by Stage 4, GC has been triggered by intermediate allocations and the shared butterfly is gone. All `read64`/`write64` calls then return NaN.

### Why the original confusion works

The type confusion succeeds because both arrays use **legitimately signed** butterfly pointers - we're just reinterpreting the same memory. Fake objects with arbitrary unsigned pointers crash on PAC check.

### Potential bypass avenues

1. JIT code paths that might skip authentication
2. Gadgets that sign arbitrary pointers
3. Leveraging the ANGLE OOB differently
4. Alternative primitives that don't require fake objects
5. Stabilize UAF primitives by running validation within Stage 1's critical window
6. Wasm memory backing store as PAC-free, GC-stable read/write surface

---

## Current capabilities

| Primitive | Status | Notes |
|-----------|--------|-------|
| `addrof(obj)` | **Working** | Verified in probe |
| `fakeobj(addr)` | **Working** | Verified against known objects |
| Address leaking | **Working** | 20+ addresses per run |
| Inline slot read/write | **Working** | Verified on known inline slots (object-address-based) |
| `read64(addr)` | **Implemented** | 3-tier strategy: fast path → StructureID overwrite → watchdog |
| `write64(addr, val)` | **Implemented** | StructureID overwrite with save/restore |
| NaN-hole detection | **Implemented** | Detects NaN-patterned memory reads |
| Wasm memory probe | **Implemented** | Scans for PAC-free backing store |
| Butterfly steal | **Implemented** | Adjacency-based signed pointer extraction |
| Watchdog self-test | **Implemented** | Periodic primitive health check |

### read64/write64 Implementation Details

The `read64`/`write64` primitives use a **3-tier strategy** to handle the StructureID validation problem on arm64e:

1. **Fast path**: Direct `fakeobj(addr - 0x10).slot0` — works when the 4-byte StructureID at `(addr - 0x10)` happens to be valid (e.g., reading JSC heap objects that have proper headers nearby).

2. **Reliable path (Phase 2 — StructureID overwrite)**: Before reading at address X:
   - Save the 8 bytes at `X - 0x10` (the would-be JSCell header)
   - Overwrite with a known-good StructureID + flags harvested from spray objects
   - Read `fakeobj(X - 0x10).slot0` → returns the 8 bytes at X
   - Restore the original bytes at `X - 0x10`

3. **Watchdog**: Every Nth call runs a self-test (write+read marker at a known address) to detect if the UAF-based primitive has degraded due to GC.

**Known limitation — NaN hole**: If the 8 bytes at the target address form an IEEE 754 NaN pattern (exponent bits all 1s, fraction ≠ 0), JSC canonicalizes it to `0x7ff8000000000000`. This affects ~0.098% of possible 64-bit values.

### Alternative bypass strategies explored

| Strategy | Status | Notes |
|----------|--------|-------|
| Phase 3B: Wasm memory | Probe implemented | Scans Wasm ArrayBuffer for PAC-free backing store |
| Phase 3C: ANGLE in-process | Stage 3 trigger | Depends on in-process GPU configuration |
| Phase 3D: Butterfly steal | Probe implemented | Uses heap adjacency (diff=0x08) to read signed pointers |

---

## Evidence summary (latest probe run)

- **Verified:** `addrof`, `fakeobj`, address leaks, inline-slot read/write on known objects
- **Verified (Stage 1 only):** `read64`/`write64` inline storage tests pass during critical window
- **Implemented:** `read64`/`write64` with 3-tier strategy (fast path, StructureID overwrite, watchdog)
- **Implemented:** `buildStablePrimitives` called during Stage 1 for StructureID harvest
- **Probed:** Wasm PAC-free backing store detection, butterfly pointer stealing via adjacency
- **Diagnosed:** NaN-hole in read path (~0.098% blind spot), StructureID validation requirements
- **Diagnosed:** Primitive degradation — UAF butterfly invalidated by GC between Stage 1 and Stage 4
- **Unverified:** arbitrary `read64`/`write64` backing-store round-trip proof, renderer→GPU escape chain, sandbox escape
- **ANGLE probe:** WebGL2 PBO path triggers with NO_ERROR; ANGLE in-process corruption not detected

---

## Repository structure

```
├── README.md                 # This file
├── poc/
│   └── chained_exploit_probe.html   # Main PoC with all stages
└── analysis/
    ├── pac_analysis.md       # Detailed PAC findings
    └── crash_logs/           # Example crash reports
```

### PoC stages

| Stage | Function | Description |
|-------|----------|-------------|
| 1 | `runStage1()` | WebKit UAF trigger, butterfly reclaim, addrof/fakeobj, BSP StructureID harvest, read64/write64 construction |
| 2 | `runStage2()` | Corruption target verification |
| 3 | `runStage3()` | ANGLE OOB write trigger (CVE-2025-14174) |
| 4 | `runStage4()` | Validation proofs: early health check, backing-store round-trip, JSCell dumps, JIT leak, dyld read, BSP results |

---

## Acknowledgments

The CVE-2025-43529 UAF trigger, butterfly reclaim technique, and `addrof`/`fakeobj` primitive construction are based on the work of **[jir4vv1t](https://github.com/jir4vv1t/CVE-2025-43529)**. Their detailed analysis of the DFG Store Barrier bug and race condition exploitation was instrumental to this research.

---

## References

- [jir4vv1t/CVE-2025-43529](https://github.com/jir4vv1t/CVE-2025-43529) - Original UAF exploit and analysis
- WebKit Bugzilla: 302502, 303614
- Apple Security Updates - iOS 26
- Google Threat Analysis Group

---

**Work in progress.**
