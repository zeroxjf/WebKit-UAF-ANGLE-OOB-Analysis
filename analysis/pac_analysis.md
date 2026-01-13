# arm64e PAC Analysis for WebKit Exploitation

## Overview

This document details the Pointer Authentication Code (PAC) mitigations encountered during exploitation of CVE-2025-43529 on arm64e devices (iPhone XS and newer running iOS 26.1).

## Background: Pointer Authentication

arm64e introduces hardware-enforced pointer authentication using cryptographic signatures embedded in the upper bits of pointers. When a pointer is dereferenced, the CPU verifies its signature before use.

### PAC Keys

| Key | Usage |
|-----|-------|
| IA | Instruction Address (code pointers) |
| IB | Instruction Address (alternate) |
| DA | Data Address (data pointers) |
| DB | Data Address (alternate) |
| GA | Generic Authentication |

### Signing/Verification

```
Signed Pointer = Raw Pointer | (PAC << 48)
PAC = f(Raw Pointer, Context/Modifier, Key)
```

## JSC Pointer Authentication

JavaScriptCore uses PAC to protect critical internal pointers.

### JSArrayBufferView Layout (Float64Array)

```
Offset  Field           PAC Protected
------  -----           -------------
+0x00   JSCell header   No (structure ID, type, flags)
+0x08   m_butterfly     Yes (DA key)
+0x10   m_vector        Yes (DA key)
+0x18   m_length        No
+0x20   m_byteOffset    No
+0x28   m_mode          No
```

### JSArray Layout

```
Offset  Field           PAC Protected
------  -----           -------------
+0x00   JSCell header   No
+0x08   m_butterfly     Yes (DA key)
```

## Crash Analysis

### Crash Signature

```
Exception Type:  EXC_BAD_ACCESS (SIGBUS)
Exception Codes: KERN_INVALID_ADDRESS at 0x0001fffffffffffc

Thread 0 Crashed:
0   JavaScriptCore  jsc_llint_llintOpWithMetadata__opGetByValNotDouble + 0
```

### Address Breakdown

```
Failed Address: 0x0001fffffffffffc
                ^^^^---------------- PAC failure indicator
                    ^^^^^^^^^^^^^^^^ Original pointer (corrupted)

Decoded:        0x0000007ffffffffc
                     ^^^^^^^^^^^^^^ Our intended address (backing store)
```

### PAC Failure Mechanism

1. Fake Float64Array created at container's inline properties
2. `m_vector` field contains unsigned pointer to target address
3. LLInt executes `get_by_val` for array element access
4. CPU attempts to authenticate `m_vector` pointer:
   ```
   autda m_vector, context
   ```
5. Authentication fails (no valid PAC signature)
6. Upper bits set to indicate failure: `0x0001...`
7. Memory access to corrupted address causes SIGBUS

## Why Original Confusion Works

The boxed/unboxed type confusion succeeds because both arrays have **legitimately signed pointers**:

```
Spray Array Allocation:
1. JSC allocates butterfly via MarkedAllocator
2. Butterfly pointer is signed: pacia butterfly, context
3. Signed pointer stored in array's m_butterfly field

Reclaimed Date Butterfly:
1. Date's butterfly was legitimately allocated
2. Date freed, butterfly returned to free list
3. Spray array's butterfly allocation reclaims same memory
4. Spray array has legitimately signed pointer to this memory
5. Freed Date still has old (but valid) signed pointer

Type Confusion:
- boxed_arr: Uses legitimate signed butterfly pointer
- unboxed_arr (freed Date): Uses same legitimate signed butterfly pointer
- Both pointers are valid - just reinterpreting the data differently
```

## Failed Bypass Attempts

### Attempt 1: Direct Fake TypedArray

**Approach**: Create fake Float64Array with arbitrary `m_vector`

```javascript
fakeArrayContainer.vector = itof(targetAddress);
const fake = fakeobj(containerAddr + 0x10n);
fake[0];  // CRASH - PAC failure
```

**Result**: Immediate crash in `llint_op_get_by_val`

### Attempt 2: Fake JSArray with Arbitrary Butterfly

**Approach**: Create fake JSArray, set butterfly to target address

```javascript
arrayReaderContainer.butterfly = itof(targetAddress);
const fake = fakeobj(arrayReaderPropsAddr);
fake[0];  // CRASH - PAC failure
```

**Result**: Crash - butterfly is also PAC protected

### Attempt 3: Steal Signed Pointer

**Approach**: Read PAC-signed `m_vector` from real TypedArray, reuse it

**Problem**: Cannot read the signed pointer without already having read primitive

**Additional Issue**: PAC context may include object address:
```
Real TypedArray at address X: m_vector signed with context(X)
Fake TypedArray at address Y: needs m_vector signed with context(Y)
```
Cannot forge correct signature for different address.

## Potential Bypass Strategies

### 1. JIT Compilation Path

Some JIT-compiled code paths may skip PAC verification:
- Inline caches
- Optimized property access
- Speculative execution paths

**Investigation needed**: Force JIT compilation of array access, analyze generated code.

### 2. PAC Signing Gadget

Find existing code that signs arbitrary pointers:
```
; Gadget pattern
mov x0, [controlled]
pacia x0, x1
str x0, [controlled]
```

**Challenge**: Such gadgets are rare and typically not controllable.

### 3. Structure ID Manipulation

If we can control structure ID lookup:
1. Create fake Structure with custom property offsets
2. Property access might read from controlled location
3. Potentially bypass m_vector PAC check

**Challenge**: Structure table access is also protected.

### 4. PAC Key Corruption

Via separate vulnerability (kernel or hardware):
1. Corrupt PAC keys in memory
2. All PAC verification becomes predictable/bypassable

**Challenge**: Requires separate powerful primitive.

### 5. ANGLE Chain

Use ANGLE OOB to corrupt GPU process memory:
1. GPU process may have different PAC policies
2. Potentially corrupt WebKit shared memory
3. Modify pointers in shared IPC buffers

**Status**: Under investigation.

## Conclusion

arm64e PAC effectively prevents the traditional fake object technique for achieving arbitrary read/write. The exploit successfully achieves:

- **addrof**: Working (via legitimate butterfly reuse)
- **fakeobj**: Working (object reference creation)
- **Address leaking**: Working (20+ addresses)

But fails to achieve:
- **read64/write64**: Blocked by PAC on m_vector/butterfly

Further research is needed to bypass PAC or find alternative primitives.

---

**Last Updated**: January 2026
