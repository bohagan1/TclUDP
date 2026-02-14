# TECLAB Changes to tcludp

This file documents modifications made to the tcludp source code.

## Build Environment
- **Compiler**: gcc (Rev8, Built by MSYS2 project) 15.2.0
- **Platform**: Windows (MSYS2 MinGW64)
- **Target**: Tcl 9.0 (with Tcl 8.6 backward compatibility)
- **Date**: 2026-02-14

---

## Tcl 9 Migration (2026-02-14)

### 3. Added lowercase init aliases for Tcl 9 `load` command

**File**: `generic/udp_tcl.c`

**Issue**: Tcl 9 no longer auto-capitalizes the package name when looking up init functions. Without lowercase aliases, `load` would fail to find the entry point.

**Change**: Added after `Udp_SafeInit`:
```c
int udp_Init(Tcl_Interp *interp) { return Udp_Init(interp); }
int udp_SafeInit(Tcl_Interp *interp) { return Udp_SafeInit(interp); }
```

### 4. Fixed channel type `closeProc` field for Tcl 9

**File**: `generic/udp_tcl.c`

**Issue**: In Tcl 9, the `closeProc` field (field 3) of `Tcl_ChannelType` changed from `Tcl_DriverCloseProc *` to `void *` (deprecated/unused). Assigning a function pointer to `void *` produces a compiler warning.

**Change**: Conditional NULL for Tcl 9 in `Udp_ChannelType`:
```c
#if TCL_MAJOR_VERSION > 8
    NULL,                  /* closeProc - not used in Tcl 9 */
#else
    udpClose,              /* Close channel, clean instance data */
#endif
```

**Note**: `udpClose2` (the `close2Proc`) already calls `udpClose(clientData, interp)` when `flags == 0`, so close behavior is preserved.

### 5. Replaced deprecated `Tcl_DStringResult`

**File**: `generic/udp_tcl.c`

**Issue**: `Tcl_DStringResult` is deprecated in Tcl 9.

**Change**:
```diff
- Tcl_DStringResult(interp, &ds);
+ Tcl_SetObjResult(interp, Tcl_NewStringObj(Tcl_DStringValue(&ds), Tcl_DStringLength(&ds)));
```

### Build Results

- **Status**: Compilation successful
- **Output**: `tcl9udp1012.dll`
- **Installation**: `release/lib/udp1.0.12/`
- **Exported symbols**: `Udp_Init`, `udp_Init`, `Udp_SafeInit`, `udp_SafeInit`
- **Remaining Warnings**: Format string warnings (non-critical, pre-existing)

### Test Results

- **Total**: 116 tests
- **Passed**: 99 tests
- **Skipped**: 17 tests (platform-specific constraints)
- **Failed**: 0 tests

---

## Windows Compiler Fixes (2026-01-07)

### 1. Fixed ioctlsocket() Type Compatibility (Line 1972)

**File**: `generic/udp_tcl.c`

**Issue**: The `ioctlsocket()` function expects a `u_long*` pointer for its third argument, but an `int*` was being passed, causing a compilation error with strict type checking in newer gcc versions.

**Change**:
```diff
- int one = 1;
+ u_long one = 1;
  ioctlsocket(sock, FIONBIO, &one);
```

### 2. Fixed WSAAddressToStringA() Type Compatibility (Line 394)

**File**: `generic/udp_tcl.c`

**Issue**: The `WSAAddressToStringA()` function expects a `LPDWORD` (unsigned long*) for its fifth argument, but an `int*` was being passed.

**Change**:
```diff
- int remoteaddrlen; /* bytes for ANSI strings, WCHARs for Unicode */
+ DWORD remoteaddrlen; /* bytes for ANSI strings, WCHARs for Unicode */
```

## Notes

All changes maintain backward compatibility with Tcl 8.6. The Tcl 9 migration leverages the existing `Tcl_Size` compatibility shim in `udp_tcl.h` and the conditional `TCL_MAJOR_VERSION` branches already present in the code. No functional changes were made to the UDP socket implementation.
