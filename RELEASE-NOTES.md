# KokSpy v0.2.2

KokSpy v0.2.2 fixes the scrolling/paint corruption reported in the native Hex View.

## Fixed

- Replaced the Hex View multiline Win32 `EDIT` renderer with a native double-buffered report/list view. Hex data now uses stable Address, Bytes, and ASCII columns.
- Fixed background painting for KokSpy's read-only output control. Windows sends `WM_CTLCOLORSTATIC` for read-only edit controls; v0.2.1 left the text DC transparent, allowing stale glyph pixels to survive during scrolling.
- Removed the unsupported `DarkMode_Explorer` theme from the multiline read-only output control. KokSpy continues to apply its dark colours directly.
- Hex rows can now be double-clicked to jump directly to that address in Disassembly.
- Hex View window increased to 4096 bytes per page while remaining inexpensive to scroll.

## Retained from v0.2.1

- Win32 UI thread pinned with `runtime.LockOSThread`.
- Deferred startup rendering.
- Background target loading.
- Re-entry guards for render/layout.

---

# KokSpy v0.2.1

KokSpy v0.2.1 is a stability hotfix for the native Windows UI.

## Critical UI fixes

- Pins the Win32 GUI lifetime to one OS thread with `runtime.LockOSThread`. Windows message queues are thread-bound; allowing Go to migrate the UI goroutine could leave the window alive while its message pump ran on another thread, producing a permanent Not Responding state.
- Removes full workspace rendering from `WM_CREATE`; initial rendering is posted only after the top-level window exists and the normal message queue is active.
- Adds render and layout re-entry guards to prevent nested native control updates from recursively triggering expensive work.
- Moves PE/project opening and initial parsing to a worker goroutine. The UI remains responsive while a target is being opened, and the completed model is handed back to the UI thread through a custom window message.
- Disables analysis controls while a target is loading to avoid conflicting model changes.

## Validation

- Native Linux tests: `go test ./...`
- Windows/amd64 GUI cross-build with `CGO_ENABLED=0`
- Windows GUI subsystem verification
- Self-analysis of the exact produced GUI executable using KokSpy's PE parser
- Existing `.kspy` project and `.kcfg` tests retained

---

# KokSpy v0.2.0

KokSpy v0.2 replaces the terminal-first product interface with a native Windows desktop application while retaining the existing static-analysis engine.

## New desktop UI

- Native Windows GUI executable; no command window is created on launch
- Launches cleanly with no target and displays a welcome workspace
- Open `.exe`, `.dll` and `.kspy` from a file picker
- Drag-and-drop target opening
- Left-side analysis navigator
- Overview dashboard
- Disassembly workspace
- Sections, imports, exports and symbols views
- Strings, function candidates and xrefs views
- Hex view
- Search results workspace
- Annotation editor and annotations view
- Persistent settings view
- Address/RVA navigation
- Entry-point shortcut
- Back/forward address history
- Intel / GNU / Go syntax selector
- Persistent status bar
- Dark Windows styling and monospace analysis view

## Core analysis retained

- PE32 / PE32+
- x86 / x86-64 decoding
- Section permissions and entropy
- Imports / exports / COFF symbols
- ASCII / UTF-16LE strings
- Wildcard byte search
- Direct relative xrefs
- Heuristic function candidates
- Persistent `.kspy`, `.ksym`, `.kann`, `.kcfg` formats

## CLI

The v0.1 REPL remains available as `tools\KokSpy-CLI.exe` for scripting and debugging. It is no longer the normal application frontend.

## Validation

Release validation includes:

- `go test ./...`
- `go vet ./...`
- Windows/amd64 GUI cross-build with `CGO_ENABLED=0`
- PE subsystem verification confirms `KokSpy.exe` is `Windows GUI`
- Self-analysis of the produced GUI executable with KokSpy's PE parser
- Entry-point x86-64 disassembly of the produced executable
- Imports, sections, strings and search engine exercise against the produced executable
- `.kspy` save/reload tests
- `.kcfg` persistence tests

## Current limits

- Static analysis only
- Instruction decoding currently x86/x86-64
- No live debugger or process attachment yet
- Function candidates and linear-sweep xrefs are heuristic
- Control-flow graph reconstruction and decompilation are future analysis layers
