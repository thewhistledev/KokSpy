# KokSpy roadmap

## v0.1 — static analysis core

Implemented:

- PE32/PE32+ loader
- x86/x64 decoder
- syntax switching
- imports/exports/sections
- strings, entropy, hex view, byte search
- direct relative xrefs
- heuristic function candidates
- annotations
- `.kspy`, `.ksym`, `.kann`, `.kcfg`

## v0.2 — native Windows desktop UI

Implemented:

- Windows GUI-subsystem executable with no console window
- Welcome workspace and drag-and-drop opening
- Native analysis navigator
- Native report tables for disassembly and PE datasets
- Address/RVA navigation
- Entry-point shortcut
- Back/forward address history
- Search workspace
- Persistent annotations
- Syntax selector
- Settings and status views
- Optional CLI isolated under `tools/`

## v0.3 — code discovery

Planned engineering targets:

- Recursive traversal from entry/export/call targets
- Basic-block model and control-flow graph
- Better function-boundary recovery
- Import Address Table address resolution and call naming
- RIP-relative data references
- User-defined symbols and renaming
- Section/resource extraction
- Split disassembly/details panes

## v0.4 — Windows analysis depth

- PE resources and version information
- TLS directory and callbacks
- Load Config / CFG information
- Exception/unwind data
- Authenticode/signature metadata
- PDB/CodeView discovery
- C++ name demangling
- Delay-load imports

## v0.5 — advanced workflow

- Graph rendering
- Binary diffing
- Plugin API
- Scriptable analysis commands
- Search indexes for very large binaries
- Cross-reference side panes
- Function renaming and user-defined types

The roadmap separates trustworthy parsing from heuristic analysis. Conflating the two is how disassemblers end up confidently inventing functions in JPEG data.
