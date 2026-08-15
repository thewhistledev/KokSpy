# KokSpy desktop UI

KokSpy v0.2 uses a native Windows desktop frontend backed by the same Go analysis engine used by the optional CLI.

## Window regions

### Navigator

The left navigator switches the analysis workspace between:

1. Overview
2. Disassembly
3. Sections
4. Imports
5. Exports
6. Symbols
7. Strings
8. Functions
9. XRefs
10. Hex View
11. Annotations
12. Settings

The selected view is marked directly in the navigator.

### Top toolbar

- **Open File** opens PE executables, DLLs and `.kspy` workspaces.
- **Save Project** stores the current workspace as `.kspy`.
- **< / >** navigate address history.
- **Entry** jumps to the PE entry point.
- **Address / RVA** accepts a VA or RVA.
- **Go** disassembles the requested address.
- **Search** searches executable bytes. Prefix patterns with `hex:` for wildcard byte search.
- **Syntax** changes Intel/GNU/Go assembly rendering and persists it to `.kcfg`.

### Analysis workspace

The central workspace changes by analysis type. Disassembly, sections, imports, exports, symbols, strings, functions, xrefs and annotations use native Windows report tables with real columns and row selection. Double-clicking an address-bearing row navigates directly into disassembly. Overview, hex, settings and raw search results use a read-only monospace text surface with normal selection/copy and horizontal/vertical scrolling.

### Annotation bar

Enter an address in the address field, type a comment in the annotation bar and press **Add / Update**. Clearing the comment and updating removes the annotation. Annotations are stored in `.kspy` projects as `.kann` data.

### Status bar

Shows the active image, architecture, PE class, entry point, number of sections and current annotation count.

## Drag and drop

Dropping an `.exe`, `.dll` or `.kspy` file onto the main window immediately replaces the active analysis target.

## UI architecture

`internal/ui/model.go` is platform-neutral and owns analysis presentation/state. `internal/ui/ui_windows.go` owns the native Win32 window and controls. This keeps the PE/disassembler packages independent of the user interface and makes a future alternative frontend possible without duplicating analysis logic.
