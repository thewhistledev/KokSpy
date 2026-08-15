# KokSpy

KokSpy is a Windows-first PE disassembler and static executable-analysis application written in Go.

KokSpy v0.2.2 is a desktop GUI application. Double-clicking `KokSpy.exe` opens the interface directly.


### v0.2.2 UI stability fixes

The native Win32 UI remains pinned to a single OS thread, initial rendering is deferred until the Windows message pump is active, and target loading/parsing runs off the UI thread. v0.2.2 also replaces the old multiline-text Hex View with a double-buffered table and corrects read-only control background painting to eliminate scroll ghosting.

## Desktop interface

The main window is organised around a fast analysis workspace:

- **Analysis navigator** on the left for Overview, Disassembly, Sections, Imports, Exports, Symbols, Strings, Functions, XRefs, Hex View, Annotations and Settings.
- **Navigation toolbar** with Open File, Save Project, Back, Forward and Entry controls.
- **Address / RVA box** for immediate disassembly at an arbitrary virtual address or RVA.
- **Search box** for text search and wildcard byte search (`hex: 48 8B ?? E8`).
- **Syntax selector** for Intel, GNU/AT&T and Go assembly syntax.
- **Native report-table workspaces** for disassembly, sections, imports, exports, symbols, strings, functions, xrefs and annotations, including selectable rows and double-click address navigation.
- **Monospace text workspaces** for the overview, hex view, settings and raw search results, with copy/select and horizontal/vertical scrolling.
- **Annotation bar** for persistent comments at the current address.
- **Persistent status bar** showing the loaded image, architecture, PE class, entry point, section count and annotation count.
- **Drag and drop** for `.exe`, `.dll` and `.kspy` files.
- A proper **welcome screen** when no target is loaded.

## Analysis features

- PE32 and PE32+ parsing
- x86 and x86-64 instruction decoding
- Intel, GNU/AT&T and Go assembly syntax
- Entry-point and arbitrary-address disassembly
- PE section table, R/W/X permissions and entropy
- Imports and exports
- COFF symbols when present
- Heuristic function candidates from direct `CALL` targets
- ASCII and UTF-16LE string extraction
- Hex/ASCII view
- ASCII search and wildcard hex-byte search
- Direct relative `CALL`/branch xrefs
- Address annotations/comments
- SHA-256 target identity
- Versioned `.kspy` project bundles
- `.ksym`, `.kann` and persistent `.kcfg` KokSpy formats
- Self-contained x86/x64 decoder with no runtime module downloads
- Static analysis only: KokSpy does not execute or instrument the target

## Run on Windows

1. Extract the ZIP.
2. Double-click `KokSpy.exe`.
3. Press **Open File**, or drag an `.exe`, `.dll`, or `.kspy` onto the KokSpy window.

You can also associate or pass a target directly:

```powershell
.\KokSpy.exe C:\path\to\program.exe
.\KokSpy.exe C:\path\to\analysis.kspy
```

Because `KokSpy.exe` is built with the Windows GUI subsystem, those commands open the desktop application without creating a console window.

## Using the interface

### Disassemble an address

Enter either a VA such as:

```text
0x140001000
```

or an RVA such as:

```text
0x1000
```

then press **Go**. Values below the PE image base are interpreted as RVAs.

### Search

Normal text searches raw executable bytes:

```text
https://
```

Prefix a byte pattern with `hex:` for wildcard byte search:

```text
hex: 48 8B ?? ?? E8
```

`??` matches any one byte.

### Save an analysis workspace

Press **Save Project**. KokSpy writes a `.kspy` workspace containing the manifest, symbols and annotations. Opening that `.kspy` later restores the workspace and reconnects it to the analysed executable.

## KokSpy formats

- **`.kspy`**: portable KokSpy analysis workspace. It is a ZIP container with a versioned manifest and companion analysis files.
- **`.ksym`**: KokSpy symbol database.
- **`.kann`**: KokSpy annotations/comments.
- **`.kcfg`**: persistent KokSpy application settings.

See `docs/FORMATS.md` for schemas and compatibility rules.

## Optional CLI

The old immediate console frontend still exists for scripting and automation, but it is not the normal application. Release builds place it under:

```text
tools\KokSpy-CLI.exe
```

Examples:

```powershell
tools\KokSpy-CLI.exe -cmd "info" program.exe
tools\KokSpy-CLI.exe -cmd "disasm 0x1000 80" program.exe
```

## Build from source

Requires Go 1.23+.

Use `build-windows.cmd`, or build manually:

```powershell
go test ./...
go build -trimpath -ldflags "-H windowsgui -s -w" -o KokSpy.exe ./cmd/kokspy
go build -trimpath -ldflags "-s -w" -o tools\KokSpy-CLI.exe ./cmd/kokspy-cli
```

The x86/x64 decoder is vendored from Go's `x/arch/x86/x86asm` implementation under its BSD license. See `internal/vendorx86/LICENSE`.

## Scope

KokSpy is currently a static PE analysis application. Function discovery and direct xref recovery are heuristic on x86/x64, because pretending arbitrary x86 bytes always have a single perfect interpretation is how disassemblers develop delusions of grandeur.

The architecture is intentionally separated into the PE parser, disassembly engine, project/config formats, portable UI model and Windows desktop frontend so later releases can add control-flow graphs, recursive traversal, PDBs, resources, TLS/load-config inspection, Authenticode, binary diffing and plugins without replacing the core.
