# KokSpy internal file formats

KokSpy formats are versioned, documented, and recoverable. A reverse-engineering tool should not make its own files require reverse engineering. Humans have already supplied enough irony.

## `.kspy` — KokSpy Project Bundle

**Purpose:** portable analysis workspace.

**Container:** standard ZIP archive.

Required members:

- `manifest.json` — project metadata and exact target identity.
- `annotations.kann` — analyst comments.
- `symbols.ksym` — symbol snapshot.
- `README.txt` — human-readable recovery hint.

`manifest.json` format version 1:

```json
{
  "format": "kokspy-project",
  "version": 1,
  "created_utc": "2026-08-15T14:00:00Z",
  "updated_utc": "2026-08-15T14:00:00Z",
  "target_path": "C:\\samples\\program.exe",
  "target_name": "program.exe",
  "target_sha256": "...",
  "architecture": "x86-64",
  "image_base": 5368709120,
  "entry_va": 5368713216
}
```

KokSpy does **not** embed the executable by default. This keeps project files small and avoids silently copying analyzed binaries. The SHA-256 binds the workspace to the exact target build. If the original path no longer exists, KokSpy checks beside the `.kspy` file for `target_name` and still verifies the hash.

## `.ksym` — KokSpy Symbol File

UTF-8 JSON used inside `.kspy` bundles:

```json
{
  "format": "kokspy-symbols",
  "version": 1,
  "items": [
    {"name":"entry_point","address":5368713216,"kind":"entry"}
  ]
}
```

Kinds currently include `entry`, `export`, `forwarded-export`, and `coff`. Heuristic `sub_<address>` function names are generated on demand and are not persisted as authoritative symbols in v0.1.

## `.kann` — KokSpy Annotation File

UTF-8 JSON used inside `.kspy` bundles:

```json
{
  "format": "kokspy-annotations",
  "version": 1,
  "items": [
    {"address":5368713216,"text":"startup path"}
  ]
}
```

Addresses are stored as numeric virtual addresses so formatting choices do not leak into the data model.

## `.kcfg` — KokSpy Configuration File

Persistent UTF-8 JSON preferences. On Windows the default location is `%APPDATA%\KokSpy\kokspy.kcfg`.

Version 1:

```json
{
  "format": "kokspy-config",
  "version": 1,
  "syntax": "intel",
  "default_instruction_count": 40,
  "string_min_length": 5
}
```

Supported `syntax` values are `intel`, `gnu`, and `go`.

KokSpy writes this file when a `set` command changes a persistent setting.

## Compatibility rules

1. Readers reject newer format versions they cannot safely interpret.
2. Unknown JSON fields should be ignored where possible for forward compatibility.
3. Addresses are stored as unsigned virtual addresses, not formatted strings.
4. Project target identity is SHA-256, not merely path or filename.
5. Native formats never contain executable scripts or auto-run hooks.
6. `.kspy` remains a normal ZIP container so recovery does not depend on KokSpy itself.
