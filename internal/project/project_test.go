package project

import (
	"path/filepath"
	"testing"

	"github.com/thewhistledev/kokspy/internal/analysis"
)

func TestProjectRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sample.kspy")
	m := Manifest{
		TargetName:   "sample.exe",
		Architecture: "x86-64",
		ImageBase:    0x140000000,
		EntryVA:      0x140001000,
	}
	anns := []analysis.Annotation{{Address: 0x140001000, Text: "entry"}}
	syms := []analysis.Symbol{{Name: "entry_point", Address: 0x140001000, Kind: "entry"}}
	if err := Save(path, m, anns, syms); err != nil {
		t.Fatal(err)
	}
	got, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if got.Manifest.Format != "kokspy-project" || got.Manifest.Version != FormatVersion {
		t.Fatalf("bad manifest: %+v", got.Manifest)
	}
	if len(got.Annotations) != 1 || got.Annotations[0].Text != "entry" {
		t.Fatalf("bad annotations: %+v", got.Annotations)
	}
	if len(got.Symbols) != 1 || got.Symbols[0].Name != "entry_point" {
		t.Fatalf("bad symbols: %+v", got.Symbols)
	}
}
