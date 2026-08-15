package config

import (
	"path/filepath"
	"testing"
)

func TestSaveLoad(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "kokspy.kcfg")
	want := Default()
	want.Syntax = "gnu"
	want.DefaultInstructionCount = 77
	want.StringMinLength = 9
	if err := Save(path, want); err != nil {
		t.Fatal(err)
	}
	got, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if got.Syntax != want.Syntax || got.DefaultInstructionCount != want.DefaultInstructionCount || got.StringMinLength != want.StringMinLength {
		t.Fatalf("round trip mismatch: got %+v want %+v", got, want)
	}
}

func TestMissingReturnsDefaults(t *testing.T) {
	got, err := Load(filepath.Join(t.TempDir(), "missing.kcfg"))
	if err != nil {
		t.Fatal(err)
	}
	if got.Syntax != "intel" || got.DefaultInstructionCount != 40 || got.StringMinLength != 5 {
		t.Fatalf("unexpected defaults: %+v", got)
	}
}
