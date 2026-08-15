package project

import (
	"archive/zip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/thewhistledev/kokspy/internal/analysis"
	"github.com/thewhistledev/kokspy/internal/util"
)

const FormatVersion = 1

type Manifest struct {
	Format       string `json:"format"`
	Version      int    `json:"version"`
	CreatedUTC   string `json:"created_utc"`
	UpdatedUTC   string `json:"updated_utc"`
	TargetPath   string `json:"target_path"`
	TargetName   string `json:"target_name"`
	TargetSHA256 string `json:"target_sha256"`
	Architecture string `json:"architecture"`
	ImageBase    uint64 `json:"image_base"`
	EntryVA      uint64 `json:"entry_va"`
}

type AnnotationFile struct {
	Format  string                `json:"format"`
	Version int                   `json:"version"`
	Items   []analysis.Annotation `json:"items"`
}
type SymbolFile struct {
	Format  string            `json:"format"`
	Version int               `json:"version"`
	Items   []analysis.Symbol `json:"items"`
}

type Loaded struct {
	Manifest    Manifest
	Annotations []analysis.Annotation
	Symbols     []analysis.Symbol
}

func Save(path string, m Manifest, annotations []analysis.Annotation, symbols []analysis.Symbol) error {
	if filepath.Ext(path) == "" {
		path += ".kspy"
	}
	if filepath.Ext(path) != ".kspy" {
		return errors.New("KokSpy project files must use .kspy")
	}
	if m.TargetSHA256 == "" && m.TargetPath != "" {
		h, err := util.SHA256File(m.TargetPath)
		if err == nil {
			m.TargetSHA256 = h
		}
	}
	now := time.Now().UTC().Format(time.RFC3339)
	if m.CreatedUTC == "" {
		m.CreatedUTC = now
	}
	m.UpdatedUTC = now
	m.Format = "kokspy-project"
	m.Version = FormatVersion
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	zw := zip.NewWriter(f)
	if err := writeJSON(zw, "manifest.json", m); err != nil {
		return err
	}
	if err := writeJSON(zw, "annotations.kann", AnnotationFile{Format: "kokspy-annotations", Version: 1, Items: annotations}); err != nil {
		return err
	}
	if err := writeJSON(zw, "symbols.ksym", SymbolFile{Format: "kokspy-symbols", Version: 1, Items: symbols}); err != nil {
		return err
	}
	readme := "KokSpy project bundle. This is a ZIP container; see docs/FORMATS.md in the KokSpy distribution.\n"
	w, _ := zw.Create("README.txt")
	_, _ = io.WriteString(w, readme)
	return zw.Close()
}

func Load(path string) (*Loaded, error) {
	zr, err := zip.OpenReader(path)
	if err != nil {
		return nil, fmt.Errorf("open .kspy: %w", err)
	}
	defer zr.Close()
	var out Loaded
	gotManifest := false
	for _, f := range zr.File {
		switch f.Name {
		case "manifest.json":
			if err := readJSON(f, &out.Manifest); err != nil {
				return nil, err
			}
			gotManifest = true
		case "annotations.kann":
			var a AnnotationFile
			if err := readJSON(f, &a); err != nil {
				return nil, err
			}
			out.Annotations = a.Items
		case "symbols.ksym":
			var s SymbolFile
			if err := readJSON(f, &s); err != nil {
				return nil, err
			}
			out.Symbols = s.Items
		}
	}
	if !gotManifest {
		return nil, errors.New("invalid .kspy: manifest.json missing")
	}
	if out.Manifest.Format != "kokspy-project" || out.Manifest.Version > FormatVersion {
		return nil, fmt.Errorf("unsupported .kspy format %q v%d", out.Manifest.Format, out.Manifest.Version)
	}
	return &out, nil
}

func writeJSON(zw *zip.Writer, name string, v any) error {
	w, err := zw.Create(name)
	if err != nil {
		return err
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}
func readJSON(f *zip.File, v any) error {
	r, err := f.Open()
	if err != nil {
		return err
	}
	defer r.Close()
	return json.NewDecoder(r).Decode(v)
}
