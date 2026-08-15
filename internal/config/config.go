package config

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
)

const Version = 1

type Config struct {
	Format                  string `json:"format"`
	Version                 int    `json:"version"`
	Syntax                  string `json:"syntax"`
	DefaultInstructionCount int    `json:"default_instruction_count"`
	StringMinLength         int    `json:"string_min_length"`
}

func Default() Config {
	return Config{
		Format:                  "kokspy-config",
		Version:                 Version,
		Syntax:                  "intel",
		DefaultInstructionCount: 40,
		StringMinLength:         5,
	}
}

func Path() string {
	if appData := os.Getenv("APPDATA"); appData != "" {
		return filepath.Join(appData, "KokSpy", "kokspy.kcfg")
	}
	if home, err := os.UserHomeDir(); err == nil {
		return filepath.Join(home, ".kokspy", "kokspy.kcfg")
	}
	return "kokspy.kcfg"
}

func Load(path string) (Config, error) {
	cfg := Default()
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return cfg, nil
	}
	if err != nil {
		return cfg, err
	}
	if err := json.Unmarshal(b, &cfg); err != nil {
		return Default(), err
	}
	if cfg.Format != "kokspy-config" || cfg.Version > Version {
		return Default(), errors.New("unsupported KokSpy configuration format")
	}
	normalize(&cfg)
	return cfg, nil
}

func Save(path string, cfg Config) error {
	normalize(&cfg)
	cfg.Format = "kokspy-config"
	cfg.Version = Version
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil && filepath.Dir(path) != "." {
		return err
	}
	b, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	return os.WriteFile(path, b, 0o644)
}

func normalize(cfg *Config) {
	switch cfg.Syntax {
	case "intel", "gnu", "go":
	default:
		cfg.Syntax = "intel"
	}
	if cfg.DefaultInstructionCount < 1 || cfg.DefaultInstructionCount > 10000 {
		cfg.DefaultInstructionCount = 40
	}
	if cfg.StringMinLength < 3 || cfg.StringMinLength > 1000 {
		cfg.StringMinLength = 5
	}
}
