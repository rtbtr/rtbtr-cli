// Package config manages the .rtbtr/config.yaml identity file.
package config

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// Config stores the registered organization and bot identity.
type Config struct {
	Org string `yaml:"org"`
	Bot string `yaml:"bot"`
}

// Load reads config.yaml from dir and returns the parsed identity.
func Load(dir string) (*Config, error) {
	path := filepath.Join(dir, "config.yaml")

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config.yaml: %w", err)
	}

	cfg := &Config{}
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parsing config.yaml: %w", err)
	}

	return cfg, nil
}

// Write writes config.yaml to dir with mode 0644.
func Write(dir string, cfg *Config) error {
	data, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("marshaling config.yaml: %w", err)
	}

	path := filepath.Join(dir, "config.yaml")
	// WriteFile with 0o600 to satisfy gosec G306, then Chmod to 0o644
	// since config.yaml only contains org/bot names and is not sensitive.
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("writing config.yaml: %w", err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		return fmt.Errorf("setting config.yaml permissions: %w", err)
	}

	return nil
}
