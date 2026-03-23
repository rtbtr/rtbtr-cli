package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// T-01: config.Load reads a config.yaml with known org/bot values and returns the correct fields.
func TestLoadReadsConfig(t *testing.T) {
	dir := t.TempDir()
	content := "org: myorg\nbot: mybot\n"
	if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte(content), 0o644); err != nil {
		t.Fatalf("writing config.yaml: %v", err)
	}

	cfg, err := Load(dir)
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}

	if cfg.Org != "myorg" {
		t.Errorf("Config.Org = %q, want %q", cfg.Org, "myorg")
	}
	if cfg.Bot != "mybot" {
		t.Errorf("Config.Bot = %q, want %q", cfg.Bot, "mybot")
	}
}

// T-01: config.Load returns error for missing file.
func TestLoadMissingFile(t *testing.T) {
	dir := t.TempDir()

	_, err := Load(dir)
	if err == nil {
		t.Fatal("Load should return error for missing config.yaml")
	}
}

// T-01: config.Load returns error for malformed YAML.
func TestLoadMalformedYAML(t *testing.T) {
	dir := t.TempDir()
	content := ":::not valid yaml\n\t\t{{{{"
	if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte(content), 0o644); err != nil {
		t.Fatalf("writing config.yaml: %v", err)
	}

	_, err := Load(dir)
	if err == nil {
		t.Fatal("Load should return error for malformed YAML")
	}
}

// T-02: config.Write creates config.yaml that can be read back with correct org/bot values.
func TestWriteCreatesConfigFile(t *testing.T) {
	dir := t.TempDir()

	cfg := &Config{Org: "testorg", Bot: "testbot"}
	if err := Write(dir, cfg); err != nil {
		t.Fatalf("Write returned error: %v", err)
	}

	data, err := os.ReadFile(filepath.Join(dir, "config.yaml"))
	if err != nil {
		t.Fatalf("reading config.yaml: %v", err)
	}

	content := string(data)
	if !strings.Contains(content, "org: testorg") {
		t.Errorf("config.yaml does not contain 'org: testorg': %q", content)
	}
	if !strings.Contains(content, "bot: testbot") {
		t.Errorf("config.yaml does not contain 'bot: testbot': %q", content)
	}
}

// T-02: Write then Load round-trip preserves org and bot values.
func TestWriteRoundTrip(t *testing.T) {
	dir := t.TempDir()

	original := &Config{Org: "roundorg", Bot: "roundbot"}
	if err := Write(dir, original); err != nil {
		t.Fatalf("Write returned error: %v", err)
	}

	loaded, err := Load(dir)
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}

	if loaded.Org != original.Org {
		t.Errorf("round-trip Org = %q, want %q", loaded.Org, original.Org)
	}
	if loaded.Bot != original.Bot {
		t.Errorf("round-trip Bot = %q, want %q", loaded.Bot, original.Bot)
	}
}

// T-02: Write overwrites an existing config.yaml.
func TestWriteOverwritesExistingConfig(t *testing.T) {
	dir := t.TempDir()

	first := &Config{Org: "first", Bot: "firstbot"}
	if err := Write(dir, first); err != nil {
		t.Fatalf("first Write returned error: %v", err)
	}

	second := &Config{Org: "second", Bot: "secondbot"}
	if err := Write(dir, second); err != nil {
		t.Fatalf("second Write returned error: %v", err)
	}

	loaded, err := Load(dir)
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}

	if loaded.Org != "second" {
		t.Errorf("Org = %q after overwrite, want %q", loaded.Org, "second")
	}
	if loaded.Bot != "secondbot" {
		t.Errorf("Bot = %q after overwrite, want %q", loaded.Bot, "secondbot")
	}
}

// T-02: Written file has mode 0600.
func TestWriteFilePermissions(t *testing.T) {
	dir := t.TempDir()

	cfg := &Config{Org: "permorg", Bot: "permbot"}
	if err := Write(dir, cfg); err != nil {
		t.Fatalf("Write returned error: %v", err)
	}

	info, err := os.Stat(filepath.Join(dir, "config.yaml"))
	if err != nil {
		t.Fatalf("stat config.yaml: %v", err)
	}

	perm := info.Mode().Perm()
	if perm != 0o600 {
		t.Errorf("config.yaml permissions = %o, want %o", perm, 0o600)
	}
}
