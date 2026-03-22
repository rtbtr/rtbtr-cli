package home

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestResolveExplicitHome(t *testing.T) {
	dir := t.TempDir()
	explicitHome := filepath.Join(dir, ".rtbtr")
	if err := os.MkdirAll(explicitHome, 0o755); err != nil {
		t.Fatalf("creating explicit home directory: %v", err)
	}

	t.Chdir(t.TempDir())

	got, err := Resolve(explicitHome, false)
	if err != nil {
		t.Fatalf("Resolve returned error: %v", err)
	}

	if got != explicitHome {
		t.Errorf("Resolve() = %q, want %q", got, explicitHome)
	}
}

func TestResolveWalkUp(t *testing.T) {
	root := t.TempDir()
	rtbtrDir := filepath.Join(root, ".rtbtr")
	if err := os.MkdirAll(rtbtrDir, 0o755); err != nil {
		t.Fatalf("creating .rtbtr directory: %v", err)
	}

	nested := filepath.Join(root, "a", "b", "c")
	if err := os.MkdirAll(nested, 0o755); err != nil {
		t.Fatalf("creating nested directory: %v", err)
	}

	t.Chdir(nested)

	got, err := Resolve("", false)
	if err != nil {
		t.Fatalf("Resolve returned error: %v", err)
	}

	if got != rtbtrDir {
		t.Errorf("Resolve() = %q, want %q", got, rtbtrDir)
	}

	for _, subpath := range []string{"a", filepath.Join("a", "b"), filepath.Join("a", "b", "c")} {
		if _, err := os.Stat(filepath.Join(root, subpath, ".rtbtr")); !os.IsNotExist(err) {
			t.Errorf("unexpected .rtbtr directory found under %q", subpath)
		}
	}
}

func TestResolveCreatesDir(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)

	expected := filepath.Join(dir, ".rtbtr")
	got, err := Resolve("", true)
	if err != nil {
		t.Fatalf("Resolve returned error: %v", err)
	}

	if got != expected {
		t.Errorf("Resolve() = %q, want %q", got, expected)
	}

	info, err := os.Stat(expected)
	if err != nil {
		t.Errorf("stat .rtbtr directory: %v", err)
	}
	if err == nil && !info.IsDir() {
		t.Errorf("Resolve() created %q, want directory", expected)
	}
}

func TestResolveNotFoundError(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)

	_, err := Resolve("", false)
	if err == nil {
		t.Fatal("Resolve should return error when .rtbtr not found")
	}

	if !strings.Contains(err.Error(), ".rtbtr directory not found") {
		t.Errorf("error = %q, want it to contain %q", err.Error(), ".rtbtr directory not found")
	}

	if _, statErr := os.Stat(filepath.Join(dir, ".rtbtr")); statErr == nil {
		t.Errorf(".rtbtr directory was created unexpectedly")
	}
}
