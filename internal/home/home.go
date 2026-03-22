// Package home resolves the .rtbtr home directory.
package home

import (
	"fmt"
	"os"
	"path/filepath"
)

// FindDirUp walks up from startDir looking for a subdirectory named name.
// It returns the full path and true if found, or empty string and false otherwise.
func FindDirUp(startDir, name string) (string, bool) {
	dir := startDir
	for {
		candidate := filepath.Join(dir, name)
		if info, err := os.Stat(candidate); err == nil && info.IsDir() {
			return candidate, true
		}

		parent := filepath.Dir(dir)
		if parent == dir {
			return "", false
		}
		dir = parent
	}
}

// Resolve returns the .rtbtr home directory path.
//
// If explicitHome is non-empty it is returned as-is without validation;
// the caller is responsible for creating the directory if needed.
// Otherwise, Resolve walks up from cwd looking for a .rtbtr/ subdirectory.
// If none is found and allowCreate is true, .rtbtr/ is created in cwd.
func Resolve(explicitHome string, allowCreate bool) (string, error) {
	if explicitHome != "" {
		return explicitHome, nil
	}

	cwd, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("getting working directory: %w", err)
	}

	if found, ok := FindDirUp(cwd, ".rtbtr"); ok {
		return found, nil
	}

	if !allowCreate {
		return "", fmt.Errorf(".rtbtr directory not found")
	}

	path := filepath.Join(cwd, ".rtbtr")
	if err := os.MkdirAll(path, 0o755); err != nil {
		return "", fmt.Errorf("creating .rtbtr directory: %w", err)
	}

	return path, nil
}
