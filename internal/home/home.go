// Package home resolves the .rtbtr home directory.
package home

import (
	"fmt"
	"os"
	"path/filepath"
)

// Resolve returns the .rtbtr home directory path.
func Resolve(explicitHome string, allowCreate bool) (string, error) {
	if explicitHome != "" {
		return explicitHome, nil
	}

	cwd, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("getting working directory: %w", err)
	}

	dir := cwd
	for {
		candidate := filepath.Join(dir, ".rtbtr")
		info, err := os.Stat(candidate)
		if err == nil && info.IsDir() {
			return candidate, nil
		}

		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}

		dir = parent
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
