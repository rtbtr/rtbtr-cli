package cmd

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/rtbtr/rtbtr-cli/internal/home"
)

const maxSignInputBytes = 1 << 20 // 1MB

var signCmd = &cobra.Command{
	Use:   "sign",
	Short: "Sign stdin with your Ed25519 private key",
	Long: `Sign stdin with the Ed25519 private key from the .rtbtr directory.

Reads all of stdin as the content to sign (max 1MB) and outputs
the 64-byte Ed25519 signature as URL-safe base64 (no padding) to stdout.

Nothing else is written to stdout — clean for piping.`,
	Args: cobra.NoArgs,
	RunE: runSign,
}

func runSign(cmd *cobra.Command, args []string) error {
	homeDir, err := home.Resolve(homeFlag, false)
	if err != nil {
		return fmt.Errorf("resolving home directory: %w", err)
	}

	seed, err := loadSignPrivateKey(homeDir)
	if err != nil {
		return err
	}

	content, err := io.ReadAll(io.LimitReader(cmd.InOrStdin(), maxSignInputBytes+1))
	if err != nil {
		return fmt.Errorf("reading stdin: %w", err)
	}
	if len(content) == 0 {
		return errors.New("empty input: stdin must contain data to sign")
	}
	if len(content) > maxSignInputBytes {
		return errors.New("input too large (max 1MB)")
	}

	privKey := ed25519.NewKeyFromSeed(seed)
	sig := ed25519.Sign(privKey, content)

	sigB64 := base64.RawURLEncoding.EncodeToString(sig)
	if _, err := fmt.Fprint(cmd.OutOrStdout(), sigB64); err != nil {
		return fmt.Errorf("writing signature to stdout: %w", err)
	}

	return nil
}

func loadSignPrivateKey(homeDir string) ([]byte, error) {
	path := filepath.Join(homeDir, "private_key")
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, errors.New("private key not found, run rtbtr keygen first")
		}
		return nil, fmt.Errorf("reading private key: %w", err)
	}

	raw := string(data)
	seed, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil {
		return nil, fmt.Errorf("decoding private key: %w", err)
	}

	if len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("invalid private key seed length: got %d bytes, want %d", len(seed), ed25519.SeedSize)
	}

	return seed, nil
}
