package cmd

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"io"

	"github.com/spf13/cobra"

	"github.com/rtbtr/rtbtr-cli/internal/home"
)

const maxSignInputBytes = 1 << 20 // 1MB

var signCmd = &cobra.Command{
	Use:   "sign",
	Short: "Sign stdin with your Ed25519 private key",
	Long: `Sign stdin with the Ed25519 private key from the .rtbtr directory.

Reads all of stdin as the content to sign (max 1MB) and outputs
the 64-byte Ed25519 signature as URL-safe base64 (no padding) to stdout.`,
	Args: cobra.NoArgs,
	RunE: runSign,
}

func runSign(cmd *cobra.Command, args []string) error {
	homeDir, err := home.Resolve(homeFlag, false)
	if err != nil {
		return fmt.Errorf("resolving home directory: %w", err)
	}

	seed, err := home.LoadPrivateKey(homeDir)
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
	_, err = fmt.Fprintln(cmd.OutOrStdout(), sigB64)
	return err
}
