package cmd

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/rtbtr/rtbtr-cli/internal/home"
)

var forceFlag bool

var keygenCmd = &cobra.Command{
	Use:   "keygen",
	Short: "Generate an Ed25519 keypair",
	Long: `Generate an Ed25519 keypair and store it in the .rtbtr directory.

The private key seed and public key are written as URL-safe base64
(no padding) to private_key and public_key files respectively.
The public key is also printed to stdout.`,
	RunE: runKeygen,
}

func runKeygen(cmd *cobra.Command, args []string) error {
	homeDir, err := home.Resolve(homeFlag, true)
	if err != nil {
		return fmt.Errorf("resolving home directory: %w", err)
	}

	if mkErr := os.MkdirAll(homeDir, 0o755); mkErr != nil {
		return fmt.Errorf("creating home directory: %w", mkErr)
	}

	privPath := filepath.Join(homeDir, "private_key")
	pubPath := filepath.Join(homeDir, "public_key")

	if !forceFlag {
		if _, statErr := os.Stat(privPath); statErr == nil {
			return fmt.Errorf("private key already exists at %s, use --force to overwrite", privPath)
		}

		if _, statErr := os.Stat(pubPath); statErr == nil {
			return fmt.Errorf("public key already exists at %s, use --force to overwrite", pubPath)
		}
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("generating keypair: %w", err)
	}

	seed := priv.Seed()
	privB64 := base64.RawURLEncoding.EncodeToString(seed)
	pubB64 := base64.RawURLEncoding.EncodeToString(pub)

	if err := os.WriteFile(privPath, []byte(privB64), 0o600); err != nil {
		return fmt.Errorf("writing private key: %w", err)
	}

	if err := os.WriteFile(pubPath, []byte(pubB64), 0o600); err != nil {
		return fmt.Errorf("writing public key: %w", err)
	}

	warnIfGitRepo(cmd.ErrOrStderr(), homeDir)

	if _, err := fmt.Fprintln(cmd.OutOrStdout(), pubB64); err != nil {
		return fmt.Errorf("writing public key to stdout: %w", err)
	}

	return nil
}

// warnIfGitRepo walks up from homeDir looking for a .git directory.
// If found, it prints a warning to w advising the user to update .gitignore.
func warnIfGitRepo(w io.Writer, homeDir string) {
	if _, ok := home.FindDirUp(filepath.Dir(homeDir), ".git"); ok {
		fmt.Fprintln(w, "warning: .rtbtr is inside a git repository; add private_key to .gitignore to avoid committing secrets")
	}
}

func init() {
	keygenCmd.Flags().BoolVar(&forceFlag, "force", false, "overwrite existing key files")
}
