package cmd

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"
)

const maxVerifyInputBytes = 1 << 20 // 1MB

var (
	verifyKeyFlag       string
	verifySignatureFlag string
)

// osExit is a package-level variable so tests can override it.
var osExit = os.Exit

var verifyCmd = &cobra.Command{
	Use:   "verify",
	Short: "Verify an Ed25519 signature against a public key",
	Long: `Verify an Ed25519 signature against a public key.

Content to verify is read from stdin (max 1MB). The public key and
signature are provided as URL-safe base64 (no padding) via flags.

Prints "valid" and exits 0 if the signature is good.
Prints "invalid" and exits 1 if the signature is bad.`,
	Args: cobra.NoArgs,
	RunE: runVerify,
}

func runVerify(cmd *cobra.Command, args []string) error {
	pubBytes, err := base64.RawURLEncoding.DecodeString(verifyKeyFlag)
	if err != nil {
		return fmt.Errorf("decoding public key: %w", err)
	}
	if len(pubBytes) != ed25519.PublicKeySize {
		return fmt.Errorf("invalid public key length: got %d bytes, want %d", len(pubBytes), ed25519.PublicKeySize)
	}

	sigBytes, err := base64.RawURLEncoding.DecodeString(verifySignatureFlag)
	if err != nil {
		return fmt.Errorf("decoding signature: %w", err)
	}
	if len(sigBytes) != ed25519.SignatureSize {
		return fmt.Errorf("invalid signature length: got %d bytes, want %d", len(sigBytes), ed25519.SignatureSize)
	}

	content, err := io.ReadAll(io.LimitReader(cmd.InOrStdin(), maxVerifyInputBytes+1))
	if err != nil {
		return fmt.Errorf("reading stdin: %w", err)
	}
	if len(content) == 0 {
		return errors.New("empty input: stdin must contain data to verify")
	}
	if len(content) > maxVerifyInputBytes {
		return errors.New("input too large (max 1MB)")
	}

	pubKey := ed25519.PublicKey(pubBytes)
	if ed25519.Verify(pubKey, content, sigBytes) {
		if _, err := fmt.Fprintln(cmd.OutOrStdout(), "valid"); err != nil {
			return fmt.Errorf("writing result to stdout: %w", err)
		}
		return nil
	}

	fmt.Fprintln(cmd.OutOrStdout(), "invalid")
	osExit(1)
	return nil // unreachable in production; allows tests to continue
}

func init() {
	verifyCmd.Flags().StringVar(&verifyKeyFlag, "key", "", "signer's Ed25519 public key (URL-safe base64, no padding)")
	verifyCmd.Flags().StringVar(&verifySignatureFlag, "signature", "", "signature to verify (URL-safe base64, no padding)")

	if err := verifyCmd.MarkFlagRequired("key"); err != nil {
		panic(err)
	}
	if err := verifyCmd.MarkFlagRequired("signature"); err != nil {
		panic(err)
	}
}
