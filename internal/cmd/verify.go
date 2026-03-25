package cmd

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"io"

	"github.com/spf13/cobra"
)

const maxVerifyInputBytes = 1 << 20 // 1MB

// ErrInvalidSignature is returned when signature verification fails.
// This is not a command error — callers should exit 1 without printing "Error:".
var ErrInvalidSignature = errors.New("invalid signature")

var (
	verifyKeyFlag       string
	verifySignatureFlag string
)

var verifyCmd = &cobra.Command{
	Use:   "verify",
	Short: "Verify an Ed25519 signature against a public key",
	Long: `Verify an Ed25519 signature against a public key.

The signer's key can be specified as org/bot (fetches the public key from
the rtbtr API) or as a raw Ed25519 public key (URL-safe base64, no padding).

Content to verify is read from stdin (max 1MB).

Prints "valid" and exits 0 if the signature is good.
Prints "invalid" and exits 1 if the signature is bad.`,
	Args: cobra.NoArgs,
	RunE: runVerify,
}

func runVerify(cmd *cobra.Command, args []string) error {
	pubBytes, err := resolvePublicKey(cmd, verifyKeyFlag)
	if err != nil {
		return err
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
		_, err = fmt.Fprintln(cmd.OutOrStdout(), "valid")
		return err
	}

	fmt.Fprintln(cmd.OutOrStdout(), "invalid")
	return ErrInvalidSignature
}

func init() {
	verifyCmd.Flags().StringVar(&verifyKeyFlag, "key", "", "signer as org/bot or Ed25519 public key (URL-safe base64)")
	verifyCmd.Flags().StringVar(&verifySignatureFlag, "signature", "", "signature to verify (URL-safe base64, no padding)")

	if err := verifyCmd.MarkFlagRequired("key"); err != nil {
		panic(err)
	}
	if err := verifyCmd.MarkFlagRequired("signature"); err != nil {
		panic(err)
	}
}
