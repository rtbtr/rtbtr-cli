package cmd

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/spf13/cobra"

	rtbtrcrypto "github.com/rtbtr/rtbtr-cli/internal/crypto"
)

var (
	encryptToFlag      string
	encryptMessageFlag string
)

type encryptEnvelope struct {
	Ciphertext         string `json:"ciphertext"`
	EphemeralPublicKey string `json:"ephemeral_public_key"`
	Algorithm          string `json:"algorithm"`
}

var encryptCmd = &cobra.Command{
	Use:   "encrypt",
	Short: "Encrypt a message for a recipient's Ed25519 public key",
	Long: `Encrypt a message using X25519 ECDH + AES-256-GCM.

Accepts the recipient's Ed25519 public key (URL-safe base64, no padding)
via --to. The message can be provided via --message or piped from stdin.

Outputs a JSON envelope to stdout containing:
  - ciphertext (standard base64)
  - ephemeral_public_key (URL-safe base64, no padding)
  - algorithm ("x25519-aes256gcm")

This command is fully offline — no private key or .rtbtr directory is needed.`,
	Args: cobra.NoArgs,
	RunE: runEncrypt,
}

func runEncrypt(cmd *cobra.Command, args []string) error {
	if encryptToFlag == "" {
		return errors.New("recipient required: use --to <ed25519-public-key>")
	}

	recipientEd25519, err := base64.RawURLEncoding.DecodeString(encryptToFlag)
	if err != nil {
		return fmt.Errorf("invalid recipient public key: %w", err)
	}
	if len(recipientEd25519) != 32 {
		return fmt.Errorf("invalid recipient public key length: got %d bytes, want 32", len(recipientEd25519))
	}

	message, err := resolveMessageInput(cmd, encryptMessageFlag)
	if err != nil {
		return err
	}
	if len(message) > maxMessageBytes {
		return errors.New("message too large (max 1MB)")
	}

	recipientX25519, err := rtbtrcrypto.Ed25519PublicToX25519(recipientEd25519)
	if err != nil {
		return fmt.Errorf("converting recipient key: %w", err)
	}

	ciphertext, ephPub, err := rtbtrcrypto.Encrypt(message, recipientX25519)
	if err != nil {
		return fmt.Errorf("encrypting message: %w", err)
	}

	envelope := encryptEnvelope{
		Ciphertext:         base64.StdEncoding.EncodeToString(ciphertext),
		EphemeralPublicKey: base64.RawURLEncoding.EncodeToString(ephPub),
		Algorithm:          "x25519-aes256gcm",
	}

	encoded, err := json.Marshal(envelope)
	if err != nil {
		return fmt.Errorf("encoding envelope: %w", err)
	}

	_, err = fmt.Fprintln(cmd.OutOrStdout(), string(encoded))
	return err
}

func init() {
	encryptCmd.Flags().StringVar(&encryptToFlag, "to", "", "recipient Ed25519 public key (URL-safe base64)")
	encryptCmd.Flags().StringVar(&encryptMessageFlag, "message", "", "message content to encrypt")
}
