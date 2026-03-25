package cmd

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/spf13/cobra"

	rtbtrcrypto "github.com/rtbtr/rtbtr-cli/internal/crypto"
)

const maxEncryptBytes = 1 << 20 // 1MB

var (
	encryptToFlag      string
	encryptMessageFlag string
)

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

	message, err := resolveEncryptInput(cmd, encryptMessageFlag)
	if err != nil {
		return err
	}
	if len(message) > maxEncryptBytes {
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

	envelope := map[string]string{
		"ciphertext":           base64.StdEncoding.EncodeToString(ciphertext),
		"ephemeral_public_key": base64.RawURLEncoding.EncodeToString(ephPub),
		"algorithm":            "x25519-aes256gcm",
	}

	encoded, err := json.Marshal(envelope)
	if err != nil {
		return fmt.Errorf("encoding envelope: %w", err)
	}

	_, err = fmt.Fprintln(cmd.OutOrStdout(), string(encoded))
	return err
}

func resolveEncryptInput(cmd *cobra.Command, flagValue string) ([]byte, error) {
	if flag := cmd.Flags().Lookup("message"); flag != nil && flag.Changed {
		message := []byte(flagValue)
		if len(bytes.TrimSpace(message)) == 0 {
			return nil, errors.New("message cannot be empty")
		}
		return message, nil
	}

	if stdinIsTerminal() {
		return nil, errors.New("message required: use --message or pipe to stdin")
	}

	message, err := io.ReadAll(io.LimitReader(cmd.InOrStdin(), maxEncryptBytes+1))
	if err != nil {
		return nil, fmt.Errorf("reading stdin: %w", err)
	}
	if len(bytes.TrimSpace(message)) == 0 {
		return nil, errors.New("message cannot be empty")
	}

	return message, nil
}

func init() {
	encryptCmd.Flags().StringVar(&encryptToFlag, "to", "", "recipient Ed25519 public key (URL-safe base64)")
	encryptCmd.Flags().StringVar(&encryptMessageFlag, "message", "", "message content to encrypt")
}
