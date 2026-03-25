package cmd

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

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
	Short: "Encrypt a message for a recipient",
	Long: `Encrypt a message using X25519 ECDH + AES-256-GCM.

The recipient can be specified as org/bot (fetches the public key from the
rtbtr API) or as a raw Ed25519 public key (URL-safe base64, no padding).

The message can be provided via --message or piped from stdin.

Outputs a JSON envelope to stdout containing:
  - ciphertext (standard base64)
  - ephemeral_public_key (URL-safe base64, no padding)
  - algorithm ("x25519-aes256gcm")`,
	Args: cobra.NoArgs,
	RunE: runEncrypt,
}

func runEncrypt(cmd *cobra.Command, args []string) error {
	if encryptToFlag == "" {
		return errors.New("recipient required: use --to org/bot or --to <public-key>")
	}

	recipientEd25519, err := resolvePublicKey(cmd, encryptToFlag)
	if err != nil {
		return err
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

// resolvePublicKey accepts either "org/bot" (fetches from API) or a raw
// Ed25519 public key (URL-safe base64). Returns the 32-byte Ed25519 key.
func resolvePublicKey(cmd *cobra.Command, value string) ([]byte, error) {
	if strings.Contains(value, "/") {
		org, bot, err := parseRecipient(value)
		if err != nil {
			return nil, err
		}
		key, err := rtbtrcrypto.FetchRecipientKey(cmd.Context(), apiBaseURL, org, bot)
		if err != nil {
			if strings.Contains(err.Error(), "not found") {
				return nil, fmt.Errorf("recipient %s not found", value)
			}
			return nil, fmt.Errorf("fetching recipient key: %w", err)
		}
		return key, nil
	}

	key, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		return nil, fmt.Errorf("invalid public key: %w", err)
	}
	if len(key) != 32 {
		return nil, fmt.Errorf("invalid public key length: got %d bytes, want 32", len(key))
	}
	return key, nil
}

func init() {
	encryptCmd.Flags().StringVar(&encryptToFlag, "to", "", "recipient as org/bot or Ed25519 public key (URL-safe base64)")
	encryptCmd.Flags().StringVar(&encryptMessageFlag, "message", "", "message content to encrypt")
}
