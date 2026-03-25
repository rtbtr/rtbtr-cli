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

Specify the recipient as org/bot. The public key is fetched from the
rtbtr API. The message can be provided via --message or piped from stdin.

Outputs a JSON envelope to stdout containing:
  - ciphertext (standard base64)
  - ephemeral_public_key (URL-safe base64, no padding)
  - algorithm ("x25519-aes256gcm")`,
	Args: cobra.NoArgs,
	RunE: runEncrypt,
}

func runEncrypt(cmd *cobra.Command, args []string) error {
	org, bot, err := parseRecipient(encryptToFlag)
	if err != nil {
		return err
	}

	recipientEd25519, err := rtbtrcrypto.FetchRecipientKey(cmd.Context(), apiBaseURL, org, bot)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			return fmt.Errorf("recipient %s/%s not found", org, bot)
		}
		return fmt.Errorf("fetching recipient key: %w", err)
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
	encryptCmd.Flags().StringVar(&encryptToFlag, "to", "", "recipient in org/bot format")
	encryptCmd.Flags().StringVar(&encryptMessageFlag, "message", "", "message content to encrypt")

	if err := encryptCmd.MarkFlagRequired("to"); err != nil {
		panic(err)
	}
}
