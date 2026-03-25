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

var encryptCmd = &cobra.Command{
	Use:   "encrypt",
	Short: "Encrypt a message for a recipient's public key (offline)",
	Args:  cobra.NoArgs,
	RunE:  runEncrypt,
}

type encryptEnvelope struct {
	Ciphertext         string `json:"ciphertext"`
	EphemeralPublicKey string `json:"ephemeral_public_key"`
	Algorithm          string `json:"algorithm"`
}

func runEncrypt(cmd *cobra.Command, args []string) error {
	if encryptToFlag == "" {
		return errors.New("recipient required: use --to <ed25519-public-key>")
	}

	message, err := resolveMessageInput(cmd, encryptMessageFlag)
	if err != nil {
		return err
	}
	if len(message) > maxMessageBytes {
		return errors.New("message too large (max 1MB)")
	}

	recipientEd25519Pub, err := base64.RawURLEncoding.DecodeString(encryptToFlag)
	if err != nil {
		return fmt.Errorf("decoding recipient public key: %w", err)
	}

	recipientX25519, err := rtbtrcrypto.Ed25519PublicToX25519(recipientEd25519Pub)
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

	output, err := json.Marshal(envelope)
	if err != nil {
		return fmt.Errorf("marshaling envelope: %w", err)
	}

	_, err = fmt.Fprintln(cmd.OutOrStdout(), string(output))
	return err
}

func init() {
	encryptCmd.Flags().StringVar(&encryptToFlag, "to", "", "recipient Ed25519 public key (base64url)")
	encryptCmd.Flags().StringVar(&encryptMessageFlag, "message", "", "message content")

	if err := encryptCmd.MarkFlagRequired("to"); err != nil {
		panic(err)
	}
}
