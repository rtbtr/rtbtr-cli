package cmd

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/spf13/cobra"

	rtbtrcrypto "github.com/rtbtr/rtbtr-cli/internal/crypto"
	"github.com/rtbtr/rtbtr-cli/internal/home"
)

var decryptPayloadFlag string

var decryptCmd = &cobra.Command{
	Use:   "decrypt",
	Short: "Decrypt an encrypted envelope using your private key",
	Long: `Decrypt an X25519 ECDH + AES-256-GCM encrypted envelope.

Accepts a JSON envelope via --payload or piped from stdin. The envelope
must contain ciphertext, ephemeral_public_key, and algorithm fields.

Uses the Ed25519 private key from the .rtbtr directory to derive the
X25519 decryption key and recover the original plaintext.

Outputs the raw decrypted bytes to stdout — suitable for piping.`,
	Args: cobra.NoArgs,
	RunE: runDecrypt,
}

type decryptEnvelope struct {
	Ciphertext         string `json:"ciphertext"`
	EphemeralPublicKey string `json:"ephemeral_public_key"`
	Algorithm          string `json:"algorithm"`
}

func runDecrypt(cmd *cobra.Command, args []string) error {
	payload, err := resolveDecryptPayload(cmd)
	if err != nil {
		return err
	}

	var envelope decryptEnvelope
	if err := json.Unmarshal([]byte(payload), &envelope); err != nil {
		return fmt.Errorf("invalid payload: %w", err)
	}

	if envelope.Ciphertext == "" {
		return errors.New("invalid payload: missing ciphertext field")
	}
	if envelope.EphemeralPublicKey == "" {
		return errors.New("invalid payload: missing ephemeral_public_key field")
	}

	ciphertext, err := base64.StdEncoding.DecodeString(envelope.Ciphertext)
	if err != nil {
		return fmt.Errorf("decoding ciphertext: %w", err)
	}

	ephPub, err := base64.RawURLEncoding.DecodeString(envelope.EphemeralPublicKey)
	if err != nil {
		return fmt.Errorf("decoding ephemeral public key: %w", err)
	}

	homeDir, err := home.Resolve(homeFlag, false)
	if err != nil {
		return fmt.Errorf("resolving home directory: %w", err)
	}

	seed, err := home.LoadPrivateKey(homeDir)
	if err != nil {
		return err
	}

	privKey, _, err := rtbtrcrypto.DeriveX25519KeyPair(seed)
	if err != nil {
		return fmt.Errorf("deriving X25519 key: %w", err)
	}

	plaintext, err := rtbtrcrypto.Decrypt(ciphertext, ephPub, privKey)
	if err != nil {
		return fmt.Errorf("decryption failed: %w", err)
	}

	// Write raw plaintext bytes to stdout — no trailing newline, no
	// conversion. This preserves exact decrypted content for piping.
	_, err = cmd.OutOrStdout().Write(plaintext)
	return err
}

func resolveDecryptPayload(cmd *cobra.Command) (string, error) {
	if flag := cmd.Flags().Lookup("payload"); flag != nil && flag.Changed {
		if decryptPayloadFlag == "" {
			return "", errors.New("payload cannot be empty")
		}
		return decryptPayloadFlag, nil
	}

	if stdinIsTerminal() {
		return "", errors.New("payload required: use --payload or pipe to stdin")
	}

	data, err := io.ReadAll(cmd.InOrStdin())
	if err != nil {
		return "", fmt.Errorf("reading stdin: %w", err)
	}
	if len(data) == 0 {
		return "", errors.New("payload cannot be empty")
	}

	return string(data), nil
}

func init() {
	decryptCmd.Flags().StringVar(&decryptPayloadFlag, "payload", "", "JSON envelope to decrypt")
}
