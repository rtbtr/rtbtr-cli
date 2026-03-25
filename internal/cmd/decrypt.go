package cmd

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"unicode/utf8"

	"github.com/spf13/cobra"

	rtbtrcrypto "github.com/rtbtr/rtbtr-cli/internal/crypto"
	"github.com/rtbtr/rtbtr-cli/internal/home"
)

var (
	decryptPayloadFlag string
)

var decryptCmd = &cobra.Command{
	Use:   "decrypt",
	Short: "Decrypt an encrypted envelope using your private key",
	Args:  cobra.NoArgs,
	RunE:  runDecrypt,
}

type decryptInputEnvelope struct {
	Ciphertext         string `json:"ciphertext"`
	EphemeralPublicKey string `json:"ephemeral_public_key"`
	Algorithm          string `json:"algorithm"`
}

func runDecrypt(cmd *cobra.Command, args []string) error {
	payloadStr, err := resolveDecryptPayload(cmd)
	if err != nil {
		return err
	}

	var envelope decryptInputEnvelope
	if err = json.Unmarshal([]byte(payloadStr), &envelope); err != nil {
		return fmt.Errorf("parsing payload JSON: %w", err)
	}

	if envelope.Ciphertext == "" {
		return errors.New("payload missing ciphertext field")
	}
	if envelope.EphemeralPublicKey == "" {
		return errors.New("payload missing ephemeral_public_key field")
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
		return fmt.Errorf("resolving .rtbtr directory: %w", err)
	}

	seed, err := loadDecryptPrivateKey(homeDir)
	if err != nil {
		return err
	}

	privKey, _, err := rtbtrcrypto.DeriveX25519KeyPair(seed)
	if err != nil {
		return fmt.Errorf("deriving recipient X25519 key: %w", err)
	}

	plaintext, err := rtbtrcrypto.Decrypt(ciphertext, ephPub, privKey)
	if err != nil {
		return err
	}

	if utf8.Valid(plaintext) {
		_, err = fmt.Fprintln(cmd.OutOrStdout(), string(plaintext))
		return err
	}

	_, err = cmd.OutOrStdout().Write(plaintext)
	return err
}

func resolveDecryptPayload(cmd *cobra.Command) (string, error) {
	if flag := cmd.Flags().Lookup("payload"); flag != nil && flag.Changed {
		payload := decryptPayloadFlag
		if payload == "" {
			return "", errors.New("payload cannot be empty")
		}
		return payload, nil
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

func loadDecryptPrivateKey(homeDir string) ([]byte, error) {
	return home.LoadPrivateKey(homeDir)
}

func init() {
	decryptCmd.Flags().StringVar(&decryptPayloadFlag, "payload", "", "encrypted JSON envelope")
}
