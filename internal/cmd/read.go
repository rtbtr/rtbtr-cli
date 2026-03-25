package cmd

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"unicode/utf8"

	"github.com/spf13/cobra"

	rtbtrcrypto "github.com/rtbtr/rtbtr-cli/internal/crypto"
	"github.com/rtbtr/rtbtr-cli/internal/signing"
)

var (
	readJSONFlag bool
	uuidPattern  = regexp.MustCompile(`(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
)

type messageDetail struct {
	ID               string          `json:"id"`
	Sender           messageSender   `json:"sender"`
	Recipient        string          `json:"recipient"`
	EncryptedPayload string          `json:"encrypted_payload"`
	Encryption       *encryptionMeta `json:"encryption"`
	Status           string          `json:"status"`
	CreatedAt        string          `json:"created_at"`
}

type messageSender struct {
	PublicKey *string `json:"public_key"`
	Org       string  `json:"org"`
	Name      string  `json:"name"`
}

type encryptionMeta struct {
	Algorithm          string `json:"algorithm"`
	RecipientPublicKey string `json:"recipient_public_key"`
	EphemeralPublicKey string `json:"ephemeral_public_key"`
}

var readCmd = &cobra.Command{
	Use:   "read <message_id>",
	Short: "Read and decrypt a message",
	Args:  cobra.ExactArgs(1),
	RunE:  runRead,
}

func runRead(cmd *cobra.Command, args []string) error {
	messageID := args[0]
	if !uuidPattern.MatchString(messageID) {
		return fmt.Errorf("invalid message ID %q: expected UUID format", messageID)
	}

	cfg, seed, err := loadMailboxIdentity()
	if err != nil {
		return err
	}

	body, err := fetchMessageDetail(cmd, cfg.Org, cfg.Bot, seed, messageID)
	if err != nil {
		return err
	}

	var msg messageDetail
	if err := json.Unmarshal(body, &msg); err != nil {
		return fmt.Errorf("parsing response body: %w", err)
	}

	plaintext, decryptErr := decryptMessageContent(&msg, seed)
	if readJSONFlag {
		return writeReadJSONOutput(cmd, &msg, plaintext, decryptErr)
	}

	return writeReadDefaultOutput(cmd, &msg, plaintext, decryptErr)
}

func fetchMessageDetail(cmd *cobra.Command, org, bot string, seed []byte, messageID string) ([]byte, error) {
	requestURL := fmt.Sprintf("%s/orgs/%s/bots/%s/inbox/%s", apiBaseURL, org, bot, messageID)
	req, err := http.NewRequestWithContext(cmd.Context(), http.MethodGet, requestURL, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	keyID := fmt.Sprintf("%s/o/%s/%s", platformBaseURL, org, bot)
	if signErr := signing.Sign(req, seed, keyID, nil); signErr != nil {
		return nil, fmt.Errorf("signing request: %w", signErr)
	}

	body, err := doRequest(req, checkReadStatus)
	if err != nil {
		return nil, err
	}

	return body, nil
}

func decryptMessageContent(msg *messageDetail, seed []byte) ([]byte, error) {
	ciphertext, err := base64.StdEncoding.DecodeString(msg.EncryptedPayload)
	if err != nil {
		return nil, fmt.Errorf("decoding encrypted payload: %w", err)
	}
	if msg.Encryption == nil {
		return nil, errors.New("missing encryption metadata")
	}

	ephPub, err := base64.RawURLEncoding.DecodeString(msg.Encryption.EphemeralPublicKey)
	if err != nil {
		return nil, fmt.Errorf("decoding ephemeral public key: %w", err)
	}

	privKey, _, err := rtbtrcrypto.DeriveX25519KeyPair(seed)
	if err != nil {
		return nil, fmt.Errorf("deriving recipient X25519 key: %w", err)
	}

	plaintext, err := rtbtrcrypto.Decrypt(ciphertext, ephPub, privKey)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

type readJSONOutput struct {
	ID           string          `json:"id"`
	Sender       messageSender   `json:"sender"`
	Content      *string         `json:"content"`
	DecryptError *string         `json:"decrypt_error,omitempty"`
	Encryption   *encryptionMeta `json:"encryption,omitempty"`
	Status       string          `json:"status"`
	CreatedAt    string          `json:"created_at"`
}

func writeReadJSONOutput(cmd *cobra.Command, msg *messageDetail, plaintext []byte, decryptErr error) error {
	out := readJSONOutput{
		ID:         msg.ID,
		Sender:     msg.Sender,
		Encryption: msg.Encryption,
		Status:     msg.Status,
		CreatedAt:  msg.CreatedAt,
	}

	if decryptErr != nil {
		errStr := decryptErr.Error()
		out.DecryptError = &errStr
	} else {
		content := string(plaintext)
		out.Content = &content
	}

	encoded, err := json.Marshal(out)
	if err != nil {
		return fmt.Errorf("encoding JSON output: %w", err)
	}
	if _, err := fmt.Fprintln(cmd.OutOrStdout(), string(encoded)); err != nil {
		return err
	}

	if decryptErr != nil {
		if _, err := fmt.Fprintln(cmd.ErrOrStderr(), decryptErr.Error()); err != nil {
			return err
		}
		return decryptErr
	}

	return nil
}

func writeReadDefaultOutput(cmd *cobra.Command, msg *messageDetail, plaintext []byte, decryptErr error) error {
	if _, err := fmt.Fprintf(cmd.OutOrStdout(), "From: %s/%s\nDate: %s\nStatus: %s\n\n", msg.Sender.Org, msg.Sender.Name, msg.CreatedAt, msg.Status); err != nil {
		return err
	}

	if decryptErr != nil {
		if _, err := fmt.Fprintln(cmd.ErrOrStderr(), decryptErr.Error()); err != nil {
			return err
		}
		return decryptErr
	}

	if utf8.Valid(plaintext) {
		_, err := fmt.Fprintln(cmd.OutOrStdout(), string(plaintext))
		return err
	}

	_, err := cmd.OutOrStdout().Write(plaintext)
	return err
}

var checkReadStatus = newStatusChecker("read", map[int]string{
	http.StatusForbidden: "not authorized to read this message",
	http.StatusNotFound:  "message not found",
})

func init() {
	readCmd.Flags().BoolVar(&readJSONFlag, "json", false, "print raw JSON output with decrypted content")
}
