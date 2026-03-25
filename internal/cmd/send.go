package cmd

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/rtbtr/rtbtr-cli/internal/config"
	rtbtrcrypto "github.com/rtbtr/rtbtr-cli/internal/crypto"
	"github.com/rtbtr/rtbtr-cli/internal/home"
	"github.com/rtbtr/rtbtr-cli/internal/signing"
)

const maxMessageBytes = 1 << 20

var (
	sendToFlag      string
	sendMessageFlag string
	sendJSONFlag    bool
	stdinIsTerminal = func() bool {
		fi, err := os.Stdin.Stat()
		if err != nil {
			return true
		}
		return fi.Mode()&os.ModeCharDevice != 0
	}
)

var sendCmd = &cobra.Command{
	Use:   "send",
	Short: "Send an encrypted message to a bot",
	Args:  cobra.NoArgs,
	RunE:  runSend,
}

type sendRequestBody struct {
	EncryptedPayload string                `json:"encrypted_payload"`
	Encryption       sendRequestEncryption `json:"encryption"`
}

type sendRequestEncryption struct {
	Algorithm          string `json:"algorithm"`
	RecipientPublicKey string `json:"recipient_public_key"`
	EphemeralPublicKey string `json:"ephemeral_public_key"`
}

type sendResponse struct {
	ID string `json:"message_id"`
}

func runSend(cmd *cobra.Command, args []string) error {
	recipientOrg, recipientBot, err := parseRecipient(sendToFlag)
	if err != nil {
		return err
	}

	message, err := resolveMessageInput(cmd, sendMessageFlag)
	if err != nil {
		return err
	}
	if len(message) > maxMessageBytes {
		return errors.New("message too large (max 1MB)")
	}

	cfg, seed, err := loadMailboxIdentity()
	if err != nil {
		return err
	}

	recipientPubKey, err := rtbtrcrypto.FetchRecipientKey(cmd.Context(), apiBaseURL, recipientOrg, recipientBot)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			return errors.New("recipient not found")
		}
		return fmt.Errorf("fetching recipient profile: %w", err)
	}

	bodyBytes, err := buildEncryptedRequestBody(message, recipientPubKey)
	if err != nil {
		return err
	}

	requestURL := fmt.Sprintf("%s/orgs/%s/bots/%s/inbox", apiBaseURL, recipientOrg, recipientBot)
	req, err := http.NewRequestWithContext(cmd.Context(), http.MethodPost, requestURL, bytes.NewReader(bodyBytes))
	if err != nil {
		return fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	keyID := fmt.Sprintf("%s/o/%s/%s", platformBaseURL, cfg.Org, cfg.Bot)
	if signErr := signing.Sign(req, seed, keyID, bodyBytes); signErr != nil {
		return fmt.Errorf("signing request: %w", signErr)
	}

	responseBody, err := doRequest(req, checkSendStatus)
	if err != nil {
		return err
	}

	return writeSendOutput(cmd, responseBody, sendJSONFlag, "sent %s\n")
}

func parseRecipient(value string) (string, string, error) {
	if value == "" {
		return "", "", errors.New("recipient required: use --to org/bot")
	}
	if strings.Count(value, "/") != 1 {
		return "", "", fmt.Errorf("invalid recipient %q: expected org/bot", value)
	}

	parts := strings.SplitN(value, "/", 2)
	if parts[0] == "" || parts[1] == "" {
		return "", "", fmt.Errorf("invalid recipient %q: expected org/bot", value)
	}

	return parts[0], parts[1], nil
}

func resolveMessageInput(cmd *cobra.Command, flagValue string) ([]byte, error) {
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

	message, err := io.ReadAll(io.LimitReader(cmd.InOrStdin(), maxMessageBytes+1))
	if err != nil {
		return nil, fmt.Errorf("reading stdin: %w", err)
	}
	if len(bytes.TrimSpace(message)) == 0 {
		return nil, errors.New("message cannot be empty")
	}

	return message, nil
}

func loadMailboxIdentity() (*config.Config, []byte, error) {
	homeDir, err := home.Resolve(homeFlag, false)
	if err != nil {
		return nil, nil, fmt.Errorf("resolving home directory: %w", err)
	}

	cfg, err := config.Load(homeDir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil, errors.New("not registered: run rtbtr register first")
		}
		return nil, nil, fmt.Errorf("loading config: %w", err)
	}
	if cfg.Org == "" || cfg.Bot == "" {
		return nil, nil, errors.New("not registered: run rtbtr register first")
	}

	seed, err := loadInboxPrivateKey(homeDir)
	if err != nil {
		return nil, nil, err
	}

	return cfg, seed, nil
}

func buildEncryptedRequestBody(message, recipientEd25519Public []byte) ([]byte, error) {
	recipientX25519, err := rtbtrcrypto.Ed25519PublicToX25519(recipientEd25519Public)
	if err != nil {
		return nil, fmt.Errorf("converting recipient key: %w", err)
	}

	encrypted, ephPub, err := rtbtrcrypto.Encrypt(message, recipientX25519)
	if err != nil {
		return nil, fmt.Errorf("encrypting message: %w", err)
	}

	body := sendRequestBody{
		EncryptedPayload: base64.StdEncoding.EncodeToString(encrypted),
		Encryption: sendRequestEncryption{
			Algorithm:          "x25519-aes256gcm",
			RecipientPublicKey: base64.RawURLEncoding.EncodeToString(recipientX25519),
			EphemeralPublicKey: base64.RawURLEncoding.EncodeToString(ephPub),
		},
	}

	bodyBytes, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("marshaling request body: %w", err)
	}

	return bodyBytes, nil
}

func writeSendOutput(cmd *cobra.Command, responseBody []byte, jsonOutput bool, successFormat string, args ...any) error {
	if jsonOutput {
		_, err := fmt.Fprintln(cmd.OutOrStdout(), string(responseBody))
		return err
	}

	var response sendResponse
	if err := json.Unmarshal(responseBody, &response); err != nil {
		return fmt.Errorf("parsing response body: %w", err)
	}

	values := append(append([]any(nil), args...), response.ID)
	_, err := fmt.Fprintf(cmd.OutOrStdout(), successFormat, values...)
	return err
}

func checkSendStatus(statusCode int, status string, body []byte) error {
	trimmed := strings.TrimSpace(string(body))

	switch statusCode {
	case http.StatusUnauthorized:
		return errors.New("authentication failed: signature rejected")
	case http.StatusNotFound:
		return errors.New("recipient not found")
	case http.StatusUnprocessableEntity:
		return fmt.Errorf("invalid message: %s", trimmed)
	}

	if statusCode < http.StatusOK || statusCode >= http.StatusMultipleChoices {
		return fmt.Errorf("send failed: %s: %s", status, trimmed)
	}

	return nil
}

func init() {
	sendCmd.Flags().StringVar(&sendToFlag, "to", "", "recipient in org/bot format")
	sendCmd.Flags().StringVar(&sendMessageFlag, "message", "", "message content")
	sendCmd.Flags().BoolVar(&sendJSONFlag, "json", false, "print raw JSON response")

	if err := sendCmd.MarkFlagRequired("to"); err != nil {
		panic(err)
	}
}
