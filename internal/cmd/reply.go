package cmd

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/rtbtr/rtbtr-cli/internal/signing"
	"github.com/spf13/cobra"
)

var (
	replyMessageFlag string
	replyJsonFlag    bool
)

var replyCmd = &cobra.Command{
	Use:   "reply <message_id>",
	Short: "Reply to a message",
	Args:  cobra.ExactArgs(1),
	RunE:  runReply,
}

func runReply(cmd *cobra.Command, args []string) error {
	messageID := args[0]
	if !uuidPattern.MatchString(messageID) {
		return fmt.Errorf("invalid message ID %q: expected UUID format", messageID)
	}

	message, err := resolveMessageInput(cmd, replyMessageFlag)
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

	body, err := fetchMessageDetail(cmd, cfg.Org, cfg.Bot, seed, messageID)
	if err != nil {
		return err
	}

	var msg messageDetail
	if err := json.Unmarshal(body, &msg); err != nil {
		return fmt.Errorf("parsing response body: %w", err)
	}
	if msg.Sender.PublicKey == nil {
		return errors.New("cannot reply: sender's key has been revoked")
	}
	if msg.Sender.Org == "unknown" && msg.Sender.Bot == "unknown" {
		return errors.New("cannot reply: sender no longer exists")
	}

	senderEd25519Pub, err := base64.RawURLEncoding.DecodeString(*msg.Sender.PublicKey)
	if err != nil {
		return fmt.Errorf("decoding sender public key: %w", err)
	}

	bodyBytes, err := buildEncryptedRequestBody(message, senderEd25519Pub)
	if err != nil {
		return err
	}

	requestURL := fmt.Sprintf("%s/orgs/%s/bots/%s/inbox", apiBaseURL, msg.Sender.Org, msg.Sender.Bot)
	req, err := http.NewRequestWithContext(cmd.Context(), http.MethodPost, requestURL, bytes.NewReader(bodyBytes))
	if err != nil {
		return fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	keyID := fmt.Sprintf("%s/o/%s/%s", platformBaseURL, cfg.Org, cfg.Bot)
	if err := signing.Sign(req, seed, keyID, bodyBytes); err != nil {
		return fmt.Errorf("signing request: %w", err)
	}

	responseBody, err := doRequest(req, checkSendStatus)
	if err != nil {
		return err
	}

	if replyJsonFlag {
		return writeSendOutput(cmd, responseBody, true, "")
	}
	return writeSendOutput(cmd, responseBody, false, "replied to %s -> sent %s\n", messageID)
}

func init() {
	replyCmd.Flags().StringVar(&replyMessageFlag, "message", "", "reply content")
	replyCmd.Flags().BoolVar(&replyJsonFlag, "json", false, "print raw JSON response")
}
