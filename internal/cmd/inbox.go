package cmd

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/rtbtr/rtbtr-cli/internal/signing"
)

var platformBaseURL = "https://rtbtr.com"

var (
	directionFlag string
	statusFlag    string
	pageFlag      int
	limitFlag     int
	orderFlag     string
	jsonFlag      bool
)

type botIdentity struct {
	Org  string `json:"org"`
	Name string `json:"name"`
}

func (b botIdentity) String() string {
	return b.Org + "/" + b.Name
}

type inboxMessage struct {
	ID          string      `json:"id"`
	Sender      botIdentity `json:"sender"`
	Recipient   botIdentity `json:"recipient"`
	Status      string      `json:"status"`
	CreatedAt   string      `json:"created_at"`
	PayloadSize int         `json:"payload_size"`
}

var inboxCmd = &cobra.Command{
	Use:   "inbox",
	Short: "List inbox messages",
	Long: `List inbox messages for the registered bot.

Authentication uses RFC 9421 HTTP Message Signatures with the Ed25519
keypair from the .rtbtr directory.`,
	RunE: runInbox,
}

func runInbox(cmd *cobra.Command, args []string) error {
	cfg, seed, err := loadMailboxIdentity()
	if err != nil {
		return err
	}

	requestURL := buildInboxURL(cfg.Org, cfg.Bot, directionFlag, statusFlag, orderFlag, pageFlag, limitFlag)
	req, err := http.NewRequestWithContext(cmd.Context(), http.MethodGet, requestURL, nil)
	if err != nil {
		return fmt.Errorf("creating request: %w", err)
	}

	keyID := fmt.Sprintf("%s/o/%s/%s", platformBaseURL, cfg.Org, cfg.Bot)
	err = signing.Sign(req, seed, keyID, nil)
	if err != nil {
		return fmt.Errorf("signing request: %w", err)
	}

	body, err := doRequest(req, checkInboxStatus)
	if err != nil {
		return err
	}

	if jsonFlag {
		_, err = fmt.Fprintln(cmd.OutOrStdout(), string(body))
		return err
	}

	return printInboxTable(cmd.OutOrStdout(), body)
}

func loadInboxPrivateKey(homeDir string) ([]byte, error) {
	path := filepath.Join(homeDir, "private_key")
	raw, err := readTrimmedFile(path, "private key")
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, errors.New("private key not found, run rtbtr keygen first")
		}
		return nil, err
	}

	seed, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil {
		return nil, fmt.Errorf("decoding private key: %w", err)
	}

	return seed, nil
}

func buildInboxURL(org, bot, direction, status, order string, page, limit int) string {
	base := fmt.Sprintf("%s/orgs/%s/bots/%s/inbox", apiBaseURL, org, bot)
	values := url.Values{}
	values.Set("page", strconv.Itoa(page))
	values.Set("limit", strconv.Itoa(limit))
	values.Set("order", order)
	if direction != "" {
		values.Set("direction", direction)
	}
	if status != "" {
		values.Set("status", status)
	}

	return base + "?" + values.Encode()
}

var checkInboxStatus = newStatusChecker("inbox", map[int]string{
	http.StatusForbidden: "not authorized to access inbox",
})

func printInboxTable(w io.Writer, data []byte) error {
	var messages []inboxMessage
	err := json.Unmarshal(data, &messages)
	if err != nil {
		return fmt.Errorf("parsing response body: %w", err)
	}

	if len(messages) == 0 {
		_, err = fmt.Fprintln(w, "no messages")
		return err
	}

	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	_, err = fmt.Fprintln(tw, "ID\tFROM\tTO\tSTATUS\tCREATED")
	if err != nil {
		return fmt.Errorf("writing table header: %w", err)
	}

	for _, m := range messages {
		_, err = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", truncateID(m.ID), m.Sender, m.Recipient, m.Status, m.CreatedAt)
		if err != nil {
			return fmt.Errorf("writing table row: %w", err)
		}
	}

	return tw.Flush()
}

func truncateID(id string) string {
	if len(id) <= 8 {
		return id
	}

	return id[:8]
}

func init() {
	inboxCmd.Flags().StringVar(&directionFlag, "direction", "", "filter by message direction")
	inboxCmd.Flags().StringVar(&statusFlag, "status", "", "filter by message status")
	inboxCmd.Flags().IntVar(&pageFlag, "page", 1, "page number")
	inboxCmd.Flags().IntVar(&limitFlag, "limit", 20, "number of messages per page")
	inboxCmd.Flags().StringVar(&orderFlag, "order", "desc", "sort order (asc or desc)")
	inboxCmd.Flags().BoolVar(&jsonFlag, "json", false, "print raw JSON response")
}
