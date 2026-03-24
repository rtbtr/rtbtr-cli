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
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/rtbtr/rtbtr-cli/internal/config"
	"github.com/rtbtr/rtbtr-cli/internal/home"
	"github.com/rtbtr/rtbtr-cli/internal/signing"
)

var (
	directionFlag string
	statusFlag    string
	pageFlag      int
	limitFlag     int
	orderFlag     string
	jsonFlag      bool
)

var inboxCmd = &cobra.Command{
	Use:   "inbox",
	Short: "List inbox messages",
	Long: `List inbox messages for the registered bot.

Authentication uses RFC 9421 HTTP Message Signatures with the Ed25519
keypair from the .rtbtr directory.`,
	RunE: runInbox,
}

func runInbox(cmd *cobra.Command, args []string) error {
	homeDir, err := home.Resolve(homeFlag, false)
	if err != nil {
		return fmt.Errorf("resolving home directory: %w", err)
	}

	cfg, err := config.Load(homeDir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return errors.New("not registered: run rtbtr register first")
		}
		return fmt.Errorf("loading config: %w", err)
	}

	if cfg.Org == "" || cfg.Bot == "" {
		return errors.New("not registered: run rtbtr register first")
	}

	seed, err := loadInboxPrivateKey(homeDir)
	if err != nil {
		return err
	}

	requestURL := buildInboxURL(cfg.Org, cfg.Bot)
	req, err := http.NewRequestWithContext(cmd.Context(), http.MethodGet, requestURL, nil)
	if err != nil {
		return fmt.Errorf("creating request: %w", err)
	}

	keyID := cfg.Org + "/" + cfg.Bot
	err = signing.Sign(req, seed, keyID)
	if err != nil {
		return fmt.Errorf("signing request: %w", err)
	}

	body, err := executeInboxRequest(req)
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
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, errors.New("private key not found, run rtbtr keygen first")
		}
		return nil, fmt.Errorf("reading private key: %w", err)
	}

	trimmed := strings.TrimSpace(string(data))
	seed, err := base64.RawURLEncoding.DecodeString(trimmed)
	if err != nil {
		return nil, fmt.Errorf("decoding private key: %w", err)
	}

	return seed, nil
}

func buildInboxURL(org, bot string) string {
	base := fmt.Sprintf("%s/orgs/%s/bots/%s/inbox", apiBaseURL, org, bot)
	values := url.Values{}
	values.Set("page", strconv.Itoa(pageFlag))
	values.Set("limit", strconv.Itoa(limitFlag))
	values.Set("order", orderFlag)
	if directionFlag != "" {
		values.Set("direction", directionFlag)
	}
	if statusFlag != "" {
		values.Set("status", statusFlag)
	}

	return base + "?" + values.Encode()
}

func executeInboxRequest(req *http.Request) ([]byte, error) {
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("sending request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response body: %w", err)
	}

	statusErr := checkInboxStatus(resp.StatusCode, resp.Status, body)
	if statusErr != nil {
		return nil, statusErr
	}

	return body, nil
}

func checkInboxStatus(statusCode int, status string, body []byte) error {
	switch statusCode {
	case http.StatusUnauthorized:
		return errors.New("authentication failed: signature rejected")
	case http.StatusForbidden:
		return errors.New("not authorized to access inbox")
	}

	if statusCode < http.StatusOK || statusCode >= http.StatusMultipleChoices {
		return fmt.Errorf("inbox failed: %s: %s", status, strings.TrimSpace(string(body)))
	}

	return nil
}

func printInboxTable(w io.Writer, data []byte) error {
	var messages []map[string]interface{}
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

	for _, message := range messages {
		id := truncateID(getStr(message, "id"))
		_, err = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", id, getStr(message, "sender"), getStr(message, "recipient"), getStr(message, "status"), getStr(message, "created_at"))
		if err != nil {
			return fmt.Errorf("writing table row: %w", err)
		}
	}

	err = tw.Flush()
	if err != nil {
		return fmt.Errorf("flushing table writer: %w", err)
	}

	return nil
}

func truncateID(id string) string {
	if len(id) <= 8 {
		return id
	}

	return id[:8]
}

func getStr(m map[string]interface{}, key string) string {
	if v, ok := m[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}

	return "-"
}

func init() {
	inboxCmd.Flags().StringVar(&directionFlag, "direction", "", "filter by message direction")
	inboxCmd.Flags().StringVar(&statusFlag, "status", "", "filter by message status")
	inboxCmd.Flags().IntVar(&pageFlag, "page", 1, "page number")
	inboxCmd.Flags().IntVar(&limitFlag, "limit", 20, "number of messages per page")
	inboxCmd.Flags().StringVar(&orderFlag, "order", "desc", "sort order (asc or desc)")
	inboxCmd.Flags().BoolVar(&jsonFlag, "json", false, "print raw JSON response")
}
