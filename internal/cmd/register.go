package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/rtbtr/rtbtr-cli/internal/config"
	"github.com/rtbtr/rtbtr-cli/internal/home"
)

var (
	orgFlag           string
	botFlag           string
	registerForceFlag bool
	apiBaseURL        = "https://api.rtbtr.com"
	httpClient        = &http.Client{Timeout: 30 * time.Second}
	slugPattern       = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)
)

const maxResponseBytes = 1 << 20

type registerRequest struct {
	Name      string `json:"name"`
	PublicKey string `json:"public_key"`
}

type registerResponse struct {
	BotID string `json:"bot_id"`
}

var registerCmd = &cobra.Command{
	Use:   "register",
	Short: "Register bot with the rtbtr platform",
	RunE:  runRegister,
}

func runRegister(cmd *cobra.Command, args []string) error {
	if !slugPattern.MatchString(orgFlag) {
		return fmt.Errorf("invalid org %q: must contain only letters, digits, hyphens, or underscores", orgFlag)
	}
	if !slugPattern.MatchString(botFlag) {
		return fmt.Errorf("invalid bot %q: must contain only letters, digits, hyphens, or underscores", botFlag)
	}

	homeDir, err := home.Resolve(homeFlag, false)
	if err != nil {
		return fmt.Errorf("resolving home directory: %w", err)
	}

	if err = rejectExistingRegistration(homeDir); err != nil {
		return err
	}

	pubPath, tokenPath, err := ensureRegisterInputs(homeDir)
	if err != nil {
		return err
	}

	pubKey, err := readTrimmedFile(pubPath, "public key")
	if err != nil {
		return err
	}

	orgToken, err := readTrimmedFile(tokenPath, "org token")
	if err != nil {
		return err
	}

	response, err := registerBot(cmd.Context(), orgFlag, botFlag, pubKey, orgToken)
	if err != nil {
		return err
	}

	if err = config.Write(homeDir, &config.Config{Org: orgFlag, Bot: botFlag}); err != nil {
		return fmt.Errorf("writing config: %w", err)
	}

	return printRegistrationSuccess(cmd.OutOrStdout(), orgFlag, botFlag, response.BotID)
}

func rejectExistingRegistration(homeDir string) error {
	if registerForceFlag {
		return nil
	}

	cfg, err := config.Load(homeDir)
	if err != nil {
		return nil
	}

	if cfg.Org == "" || cfg.Bot == "" {
		return nil
	}

	return fmt.Errorf("already registered as %s/%s, use --force to re-register (warning: re-registering will lose access to all existing messages; this is irrecoverable)", cfg.Org, cfg.Bot)
}

func ensureRegisterInputs(homeDir string) (string, string, error) {
	pubPath := filepath.Join(homeDir, "public_key")
	if err := requireFile(pubPath, "public key", "public key not found, run rtbtr keygen first"); err != nil {
		return "", "", err
	}

	tokenPath := filepath.Join(homeDir, "org_token")
	if err := requireFile(tokenPath, "org token", "org token not found, place your org token in .rtbtr/org_token"); err != nil {
		return "", "", err
	}

	return pubPath, tokenPath, nil
}

func requireFile(path, name, notFoundMessage string) error {
	_, statErr := os.Stat(path)
	if statErr == nil {
		return nil
	}

	if os.IsNotExist(statErr) {
		return errors.New(notFoundMessage)
	}

	return fmt.Errorf("stat %s: %w", name, statErr)
}

func readTrimmedFile(path, name string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("reading %s: %w", name, err)
	}

	return strings.TrimSpace(string(data)), nil
}

func registerBot(ctx context.Context, org, bot, pubKey, orgToken string) (*registerResponse, error) {
	requestBody, err := json.Marshal(registerRequest{Name: bot, PublicKey: pubKey})
	if err != nil {
		return nil, fmt.Errorf("marshaling request body: %w", err)
	}

	requestURL := fmt.Sprintf("%s/orgs/%s/bots", apiBaseURL, org)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, requestURL, bytes.NewReader(requestBody))
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}
	applyRegisterHeaders(req, orgToken)

	responseBody, err := doRequest(req, checkRegisterStatus)
	if err != nil {
		return nil, err
	}

	response := &registerResponse{}
	if err := json.Unmarshal(responseBody, response); err != nil {
		return nil, fmt.Errorf("parsing response body: %w", err)
	}

	return response, nil
}

func applyRegisterHeaders(req *http.Request, orgToken string) {
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+orgToken)
}

type statusChecker func(statusCode int, status string, body []byte) error

// newStatusChecker builds a statusChecker for authenticated endpoints.
// All authenticated endpoints map 401 to "authentication failed: signature rejected".
// Additional status codes are mapped via the codes map. If a code's message
// contains %s, the trimmed response body is interpolated.
func newStatusChecker(verb string, codes map[int]string) statusChecker {
	return func(statusCode int, status string, body []byte) error {
		if statusCode == http.StatusUnauthorized {
			return errors.New("authentication failed: signature rejected")
		}
		if msg, ok := codes[statusCode]; ok {
			if strings.Contains(msg, "%s") {
				return fmt.Errorf(msg, strings.TrimSpace(string(body)))
			}
			return errors.New(msg)
		}
		if statusCode < http.StatusOK || statusCode >= http.StatusMultipleChoices {
			return fmt.Errorf("%s failed: %s: %s", verb, status, strings.TrimSpace(string(body)))
		}
		return nil
	}
}

func doRequest(req *http.Request, check statusChecker) ([]byte, error) {
	resp, err := httpClient.Do(req) //nolint:gosec // request URL is built from validated org/bot inputs, not arbitrary user strings
	if err != nil {
		return nil, fmt.Errorf("sending request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return nil, fmt.Errorf("reading response body: %w", err)
	}

	if err := check(resp.StatusCode, resp.Status, body); err != nil {
		return nil, err
	}

	return body, nil
}

func checkRegisterStatus(statusCode int, status string, responseBody []byte) error {
	responseText := strings.TrimSpace(string(responseBody))

	switch statusCode {
	case http.StatusUnauthorized:
		return errors.New("org token is invalid or expired")
	case http.StatusConflict:
		return errors.New("bot already has an active key, revoke it first")
	case http.StatusUnprocessableEntity:
		if strings.Contains(responseText, "Public key has already been used") {
			return errors.New("public key has already been used for this bot, run rtbtr keygen --force to generate a new keypair")
		}
	}

	if statusCode < http.StatusOK || statusCode >= http.StatusMultipleChoices {
		return fmt.Errorf("register failed: %s: %s", status, responseText)
	}

	return nil
}

func printRegistrationSuccess(w io.Writer, org, bot, botID string) error {
	_, err := fmt.Fprintf(w, "registered as %s/%s\nbot_id: %s\n", org, bot, botID)
	return err
}

func init() {
	registerCmd.Flags().StringVar(&orgFlag, "org", "", "organization slug")
	registerCmd.Flags().StringVar(&botFlag, "bot", "", "bot name")
	registerCmd.Flags().BoolVar(&registerForceFlag, "force", false, "re-register even if config.yaml already exists")

	if err := registerCmd.MarkFlagRequired("org"); err != nil {
		panic(err)
	}
	if err := registerCmd.MarkFlagRequired("bot"); err != nil {
		panic(err)
	}
}
