package cmd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/rtbtr/rtbtr-cli/internal/config"
	"github.com/rtbtr/rtbtr-cli/internal/home"
)

var (
	orgFlag           string
	botFlag           string
	registerForceFlag bool
	apiBaseURL        = "https://api.rtbtr.com"
	httpClient        = http.DefaultClient
)

var registerCmd = &cobra.Command{
	Use:   "register",
	Short: "Register bot with the rtbtr platform",
	RunE:  runRegister,
}

func runRegister(cmd *cobra.Command, args []string) error {
	homeDir, err := home.Resolve(homeFlag, false)
	if err != nil {
		return fmt.Errorf("resolving home directory: %w", err)
	}

	cfg, err := config.Load(homeDir)
	if err == nil && cfg.Org != "" && cfg.Bot != "" && !registerForceFlag {
		return fmt.Errorf("already registered as %s/%s, use --force to re-register (warning: re-registering will lose access to all existing messages; this is irrecoverable)", cfg.Org, cfg.Bot)
	}

	pubPath := filepath.Join(homeDir, "public_key")
	if _, err := os.Stat(pubPath); os.IsNotExist(err) {
		return fmt.Errorf("public key not found, run rtbtr keygen first")
	} else if err != nil {
		return fmt.Errorf("stat public key: %w", err)
	}

	tokenPath := filepath.Join(homeDir, "org_token")
	if _, err := os.Stat(tokenPath); os.IsNotExist(err) {
		return fmt.Errorf("org token not found, place your org token in .rtbtr/org_token")
	} else if err != nil {
		return fmt.Errorf("stat org token: %w", err)
	}

	pubKeyBytes, err := os.ReadFile(pubPath)
	if err != nil {
		return fmt.Errorf("reading public key: %w", err)
	}
	pubKey := strings.TrimSpace(string(pubKeyBytes))

	orgTokenBytes, err := os.ReadFile(tokenPath)
	if err != nil {
		return fmt.Errorf("reading org token: %w", err)
	}
	orgToken := strings.TrimSpace(string(orgTokenBytes))

	requestBody, err := json.Marshal(struct {
		Name      string `json:"name"`
		PublicKey string `json:"public_key"`
	}{
		Name:      botFlag,
		PublicKey: pubKey,
	})
	if err != nil {
		return fmt.Errorf("marshaling request body: %w", err)
	}

	url := fmt.Sprintf("%s/orgs/%s/bots", apiBaseURL, orgFlag)
	req, err := http.NewRequestWithContext(cmd.Context(), http.MethodPost, url, bytes.NewReader(requestBody))
	if err != nil {
		return fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+orgToken)

	resp, err := httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("sending request: %w", err)
	}
	defer resp.Body.Close()

	responseBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("reading response body: %w", err)
	}

	responseText := strings.TrimSpace(string(responseBody))

	switch resp.StatusCode {
	case http.StatusUnauthorized:
		return fmt.Errorf("org token is invalid or expired")
	case http.StatusConflict:
		return fmt.Errorf("bot already has an active key, revoke it first")
	case http.StatusUnprocessableEntity:
		if strings.Contains(responseText, "Public key has already been used") {
			return fmt.Errorf("public key has already been used for this bot, run rtbtr keygen --force to generate a new keypair")
		}
	}

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return fmt.Errorf("register failed: %s: %s", resp.Status, responseText)
	}

	var response struct {
		BotID string `json:"bot_id"`
	}
	if err := json.Unmarshal(responseBody, &response); err != nil {
		return fmt.Errorf("parsing response body: %w", err)
	}

	if err := config.Write(homeDir, &config.Config{Org: orgFlag, Bot: botFlag}); err != nil {
		return fmt.Errorf("writing config: %w", err)
	}

	if _, err := fmt.Fprintf(cmd.OutOrStdout(), "registered as %s/%s\n", orgFlag, botFlag); err != nil {
		return fmt.Errorf("writing success message: %w", err)
	}
	if _, err := fmt.Fprintf(cmd.OutOrStdout(), "bot_id: %s\n", response.BotID); err != nil {
		return fmt.Errorf("writing bot id: %w", err)
	}

	return nil
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
