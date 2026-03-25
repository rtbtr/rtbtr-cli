package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/spf13/cobra"
)

var lookupJSONFlag bool

var lookupCmd = &cobra.Command{
	Use:   "lookup <org>/<bot>",
	Short: "Fetch a bot's public profile and public key",
	Long: `Fetch a bot's public profile and public key from the rtbtr API.

The lookup command retrieves the public profile of a registered bot,
including its public key, without requiring authentication.`,
	Args: cobra.ExactArgs(1),
	RunE: runLookup,
}

type lookupProfile struct {
	Org       string `json:"org"`
	Bot       string `json:"bot"`
	PublicKey string `json:"public_key"`
	CreatedAt string `json:"created_at"`
}

func runLookup(cmd *cobra.Command, args []string) error {
	org, bot, err := parseLookupArg(args[0])
	if err != nil {
		return err
	}

	requestURL := fmt.Sprintf("%s/orgs/%s/bots/%s", apiBaseURL, org, bot)
	req, err := http.NewRequestWithContext(cmd.Context(), http.MethodGet, requestURL, nil)
	if err != nil {
		return fmt.Errorf("creating request: %w", err)
	}

	body, err := doRequest(req, checkLookupStatus)
	if err != nil {
		return err
	}

	if lookupJSONFlag {
		_, err = fmt.Fprintln(cmd.OutOrStdout(), string(body))
		return err
	}

	return printLookupTable(cmd.OutOrStdout(), body)
}

func parseLookupArg(arg string) (string, string, error) {
	parts := strings.Split(arg, "/")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", "", fmt.Errorf("invalid argument %q: expected format org/bot", arg)
	}
	return parts[0], parts[1], nil
}

var checkLookupStatus = newStatusChecker("lookup", map[int]string{
	http.StatusNotFound: "bot not found",
})

func printLookupTable(w io.Writer, data []byte) error {
	var profile lookupProfile
	if err := json.Unmarshal(data, &profile); err != nil {
		return fmt.Errorf("parsing response body: %w", err)
	}

	fmt.Fprintf(w, "Org:        %s\n", profile.Org)
	fmt.Fprintf(w, "Bot:        %s\n", profile.Bot)
	fmt.Fprintf(w, "Public Key: %s\n", profile.PublicKey)
	fmt.Fprintf(w, "Created:    %s\n", profile.CreatedAt)
	return nil
}

func init() {
	lookupCmd.Flags().BoolVar(&lookupJSONFlag, "json", false, "print raw JSON response")
}
