package cmd

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"
)

var (
	claimsPageFlag  int
	claimsLimitFlag int
	claimsOrderFlag string
	claimsJSONFlag  bool
)

var claimsCmd = &cobra.Command{
	Use:   "claims <org>/<bot>",
	Short: "List notarized hash claims for a bot",
	Long: `List notarized hash claims for a bot.

This is a public endpoint — no local identity or authentication is required.`,
	Args: func(cmd *cobra.Command, args []string) error {
		if len(args) == 0 {
			return errors.New("requires org/bot argument")
		}
		if len(args) > 1 {
			return fmt.Errorf("accepts 1 arg(s), received %d", len(args))
		}
		return nil
	},
	RunE: runClaims,
}

type claimsEntry struct {
	ID        string `json:"id"`
	Hash      string `json:"hash"`
	CreatedAt string `json:"created_at"`
}

func runClaims(cmd *cobra.Command, args []string) error {
	org, bot, err := parseClaimsArg(args[0])
	if err != nil {
		return err
	}

	requestURL := buildClaimsURL(org, bot, claimsPageFlag, claimsLimitFlag, claimsOrderFlag)
	req, err := http.NewRequestWithContext(cmd.Context(), http.MethodGet, requestURL, nil)
	if err != nil {
		return fmt.Errorf("creating request: %w", err)
	}

	body, err := doRequest(req, checkClaimsStatus)
	if err != nil {
		return err
	}

	if claimsJSONFlag {
		_, err = fmt.Fprintln(cmd.OutOrStdout(), string(body))
		return err
	}

	return printClaimsTable(cmd.OutOrStdout(), body)
}

func parseClaimsArg(arg string) (string, string, error) {
	parts := strings.Split(arg, "/")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", "", fmt.Errorf("invalid argument %q: expected format org/bot", arg)
	}
	return parts[0], parts[1], nil
}

func buildClaimsURL(org, bot string, page, limit int, order string) string {
	base := fmt.Sprintf("%s/orgs/%s/bots/%s/claims", apiBaseURL, org, bot)
	values := url.Values{}
	values.Set("page", strconv.Itoa(page))
	values.Set("limit", strconv.Itoa(limit))
	values.Set("order", order)
	return base + "?" + values.Encode()
}

func checkClaimsStatus(statusCode int, status string, body []byte) error {
	switch statusCode {
	case http.StatusNotFound:
		return errors.New("bot not found")
	case http.StatusUnprocessableEntity:
		return fmt.Errorf("invalid parameters: %s", strings.TrimSpace(string(body)))
	}
	if statusCode < http.StatusOK || statusCode >= http.StatusMultipleChoices {
		return fmt.Errorf("claims failed: %s: %s", status, strings.TrimSpace(string(body)))
	}
	return nil
}

func printClaimsTable(w io.Writer, data []byte) error {
	var claims []claimsEntry
	if err := json.Unmarshal(data, &claims); err != nil {
		return fmt.Errorf("parsing response body: %w", err)
	}

	if len(claims) == 0 {
		_, err := fmt.Fprintln(w, "no claims")
		return err
	}

	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	if _, err := fmt.Fprintln(tw, "ID\tHASH\tCREATED"); err != nil {
		return fmt.Errorf("writing table header: %w", err)
	}

	for _, c := range claims {
		if _, err := fmt.Fprintf(tw, "%s\t%s\t%s\n", c.ID, c.Hash, c.CreatedAt); err != nil {
			return fmt.Errorf("writing table row: %w", err)
		}
	}

	return tw.Flush()
}

func init() {
	claimsCmd.Flags().IntVar(&claimsPageFlag, "page", 1, "page number")
	claimsCmd.Flags().IntVar(&claimsLimitFlag, "limit", 20, "number of claims per page")
	claimsCmd.Flags().StringVar(&claimsOrderFlag, "order", "desc", "sort order (asc or desc)")
	claimsCmd.Flags().BoolVar(&claimsJSONFlag, "json", false, "print raw JSON response")
}
