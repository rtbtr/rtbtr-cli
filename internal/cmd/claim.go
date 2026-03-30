package cmd

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/spf13/cobra"

	"github.com/rtbtr/rtbtr-cli/internal/signing"
)

var (
	claimFileFlag  string
	claimStdinFlag bool
	claimHashFlag  string
	claimJSONFlag  bool
)

var claimCmd = &cobra.Command{
	Use:   "claim",
	Short: "Notarize a signed hash claim",
	Long: `Submit a signed hash claim for notarization.

Provide the content to hash via --file, --stdin, or --hash.
Exactly one source must be specified.

Authentication uses RFC 9421 HTTP Message Signatures with the Ed25519
keypair from the .rtbtr directory.`,
	Args: func(cmd *cobra.Command, args []string) error {
		if len(args) > 0 {
			return fmt.Errorf("accepts 0 args, received %d", len(args))
		}
		return nil
	},
	RunE: runClaim,
}

type claimRequestBody struct {
	Hash string `json:"hash"`
}

type claimResponse struct {
	ClaimID string `json:"claim_id"`
	Hash    string `json:"hash"`
}

func runClaim(cmd *cobra.Command, args []string) error {
	hash, err := resolveClaimHash(cmd)
	if err != nil {
		return err
	}

	cfg, seed, err := loadMailboxIdentity()
	if err != nil {
		return err
	}

	bodyBytes, err := json.Marshal(claimRequestBody{Hash: hash})
	if err != nil {
		return fmt.Errorf("marshaling request body: %w", err)
	}

	requestURL := fmt.Sprintf("%s/orgs/%s/bots/%s/claims", apiBaseURL, cfg.Org, cfg.Bot)
	req, err := http.NewRequestWithContext(cmd.Context(), http.MethodPost, requestURL, bytes.NewReader(bodyBytes))
	if err != nil {
		return fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	keyID := fmt.Sprintf("%s/o/%s/%s", platformBaseURL, cfg.Org, cfg.Bot)
	if signErr := signing.Sign(req, seed, keyID, bodyBytes); signErr != nil {
		return fmt.Errorf("signing request: %w", signErr)
	}

	responseBody, err := doRequest(req, checkClaimStatus)
	if err != nil {
		return err
	}

	if claimJSONFlag {
		_, err = fmt.Fprintln(cmd.OutOrStdout(), string(responseBody))
		return err
	}

	var resp claimResponse
	if err := json.Unmarshal(responseBody, &resp); err != nil {
		return fmt.Errorf("parsing response body: %w", err)
	}

	fmt.Fprintf(cmd.OutOrStdout(), "claimed %s\nhash: %s\n", resp.ClaimID, resp.Hash)
	return nil
}

func resolveClaimHash(cmd *cobra.Command) (string, error) {
	sourceCount := 0
	if claimFileFlag != "" {
		sourceCount++
	}
	if claimStdinFlag {
		sourceCount++
	}
	if claimHashFlag != "" {
		sourceCount++
	}

	if sourceCount == 0 {
		return "", errors.New("provide a hash source: --file, --stdin, or --hash")
	}
	if sourceCount > 1 {
		return "", errors.New("only one of --file, --stdin, or --hash may be provided")
	}

	if claimFileFlag != "" {
		return hashFile(claimFileFlag)
	}
	if claimStdinFlag {
		return hashStdin(cmd)
	}
	return validateHash(claimHashFlag)
}

func hashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("opening file: %w", err)
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", fmt.Errorf("reading file: %w", err)
	}

	return base64.RawURLEncoding.EncodeToString(h.Sum(nil)), nil
}

func hashStdin(cmd *cobra.Command) (string, error) {
	h := sha256.New()
	n, err := io.Copy(h, cmd.InOrStdin())
	if err != nil {
		return "", fmt.Errorf("reading stdin: %w", err)
	}
	if n == 0 {
		return "", errors.New("empty stdin: nothing to hash")
	}

	return base64.RawURLEncoding.EncodeToString(h.Sum(nil)), nil
}

func validateHash(value string) (string, error) {
	if len(value) != 43 {
		return "", fmt.Errorf("invalid hash: expected 43 characters, got %d", len(value))
	}

	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		return "", fmt.Errorf("invalid hash: not valid URL-safe base64: %w", err)
	}

	if len(decoded) != 32 {
		return "", fmt.Errorf("invalid hash: decoded to %d bytes, expected 32", len(decoded))
	}

	return value, nil
}

var checkClaimStatus = newStatusChecker("claim", map[int]string{
	http.StatusNotFound:            "not found",
	http.StatusUnprocessableEntity: "invalid hash: %s",
})

func init() {
	claimCmd.Flags().StringVar(&claimFileFlag, "file", "", "path to file to hash")
	claimCmd.Flags().BoolVar(&claimStdinFlag, "stdin", false, "read from stdin")
	claimCmd.Flags().StringVar(&claimHashFlag, "hash", "", "precomputed SHA-256 hash (43-char URL-safe base64)")
	claimCmd.Flags().BoolVar(&claimJSONFlag, "json", false, "print raw JSON response")
}
