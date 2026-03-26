package cmd

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"unicode/utf8"

	"github.com/spf13/cobra"

	"github.com/rtbtr/rtbtr-cli/internal/signing"
)

var (
	profileNameFlag        string
	profileDescriptionFlag string
	profileForceFlag       bool
)

var namePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]*[a-z0-9]$`)

var profileCmd = &cobra.Command{
	Use:   "profile",
	Short: "Update bot profile (name, description)",
	Long: `Update the profile for the registered bot.

Use --description to set or update the bot description.
Use --name with --force to change the bot name.

Authentication uses RFC 9421 HTTP Message Signatures with the Ed25519
keypair from the .rtbtr directory.`,
	Args: cobra.NoArgs,
	RunE: runProfile,
}

type profileRequest struct {
	Name        *string `json:"name,omitempty"`
	Description *string `json:"description,omitempty"`
}

type profileResponse struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Org         string `json:"org"`
}

func runProfile(cmd *cobra.Command, args []string) error {
	nameChanged := cmd.Flags().Lookup("name").Changed
	descChanged := cmd.Flags().Lookup("description").Changed

	if !nameChanged && !descChanged {
		return errors.New("at least one of --name or --description is required")
	}

	if nameChanged {
		if err := validateName(profileNameFlag); err != nil {
			return err
		}
		if !profileForceFlag {
			return errors.New("changing bot name is irreversible; use --force to confirm")
		}
	}

	if descChanged {
		runeCount := utf8.RuneCountInString(profileDescriptionFlag)
		if runeCount > 500 {
			return fmt.Errorf("description must be 500 characters or fewer (got %d)", runeCount)
		}
	}

	cfg, seed, err := loadMailboxIdentity()
	if err != nil {
		return err
	}

	body := profileRequest{}
	if nameChanged {
		body.Name = &profileNameFlag
	}
	if descChanged {
		body.Description = &profileDescriptionFlag
	}

	bodyBytes, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("marshaling request body: %w", err)
	}

	requestURL := fmt.Sprintf("%s/orgs/%s/bots/%s", apiBaseURL, cfg.Org, cfg.Bot)
	req, err := http.NewRequestWithContext(cmd.Context(), http.MethodPatch, requestURL, bytes.NewReader(bodyBytes))
	if err != nil {
		return fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	keyID := fmt.Sprintf("%s/o/%s/%s", platformBaseURL, cfg.Org, cfg.Bot)
	if signErr := signing.Sign(req, seed, keyID, bodyBytes); signErr != nil {
		return fmt.Errorf("signing request: %w", signErr)
	}

	responseBody, err := doRequest(req, checkProfileStatus)
	if err != nil {
		return err
	}

	return printProfileResult(cmd.OutOrStdout(), responseBody)
}

func validateName(name string) error {
	if len(name) < 2 {
		return fmt.Errorf("name must be at least 2 characters")
	}
	if !namePattern.MatchString(name) {
		return fmt.Errorf("name must match pattern %s (lowercase alphanumeric and hyphens, cannot start or end with hyphen)", namePattern.String())
	}
	return nil
}

var checkProfileStatus = newStatusChecker("profile", map[int]string{
	http.StatusForbidden:           "cannot update another bot",
	http.StatusNotFound:            "bot not found",
	http.StatusConflict:            "name conflict: name is already taken",
	http.StatusUnprocessableEntity: "validation error: %s",
})

func printProfileResult(w io.Writer, data []byte) error {
	var resp profileResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return fmt.Errorf("parsing response: %w", err)
	}

	fmt.Fprintf(w, "name: %s\n", resp.Name)
	fmt.Fprintf(w, "org: %s\n", resp.Org)
	if resp.Description != "" {
		fmt.Fprintf(w, "description: %s\n", resp.Description)
	}

	return nil
}

func init() {
	profileCmd.Flags().StringVar(&profileNameFlag, "name", "", "new bot name")
	profileCmd.Flags().StringVar(&profileDescriptionFlag, "description", "", "bot description (max 500 characters)")
	profileCmd.Flags().BoolVar(&profileForceFlag, "force", false, "confirm irreversible name change")
}
