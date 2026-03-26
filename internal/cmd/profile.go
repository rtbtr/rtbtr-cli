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

	"github.com/rtbtr/rtbtr-cli/internal/config"
	"github.com/rtbtr/rtbtr-cli/internal/home"
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

	if err := validateProfileFlags(nameChanged, descChanged); err != nil {
		return err
	}

	cfg, seed, err := loadMailboxIdentity()
	if err != nil {
		return err
	}

	body := buildProfileBody(nameChanged, descChanged)

	bodyBytes, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("marshaling request body: %w", err)
	}

	responseBody, err := sendProfilePatch(cmd, cfg, seed, bodyBytes)
	if err != nil {
		return err
	}

	if nameChanged {
		if err := persistRenamedBot(cfg.Org); err != nil {
			return err
		}
	}

	return printProfileResult(cmd.OutOrStdout(), responseBody)
}

func validateProfileFlags(nameChanged, descChanged bool) error {
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
	return nil
}

func buildProfileBody(nameChanged, descChanged bool) profileRequest {
	body := profileRequest{}
	if nameChanged {
		body.Name = &profileNameFlag
	}
	if descChanged {
		body.Description = &profileDescriptionFlag
	}
	return body
}

func sendProfilePatch(cmd *cobra.Command, cfg *config.Config, seed, bodyBytes []byte) ([]byte, error) {
	requestURL := fmt.Sprintf("%s/orgs/%s/bots/%s", apiBaseURL, cfg.Org, cfg.Bot)
	req, err := http.NewRequestWithContext(cmd.Context(), http.MethodPatch, requestURL, bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	keyID := fmt.Sprintf("%s/o/%s/%s", platformBaseURL, cfg.Org, cfg.Bot)
	if signErr := signing.Sign(req, seed, keyID, bodyBytes); signErr != nil {
		return nil, fmt.Errorf("signing request: %w", signErr)
	}

	return doRequest(req, checkProfileStatus)
}

func persistRenamedBot(org string) error {
	homeDir, err := home.Resolve(homeFlag, false)
	if err != nil {
		return fmt.Errorf("resolving home directory: %w", err)
	}
	if err := config.Write(homeDir, &config.Config{Org: org, Bot: profileNameFlag}); err != nil {
		return fmt.Errorf("writing config: %w", err)
	}
	return nil
}

func validateName(name string) error {
	if len(name) < 2 {
		return errors.New("name must be at least 2 characters")
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
