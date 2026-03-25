package cmd

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/rtbtr/rtbtr-cli/internal/config"
	"github.com/rtbtr/rtbtr-cli/internal/home"
)

var whoamiJSONFlag bool

type whoamiOutput struct {
	Org       string `json:"org"`
	Bot       string `json:"bot"`
	PublicKey string `json:"public_key"`
}

var whoamiCmd = &cobra.Command{
	Use:   "whoami",
	Short: "Print the local bot identity",
	Long: `Print the local bot identity from the .rtbtr home directory.

Reads the config.yaml and public_key files and displays the
organization, bot name, and public key. Fully offline.`,
	RunE: runWhoami,
}

func runWhoami(cmd *cobra.Command, args []string) error {
	homeDir, err := home.Resolve(homeFlag, false)
	if err != nil {
		return err
	}

	cfg, err := config.Load(homeDir)
	if err != nil {
		return fmt.Errorf("reading config: %w", err)
	}

	if cfg.Org == "" || cfg.Bot == "" {
		return errors.New("not registered: run rtbtr register first")
	}

	pubKeyPath := filepath.Join(homeDir, "public_key")
	pubKeyData, err := os.ReadFile(pubKeyPath)
	if err != nil {
		return fmt.Errorf("reading public key: %w", err)
	}

	pubKey := strings.TrimSpace(string(pubKeyData))

	if whoamiJSONFlag {
		data, err := json.Marshal(whoamiOutput{
			Org:       cfg.Org,
			Bot:       cfg.Bot,
			PublicKey: pubKey,
		})
		if err != nil {
			return fmt.Errorf("marshaling JSON: %w", err)
		}
		fmt.Fprintln(cmd.OutOrStdout(), string(data))
		return nil
	}

	fmt.Fprintf(cmd.OutOrStdout(), "Org:        %s\n", cfg.Org)
	fmt.Fprintf(cmd.OutOrStdout(), "Bot:        %s\n", cfg.Bot)
	fmt.Fprintf(cmd.OutOrStdout(), "Public Key: %s\n", pubKey)

	return nil
}

func init() {
	whoamiCmd.Flags().BoolVar(&whoamiJSONFlag, "json", false, "output as JSON")
}
