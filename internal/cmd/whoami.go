package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/rtbtr/rtbtr-cli/internal/config"
	"github.com/rtbtr/rtbtr-cli/internal/home"
)

var whoamiJSONFlag bool

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
		return fmt.Errorf(".rtbtr directory not found: %w", err)
	}

	cfg, err := config.Load(homeDir)
	if err != nil {
		return fmt.Errorf("reading config: %w", err)
	}

	pubKeyPath := filepath.Join(homeDir, "public_key")
	pubKeyData, err := os.ReadFile(pubKeyPath)
	if err != nil {
		return fmt.Errorf("reading public key: %w", err)
	}

	pubKey := strings.TrimSpace(string(pubKeyData))

	if whoamiJSONFlag {
		result := map[string]string{
			"org":        cfg.Org,
			"bot":        cfg.Bot,
			"public_key": pubKey,
		}
		data, err := json.MarshalIndent(result, "", "  ")
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
	rootCmd.AddCommand(whoamiCmd)
}
