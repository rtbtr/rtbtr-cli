package cmd

import (
	"github.com/spf13/cobra"
)

var whoamiJsonFlag bool

var whoamiCmd = &cobra.Command{
	Use:   "whoami",
	Short: "Print the local bot identity",
	Long: `Print the local bot identity from the .rtbtr home directory.

Reads the config.yaml and public_key files and displays the
organization, bot name, and public key. Fully offline.`,
	RunE: runWhoami,
}

func runWhoami(cmd *cobra.Command, args []string) error {
	// TODO: implement whoami command
	return nil
}

func init() {
	whoamiCmd.Flags().BoolVar(&whoamiJsonFlag, "json", false, "output as JSON")
	rootCmd.AddCommand(whoamiCmd)
}
