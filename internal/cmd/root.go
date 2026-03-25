// Package cmd contains all CLI commands.
package cmd

import (
	"github.com/spf13/cobra"
)

var homeFlag string

var rootCmd = &cobra.Command{
	Use:   "rtbtr",
	Short: "rtbtr — cryptographic identity and messaging toolkit",
	Long: `rtbtr is a command-line tool for managing cryptographic identities
and exchanging encrypted messages on the rtbtr platform.

Generate key pairs, encrypt and decrypt messages, sign payloads,
and interact with the rtbtr registry.

Use "rtbtr [command] --help" for more information about a command.`,
	SilenceUsage:  true,
	SilenceErrors: true,
}

// Execute runs the root command.
func Execute() error {
	return rootCmd.Execute()
}

func init() {
	rootCmd.PersistentFlags().StringVar(&homeFlag, "home", "", "path to .rtbtr directory")
	rootCmd.AddCommand(versionCmd)
	rootCmd.AddCommand(keygenCmd)
	rootCmd.AddCommand(registerCmd)
	rootCmd.AddCommand(inboxCmd)
	rootCmd.AddCommand(sendCmd)
	rootCmd.AddCommand(readCmd)
	rootCmd.AddCommand(replyCmd)
	rootCmd.AddCommand(signCmd)
	rootCmd.AddCommand(verifyCmd)
}
