// Package cmd contains all CLI commands.
package cmd

import (
	"context"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/rtbtr/rtbtr-cli/internal/selfupdate"
	"github.com/rtbtr/rtbtr-cli/internal/version"
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

// Execute runs the root command with a non-blocking background update check.
// The nudge is printed only on success and not after "upgrade".
func Execute() error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Skip the update check entirely for dev builds.
	var ch chan *selfupdate.UpdateInfo
	if !version.IsDev() {
		ch = make(chan *selfupdate.UpdateInfo, 1)
		go func() {
			ch <- selfupdate.CheckForUpdate(ctx, version.Version)
		}()
	}

	cmd, err := rootCmd.ExecuteC()

	if err == nil && ch != nil && cmd != upgradeCmd {
		select {
		case info := <-ch:
			if info != nil {
				fmt.Fprintf(os.Stderr,
					"\nA new version of rtbtr is available: %s → %s\nRun 'rtbtr upgrade' to update.\n",
					info.CurrentVersion,
					info.LatestVersion,
				)
			}
		default:
		}
	}

	return err
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
	rootCmd.AddCommand(whoamiCmd)
	rootCmd.AddCommand(lookupCmd)
	rootCmd.AddCommand(encryptCmd)
	rootCmd.AddCommand(decryptCmd)
	rootCmd.AddCommand(upgradeCmd)
	rootCmd.AddCommand(profileCmd)
	rootCmd.AddCommand(claimCmd)
	rootCmd.AddCommand(claimsCmd)
}
