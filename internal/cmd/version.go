package cmd

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/rtbtr/rtbtr-cli/internal/version"
)

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print version information",
	Long:  `Print the version, commit hash, and build time of the rtbtr CLI.`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("rtbtr " + version.Info())
	},
}
