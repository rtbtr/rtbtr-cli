package cmd

import (
	"fmt"
	"runtime"

	"github.com/spf13/cobra"

	"github.com/rtbtr/rtbtr-cli/internal/selfupdate"
	"github.com/rtbtr/rtbtr-cli/internal/version"
)

var (
	detectUpgrade = selfupdate.DetectUpgrade
	applyUpgrade  = selfupdate.ApplyUpgrade
)

var upgradeCmd = &cobra.Command{
	Use:   "upgrade",
	Short: "Upgrade rtbtr to the latest version",
	Long:  "Download and install the latest version of rtbtr from GitHub Releases.",
	RunE:  runUpgrade,
}

func runUpgrade(cmd *cobra.Command, _ []string) error {
	if version.IsDev() {
		return fmt.Errorf("cannot upgrade a dev build")
	}

	w := cmd.OutOrStdout()

	if _, err := fmt.Fprintln(w, "Checking for updates..."); err != nil {
		return err
	}

	ctx := cmd.Context()
	info, err := detectUpgrade(ctx, version.Version)
	if err != nil {
		return fmt.Errorf("check for updates: %w", err)
	}
	if info == nil {
		_, err = fmt.Fprintf(w, "rtbtr is already up to date (%s)\n", version.Version)
		return err
	}

	if _, err = fmt.Fprintf(w, "Downloading rtbtr %s (%s-%s)...\n", info.NewVersion, runtime.GOOS, runtime.GOARCH); err != nil {
		return err
	}

	if applyErr := applyUpgrade(ctx, info); applyErr != nil {
		return fmt.Errorf("upgrade failed: %w", applyErr)
	}

	_, err = fmt.Fprintf(w, "Updated rtbtr %s → %s\n", version.Version, info.NewVersion)
	return err
}
