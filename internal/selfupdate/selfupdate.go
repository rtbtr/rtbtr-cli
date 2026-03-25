// Package selfupdate provides update checking and binary replacement
// for the rtbtr CLI using GitHub Releases.
package selfupdate

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"runtime"
	"strings"
	"time"

	goselfupdate "github.com/creativeprojects/go-selfupdate"
	"golang.org/x/mod/semver"
)

var latestReleaseURL = "https://api.github.com/repos/rtbtr/rtbtr-cli/releases/latest"

const (
	checkTimeout    = 2 * time.Second
	maxReleaseBytes = 1 << 20 // 1MB cap on release API response
)

type releaseResponse struct {
	TagName string `json:"tag_name"`
}

// UpdateInfo holds the result of a background version check.
type UpdateInfo struct {
	CurrentVersion string
	LatestVersion  string
}

// UpgradeInfo holds the detected upgrade target returned by DetectUpgrade.
type UpgradeInfo struct {
	release        *goselfupdate.Release
	updater        *goselfupdate.Updater
	CurrentVersion string
	NewVersion     string
}

var newUpdater = defaultNewUpdater

func defaultNewUpdater() (*goselfupdate.Updater, error) {
	source, err := goselfupdate.NewGitHubSource(goselfupdate.GitHubConfig{})
	if err != nil {
		return nil, fmt.Errorf("create github source: %w", err)
	}
	return goselfupdate.NewUpdater(goselfupdate.Config{Source: source})
}

func repo() goselfupdate.RepositorySlug {
	return goselfupdate.NewRepositorySlug("rtbtr", "rtbtr-cli")
}

// CheckForUpdate checks whether a newer release exists.
// Returns nil on all failures to avoid disrupting CLI usage.
func CheckForUpdate(ctx context.Context, currentVersion string) *UpdateInfo {
	if !semver.IsValid(currentVersion) {
		return nil
	}

	client := &http.Client{Timeout: checkTimeout}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, latestReleaseURL, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil
	}

	var release releaseResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxReleaseBytes)).Decode(&release); err != nil {
		return nil
	}
	if !semver.IsValid(release.TagName) {
		return nil
	}
	if semver.Compare(release.TagName, currentVersion) <= 0 {
		return nil
	}

	return &UpdateInfo{
		CurrentVersion: currentVersion,
		LatestVersion:  release.TagName,
	}
}

// DetectUpgrade checks if a newer release is available for upgrading.
// Unlike CheckForUpdate, this surfaces errors and returns an UpgradeInfo
// that can be passed to ApplyUpgrade.
func DetectUpgrade(ctx context.Context, currentVersion string) (*UpgradeInfo, error) {
	if !semver.IsValid(currentVersion) {
		return nil, fmt.Errorf("invalid version %q: not a valid semver string", currentVersion)
	}

	updater, err := newUpdater()
	if err != nil {
		return nil, fmt.Errorf("create updater: %w", err)
	}

	latest, found, err := updater.DetectLatest(ctx, repo())
	if err != nil {
		return nil, fmt.Errorf("check for updates: %w", err)
	}
	if !found {
		return nil, fmt.Errorf("no release asset found for %s/%s", runtime.GOOS, runtime.GOARCH)
	}

	currentClean := strings.TrimPrefix(currentVersion, "v")
	if latest.LessOrEqual(currentClean) {
		return nil, nil
	}

	return &UpgradeInfo{
		updater:        updater,
		release:        latest,
		CurrentVersion: currentVersion,
		NewVersion:     "v" + latest.Version(),
	}, nil
}

// ApplyUpgrade downloads the release and replaces the running binary.
// Reuses the updater from DetectUpgrade to avoid redundant initialization.
func ApplyUpgrade(_ context.Context, info *UpgradeInfo) error {
	exe, err := goselfupdate.ExecutablePath()
	if err != nil {
		return fmt.Errorf("resolve executable path: %w", err)
	}

	if err := info.updater.UpdateTo(context.Background(), info.release, exe); err != nil {
		if errors.Is(err, os.ErrPermission) {
			return fmt.Errorf("permission denied: try running 'sudo rtbtr upgrade'")
		}
		return fmt.Errorf("update binary: %w", err)
	}

	return nil
}

// SetLatestReleaseURLForTesting overrides the release endpoint for tests.
func SetLatestReleaseURLForTesting(url string) func() {
	original := latestReleaseURL
	latestReleaseURL = url
	return func() { latestReleaseURL = original }
}
