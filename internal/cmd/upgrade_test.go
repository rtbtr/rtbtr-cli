package cmd

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/rtbtr/rtbtr-cli/internal/selfupdate"
	"github.com/rtbtr/rtbtr-cli/internal/version"
)

func resetUpgradeFlags() {
	homeFlag = ""

	if flag := rootCmd.PersistentFlags().Lookup("home"); flag != nil {
		if err := flag.Value.Set(flag.DefValue); err != nil {
			panic(err)
		}
		flag.Changed = false
	}

	if flag := rootCmd.Flags().Lookup("help"); flag != nil {
		if err := flag.Value.Set(flag.DefValue); err != nil {
			panic(err)
		}
		flag.Changed = false
	}

	if flag := upgradeCmd.Flags().Lookup("help"); flag != nil {
		if err := flag.Value.Set(flag.DefValue); err != nil {
			panic(err)
		}
		flag.Changed = false
	}
}

func TestUpgradeRejectsDevBuild(t *testing.T) {
	resetUpgradeFlags()

	old := version.Version
	version.Version = "dev"
	defer func() { version.Version = old }()

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"upgrade"})

	err := rootCmd.Execute()
	if err == nil {
		t.Fatal("upgrade should reject dev build")
	}
	if !strings.Contains(err.Error(), "cannot upgrade a dev build") {
		t.Errorf("error = %q, want it to mention dev build", err.Error())
	}
}

func TestUpgradeAlreadyUpToDate(t *testing.T) {
	resetUpgradeFlags()

	old := version.Version
	version.Version = "v1.0.0"
	defer func() { version.Version = old }()

	oldDetect := detectUpgrade
	detectUpgrade = func(_ context.Context, _ string) (*selfupdate.UpgradeInfo, error) {
		return nil, nil
	}
	defer func() { detectUpgrade = oldDetect }()

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"upgrade"})

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("upgrade returned error: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "already up to date") {
		t.Errorf("output = %q, want it to mention already up to date", output)
	}
}

func TestUpgradeDetectError(t *testing.T) {
	resetUpgradeFlags()

	old := version.Version
	version.Version = "v1.0.0"
	defer func() { version.Version = old }()

	oldDetect := detectUpgrade
	detectUpgrade = func(_ context.Context, _ string) (*selfupdate.UpgradeInfo, error) {
		return nil, errors.New("network error")
	}
	defer func() { detectUpgrade = oldDetect }()

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"upgrade"})

	err := rootCmd.Execute()
	if err == nil {
		t.Fatal("upgrade should return error on detect failure")
	}
	if !strings.Contains(err.Error(), "network error") {
		t.Errorf("error = %q, want it to contain 'network error'", err.Error())
	}
}

func TestUpgradeApplyError(t *testing.T) {
	resetUpgradeFlags()

	old := version.Version
	version.Version = "v1.0.0"
	defer func() { version.Version = old }()

	oldDetect := detectUpgrade
	detectUpgrade = func(_ context.Context, _ string) (*selfupdate.UpgradeInfo, error) {
		return &selfupdate.UpgradeInfo{
			CurrentVersion: "v1.0.0",
			NewVersion:     "v2.0.0",
		}, nil
	}
	defer func() { detectUpgrade = oldDetect }()

	oldApply := applyUpgrade
	applyUpgrade = func(_ context.Context, _ *selfupdate.UpgradeInfo) error {
		return errors.New("write failed")
	}
	defer func() { applyUpgrade = oldApply }()

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"upgrade"})

	err := rootCmd.Execute()
	if err == nil {
		t.Fatal("upgrade should return error on apply failure")
	}
	if !strings.Contains(err.Error(), "upgrade failed") {
		t.Errorf("error = %q, want it to contain 'upgrade failed'", err.Error())
	}
}

func TestUpgradeSuccess(t *testing.T) {
	resetUpgradeFlags()

	old := version.Version
	version.Version = "v1.0.0"
	defer func() { version.Version = old }()

	oldDetect := detectUpgrade
	detectUpgrade = func(_ context.Context, _ string) (*selfupdate.UpgradeInfo, error) {
		return &selfupdate.UpgradeInfo{
			CurrentVersion: "v1.0.0",
			NewVersion:     "v2.0.0",
		}, nil
	}
	defer func() { detectUpgrade = oldDetect }()

	oldApply := applyUpgrade
	applyUpgrade = func(_ context.Context, _ *selfupdate.UpgradeInfo) error {
		return nil
	}
	defer func() { applyUpgrade = oldApply }()

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"upgrade"})

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("upgrade returned error: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "Updated") {
		t.Errorf("output = %q, want it to contain 'Updated'", output)
	}
	if !strings.Contains(output, "v1.0.0") {
		t.Errorf("output = %q, want it to contain old version", output)
	}
	if !strings.Contains(output, "v2.0.0") {
		t.Errorf("output = %q, want it to contain new version", output)
	}
}

func TestUpgradeCommandHelp(t *testing.T) {
	resetUpgradeFlags()

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetArgs([]string{"upgrade", "--help"})

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("upgrade --help returned error: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "upgrade") {
		t.Errorf("help output missing 'upgrade': %q", output)
	}
}
