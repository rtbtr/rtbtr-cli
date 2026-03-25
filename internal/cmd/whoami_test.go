package cmd

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func resetWhoamiFlags() {
	homeFlag = ""
	whoamiJSONFlag = false

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

	if flag := whoamiCmd.Flags().Lookup("json"); flag != nil {
		if err := flag.Value.Set(flag.DefValue); err != nil {
			panic(err)
		}
		flag.Changed = false
	}

	if flag := whoamiCmd.Flags().Lookup("help"); flag != nil {
		if err := flag.Value.Set(flag.DefValue); err != nil {
			panic(err)
		}
		flag.Changed = false
	}
}

func setupWhoamiDir(t *testing.T, parent string, files map[string]string) string {
	t.Helper()
	rtbtrDir := filepath.Join(parent, ".rtbtr")
	if err := os.MkdirAll(rtbtrDir, 0o755); err != nil {
		t.Fatalf("creating .rtbtr directory: %v", err)
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(rtbtrDir, name), []byte(content), 0o644); err != nil {
			t.Fatalf("writing %s: %v", name, err)
		}
	}
	return rtbtrDir
}

func TestWhoamiOutput(t *testing.T) {
	resetWhoamiFlags()

	dir := t.TempDir()
	homePath := setupWhoamiDir(t, dir, map[string]string{
		"config.yaml": "org: acme\nbot: weather-bot\n",
		"public_key":  "abc123def456",
	})

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(new(bytes.Buffer))
	rootCmd.SetArgs([]string{"whoami", "--home", homePath})

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("whoami returned error: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "acme") {
		t.Errorf("output missing org: %q", output)
	}
	if !strings.Contains(output, "weather-bot") {
		t.Errorf("output missing bot: %q", output)
	}
	if !strings.Contains(output, "abc123def456") {
		t.Errorf("output missing public key: %q", output)
	}
}

func TestWhoamiJsonOutput(t *testing.T) {
	resetWhoamiFlags()

	dir := t.TempDir()
	homePath := setupWhoamiDir(t, dir, map[string]string{
		"config.yaml": "org: acme\nbot: weather-bot\n",
		"public_key":  "abc123def456",
	})

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(new(bytes.Buffer))
	rootCmd.SetArgs([]string{"whoami", "--json", "--home", homePath})

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("whoami --json returned error: %v", err)
	}

	output := strings.TrimSpace(buf.String())
	var result whoamiOutput
	if err := json.Unmarshal([]byte(output), &result); err != nil {
		t.Fatalf("output is not valid JSON: %v\noutput: %q", err, output)
	}

	if result.Org != "acme" {
		t.Errorf("org = %q, want %q", result.Org, "acme")
	}
	if result.Bot != "weather-bot" {
		t.Errorf("bot = %q, want %q", result.Bot, "weather-bot")
	}
	if result.PublicKey != "abc123def456" {
		t.Errorf("public_key = %q, want %q", result.PublicKey, "abc123def456")
	}
}

func TestWhoamiJsonKeyOrder(t *testing.T) {
	resetWhoamiFlags()

	dir := t.TempDir()
	homePath := setupWhoamiDir(t, dir, map[string]string{
		"config.yaml": "org: myorg\nbot: mybot\n",
		"public_key":  "mypub",
	})

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(new(bytes.Buffer))
	rootCmd.SetArgs([]string{"whoami", "--json", "--home", homePath})

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("whoami --json returned error: %v", err)
	}

	output := strings.TrimSpace(buf.String())
	orgIdx := strings.Index(output, `"org"`)
	botIdx := strings.Index(output, `"bot"`)
	keyIdx := strings.Index(output, `"public_key"`)

	if orgIdx < 0 || botIdx < 0 || keyIdx < 0 {
		t.Fatalf("JSON missing expected keys: %q", output)
	}
	if orgIdx >= botIdx || botIdx >= keyIdx {
		t.Errorf("JSON key order should be org, bot, public_key; got: %q", output)
	}
}

func TestWhoamiNotRegisteredMissingConfig(t *testing.T) {
	resetWhoamiFlags()

	dir := t.TempDir()
	homePath := setupWhoamiDir(t, dir, map[string]string{
		"public_key": "somepubkey",
	})

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(new(bytes.Buffer))
	rootCmd.SetArgs([]string{"whoami", "--home", homePath})

	err := rootCmd.Execute()
	if err == nil {
		t.Fatal("whoami should return error when config.yaml is missing")
	}
	if !strings.Contains(err.Error(), "config") {
		t.Errorf("error = %q, want it to reference config", err.Error())
	}
}

func TestWhoamiNotRegisteredEmptyOrgBot(t *testing.T) {
	resetWhoamiFlags()

	dir := t.TempDir()
	homePath := setupWhoamiDir(t, dir, map[string]string{
		"config.yaml": "org: \"\"\nbot: \"\"\n",
		"public_key":  "somepubkey",
	})

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(new(bytes.Buffer))
	rootCmd.SetArgs([]string{"whoami", "--home", homePath})

	err := rootCmd.Execute()
	if err == nil {
		t.Fatal("whoami should return error when org/bot are empty")
	}
	if !strings.Contains(err.Error(), "not registered") {
		t.Errorf("error = %q, want it to mention 'not registered'", err.Error())
	}
}

func TestWhoamiNoRtbtrDir(t *testing.T) {
	resetWhoamiFlags()

	dir := t.TempDir()
	t.Chdir(dir)

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(new(bytes.Buffer))
	rootCmd.SetArgs([]string{"whoami"})

	err := rootCmd.Execute()
	if err == nil {
		t.Fatal("whoami should return error when .rtbtr directory is not found")
	}
	if !strings.Contains(err.Error(), ".rtbtr") {
		t.Errorf("error = %q, want it to mention .rtbtr", err.Error())
	}
}

func TestWhoamiMissingPublicKey(t *testing.T) {
	resetWhoamiFlags()

	dir := t.TempDir()
	homePath := setupWhoamiDir(t, dir, map[string]string{
		"config.yaml": "org: myorg\nbot: mybot\n",
	})

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(new(bytes.Buffer))
	rootCmd.SetArgs([]string{"whoami", "--home", homePath})

	err := rootCmd.Execute()
	if err == nil {
		t.Fatal("whoami should return error when public_key file is missing")
	}
	if !strings.Contains(err.Error(), "public key") {
		t.Errorf("error = %q, want it to mention public key", err.Error())
	}
}

func TestWhoamiTrimsPublicKeyWhitespace(t *testing.T) {
	resetWhoamiFlags()

	dir := t.TempDir()
	homePath := setupWhoamiDir(t, dir, map[string]string{
		"config.yaml": "org: trimorg\nbot: trimbot\n",
		"public_key":  "  pubkey_with_spaces  \n",
	})

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(new(bytes.Buffer))
	rootCmd.SetArgs([]string{"whoami", "--json", "--home", homePath})

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("whoami --json returned error: %v", err)
	}

	var result whoamiOutput
	if err := json.Unmarshal([]byte(strings.TrimSpace(buf.String())), &result); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}

	if result.PublicKey != "pubkey_with_spaces" {
		t.Errorf("public_key = %q, want %q", result.PublicKey, "pubkey_with_spaces")
	}
}

func TestWhoamiDoesNotExposeSecrets(t *testing.T) {
	resetWhoamiFlags()

	dir := t.TempDir()
	homePath := setupWhoamiDir(t, dir, map[string]string{
		"config.yaml": "org: secretorg\nbot: secretbot\n",
		"public_key":  "publickeyvalue",
		"private_key": "supersecretprivatekey",
		"org_token":   "supersecrettoken",
	})

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(new(bytes.Buffer))
	rootCmd.SetArgs([]string{"whoami", "--home", homePath})

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("whoami returned error: %v", err)
	}

	output := buf.String()
	if strings.Contains(output, "supersecretprivatekey") {
		t.Errorf("output contains private key")
	}
	if strings.Contains(output, "supersecrettoken") {
		t.Errorf("output contains org token")
	}
}

func TestWhoamiRespectsHomeFlag(t *testing.T) {
	resetWhoamiFlags()

	dir := t.TempDir()
	homePath := setupWhoamiDir(t, dir, map[string]string{
		"config.yaml": "org: flagorg\nbot: flagbot\n",
		"public_key":  "flagpubkey",
	})

	t.Chdir(t.TempDir())

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(new(bytes.Buffer))
	rootCmd.SetArgs([]string{"whoami", "--home", homePath})

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("whoami --home returned error: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "flagorg") || !strings.Contains(output, "flagbot") {
		t.Errorf("output = %q, want it to contain flagorg and flagbot", output)
	}
}
