package cmd

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// resetWhoamiFlags resets all flag state between tests. This must be updated
// whenever a new flag is added to rootCmd or whoamiCmd.
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

// setupWhoamiDir creates a .rtbtr directory with the given files under parent.
// Returns the path to the .rtbtr directory.
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

// T-W01: whoami prints org, bot, and public key from config in default text format.
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
		t.Errorf("output = %q, want it to contain org 'acme'", output)
	}
	if !strings.Contains(output, "weather-bot") {
		t.Errorf("output = %q, want it to contain bot 'weather-bot'", output)
	}
	if !strings.Contains(output, "abc123def456") {
		t.Errorf("output = %q, want it to contain public key 'abc123def456'", output)
	}
}

// T-W01: whoami output includes labeled fields (Org, Bot, Public Key).
func TestWhoamiOutputFormat(t *testing.T) {
	resetWhoamiFlags()

	dir := t.TempDir()
	homePath := setupWhoamiDir(t, dir, map[string]string{
		"config.yaml": "org: testorg\nbot: testbot\n",
		"public_key":  "pubkey123",
	})

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(new(bytes.Buffer))
	rootCmd.SetArgs([]string{"whoami", "--home", homePath})

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("whoami returned error: %v", err)
	}

	output := buf.String()
	lines := strings.Split(strings.TrimSpace(output), "\n")
	if len(lines) < 3 {
		t.Fatalf("expected at least 3 lines of output, got %d: %q", len(lines), output)
	}

	// Verify each line contains expected label-value pairs
	foundOrg := false
	foundBot := false
	foundKey := false
	for _, line := range lines {
		lower := strings.ToLower(line)
		if strings.Contains(lower, "org") && strings.Contains(line, "testorg") {
			foundOrg = true
		}
		if strings.Contains(lower, "bot") && strings.Contains(line, "testbot") {
			foundBot = true
		}
		if strings.Contains(lower, "public") && strings.Contains(line, "pubkey123") {
			foundKey = true
		}
	}
	if !foundOrg {
		t.Errorf("output missing labeled org field with value 'testorg': %q", output)
	}
	if !foundBot {
		t.Errorf("output missing labeled bot field with value 'testbot': %q", output)
	}
	if !foundKey {
		t.Errorf("output missing labeled public key field with value 'pubkey123': %q", output)
	}
}

// T-W02: whoami --json outputs valid JSON with org, bot, and public_key fields.
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
	var result map[string]string
	if err := json.Unmarshal([]byte(output), &result); err != nil {
		t.Fatalf("output is not valid JSON: %v\noutput: %q", err, output)
	}

	if result["org"] != "acme" {
		t.Errorf("JSON org = %q, want %q", result["org"], "acme")
	}
	if result["bot"] != "weather-bot" {
		t.Errorf("JSON bot = %q, want %q", result["bot"], "weather-bot")
	}
	if result["public_key"] != "abc123def456" {
		t.Errorf("JSON public_key = %q, want %q", result["public_key"], "abc123def456")
	}
}

// T-W02: whoami --json output contains exactly the expected keys.
func TestWhoamiJsonKeys(t *testing.T) {
	resetWhoamiFlags()

	dir := t.TempDir()
	homePath := setupWhoamiDir(t, dir, map[string]string{
		"config.yaml": "org: keyorg\nbot: keybot\n",
		"public_key":  "keypub",
	})

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(new(bytes.Buffer))
	rootCmd.SetArgs([]string{"whoami", "--json", "--home", homePath})

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("whoami --json returned error: %v", err)
	}

	output := strings.TrimSpace(buf.String())
	var result map[string]interface{}
	if err := json.Unmarshal([]byte(output), &result); err != nil {
		t.Fatalf("output is not valid JSON: %v\noutput: %q", err, output)
	}

	expectedKeys := []string{"org", "bot", "public_key"}
	for _, key := range expectedKeys {
		if _, ok := result[key]; !ok {
			t.Errorf("JSON output missing key %q", key)
		}
	}
}

// T-W03: whoami returns error when config.yaml is missing (not registered).
func TestWhoamiNotRegistered(t *testing.T) {
	resetWhoamiFlags()

	dir := t.TempDir()
	// Create .rtbtr dir with only public_key but no config.yaml
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
	errMsg := err.Error()
	if !strings.Contains(errMsg, "config") {
		t.Errorf("error = %q, want it to reference config", errMsg)
	}
}

// T-W03: whoami returns error when .rtbtr directory does not exist.
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
	errMsg := err.Error()
	if !strings.Contains(errMsg, ".rtbtr") {
		t.Errorf("error = %q, want it to mention .rtbtr not found", errMsg)
	}
}

// T-W04: whoami returns error when public_key file is missing.
func TestWhoamiMissingPublicKey(t *testing.T) {
	resetWhoamiFlags()

	dir := t.TempDir()
	// Create .rtbtr dir with config.yaml but no public_key
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
	errMsg := err.Error()
	if !strings.Contains(errMsg, "public") || !strings.Contains(errMsg, "key") {
		t.Errorf("error = %q, want it to mention public key", errMsg)
	}
}

// T-W05: whoami subcommand is registered on the root command and functional.
func TestWhoamiSubcommandRegistered(t *testing.T) {
	resetWhoamiFlags()

	// Verify help works
	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(new(bytes.Buffer))
	rootCmd.SetArgs([]string{"whoami", "--help"})

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("whoami --help returned error: %v", err)
	}

	helpOutput := buf.String()
	if len(helpOutput) == 0 {
		t.Fatal("whoami --help produced no output")
	}
	if !strings.Contains(helpOutput, "whoami") {
		t.Errorf("help output does not contain 'whoami': %s", helpOutput)
	}

	// Verify the command actually produces output when invoked with valid config.
	// A stub that does nothing will fail here — the command must be functional.
	resetWhoamiFlags()
	dir := t.TempDir()
	homePath := setupWhoamiDir(t, dir, map[string]string{
		"config.yaml": "org: regorg\nbot: regbot\n",
		"public_key":  "regpubkey",
	})

	buf = new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(new(bytes.Buffer))
	rootCmd.SetArgs([]string{"whoami", "--home", homePath})

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("whoami returned error: %v", err)
	}

	output := strings.TrimSpace(buf.String())
	if len(output) == 0 {
		t.Fatal("whoami produced no output — command must print identity info")
	}
	if !strings.Contains(output, "regorg") {
		t.Errorf("output = %q, want it to contain org 'regorg'", output)
	}
}

// T-W05: whoami respects --home flag to override home directory.
func TestWhoamiRespectsHomeFlag(t *testing.T) {
	resetWhoamiFlags()

	dir := t.TempDir()
	homePath := setupWhoamiDir(t, dir, map[string]string{
		"config.yaml": "org: flagorg\nbot: flagbot\n",
		"public_key":  "flagpubkey",
	})

	// Change to a different directory to verify --home overrides cwd
	t.Chdir(t.TempDir())

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(new(bytes.Buffer))
	rootCmd.SetArgs([]string{"whoami", "--home", homePath})

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("whoami --home returned error: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "flagorg") {
		t.Errorf("output = %q, want it to contain 'flagorg'", output)
	}
	if !strings.Contains(output, "flagbot") {
		t.Errorf("output = %q, want it to contain 'flagbot'", output)
	}
	if !strings.Contains(output, "flagpubkey") {
		t.Errorf("output = %q, want it to contain 'flagpubkey'", output)
	}
}

// T-W06: whoami does not expose private key or org token in output.
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

	// The command must produce non-empty output containing expected identity
	// data. Without this, an empty output trivially contains no secrets.
	if len(strings.TrimSpace(output)) == 0 {
		t.Fatal("whoami produced no output — cannot verify secret exclusion on empty output")
	}
	if !strings.Contains(output, "secretorg") {
		t.Errorf("output = %q, want it to contain org 'secretorg'", output)
	}
	if !strings.Contains(output, "publickeyvalue") {
		t.Errorf("output = %q, want it to contain public key 'publickeyvalue'", output)
	}

	if strings.Contains(output, "supersecretprivatekey") {
		t.Errorf("output contains private key: %q", output)
	}
	if strings.Contains(output, "supersecrettoken") {
		t.Errorf("output contains org token: %q", output)
	}
}

// T-W06: whoami --json does not expose private key or org token.
func TestWhoamiJsonDoesNotExposeSecrets(t *testing.T) {
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
	rootCmd.SetArgs([]string{"whoami", "--json", "--home", homePath})

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("whoami --json returned error: %v", err)
	}

	output := buf.String()
	if strings.Contains(output, "supersecretprivatekey") {
		t.Errorf("JSON output contains private key: %q", output)
	}
	if strings.Contains(output, "supersecrettoken") {
		t.Errorf("JSON output contains org token: %q", output)
	}

	var result map[string]interface{}
	if err := json.Unmarshal([]byte(strings.TrimSpace(output)), &result); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	if _, ok := result["private_key"]; ok {
		t.Errorf("JSON output contains private_key field")
	}
	if _, ok := result["org_token"]; ok {
		t.Errorf("JSON output contains org_token field")
	}
}

// T-W07: whoami reads public key content, not filename or path.
func TestWhoamiReadsPublicKeyContent(t *testing.T) {
	resetWhoamiFlags()

	dir := t.TempDir()
	pubKeyValue := "dGhpcyBpcyBhIHRlc3QgcHVibGljIGtleQ"
	homePath := setupWhoamiDir(t, dir, map[string]string{
		"config.yaml": "org: contentorg\nbot: contentbot\n",
		"public_key":  pubKeyValue,
	})

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(new(bytes.Buffer))
	rootCmd.SetArgs([]string{"whoami", "--home", homePath})

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("whoami returned error: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, pubKeyValue) {
		t.Errorf("output = %q, want it to contain the public key content %q", output, pubKeyValue)
	}
}

// T-W07: whoami --json includes public key as its file content.
func TestWhoamiJsonPublicKeyContent(t *testing.T) {
	resetWhoamiFlags()

	dir := t.TempDir()
	pubKeyValue := "dGhpcyBpcyBhIHRlc3QgcHVibGljIGtleQ"
	homePath := setupWhoamiDir(t, dir, map[string]string{
		"config.yaml": "org: jsonorg\nbot: jsonbot\n",
		"public_key":  pubKeyValue,
	})

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(new(bytes.Buffer))
	rootCmd.SetArgs([]string{"whoami", "--json", "--home", homePath})

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("whoami --json returned error: %v", err)
	}

	output := strings.TrimSpace(buf.String())
	var result map[string]string
	if err := json.Unmarshal([]byte(output), &result); err != nil {
		t.Fatalf("output is not valid JSON: %v\noutput: %q", err, output)
	}

	if result["public_key"] != pubKeyValue {
		t.Errorf("JSON public_key = %q, want %q", result["public_key"], pubKeyValue)
	}
}

// T-W08: whoami trims whitespace from public key file content.
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

	output := strings.TrimSpace(buf.String())
	var result map[string]string
	if err := json.Unmarshal([]byte(output), &result); err != nil {
		t.Fatalf("output is not valid JSON: %v\noutput: %q", err, output)
	}

	if strings.HasPrefix(result["public_key"], " ") || strings.HasSuffix(result["public_key"], " ") {
		t.Errorf("JSON public_key has leading/trailing spaces: %q", result["public_key"])
	}
	if strings.Contains(result["public_key"], "\n") {
		t.Errorf("JSON public_key contains newline: %q", result["public_key"])
	}
}

// T-W09: whoami is fully offline — no network calls needed.
// This test verifies whoami works in a fully isolated temp directory
// with no network access expectations.
func TestWhoamiIsOffline(t *testing.T) {
	resetWhoamiFlags()

	dir := t.TempDir()
	homePath := setupWhoamiDir(t, dir, map[string]string{
		"config.yaml": "org: offlineorg\nbot: offlinebot\n",
		"public_key":  "offlinepubkey",
	})

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(new(bytes.Buffer))
	rootCmd.SetArgs([]string{"whoami", "--home", homePath})

	// whoami must succeed without any network — purely filesystem-based
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("whoami returned error: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "offlineorg") {
		t.Errorf("output = %q, want it to contain 'offlineorg'", output)
	}
}
