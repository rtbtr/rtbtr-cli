package cmd

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rtbtr/rtbtr-cli/internal/config"
)

func resetRegisterFlags() {
	homeFlag = ""
	orgFlag = ""
	botFlag = ""
	registerForceFlag = false

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

	if flag := registerCmd.Flags().Lookup("org"); flag != nil {
		if err := flag.Value.Set(flag.DefValue); err != nil {
			panic(err)
		}
		flag.Changed = false
	}

	if flag := registerCmd.Flags().Lookup("bot"); flag != nil {
		if err := flag.Value.Set(flag.DefValue); err != nil {
			panic(err)
		}
		flag.Changed = false
	}

	if flag := registerCmd.Flags().Lookup("force"); flag != nil {
		if err := flag.Value.Set(flag.DefValue); err != nil {
			panic(err)
		}
		flag.Changed = false
	}

	if flag := registerCmd.Flags().Lookup("help"); flag != nil {
		if err := flag.Value.Set(flag.DefValue); err != nil {
			panic(err)
		}
		flag.Changed = false
	}
}

// setupRtbtrDir creates a .rtbtr directory under parent with the specified files.
// Returns the path to the .rtbtr directory.
func setupRtbtrDir(t *testing.T, parent string, files map[string]string) string {
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

// T-03: register command rejects when --org is missing.
func TestRegisterRejectsMissingOrg(t *testing.T) {
	resetRegisterFlags()

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"register", "--bot", "mybot"})

	err := rootCmd.Execute()
	if err == nil {
		t.Fatal("register should return error when --org is missing")
	}
	errMsg := err.Error()
	if !strings.Contains(errMsg, "org") {
		t.Errorf("error = %q, want it to reference the missing org flag", errMsg)
	}
}

// T-03: register command rejects when --bot is missing.
func TestRegisterRejectsMissingBot(t *testing.T) {
	resetRegisterFlags()

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"register", "--org", "myorg"})

	err := rootCmd.Execute()
	if err == nil {
		t.Fatal("register should return error when --bot is missing")
	}
	errMsg := err.Error()
	if !strings.Contains(errMsg, "bot") {
		t.Errorf("error = %q, want it to reference the missing bot flag", errMsg)
	}
}

// T-04: register rejects if .rtbtr directory is not found.
func TestRegisterRejectsMissingRtbtrDir(t *testing.T) {
	resetRegisterFlags()

	dir := t.TempDir()
	t.Chdir(dir)

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"register", "--org", "myorg", "--bot", "mybot"})

	err := rootCmd.Execute()
	if err == nil {
		t.Fatal("register should return error when .rtbtr directory is not found")
	}
	errMsg := err.Error()
	if !strings.Contains(errMsg, ".rtbtr") {
		t.Errorf("error = %q, want it to mention .rtbtr not found", errMsg)
	}
}

// T-05: register rejects with 'already registered' message when config.yaml has identity and --force is not passed.
func TestRegisterRejectsExistingIdentity(t *testing.T) {
	resetRegisterFlags()

	dir := t.TempDir()
	setupRtbtrDir(t, dir, map[string]string{
		"config.yaml": "org: existingorg\nbot: existingbot\n",
		"public_key":  "fakepubkey",
		"org_token":   "faketoken",
	})

	homePath := filepath.Join(dir, ".rtbtr")
	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"register", "--org", "neworg", "--bot", "newbot", "--home", homePath})

	err := rootCmd.Execute()
	if err == nil {
		t.Fatal("register should return error when already registered without --force")
	}
	errMsg := err.Error()
	if !strings.Contains(errMsg, "already registered as existingorg/existingbot") {
		t.Errorf("error = %q, want it to mention 'already registered as existingorg/existingbot'", errMsg)
	}
	if !strings.Contains(errMsg, "--force") {
		t.Errorf("error = %q, want it to mention '--force'", errMsg)
	}
}

// T-06: register rejects with 'public key not found' when public_key file is absent.
func TestRegisterRejectsMissingPublicKey(t *testing.T) {
	resetRegisterFlags()

	dir := t.TempDir()
	setupRtbtrDir(t, dir, map[string]string{})

	homePath := filepath.Join(dir, ".rtbtr")
	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"register", "--org", "myorg", "--bot", "mybot", "--home", homePath})

	err := rootCmd.Execute()
	if err == nil {
		t.Fatal("register should return error when public_key is missing")
	}
	errMsg := err.Error()
	if !strings.Contains(errMsg, "public key not found") {
		t.Errorf("error = %q, want it to contain 'public key not found'", errMsg)
	}
	if !strings.Contains(errMsg, "rtbtr keygen") {
		t.Errorf("error = %q, want it to suggest running 'rtbtr keygen'", errMsg)
	}
}

// T-07: register rejects with 'org token not found' when org_token file is absent.
func TestRegisterRejectsMissingOrgToken(t *testing.T) {
	resetRegisterFlags()

	dir := t.TempDir()
	setupRtbtrDir(t, dir, map[string]string{
		"public_key": "fakepubkey",
	})

	homePath := filepath.Join(dir, ".rtbtr")
	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"register", "--org", "myorg", "--bot", "mybot", "--home", homePath})

	err := rootCmd.Execute()
	if err == nil {
		t.Fatal("register should return error when org_token is missing")
	}
	errMsg := err.Error()
	if !strings.Contains(errMsg, "org token not found") {
		t.Errorf("error = %q, want it to contain 'org token not found'", errMsg)
	}
	if !strings.Contains(errMsg, ".rtbtr/org_token") {
		t.Errorf("error = %q, want it to suggest placing token in .rtbtr/org_token", errMsg)
	}
}

// T-08: register sends a correct POST request with Bearer auth and JSON body.
func TestRegisterSendsCorrectAPIRequest(t *testing.T) {
	resetRegisterFlags()

	var capturedMethod string
	var capturedPath string
	var capturedAuth string
	var capturedBody map[string]string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedMethod = r.Method
		capturedPath = r.URL.Path
		capturedAuth = r.Header.Get("Authorization")

		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("reading request body: %v", err)
		}
		capturedBody = make(map[string]string)
		if err := json.Unmarshal(body, &capturedBody); err != nil {
			t.Errorf("parsing request body: %v", err)
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"bot_id":"test-id-123"}`))
	}))
	defer server.Close()

	oldBaseURL := apiBaseURL
	apiBaseURL = server.URL
	defer func() { apiBaseURL = oldBaseURL }()

	dir := t.TempDir()
	setupRtbtrDir(t, dir, map[string]string{
		"public_key": "mypublickey123",
		"org_token":  "mytoken456",
	})

	homePath := filepath.Join(dir, ".rtbtr")
	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"register", "--org", "myorg", "--bot", "mybot", "--home", homePath})

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("register returned error: %v", err)
	}

	if capturedMethod != "POST" {
		t.Errorf("request method = %q, want POST", capturedMethod)
	}
	if capturedPath != "/orgs/myorg/bots" {
		t.Errorf("request path = %q, want /orgs/myorg/bots", capturedPath)
	}
	if capturedAuth != "Bearer mytoken456" {
		t.Errorf("Authorization header = %q, want %q", capturedAuth, "Bearer mytoken456")
	}
	if capturedBody["name"] != "mybot" {
		t.Errorf("request body name = %q, want %q", capturedBody["name"], "mybot")
	}
	if capturedBody["public_key"] != "mypublickey123" {
		t.Errorf("request body public_key = %q, want %q", capturedBody["public_key"], "mypublickey123")
	}
}

// T-09: register maps HTTP 401 to 'org token is invalid or expired'.
func TestRegisterMaps401Error(t *testing.T) {
	resetRegisterFlags()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"error":"unauthorized"}`))
	}))
	defer server.Close()

	oldBaseURL := apiBaseURL
	apiBaseURL = server.URL
	defer func() { apiBaseURL = oldBaseURL }()

	dir := t.TempDir()
	setupRtbtrDir(t, dir, map[string]string{
		"public_key": "fakepubkey",
		"org_token":  "badtoken",
	})

	homePath := filepath.Join(dir, ".rtbtr")
	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"register", "--org", "myorg", "--bot", "mybot", "--home", homePath})

	err := rootCmd.Execute()
	if err == nil {
		t.Fatal("register should return error for HTTP 401")
	}
	if !strings.Contains(err.Error(), "org token is invalid or expired") {
		t.Errorf("error = %q, want it to contain 'org token is invalid or expired'", err.Error())
	}
}

// T-10: register maps HTTP 409 to 'bot already has an active key, revoke it first'.
func TestRegisterMaps409Error(t *testing.T) {
	resetRegisterFlags()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusConflict)
		w.Write([]byte(`{"error":"conflict"}`))
	}))
	defer server.Close()

	oldBaseURL := apiBaseURL
	apiBaseURL = server.URL
	defer func() { apiBaseURL = oldBaseURL }()

	dir := t.TempDir()
	setupRtbtrDir(t, dir, map[string]string{
		"public_key": "fakepubkey",
		"org_token":  "faketoken",
	})

	homePath := filepath.Join(dir, ".rtbtr")
	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"register", "--org", "myorg", "--bot", "mybot", "--home", homePath})

	err := rootCmd.Execute()
	if err == nil {
		t.Fatal("register should return error for HTTP 409")
	}
	if !strings.Contains(err.Error(), "bot already has an active key, revoke it first") {
		t.Errorf("error = %q, want it to contain 'bot already has an active key, revoke it first'", err.Error())
	}
}

// T-11: register maps HTTP 422 with 'Public key has already been used' body to the correct error.
func TestRegisterMaps422PublicKeyReused(t *testing.T) {
	resetRegisterFlags()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnprocessableEntity)
		w.Write([]byte(`{"detail":"Public key has already been used"}`))
	}))
	defer server.Close()

	oldBaseURL := apiBaseURL
	apiBaseURL = server.URL
	defer func() { apiBaseURL = oldBaseURL }()

	dir := t.TempDir()
	setupRtbtrDir(t, dir, map[string]string{
		"public_key": "fakepubkey",
		"org_token":  "faketoken",
	})

	homePath := filepath.Join(dir, ".rtbtr")
	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"register", "--org", "myorg", "--bot", "mybot", "--home", homePath})

	err := rootCmd.Execute()
	if err == nil {
		t.Fatal("register should return error for HTTP 422 with public key reused")
	}
	errMsg := err.Error()
	if !strings.Contains(errMsg, "public key has already been used for this bot") {
		t.Errorf("error = %q, want it to contain 'public key has already been used for this bot'", errMsg)
	}
	if !strings.Contains(errMsg, "rtbtr keygen --force") {
		t.Errorf("error = %q, want it to suggest 'rtbtr keygen --force'", errMsg)
	}
}

// T-12: On successful registration, config.yaml is written with correct org and bot.
func TestRegisterWritesConfigOnSuccess(t *testing.T) {
	resetRegisterFlags()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"bot_id":"abc123"}`))
	}))
	defer server.Close()

	oldBaseURL := apiBaseURL
	apiBaseURL = server.URL
	defer func() { apiBaseURL = oldBaseURL }()

	dir := t.TempDir()
	homePath := setupRtbtrDir(t, dir, map[string]string{
		"public_key": "fakepubkey",
		"org_token":  "faketoken",
	})

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"register", "--org", "myorg", "--bot", "mybot", "--home", homePath})

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("register returned error: %v", err)
	}

	cfg, err := config.Load(homePath)
	if err != nil {
		t.Fatalf("loading config.yaml after register: %v", err)
	}

	if cfg.Org != "myorg" {
		t.Errorf("config.Org = %q, want %q", cfg.Org, "myorg")
	}
	if cfg.Bot != "mybot" {
		t.Errorf("config.Bot = %q, want %q", cfg.Bot, "mybot")
	}
}

// T-13: On success, register prints 'registered as {org}/{bot}' and bot_id to stdout.
func TestRegisterPrintsRegistrationInfo(t *testing.T) {
	resetRegisterFlags()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"bot_id":"abc123"}`))
	}))
	defer server.Close()

	oldBaseURL := apiBaseURL
	apiBaseURL = server.URL
	defer func() { apiBaseURL = oldBaseURL }()

	dir := t.TempDir()
	homePath := setupRtbtrDir(t, dir, map[string]string{
		"public_key": "fakepubkey",
		"org_token":  "faketoken",
	})

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"register", "--org", "myorg", "--bot", "mybot", "--home", homePath})

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("register returned error: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "registered as myorg/mybot") {
		t.Errorf("stdout = %q, want it to contain 'registered as myorg/mybot'", output)
	}
	if !strings.Contains(output, "abc123") {
		t.Errorf("stdout = %q, want it to contain bot_id 'abc123'", output)
	}
}

// T-14: register --force allows overwriting existing config.yaml identity.
func TestRegisterForceOverwritesIdentity(t *testing.T) {
	resetRegisterFlags()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"bot_id":"new-id"}`))
	}))
	defer server.Close()

	oldBaseURL := apiBaseURL
	apiBaseURL = server.URL
	defer func() { apiBaseURL = oldBaseURL }()

	dir := t.TempDir()
	homePath := setupRtbtrDir(t, dir, map[string]string{
		"config.yaml": "org: oldorg\nbot: oldbot\n",
		"public_key":  "fakepubkey",
		"org_token":   "faketoken",
	})

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"register", "--org", "neworg", "--bot", "newbot", "--force", "--home", homePath})

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("register --force returned error: %v", err)
	}

	cfg, err := config.Load(homePath)
	if err != nil {
		t.Fatalf("loading config.yaml after forced register: %v", err)
	}

	if cfg.Org != "neworg" {
		t.Errorf("config.Org = %q, want %q", cfg.Org, "neworg")
	}
	if cfg.Bot != "newbot" {
		t.Errorf("config.Bot = %q, want %q", cfg.Bot, "newbot")
	}

	output := buf.String()
	if !strings.Contains(output, "registered as neworg/newbot") {
		t.Errorf("stdout = %q, want it to contain 'registered as neworg/newbot'", output)
	}
}
