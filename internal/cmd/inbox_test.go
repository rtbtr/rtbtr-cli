package cmd

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// resetInboxFlags resets all flag state between inbox tests. This must be updated
// whenever a new flag is added to rootCmd or inboxCmd.
func resetInboxFlags() {
	homeFlag = ""
	directionFlag = ""
	statusFlag = ""
	pageFlag = 1
	limitFlag = 20
	orderFlag = "desc"
	jsonFlag = false

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

	for _, name := range []string{"direction", "status", "page", "limit", "order", "json", "help"} {
		if flag := inboxCmd.Flags().Lookup(name); flag != nil {
			if err := flag.Value.Set(flag.DefValue); err != nil {
				panic(err)
			}
			flag.Changed = false
		}
	}
}

// setupInboxIdentity creates a .rtbtr directory with a valid config.yaml and
// a valid Ed25519 private_key file. Returns the home path and the public key.
func setupInboxIdentity(t *testing.T, parent string, org string, bot string) (string, ed25519.PublicKey) {
	t.Helper()

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}

	seed := priv.Seed()
	encodedSeed := base64.RawURLEncoding.EncodeToString(seed)

	homePath := setupRtbtrDir(t, parent, map[string]string{
		"config.yaml": "org: " + org + "\nbot: " + bot + "\n",
		"private_key": encodedSeed,
	})

	return homePath, pub
}

// T-I01: inbox is registered as a subcommand and produces help text.
func TestInboxSubcommandRegistered(t *testing.T) {
	resetInboxFlags()

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetArgs([]string{"inbox", "--help"})

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("inbox --help returned error: %v", err)
	}

	output := buf.String()
	if len(output) == 0 {
		t.Fatal("inbox --help produced no output")
	}
	if !strings.Contains(output, "inbox") {
		t.Errorf("help output does not contain 'inbox': %s", output)
	}
}

// T-I02: inbox rejects when .rtbtr directory does not exist.
func TestInboxRejectsMissingRtbtrDir(t *testing.T) {
	resetInboxFlags()

	dir := t.TempDir()
	t.Chdir(dir)

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"inbox"})

	err := rootCmd.Execute()
	if err == nil {
		t.Fatal("inbox should return error when .rtbtr directory is not found")
	}
	errMsg := err.Error()
	if !strings.Contains(errMsg, ".rtbtr") {
		t.Errorf("error = %q, want it to mention .rtbtr not found", errMsg)
	}
}

// T-I03: inbox rejects when config.yaml is missing.
func TestInboxRejectsMissingConfig(t *testing.T) {
	resetInboxFlags()

	dir := t.TempDir()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	encodedSeed := base64.RawURLEncoding.EncodeToString(priv.Seed())

	homePath := setupRtbtrDir(t, dir, map[string]string{
		"private_key": encodedSeed,
	})

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"inbox", "--home", homePath})

	err = rootCmd.Execute()
	if err == nil {
		t.Fatal("inbox should return error when config.yaml is missing")
	}
	errMsg := err.Error()
	if !strings.Contains(errMsg, "config") {
		t.Errorf("error = %q, want it to mention 'config'", errMsg)
	}
}

// T-I03: inbox rejects when config.yaml has empty org/bot fields.
func TestInboxRejectsEmptyOrgBot(t *testing.T) {
	resetInboxFlags()

	dir := t.TempDir()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	encodedSeed := base64.RawURLEncoding.EncodeToString(priv.Seed())

	homePath := setupRtbtrDir(t, dir, map[string]string{
		"config.yaml": "org: \"\"\nbot: \"\"\n",
		"private_key": encodedSeed,
	})

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"inbox", "--home", homePath})

	err = rootCmd.Execute()
	if err == nil {
		t.Fatal("inbox should return error when org/bot are empty")
	}
	errMsg := err.Error()
	if !strings.Contains(errMsg, "not registered") {
		t.Errorf("error = %q, want it to contain 'not registered'", errMsg)
	}
}

// T-I04: inbox rejects when private_key file is missing.
func TestInboxRejectsMissingPrivateKey(t *testing.T) {
	resetInboxFlags()

	dir := t.TempDir()
	homePath := setupRtbtrDir(t, dir, map[string]string{
		"config.yaml": "org: testorg\nbot: testbot\n",
	})

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"inbox", "--home", homePath})

	err := rootCmd.Execute()
	if err == nil {
		t.Fatal("inbox should return error when private_key is missing")
	}
	errMsg := err.Error()
	if !strings.Contains(errMsg, "private key not found") {
		t.Errorf("error = %q, want it to contain 'private key not found'", errMsg)
	}
}

// T-I05: inbox sends a GET request to /orgs/{org}/bots/{bot}/inbox with signature headers.
func TestInboxSendsCorrectAPIRequest(t *testing.T) {
	resetInboxFlags()

	var capturedMethod string
	var capturedPath string
	var capturedSigInput string
	var capturedSig string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedMethod = r.Method
		capturedPath = r.URL.Path
		capturedSigInput = r.Header.Get("Signature-Input")
		capturedSig = r.Header.Get("Signature")

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`[]`))
	}))
	defer server.Close()

	oldBaseURL := apiBaseURL
	apiBaseURL = server.URL
	defer func() { apiBaseURL = oldBaseURL }()

	dir := t.TempDir()
	homePath, _ := setupInboxIdentity(t, dir, "testorg", "testbot")

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"inbox", "--home", homePath})

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("inbox returned error: %v", err)
	}

	if capturedMethod != "GET" {
		t.Errorf("request method = %q, want GET", capturedMethod)
	}
	if capturedPath != "/orgs/testorg/bots/testbot/inbox" {
		t.Errorf("request path = %q, want /orgs/testorg/bots/testbot/inbox", capturedPath)
	}
	if capturedSigInput == "" {
		t.Error("Signature-Input header is empty")
	}
	if !strings.Contains(capturedSigInput, "testorg/testbot") {
		t.Errorf("Signature-Input = %q, want it to contain keyid 'testorg/testbot'", capturedSigInput)
	}
	if capturedSig == "" {
		t.Error("Signature header is empty")
	}
}

// T-I06: Filter flags are correctly translated to query parameters.
func TestInboxQueryParameters(t *testing.T) {
	resetInboxFlags()

	var capturedQuery map[string][]string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedQuery = r.URL.Query()

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`[]`))
	}))
	defer server.Close()

	oldBaseURL := apiBaseURL
	apiBaseURL = server.URL
	defer func() { apiBaseURL = oldBaseURL }()

	dir := t.TempDir()
	homePath, _ := setupInboxIdentity(t, dir, "testorg", "testbot")

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{
		"inbox", "--home", homePath,
		"--direction", "inbound",
		"--status", "delivered",
		"--page", "2",
		"--limit", "10",
		"--order", "asc",
	})

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("inbox returned error: %v", err)
	}

	if v := capturedQuery.Get("direction"); v != "inbound" {
		t.Errorf("query direction = %q, want 'inbound'", v)
	}
	if v := capturedQuery.Get("status"); v != "delivered" {
		t.Errorf("query status = %q, want 'delivered'", v)
	}
	if v := capturedQuery.Get("page"); v != "2" {
		t.Errorf("query page = %q, want '2'", v)
	}
	if v := capturedQuery.Get("limit"); v != "10" {
		t.Errorf("query limit = %q, want '10'", v)
	}
	if v := capturedQuery.Get("order"); v != "asc" {
		t.Errorf("query order = %q, want 'asc'", v)
	}
}

// T-I06: Default query parameters are present when optional flags are not set.
func TestInboxDefaultQueryParameters(t *testing.T) {
	resetInboxFlags()

	var capturedQuery map[string][]string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedQuery = r.URL.Query()

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`[]`))
	}))
	defer server.Close()

	oldBaseURL := apiBaseURL
	apiBaseURL = server.URL
	defer func() { apiBaseURL = oldBaseURL }()

	dir := t.TempDir()
	homePath, _ := setupInboxIdentity(t, dir, "testorg", "testbot")

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"inbox", "--home", homePath})

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("inbox returned error: %v", err)
	}

	if v := capturedQuery.Get("page"); v != "1" {
		t.Errorf("default query page = %q, want '1'", v)
	}
	if v := capturedQuery.Get("limit"); v != "20" {
		t.Errorf("default query limit = %q, want '20'", v)
	}
	if v := capturedQuery.Get("order"); v != "desc" {
		t.Errorf("default query order = %q, want 'desc'", v)
	}

	// direction and status should not be in query when not set.
	if v := capturedQuery.Get("direction"); v != "" {
		t.Errorf("default query direction = %q, want empty (not present)", v)
	}
	if v := capturedQuery.Get("status"); v != "" {
		t.Errorf("default query status = %q, want empty (not present)", v)
	}
}

// T-I07: --json flag outputs the raw API response body to stdout.
func TestInboxJsonOutput(t *testing.T) {
	resetInboxFlags()

	responseBody := `[{"id":"msg-001","sender":"org1/bot1","recipient":"org2/bot2","status":"delivered","created_at":"2026-01-01T00:00:00Z"}]`

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(responseBody))
	}))
	defer server.Close()

	oldBaseURL := apiBaseURL
	apiBaseURL = server.URL
	defer func() { apiBaseURL = oldBaseURL }()

	dir := t.TempDir()
	homePath, _ := setupInboxIdentity(t, dir, "testorg", "testbot")

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"inbox", "--json", "--home", homePath})

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("inbox --json returned error: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "msg-001") {
		t.Errorf("--json output = %q, want it to contain 'msg-001'", output)
	}
	if !strings.Contains(output, "delivered") {
		t.Errorf("--json output = %q, want it to contain 'delivered'", output)
	}
	if !strings.Contains(output, "org1/bot1") {
		t.Errorf("--json output = %q, want it to contain 'org1/bot1'", output)
	}
}

// T-I07: Table output shows header row and data rows.
func TestInboxTableOutput(t *testing.T) {
	resetInboxFlags()

	responseBody := `[{"id":"msg-001","sender":"org1/bot1","recipient":"org2/bot2","status":"delivered","created_at":"2026-01-01T00:00:00Z"}]`

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(responseBody))
	}))
	defer server.Close()

	oldBaseURL := apiBaseURL
	apiBaseURL = server.URL
	defer func() { apiBaseURL = oldBaseURL }()

	dir := t.TempDir()
	homePath, _ := setupInboxIdentity(t, dir, "testorg", "testbot")

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"inbox", "--home", homePath})

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("inbox table output returned error: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "ID") {
		t.Errorf("table output missing header 'ID': %q", output)
	}
	if !strings.Contains(output, "FROM") {
		t.Errorf("table output missing header 'FROM': %q", output)
	}
	if !strings.Contains(output, "STATUS") {
		t.Errorf("table output missing header 'STATUS': %q", output)
	}
	if !strings.Contains(output, "CREATED") {
		t.Errorf("table output missing header 'CREATED': %q", output)
	}
	if !strings.Contains(output, "msg-001") {
		t.Errorf("table output missing message id: %q", output)
	}
	if !strings.Contains(output, "delivered") {
		t.Errorf("table output missing status: %q", output)
	}
}

// T-I07: Empty response prints 'no messages'.
func TestInboxEmptyTableOutput(t *testing.T) {
	resetInboxFlags()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`[]`))
	}))
	defer server.Close()

	oldBaseURL := apiBaseURL
	apiBaseURL = server.URL
	defer func() { apiBaseURL = oldBaseURL }()

	dir := t.TempDir()
	homePath, _ := setupInboxIdentity(t, dir, "testorg", "testbot")

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"inbox", "--home", homePath})

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("inbox empty table returned error: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "no messages") {
		t.Errorf("empty table output = %q, want it to contain 'no messages'", output)
	}
}

// T-I08a: HTTP 401 maps to 'authentication failed: signature rejected'.
func TestInboxMaps401Error(t *testing.T) {
	resetInboxFlags()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"error":"unauthorized"}`))
	}))
	defer server.Close()

	oldBaseURL := apiBaseURL
	apiBaseURL = server.URL
	defer func() { apiBaseURL = oldBaseURL }()

	dir := t.TempDir()
	homePath, _ := setupInboxIdentity(t, dir, "testorg", "testbot")

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"inbox", "--home", homePath})

	err := rootCmd.Execute()
	if err == nil {
		t.Fatal("inbox should return error for HTTP 401")
	}
	if !strings.Contains(err.Error(), "authentication failed: signature rejected") {
		t.Errorf("error = %q, want it to contain 'authentication failed: signature rejected'", err.Error())
	}
}

// T-I08b: HTTP 403 maps to 'not authorized to access inbox'.
func TestInboxMaps403Error(t *testing.T) {
	resetInboxFlags()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte(`{"error":"forbidden"}`))
	}))
	defer server.Close()

	oldBaseURL := apiBaseURL
	apiBaseURL = server.URL
	defer func() { apiBaseURL = oldBaseURL }()

	dir := t.TempDir()
	homePath, _ := setupInboxIdentity(t, dir, "testorg", "testbot")

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"inbox", "--home", homePath})

	err := rootCmd.Execute()
	if err == nil {
		t.Fatal("inbox should return error for HTTP 403")
	}
	if !strings.Contains(err.Error(), "not authorized to access inbox") {
		t.Errorf("error = %q, want it to contain 'not authorized to access inbox'", err.Error())
	}
}

// T-I08c: Non-2xx HTTP responses other than 401/403 map to 'inbox failed: {status}: {body}'.
func TestInboxMaps500GenericError(t *testing.T) {
	resetInboxFlags()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"error":"internal"}`))
	}))
	defer server.Close()

	oldBaseURL := apiBaseURL
	apiBaseURL = server.URL
	defer func() { apiBaseURL = oldBaseURL }()

	dir := t.TempDir()
	homePath, _ := setupInboxIdentity(t, dir, "testorg", "testbot")

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"inbox", "--home", homePath})

	err := rootCmd.Execute()
	if err == nil {
		t.Fatal("inbox should return error for HTTP 500")
	}
	errMsg := err.Error()
	if !strings.Contains(errMsg, "inbox failed") {
		t.Errorf("error = %q, want it to contain 'inbox failed'", errMsg)
	}
	if !strings.Contains(errMsg, "500") {
		t.Errorf("error = %q, want it to contain status code '500'", errMsg)
	}
}

// T-I05: Verify the key ID used for signing is {org}/{bot}.
func TestInboxSigningKeyID(t *testing.T) {
	resetInboxFlags()

	var capturedSigInput string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedSigInput = r.Header.Get("Signature-Input")

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`[]`))
	}))
	defer server.Close()

	oldBaseURL := apiBaseURL
	apiBaseURL = server.URL
	defer func() { apiBaseURL = oldBaseURL }()

	dir := t.TempDir()
	homePath, _ := setupInboxIdentity(t, dir, "myorg", "mybot")

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"inbox", "--home", homePath})

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("inbox returned error: %v", err)
	}

	if !strings.Contains(capturedSigInput, `keyid="myorg/mybot"`) {
		t.Errorf("Signature-Input = %q, want it to contain keyid=\"myorg/mybot\"", capturedSigInput)
	}
}

// T-I04: Verify the private key file is trimmed and base64url-no-pad decoded.
func TestInboxPrivateKeyTrimmedAndDecoded(t *testing.T) {
	resetInboxFlags()

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	encodedSeed := base64.RawURLEncoding.EncodeToString(priv.Seed())

	// Add whitespace around the key to ensure trimming.
	paddedKey := "  \n" + encodedSeed + "\n  "

	dir := t.TempDir()
	rtbtrDir := filepath.Join(dir, ".rtbtr")
	if err := os.MkdirAll(rtbtrDir, 0o755); err != nil {
		t.Fatalf("creating .rtbtr dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(rtbtrDir, "config.yaml"), []byte("org: testorg\nbot: testbot\n"), 0o644); err != nil {
		t.Fatalf("writing config: %v", err)
	}
	if err := os.WriteFile(filepath.Join(rtbtrDir, "private_key"), []byte(paddedKey), 0o600); err != nil {
		t.Fatalf("writing private_key: %v", err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`[]`))
	}))
	defer server.Close()

	oldBaseURL := apiBaseURL
	apiBaseURL = server.URL
	defer func() { apiBaseURL = oldBaseURL }()

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"inbox", "--home", rtbtrDir})

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("inbox should handle whitespace-padded private_key, got error: %v", err)
	}
}
