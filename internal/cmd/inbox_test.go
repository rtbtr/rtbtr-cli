package cmd

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// resetInboxFlags resets all flag state between inbox tests.
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
// a valid Ed25519 private_key file. Returns the home path.
func setupInboxIdentity(t *testing.T, parent string, org string, bot string) string {
	t.Helper()

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}

	seed := priv.Seed()
	encodedSeed := base64.RawURLEncoding.EncodeToString(seed)

	homePath := setupRtbtrDir(t, parent, map[string]string{
		"config.yaml": "org: " + org + "\nbot: " + bot + "\n",
		"private_key": encodedSeed,
	})

	return homePath
}

// T-I01: inbox is registered as a subcommand and produces help text.
func TestInboxCommandHelp(t *testing.T) {
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
func TestInboxErrorOnMissingRtbtrDir(t *testing.T) {
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
	if !strings.Contains(err.Error(), ".rtbtr") {
		t.Errorf("error = %q, want it to mention .rtbtr", err.Error())
	}
}

// T-I03: inbox rejects when config.yaml is missing from .rtbtr.
func TestInboxErrorOnMissingConfig(t *testing.T) {
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
	if !strings.Contains(err.Error(), "not registered: run rtbtr register first") {
		t.Errorf("error = %q, want it to contain 'not registered: run rtbtr register first'", err.Error())
	}
}

// T-I03: inbox rejects when org/bot are empty in config.yaml.
func TestInboxErrorOnEmptyOrgBot(t *testing.T) {
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
	if !strings.Contains(err.Error(), "not registered") {
		t.Errorf("error = %q, want it to contain 'not registered'", err.Error())
	}
}

// T-I04: inbox rejects when private_key file is missing.
func TestInboxErrorOnMissingPrivateKey(t *testing.T) {
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
	if !strings.Contains(err.Error(), "private key not found") {
		t.Errorf("error = %q, want it to contain 'private key not found'", err.Error())
	}
}

// T-I04: inbox trims whitespace around private_key before decoding.
func TestInboxTrimsPrivateKeyWhitespace(t *testing.T) {
	resetInboxFlags()

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	encodedSeed := base64.RawURLEncoding.EncodeToString(priv.Seed())

	// Add whitespace around the key content.
	paddedKey := "  \n" + encodedSeed + "\n  "

	dir := t.TempDir()
	rtbtrDir := filepath.Join(dir, ".rtbtr")
	if mkErr := os.MkdirAll(rtbtrDir, 0o755); mkErr != nil {
		t.Fatalf("creating .rtbtr dir: %v", mkErr)
	}
	if wErr := os.WriteFile(filepath.Join(rtbtrDir, "config.yaml"), []byte("org: testorg\nbot: testbot\n"), 0o644); wErr != nil {
		t.Fatalf("writing config: %v", wErr)
	}
	if wErr := os.WriteFile(filepath.Join(rtbtrDir, "private_key"), []byte(paddedKey), 0o600); wErr != nil {
		t.Fatalf("writing private_key: %v", wErr)
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

	if execErr := rootCmd.Execute(); execErr != nil {
		t.Fatalf("inbox should handle whitespace-padded private_key, got error: %v", execErr)
	}
}

// T-I05: inbox sends GET to /orgs/{org}/bots/{bot}/inbox with signature headers.
func TestInboxSendsSignedGetRequest(t *testing.T) {
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
	homePath := setupInboxIdentity(t, dir, "testorg", "testbot")

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
	if capturedSig == "" {
		t.Error("Signature header is empty")
	}
}

// T-I05: The key ID used for signing is {org}/{bot}.
func TestInboxSigningUsesOrgBotKeyID(t *testing.T) {
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
	homePath := setupInboxIdentity(t, dir, "acme", "helper")

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"inbox", "--home", homePath})

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("inbox returned error: %v", err)
	}

	expectedKeyID := fmt.Sprintf(`keyid="%s/o/acme/helper"`, platformBaseURL)
	if !strings.Contains(capturedSigInput, expectedKeyID) {
		t.Errorf("Signature-Input = %q, want it to contain %s", capturedSigInput, expectedKeyID)
	}
}

// T-I06: Filter flags are correctly translated to query parameters.
func TestInboxFilterFlagsAsQueryParameters(t *testing.T) {
	resetInboxFlags()

	var capturedQuery url.Values

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
	homePath := setupInboxIdentity(t, dir, "testorg", "testbot")

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{
		"inbox", "--home", homePath,
		"--direction", "inbound",
		"--status", "delivered",
		"--page", "3",
		"--limit", "50",
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
	if v := capturedQuery.Get("page"); v != "3" {
		t.Errorf("query page = %q, want '3'", v)
	}
	if v := capturedQuery.Get("limit"); v != "50" {
		t.Errorf("query limit = %q, want '50'", v)
	}
	if v := capturedQuery.Get("order"); v != "asc" {
		t.Errorf("query order = %q, want 'asc'", v)
	}
}

// T-I06: Default query parameters present when optional flags not set.
func TestInboxDefaultQueryParams(t *testing.T) {
	resetInboxFlags()

	var capturedQuery url.Values

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
	homePath := setupInboxIdentity(t, dir, "testorg", "testbot")

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

	// direction and status should not be present when not set.
	if v := capturedQuery.Get("direction"); v != "" {
		t.Errorf("default query direction = %q, want empty (not present)", v)
	}
	if v := capturedQuery.Get("status"); v != "" {
		t.Errorf("default query status = %q, want empty (not present)", v)
	}
}

// T-I07: --json flag outputs the raw API JSON response body.
func TestInboxJsonFlagOutputsRawBody(t *testing.T) {
	resetInboxFlags()

	responseBody := `[{"id":"msg-abc","sender":{"org":"org1","name":"bot1"},"recipient":{"org":"org2","name":"bot2"},"status":"delivered","created_at":"2026-03-01T12:00:00Z","payload_size":128}]`

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
	homePath := setupInboxIdentity(t, dir, "testorg", "testbot")

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"inbox", "--json", "--home", homePath})

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("inbox --json returned error: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "msg-abc") {
		t.Errorf("--json output missing message id: %q", output)
	}
	if !strings.Contains(output, "delivered") {
		t.Errorf("--json output missing status: %q", output)
	}
	if !strings.Contains(output, "org1") || !strings.Contains(output, "bot1") {
		t.Errorf("--json output missing sender identity: %q", output)
	}
}

// T-I07: Table output includes header row and message data rows.
func TestInboxTableOutputFormat(t *testing.T) {
	resetInboxFlags()

	responseBody := `[{"id":"msg-12345678","sender":{"org":"org1","name":"bot1"},"recipient":{"org":"org2","name":"bot2"},"status":"delivered","created_at":"2026-03-01T12:00:00Z","payload_size":128}]`

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
	homePath := setupInboxIdentity(t, dir, "testorg", "testbot")

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"inbox", "--home", homePath})

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("inbox table output returned error: %v", err)
	}

	output := buf.String()

	// Must include header columns.
	for _, header := range []string{"ID", "FROM", "TO", "STATUS", "CREATED"} {
		if !strings.Contains(output, header) {
			t.Errorf("table output missing header %q: %q", header, output)
		}
	}

	// Must include message data.
	if !strings.Contains(output, "msg-1234") {
		t.Errorf("table output missing truncated message id: %q", output)
	}
	if !strings.Contains(output, "delivered") {
		t.Errorf("table output missing status: %q", output)
	}
}

// T-I07: Empty response array prints "no messages".
func TestInboxEmptyResponsePrintsNoMessages(t *testing.T) {
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
	homePath := setupInboxIdentity(t, dir, "testorg", "testbot")

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"inbox", "--home", homePath})

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("inbox empty response returned error: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "no messages") {
		t.Errorf("empty table output = %q, want it to contain 'no messages'", output)
	}
}

// T-I08: HTTP 401 maps to "authentication failed: signature rejected".
func TestInboxHttp401ErrorMapping(t *testing.T) {
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
	homePath := setupInboxIdentity(t, dir, "testorg", "testbot")

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

// T-I08: HTTP 403 maps to "not authorized to access inbox".
func TestInboxHttp403ErrorMapping(t *testing.T) {
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
	homePath := setupInboxIdentity(t, dir, "testorg", "testbot")

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

// T-I08: Non-2xx (e.g. 500) maps to "inbox failed: {status}: {body}".
func TestInboxHttp500GenericErrorMapping(t *testing.T) {
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
	homePath := setupInboxIdentity(t, dir, "testorg", "testbot")

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
