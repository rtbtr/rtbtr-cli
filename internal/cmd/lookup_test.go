package cmd

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// resetLookupFlags resets all flag state between lookup tests.
func resetLookupFlags() {
	homeFlag = ""
	lookupJSONFlag = false

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

	for _, name := range []string{"json", "help"} {
		if flag := lookupCmd.Flags().Lookup(name); flag != nil {
			if err := flag.Value.Set(flag.DefValue); err != nil {
				panic(err)
			}
			flag.Changed = false
		}
	}
}

// L-01: lookup is registered as a subcommand and produces help text.
func TestLookupCommandHelp(t *testing.T) {
	resetLookupFlags()

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetArgs([]string{"lookup", "--help"})

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("lookup --help returned error: %v", err)
	}

	output := buf.String()
	if len(output) == 0 {
		t.Fatal("lookup --help produced no output")
	}
	if !strings.Contains(output, "lookup") {
		t.Errorf("help output does not contain 'lookup': %s", output)
	}
}

// L-02: lookup rejects when no positional argument is given.
func TestLookupRejectsMissingArgument(t *testing.T) {
	resetLookupFlags()

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"lookup"})

	err := rootCmd.Execute()
	if err == nil {
		t.Fatal("lookup should return error when no argument is given")
	}
}

// L-02: lookup rejects when more than one positional argument is given.
func TestLookupRejectsExtraArguments(t *testing.T) {
	resetLookupFlags()

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"lookup", "org/bot", "extra"})

	err := rootCmd.Execute()
	if err == nil {
		t.Fatal("lookup should return error when extra arguments are given")
	}
}

// L-03: lookup rejects malformed input without a slash.
func TestLookupRejectsInputWithoutSlash(t *testing.T) {
	resetLookupFlags()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("server should not be called for invalid input")
	}))
	defer server.Close()

	oldBaseURL := apiBaseURL
	apiBaseURL = server.URL
	defer func() { apiBaseURL = oldBaseURL }()

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"lookup", "noslash"})

	err := rootCmd.Execute()
	if err == nil {
		t.Fatal("lookup should return error for input without slash")
	}
	if !strings.Contains(err.Error(), "org/bot") {
		t.Errorf("error = %q, want it to reference expected org/bot format", err.Error())
	}
}

// L-03: lookup rejects input with multiple slashes.
func TestLookupRejectsInputWithMultipleSlashes(t *testing.T) {
	resetLookupFlags()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("server should not be called for invalid input")
	}))
	defer server.Close()

	oldBaseURL := apiBaseURL
	apiBaseURL = server.URL
	defer func() { apiBaseURL = oldBaseURL }()

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"lookup", "a/b/c"})

	err := rootCmd.Execute()
	if err == nil {
		t.Fatal("lookup should return error for input with multiple slashes")
	}
	if !strings.Contains(err.Error(), "org/bot") {
		t.Errorf("error = %q, want it to reference expected org/bot format", err.Error())
	}
}

// L-03: lookup rejects input with empty org part.
func TestLookupRejectsEmptyOrg(t *testing.T) {
	resetLookupFlags()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("server should not be called for invalid input")
	}))
	defer server.Close()

	oldBaseURL := apiBaseURL
	apiBaseURL = server.URL
	defer func() { apiBaseURL = oldBaseURL }()

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"lookup", "/bot"})

	err := rootCmd.Execute()
	if err == nil {
		t.Fatal("lookup should return error for empty org part")
	}
	if !strings.Contains(err.Error(), "org/bot") {
		t.Errorf("error = %q, want it to reference expected org/bot format", err.Error())
	}
}

// L-03: lookup rejects input with empty bot part.
func TestLookupRejectsEmptyBot(t *testing.T) {
	resetLookupFlags()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("server should not be called for invalid input")
	}))
	defer server.Close()

	oldBaseURL := apiBaseURL
	apiBaseURL = server.URL
	defer func() { apiBaseURL = oldBaseURL }()

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"lookup", "org/"})

	err := rootCmd.Execute()
	if err == nil {
		t.Fatal("lookup should return error for empty bot part")
	}
	if !strings.Contains(err.Error(), "org/bot") {
		t.Errorf("error = %q, want it to reference expected org/bot format", err.Error())
	}
}

// L-04: lookup sends an unauthenticated GET to /orgs/{org}/bots/{bot}.
func TestLookupSendsCorrectGetRequest(t *testing.T) {
	resetLookupFlags()

	var capturedMethod string
	var capturedPath string
	var capturedAuth string
	var capturedSigInput string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedMethod = r.Method
		capturedPath = r.URL.Path
		capturedAuth = r.Header.Get("Authorization")
		capturedSigInput = r.Header.Get("Signature-Input")

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"bot_id":"uuid-1234","org":"acme","public_key":"abc123def456","description":"Weather data bot","created_at":"2026-03-23T14:00:00Z"}`))
	}))
	defer server.Close()

	oldBaseURL := apiBaseURL
	apiBaseURL = server.URL
	defer func() { apiBaseURL = oldBaseURL }()

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"lookup", "acme/weather-bot"})

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("lookup returned error: %v", err)
	}

	if capturedMethod != "GET" {
		t.Errorf("request method = %q, want GET", capturedMethod)
	}
	if capturedPath != "/orgs/acme/bots/weather-bot" {
		t.Errorf("request path = %q, want /orgs/acme/bots/weather-bot", capturedPath)
	}
	if capturedAuth != "" {
		t.Errorf("Authorization header = %q, want empty (unauthenticated)", capturedAuth)
	}
	if capturedSigInput != "" {
		t.Errorf("Signature-Input header = %q, want empty (unauthenticated)", capturedSigInput)
	}
}

// L-05: lookup default output displays table with Org, Bot, Public Key, and Created fields.
func TestLookupTableOutput(t *testing.T) {
	resetLookupFlags()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"bot_id":"uuid-1234","org":"acme","public_key":"abc123def456","description":"Weather data bot","created_at":"2026-03-23T14:00:00Z"}`))
	}))
	defer server.Close()

	oldBaseURL := apiBaseURL
	apiBaseURL = server.URL
	defer func() { apiBaseURL = oldBaseURL }()

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"lookup", "acme/weather-bot"})

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("lookup returned error: %v", err)
	}

	output := buf.String()

	// Must display key profile fields.
	if !strings.Contains(output, "acme") {
		t.Errorf("table output missing org 'acme': %q", output)
	}
	if !strings.Contains(output, "weather-bot") {
		t.Errorf("table output missing bot 'weather-bot': %q", output)
	}
	if !strings.Contains(output, "abc123def456") {
		t.Errorf("table output missing public key 'abc123def456': %q", output)
	}
	if !strings.Contains(output, "2026-03-23T14:00:00Z") {
		t.Errorf("table output missing created timestamp: %q", output)
	}

	// Must include field labels.
	if !strings.Contains(output, "Org") {
		t.Errorf("table output missing 'Org' label: %q", output)
	}
	if !strings.Contains(output, "Bot") {
		t.Errorf("table output missing 'Bot' label: %q", output)
	}
	if !strings.Contains(output, "Public Key") {
		t.Errorf("table output missing 'Public Key' label: %q", output)
	}
	if !strings.Contains(output, "Created") {
		t.Errorf("table output missing 'Created' label: %q", output)
	}
}

// L-06: --json flag outputs raw API response body.
func TestLookupJsonOutput(t *testing.T) {
	resetLookupFlags()

	responseBody := `{"bot_id":"uuid-1234","org":"acme","public_key":"abc123def456","description":"Weather data bot","created_at":"2026-03-23T14:00:00Z"}`

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(responseBody))
	}))
	defer server.Close()

	oldBaseURL := apiBaseURL
	apiBaseURL = server.URL
	defer func() { apiBaseURL = oldBaseURL }()

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"lookup", "--json", "acme/weather-bot"})

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("lookup --json returned error: %v", err)
	}

	output := buf.String()

	// Raw JSON must contain the response fields.
	if !strings.Contains(output, "acme") {
		t.Errorf("--json output missing org: %q", output)
	}
	if !strings.Contains(output, "uuid-1234") {
		t.Errorf("--json output missing bot_id: %q", output)
	}
	if !strings.Contains(output, "abc123def456") {
		t.Errorf("--json output missing public_key: %q", output)
	}
	if !strings.Contains(output, "2026-03-23T14:00:00Z") {
		t.Errorf("--json output missing created_at: %q", output)
	}

	// Should not contain the table labels (proving it's raw JSON, not table output).
	if strings.Contains(output, "Org:") {
		t.Errorf("--json output should not contain table label 'Org:': %q", output)
	}
}

// L-07: HTTP 404 maps to a clean "not found" error message.
func TestLookupNotFound(t *testing.T) {
	resetLookupFlags()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`{"error":"not found"}`))
	}))
	defer server.Close()

	oldBaseURL := apiBaseURL
	apiBaseURL = server.URL
	defer func() { apiBaseURL = oldBaseURL }()

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"lookup", "acme/nonexistent"})

	err := rootCmd.Execute()
	if err == nil {
		t.Fatal("lookup should return error for HTTP 404")
	}
	errMsg := err.Error()
	if !strings.Contains(errMsg, "not found") {
		t.Errorf("error = %q, want it to contain 'not found'", errMsg)
	}
}

// L-08: Non-2xx responses (e.g. 500) map to a generic error including the status.
func TestLookupGenericServerError(t *testing.T) {
	resetLookupFlags()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"error":"internal server error"}`))
	}))
	defer server.Close()

	oldBaseURL := apiBaseURL
	apiBaseURL = server.URL
	defer func() { apiBaseURL = oldBaseURL }()

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"lookup", "acme/weather-bot"})

	err := rootCmd.Execute()
	if err == nil {
		t.Fatal("lookup should return error for HTTP 500")
	}
	errMsg := err.Error()
	if !strings.Contains(errMsg, "lookup failed") {
		t.Errorf("error = %q, want it to contain 'lookup failed'", errMsg)
	}
	if !strings.Contains(errMsg, "500") {
		t.Errorf("error = %q, want it to contain status code '500'", errMsg)
	}
}

// L-05: Table output uses labeled field format (not tabwriter columns).
func TestLookupTableOutputFieldFormat(t *testing.T) {
	resetLookupFlags()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"bot_id":"uuid-1234","org":"acme","public_key":"abc123","description":"","created_at":"2026-03-23T14:00:00Z"}`))
	}))
	defer server.Close()

	oldBaseURL := apiBaseURL
	apiBaseURL = server.URL
	defer func() { apiBaseURL = oldBaseURL }()

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"lookup", "acme/weather-bot"})

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("lookup returned error: %v", err)
	}

	output := buf.String()
	lines := strings.Split(strings.TrimSpace(output), "\n")
	if len(lines) < 4 {
		t.Fatalf("expected at least 4 output lines, got %d: %q", len(lines), output)
	}
}

// L-04: lookup does not require --home flag (no local identity needed).
func TestLookupDoesNotRequireHomeDir(t *testing.T) {
	resetLookupFlags()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"bot_id":"uuid-5678","org":"testorg","public_key":"key123","description":"","created_at":"2026-03-23T14:00:00Z"}`))
	}))
	defer server.Close()

	oldBaseURL := apiBaseURL
	apiBaseURL = server.URL
	defer func() { apiBaseURL = oldBaseURL }()

	// Do not set --home flag, do not create any .rtbtr directory.
	dir := t.TempDir()
	t.Chdir(dir)

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"lookup", "testorg/testbot"})

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("lookup should succeed without --home or .rtbtr directory, got error: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "testorg") {
		t.Errorf("output missing org: %q", output)
	}
}

// L-08: HTTP 400 returns a generic error.
func TestLookupBadRequest(t *testing.T) {
	resetLookupFlags()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"error":"bad request"}`))
	}))
	defer server.Close()

	oldBaseURL := apiBaseURL
	apiBaseURL = server.URL
	defer func() { apiBaseURL = oldBaseURL }()

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"lookup", "acme/weather-bot"})

	err := rootCmd.Execute()
	if err == nil {
		t.Fatal("lookup should return error for HTTP 400")
	}
	errMsg := err.Error()
	if !strings.Contains(errMsg, "lookup failed") {
		t.Errorf("error = %q, want it to contain 'lookup failed'", errMsg)
	}
}

// L-06: --json flag with additional profile fields still includes them in output.
func TestLookupJsonPreservesExtraFields(t *testing.T) {
	resetLookupFlags()

	responseBody := `{"bot_id":"uuid-1234","org":"acme","public_key":"abc123","description":"Weather bot","created_at":"2026-03-23T14:00:00Z","extra_field":"bonus"}`

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(responseBody))
	}))
	defer server.Close()

	oldBaseURL := apiBaseURL
	apiBaseURL = server.URL
	defer func() { apiBaseURL = oldBaseURL }()

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"lookup", "--json", "acme/weather-bot"})

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("lookup --json returned error: %v", err)
	}

	output := buf.String()
	// Extra fields should be preserved in raw JSON output.
	if !strings.Contains(output, "uuid-1234") {
		t.Errorf("--json output missing bot_id: %q", output)
	}
	if !strings.Contains(output, "bonus") {
		t.Errorf("--json output missing extra_field: %q", output)
	}
}
