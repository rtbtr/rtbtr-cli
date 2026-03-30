package cmd

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// resetClaimsFlags resets all flag state between claims tests.
func resetClaimsFlags() {
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

	if cmd, _, err := rootCmd.Find([]string{"claims"}); err == nil && cmd.Name() == "claims" {
		for _, name := range []string{"page", "limit", "order", "json", "help"} {
			if flag := cmd.Flags().Lookup(name); flag != nil {
				if err := flag.Value.Set(flag.DefValue); err != nil {
					panic(err)
				}
				flag.Changed = false
			}
		}
	}
}

// claimsCapture holds captured HTTP request fields from a claims mock server.
type claimsCapture struct {
	Method         string
	Path           string
	Query          string
	Authorization  string
	SignatureInput string
	Signature      string
}

// setupClaimsServer creates a mock server that captures GET /orgs/{org}/bots/{bot}/claims.
func setupClaimsServer(t *testing.T, status int, response string) (*httptest.Server, *claimsCapture) {
	t.Helper()
	capture := &claimsCapture{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" && strings.Contains(r.URL.Path, "/claims") {
			capture.Method = r.Method
			capture.Path = r.URL.Path
			capture.Query = r.URL.RawQuery
			capture.Authorization = r.Header.Get("Authorization")
			capture.SignatureInput = r.Header.Get("Signature-Input")
			capture.Signature = r.Header.Get("Signature")

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(status)
			io.WriteString(w, response)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(server.Close)
	return server, capture
}

// assertClaimsNotUnknownCommand fails the test if the error is an "unknown command"
// error, which means the claims subcommand is not registered.
func assertClaimsNotUnknownCommand(t *testing.T, err error) {
	t.Helper()
	if err != nil && strings.Contains(err.Error(), "unknown command") {
		t.Fatalf("claims command is not registered: %v", err)
	}
}

// T-CLS-01: claims is registered as a root subcommand and --help succeeds.
func TestClaimsCommandHelp(t *testing.T) {
	resetClaimsFlags()

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetArgs([]string{"claims", "--help"})

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("claims --help returned error: %v", err)
	}

	output := buf.String()
	if len(output) == 0 {
		t.Fatal("claims --help produced no output")
	}
	if !strings.Contains(output, "claims") {
		t.Errorf("help output does not contain 'claims': %s", output)
	}
}

// T-CLS-02: claims requires exactly one positional argument in org/bot format.
func TestClaimsArgumentValidation(t *testing.T) {
	cases := []struct {
		name        string
		errContains string
		args        []string
	}{
		{"missing arg", "org/bot", []string{"claims"}},
		{"extra args", "arg", []string{"claims", "org/bot", "extra"}},
		{"no slash", "org/bot", []string{"claims", "orgbot"}},
		{"empty org", "org/bot", []string{"claims", "/bot"}},
		{"empty bot", "org/bot", []string{"claims", "org/"}},
		{"multiple slashes", "org/bot", []string{"claims", "a/b/c"}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resetClaimsFlags()

			buf := new(bytes.Buffer)
			rootCmd.SetOut(buf)
			rootCmd.SetErr(buf)
			rootCmd.SetArgs(tc.args)

			err := rootCmd.Execute()
			if err == nil {
				t.Fatalf("claims should reject %q", tc.name)
			}
			assertClaimsNotUnknownCommand(t, err)
			// Verify the error mentions org/bot format or argument requirements.
			errStr := strings.ToLower(err.Error())
			if !strings.Contains(errStr, tc.errContains) {
				t.Errorf("error = %q, want it to contain %q", err.Error(), tc.errContains)
			}
		})
	}
}

// T-CLS-03: claims sends an unauthenticated GET with no auth/signature headers.
func TestClaimsPublicGetNoAuth(t *testing.T) {
	resetClaimsFlags()

	// Run from a temp dir with no .rtbtr - should not matter.
	dir := t.TempDir()
	t.Chdir(dir)

	server, capture := setupClaimsServer(t, http.StatusOK, `[]`)
	oldBaseURL := apiBaseURL
	apiBaseURL = server.URL
	t.Cleanup(func() { apiBaseURL = oldBaseURL })

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"claims", "testorg/testbot"})

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("claims returned error: %v", err)
	}

	if capture.Method != "GET" {
		t.Errorf("method = %q, want GET", capture.Method)
	}
	if capture.Path != "/orgs/testorg/bots/testbot/claims" {
		t.Errorf("path = %q, want /orgs/testorg/bots/testbot/claims", capture.Path)
	}
	if capture.Authorization != "" {
		t.Errorf("Authorization header should be empty, got %q", capture.Authorization)
	}
	if capture.SignatureInput != "" {
		t.Errorf("Signature-Input header should be empty, got %q", capture.SignatureInput)
	}
	if capture.Signature != "" {
		t.Errorf("Signature header should be empty, got %q", capture.Signature)
	}
}

// T-CLS-04: claims always sends page, limit, and order query params (defaults).
func TestClaimsDefaultQueryParams(t *testing.T) {
	resetClaimsFlags()

	server, capture := setupClaimsServer(t, http.StatusOK, `[]`)
	oldBaseURL := apiBaseURL
	apiBaseURL = server.URL
	t.Cleanup(func() { apiBaseURL = oldBaseURL })

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"claims", "org/bot"})

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("claims returned error: %v", err)
	}

	query := capture.Query
	if !strings.Contains(query, "page=") {
		t.Errorf("query %q missing 'page' parameter", query)
	}
	if !strings.Contains(query, "limit=") {
		t.Errorf("query %q missing 'limit' parameter", query)
	}
	if !strings.Contains(query, "order=") {
		t.Errorf("query %q missing 'order' parameter", query)
	}
}

// T-CLS-04: claims forwards unusual parameter values unchanged (no client-side validation).
func TestClaimsForwardsUnusualParams(t *testing.T) {
	resetClaimsFlags()

	server, capture := setupClaimsServer(t, http.StatusOK, `[]`)
	oldBaseURL := apiBaseURL
	apiBaseURL = server.URL
	t.Cleanup(func() { apiBaseURL = oldBaseURL })

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"claims", "org/bot", "--page", "0", "--limit", "-5", "--order", "sideways"})

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("claims returned error: %v", err)
	}

	query := capture.Query
	if !strings.Contains(query, "page=0") {
		t.Errorf("query %q should contain 'page=0'", query)
	}
	if !strings.Contains(query, "limit=-5") {
		t.Errorf("query %q should contain 'limit=-5'", query)
	}
	if !strings.Contains(query, "order=sideways") {
		t.Errorf("query %q should contain 'order=sideways'", query)
	}
}

// T-CLS-05: --json outputs the raw response body.
func TestClaimsJsonOutput(t *testing.T) {
	resetClaimsFlags()

	rawResponse := `[{"id":"c1","hash":"abc","created_at":"2026-01-01T00:00:00Z"}]`

	server, _ := setupClaimsServer(t, http.StatusOK, rawResponse)
	oldBaseURL := apiBaseURL
	apiBaseURL = server.URL
	t.Cleanup(func() { apiBaseURL = oldBaseURL })

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"claims", "org/bot", "--json"})

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("claims --json returned error: %v", err)
	}

	output := strings.TrimSpace(buf.String())
	if output != rawResponse {
		t.Errorf("--json output = %q, want %q", output, rawResponse)
	}
}

// T-CLS-05: table output includes ID HASH CREATED header and row data.
func TestClaimsTableOutput(t *testing.T) {
	resetClaimsFlags()

	response := `[{"id":"claim-1","hash":"hashval1","created_at":"2026-01-01T00:00:00Z"},{"id":"claim-2","hash":"hashval2","created_at":"2026-02-01T00:00:00Z"}]`

	server, _ := setupClaimsServer(t, http.StatusOK, response)
	oldBaseURL := apiBaseURL
	apiBaseURL = server.URL
	t.Cleanup(func() { apiBaseURL = oldBaseURL })

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"claims", "org/bot"})

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("claims returned error: %v", err)
	}

	output := buf.String()
	// Check header line
	if !strings.Contains(output, "ID") || !strings.Contains(output, "HASH") || !strings.Contains(output, "CREATED") {
		t.Errorf("table output missing header columns: %q", output)
	}
	// Check row data
	if !strings.Contains(output, "claim-1") {
		t.Errorf("table output missing claim-1: %q", output)
	}
	if !strings.Contains(output, "hashval1") {
		t.Errorf("table output missing hashval1: %q", output)
	}
	if !strings.Contains(output, "claim-2") {
		t.Errorf("table output missing claim-2: %q", output)
	}
}

// T-CLS-05: empty result prints "no claims".
func TestClaimsEmptyResult(t *testing.T) {
	resetClaimsFlags()

	server, _ := setupClaimsServer(t, http.StatusOK, `[]`)
	oldBaseURL := apiBaseURL
	apiBaseURL = server.URL
	t.Cleanup(func() { apiBaseURL = oldBaseURL })

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"claims", "org/bot"})

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("claims returned error: %v", err)
	}

	output := strings.TrimSpace(buf.String())
	if output != "no claims" {
		t.Errorf("output = %q, want %q", output, "no claims")
	}
}

// T-CLS-06: claims maps 404 and 422 specially and keeps generic non-2xx under "claims failed:".
func TestClaimsHttpErrorMapping(t *testing.T) {
	cases := []struct {
		body        string
		errContains string
		errExcludes string
		status      int
	}{
		// 404 must produce "bot not found" (the special mapping, not "claims failed:").
		{`{"error":"not found"}`, "bot not found", "claims failed", http.StatusNotFound},
		// 422 must produce "invalid parameters:" with the body (not "claims failed:").
		{`bad page value`, "invalid parameters: bad page value", "claims failed", http.StatusUnprocessableEntity},
		// Generic non-2xx must use "claims failed:" prefix (not special-cased).
		{`server error`, "claims failed:", "bot not found", http.StatusInternalServerError},
	}

	for _, tc := range cases {
		t.Run(fmt.Sprintf("status_%d", tc.status), func(t *testing.T) {
			resetClaimsFlags()

			server, _ := setupClaimsServer(t, tc.status, tc.body)
			oldBaseURL := apiBaseURL
			apiBaseURL = server.URL
			t.Cleanup(func() { apiBaseURL = oldBaseURL })

			buf := new(bytes.Buffer)
			rootCmd.SetOut(buf)
			rootCmd.SetErr(buf)
			rootCmd.SetArgs([]string{"claims", "org/bot"})

			err := rootCmd.Execute()
			if err == nil {
				t.Fatalf("claims should return error for HTTP %d", tc.status)
			}
			assertClaimsNotUnknownCommand(t, err)
			if !strings.Contains(err.Error(), tc.errContains) {
				t.Errorf("error = %q, want it to contain %q", err.Error(), tc.errContains)
			}
			if tc.errExcludes != "" && strings.Contains(err.Error(), tc.errExcludes) {
				t.Errorf("error = %q, should not contain %q (wrong error mapping)", err.Error(), tc.errExcludes)
			}
		})
	}
}

// T-CLS-06: claims maps 401 as a generic error (not authentication-specific).
func TestClaimsHttp401IsGeneric(t *testing.T) {
	resetClaimsFlags()

	server, _ := setupClaimsServer(t, http.StatusUnauthorized, `unauthorized`)
	oldBaseURL := apiBaseURL
	apiBaseURL = server.URL
	t.Cleanup(func() { apiBaseURL = oldBaseURL })

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"claims", "org/bot"})

	err := rootCmd.Execute()
	if err == nil {
		t.Fatal("claims should return error for HTTP 401")
	}
	assertClaimsNotUnknownCommand(t, err)
	// claims is a public endpoint - 401 should NOT map to "authentication failed: signature rejected"
	if strings.Contains(err.Error(), "signature rejected") {
		t.Errorf("error = %q, should not contain auth-specific wording for public endpoint", err.Error())
	}
	// Verify it uses the generic error prefix
	if !strings.Contains(err.Error(), "claims failed") {
		t.Errorf("error = %q, want it to contain 'claims failed'", err.Error())
	}
}
