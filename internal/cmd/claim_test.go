package cmd

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// resetClaimFlags resets all flag state between claim tests.
func resetClaimFlags() {
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

	if cmd, _, err := rootCmd.Find([]string{"claim"}); err == nil && cmd.Name() == "claim" {
		for _, name := range []string{"file", "stdin", "hash", "json", "help"} {
			if flag := cmd.Flags().Lookup(name); flag != nil {
				if err := flag.Value.Set(flag.DefValue); err != nil {
					panic(err)
				}
				flag.Changed = false
			}
		}
	}
}

// setupClaimIdentity creates a .rtbtr home with config and keypair.
func setupClaimIdentity(t *testing.T, parent, org, bot string) string {
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

// claimCapture holds captured HTTP request fields from a claim mock server.
type claimCapture struct {
	Method         string
	Path           string
	ContentType    string
	ContentDigest  string
	SignatureInput string
	Signature      string
	Body           []byte
}

// setupClaimServer creates a mock server that captures POST /orgs/{org}/bots/{bot}/claims.
func setupClaimServer(t *testing.T, status int, response string) (*httptest.Server, *claimCapture) {
	t.Helper()
	capture := &claimCapture{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/claims") {
			capture.Method = r.Method
			capture.Path = r.URL.Path
			capture.ContentType = r.Header.Get("Content-Type")
			capture.ContentDigest = r.Header.Get("Content-Digest")
			capture.SignatureInput = r.Header.Get("Signature-Input")
			capture.Signature = r.Header.Get("Signature")
			body, _ := io.ReadAll(r.Body)
			capture.Body = body

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(status)
			w.Write([]byte(response))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(server.Close)
	return server, capture
}

// T-CL-01: claim is registered as a root subcommand and --help succeeds.
func TestClaimCommandHelp(t *testing.T) {
	resetClaimFlags()

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetArgs([]string{"claim", "--help"})

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("claim --help returned error: %v", err)
	}

	output := buf.String()
	if len(output) == 0 {
		t.Fatal("claim --help produced no output")
	}
	if !strings.Contains(output, "claim") {
		t.Errorf("help output does not contain 'claim': %s", output)
	}
}

// T-CL-01: claim rejects extra positional arguments (Args: cobra.NoArgs).
func TestClaimRejectsExtraArgs(t *testing.T) {
	resetClaimFlags()

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"claim", "unexpected-arg"})

	err := rootCmd.Execute()
	if err == nil {
		t.Fatal("claim should reject extra positional arguments")
	}
}

// T-CL-02: claim without --home fails from a directory with no .rtbtr.
func TestClaimRejectsMissingRtbtrDir(t *testing.T) {
	resetClaimFlags()

	dir := t.TempDir()
	t.Chdir(dir)

	validHash := base64.RawURLEncoding.EncodeToString(make([]byte, 32))

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"claim", "--hash", validHash})

	err := rootCmd.Execute()
	if err == nil {
		t.Fatal("claim should return error when .rtbtr directory is missing")
	}
	if !strings.Contains(err.Error(), ".rtbtr") {
		t.Errorf("error = %q, want it to mention .rtbtr", err.Error())
	}

	// Verify no .rtbtr directory was created as a side effect.
	if _, statErr := os.Stat(filepath.Join(dir, ".rtbtr")); statErr == nil {
		t.Error("claim created a .rtbtr directory, but should not have")
	}
}

// T-CL-03: missing config.yaml produces the not-registered error.
func TestClaimRejectsMissingConfig(t *testing.T) {
	resetClaimFlags()

	dir := t.TempDir()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	encodedSeed := base64.RawURLEncoding.EncodeToString(priv.Seed())

	homePath := setupRtbtrDir(t, dir, map[string]string{
		"private_key": encodedSeed,
	})

	validHash := base64.RawURLEncoding.EncodeToString(make([]byte, 32))

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"claim", "--hash", validHash, "--home", homePath})

	err = rootCmd.Execute()
	if err == nil {
		t.Fatal("claim should return error when config.yaml is missing")
	}
	if !strings.Contains(err.Error(), "not registered: run rtbtr register first") {
		t.Errorf("error = %q, want 'not registered: run rtbtr register first'", err.Error())
	}
}

// T-CL-03: empty org/bot in config produces the not-registered error.
func TestClaimRejectsEmptyOrgBot(t *testing.T) {
	resetClaimFlags()

	cases := []struct {
		name   string
		config string
	}{
		{"empty org", "org: \"\"\nbot: testbot\n"},
		{"empty bot", "org: testorg\nbot: \"\"\n"},
		{"both empty", "org: \"\"\nbot: \"\"\n"},
	}

	validHash := base64.RawURLEncoding.EncodeToString(make([]byte, 32))

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resetClaimFlags()

			dir := t.TempDir()
			_, priv, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatalf("generating key: %v", err)
			}
			encodedSeed := base64.RawURLEncoding.EncodeToString(priv.Seed())

			homePath := setupRtbtrDir(t, dir, map[string]string{
				"config.yaml": tc.config,
				"private_key": encodedSeed,
			})

			buf := new(bytes.Buffer)
			rootCmd.SetOut(buf)
			rootCmd.SetErr(buf)
			rootCmd.SetArgs([]string{"claim", "--hash", validHash, "--home", homePath})

			err = rootCmd.Execute()
			if err == nil {
				t.Fatal("claim should return error for incomplete registration")
			}
			if !strings.Contains(err.Error(), "not registered: run rtbtr register first") {
				t.Errorf("error = %q, want 'not registered: run rtbtr register first'", err.Error())
			}
		})
	}
}

// T-CL-04: registered home without a private key is rejected.
func TestClaimRejectsMissingPrivateKey(t *testing.T) {
	resetClaimFlags()

	dir := t.TempDir()
	homePath := setupRtbtrDir(t, dir, map[string]string{
		"config.yaml": "org: testorg\nbot: testbot\n",
	})

	validHash := base64.RawURLEncoding.EncodeToString(make([]byte, 32))

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"claim", "--hash", validHash, "--home", homePath})

	err := rootCmd.Execute()
	if err == nil {
		t.Fatal("claim should return error when private key is missing")
	}
	if !strings.Contains(err.Error(), "private key not found") {
		t.Errorf("error = %q, want it to contain 'private key not found'", err.Error())
	}
}

// T-CL-05: --file hashes file content as SHA-256 URL-safe base64 (43 chars, no padding).
func TestClaimFileHashesCorrectly(t *testing.T) {
	resetClaimFlags()

	content := []byte("hello world for claim hashing")
	expectedDigest := sha256.Sum256(content)
	expectedHash := base64.RawURLEncoding.EncodeToString(expectedDigest[:])

	server, capture := setupClaimServer(t, http.StatusOK, `{"claim_id":"c1","hash":"`+expectedHash+`"}`)
	oldBaseURL := apiBaseURL
	apiBaseURL = server.URL
	t.Cleanup(func() { apiBaseURL = oldBaseURL })

	dir := t.TempDir()
	homePath := setupClaimIdentity(t, dir, "testorg", "testbot")

	filePath := filepath.Join(dir, "testfile.bin")
	if err := os.WriteFile(filePath, content, 0o644); err != nil {
		t.Fatalf("writing test file: %v", err)
	}

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"claim", "--file", filePath, "--home", homePath})

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("claim --file returned error: %v", err)
	}

	var body map[string]string
	if err := json.Unmarshal(capture.Body, &body); err != nil {
		t.Fatalf("parsing request body: %v", err)
	}

	if body["hash"] != expectedHash {
		t.Errorf("hash = %q, want %q", body["hash"], expectedHash)
	}
	if len(body["hash"]) != 43 {
		t.Errorf("hash length = %d, want 43", len(body["hash"]))
	}
	if strings.Contains(body["hash"], "=") {
		t.Error("hash contains padding character '='")
	}
}

// T-CL-05: --file accepts an empty file.
func TestClaimFileAcceptsEmptyFile(t *testing.T) {
	resetClaimFlags()

	emptyDigest := sha256.Sum256(nil)
	expectedHash := base64.RawURLEncoding.EncodeToString(emptyDigest[:])

	server, capture := setupClaimServer(t, http.StatusOK, `{"claim_id":"c2","hash":"`+expectedHash+`"}`)
	oldBaseURL := apiBaseURL
	apiBaseURL = server.URL
	t.Cleanup(func() { apiBaseURL = oldBaseURL })

	dir := t.TempDir()
	homePath := setupClaimIdentity(t, dir, "testorg", "testbot")

	filePath := filepath.Join(dir, "empty.bin")
	if err := os.WriteFile(filePath, nil, 0o644); err != nil {
		t.Fatalf("writing empty file: %v", err)
	}

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"claim", "--file", filePath, "--home", homePath})

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("claim --file (empty) returned error: %v", err)
	}

	var body map[string]string
	if err := json.Unmarshal(capture.Body, &body); err != nil {
		t.Fatalf("parsing request body: %v", err)
	}

	if body["hash"] != expectedHash {
		t.Errorf("empty file hash = %q, want %q", body["hash"], expectedHash)
	}
}

// T-CL-05: --file rejects unreadable path.
func TestClaimFileRejectsUnreadablePath(t *testing.T) {
	resetClaimFlags()

	dir := t.TempDir()
	homePath := setupClaimIdentity(t, dir, "testorg", "testbot")

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"claim", "--file", "/nonexistent/path/to/file", "--home", homePath})

	err := rootCmd.Execute()
	if err == nil {
		t.Fatal("claim should fail for unreadable file path")
	}
}

// T-CL-06: --stdin hashes non-empty stdin correctly.
func TestClaimStdinHashesCorrectly(t *testing.T) {
	resetClaimFlags()

	stdinContent := []byte("stdin data for hashing")
	expectedDigest := sha256.Sum256(stdinContent)
	expectedHash := base64.RawURLEncoding.EncodeToString(expectedDigest[:])

	server, capture := setupClaimServer(t, http.StatusOK, `{"claim_id":"c3","hash":"`+expectedHash+`"}`)
	oldBaseURL := apiBaseURL
	apiBaseURL = server.URL
	t.Cleanup(func() { apiBaseURL = oldBaseURL })

	dir := t.TempDir()
	homePath := setupClaimIdentity(t, dir, "testorg", "testbot")

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetIn(bytes.NewReader(stdinContent))
	rootCmd.SetArgs([]string{"claim", "--stdin", "--home", homePath})

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("claim --stdin returned error: %v", err)
	}

	var body map[string]string
	if err := json.Unmarshal(capture.Body, &body); err != nil {
		t.Fatalf("parsing request body: %v", err)
	}

	if body["hash"] != expectedHash {
		t.Errorf("stdin hash = %q, want %q", body["hash"], expectedHash)
	}
}

// T-CL-06: --stdin rejects empty stdin (0 bytes) before sending any HTTP request.
func TestClaimStdinRejectsEmpty(t *testing.T) {
	resetClaimFlags()

	requestMade := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestMade = true
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(server.Close)

	oldBaseURL := apiBaseURL
	apiBaseURL = server.URL
	t.Cleanup(func() { apiBaseURL = oldBaseURL })

	dir := t.TempDir()
	homePath := setupClaimIdentity(t, dir, "testorg", "testbot")

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetIn(bytes.NewReader(nil))
	rootCmd.SetArgs([]string{"claim", "--stdin", "--home", homePath})

	err := rootCmd.Execute()
	if err == nil {
		t.Fatal("claim --stdin should reject empty stdin")
	}
	if requestMade {
		t.Error("claim made an HTTP request despite empty stdin")
	}
}

// T-CL-07: valid --hash value is forwarded unchanged; malformed values are rejected.
func TestClaimHashAcceptsValid(t *testing.T) {
	resetClaimFlags()

	validHash := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	if len(validHash) != 43 {
		t.Fatalf("test setup: expected 43-char hash, got %d", len(validHash))
	}

	server, capture := setupClaimServer(t, http.StatusOK, `{"claim_id":"c4","hash":"`+validHash+`"}`)
	oldBaseURL := apiBaseURL
	apiBaseURL = server.URL
	t.Cleanup(func() { apiBaseURL = oldBaseURL })

	dir := t.TempDir()
	homePath := setupClaimIdentity(t, dir, "testorg", "testbot")

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"claim", "--hash", validHash, "--home", homePath})

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("claim --hash returned error: %v", err)
	}

	var body map[string]string
	if err := json.Unmarshal(capture.Body, &body); err != nil {
		t.Fatalf("parsing request body: %v", err)
	}

	if body["hash"] != validHash {
		t.Errorf("submitted hash = %q, want %q", body["hash"], validHash)
	}
}

// T-CL-07: malformed --hash values are rejected before any HTTP call.
func TestClaimHashRejectsInvalid(t *testing.T) {
	cases := []struct {
		name  string
		value string
	}{
		{"too short", "AAAAAAAAAAAAAAAAAAAAAA"},
		{"too long", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"},
		{"standard base64 padding", base64.StdEncoding.EncodeToString(make([]byte, 32))},
		{"non-base64 chars", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA!!!"},
		{"wrong decoded size (16 bytes)", base64.RawURLEncoding.EncodeToString(make([]byte, 16))},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resetClaimFlags()

			requestMade := false
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requestMade = true
				w.WriteHeader(http.StatusOK)
			}))
			t.Cleanup(server.Close)

			oldBaseURL := apiBaseURL
			apiBaseURL = server.URL
			t.Cleanup(func() { apiBaseURL = oldBaseURL })

			dir := t.TempDir()
			homePath := setupClaimIdentity(t, dir, "testorg", "testbot")

			buf := new(bytes.Buffer)
			rootCmd.SetOut(buf)
			rootCmd.SetErr(buf)
			rootCmd.SetArgs([]string{"claim", "--hash", tc.value, "--home", homePath})

			err := rootCmd.Execute()
			if err == nil {
				t.Fatalf("claim --hash %q should be rejected", tc.value)
			}
			if requestMade {
				t.Errorf("claim made an HTTP request for invalid hash %q", tc.value)
			}
		})
	}
}

// T-CL-08: exactly one of --file, --stdin, or --hash must be provided.
func TestClaimSourceFlagExclusivity(t *testing.T) {
	validHash := base64.RawURLEncoding.EncodeToString(make([]byte, 32))

	cases := []struct {
		name string
		args []string
	}{
		{"no source flags", []string{"claim"}},
		{"file and hash", []string{"claim", "--file", "/tmp/f", "--hash", validHash}},
		{"file and stdin", []string{"claim", "--file", "/tmp/f", "--stdin"}},
		{"stdin and hash", []string{"claim", "--stdin", "--hash", validHash}},
		{"all three", []string{"claim", "--file", "/tmp/f", "--stdin", "--hash", validHash}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resetClaimFlags()

			requestMade := false
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requestMade = true
				w.WriteHeader(http.StatusOK)
			}))
			t.Cleanup(server.Close)

			oldBaseURL := apiBaseURL
			apiBaseURL = server.URL
			t.Cleanup(func() { apiBaseURL = oldBaseURL })

			dir := t.TempDir()
			homePath := setupClaimIdentity(t, dir, "testorg", "testbot")

			args := append(tc.args, "--home", homePath)

			buf := new(bytes.Buffer)
			rootCmd.SetOut(buf)
			rootCmd.SetErr(buf)
			rootCmd.SetArgs(args)

			err := rootCmd.Execute()
			if err == nil {
				t.Fatalf("claim should reject %q", tc.name)
			}
			if requestMade {
				t.Errorf("claim made HTTP request for %q", tc.name)
			}
		})
	}
}

// T-CL-09: successful submission hits the correct endpoint with JSON body.
func TestClaimPostsToCorrectEndpoint(t *testing.T) {
	resetClaimFlags()

	validHash := base64.RawURLEncoding.EncodeToString(make([]byte, 32))

	server, capture := setupClaimServer(t, http.StatusOK, `{"claim_id":"c5","hash":"`+validHash+`"}`)
	oldBaseURL := apiBaseURL
	apiBaseURL = server.URL
	t.Cleanup(func() { apiBaseURL = oldBaseURL })

	dir := t.TempDir()
	homePath := setupClaimIdentity(t, dir, "myorg", "mybot")

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"claim", "--hash", validHash, "--home", homePath})

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("claim returned error: %v", err)
	}

	if capture.Method != "POST" {
		t.Errorf("method = %q, want POST", capture.Method)
	}
	if capture.Path != "/orgs/myorg/bots/mybot/claims" {
		t.Errorf("path = %q, want /orgs/myorg/bots/mybot/claims", capture.Path)
	}
	if capture.ContentType != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", capture.ContentType)
	}

	var body map[string]string
	if err := json.Unmarshal(capture.Body, &body); err != nil {
		t.Fatalf("parsing POST body: %v", err)
	}
	if body["hash"] != validHash {
		t.Errorf("body hash = %q, want %q", body["hash"], validHash)
	}
}

// T-CL-10: claim request carries Content-Digest and HTTP signature headers.
func TestClaimPostHeaders(t *testing.T) {
	resetClaimFlags()

	validHash := base64.RawURLEncoding.EncodeToString(make([]byte, 32))

	server, capture := setupClaimServer(t, http.StatusOK, `{"claim_id":"c6","hash":"`+validHash+`"}`)
	oldBaseURL := apiBaseURL
	apiBaseURL = server.URL
	t.Cleanup(func() { apiBaseURL = oldBaseURL })

	dir := t.TempDir()
	homePath := setupClaimIdentity(t, dir, "sigorg", "sigbot")

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"claim", "--hash", validHash, "--home", homePath})

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("claim returned error: %v", err)
	}

	if capture.ContentDigest == "" {
		t.Error("Content-Digest header is empty")
	}
	if !strings.HasPrefix(capture.ContentDigest, "sha-256=:") {
		t.Errorf("Content-Digest = %q, want it to start with 'sha-256=:'", capture.ContentDigest)
	}
	if capture.SignatureInput == "" {
		t.Error("Signature-Input header is empty")
	}

	expectedKeyID := fmt.Sprintf(`keyid="%s/o/sigorg/sigbot"`, platformBaseURL)
	if !strings.Contains(capture.SignatureInput, expectedKeyID) {
		t.Errorf("Signature-Input = %q, want it to contain %s", capture.SignatureInput, expectedKeyID)
	}
	if !strings.Contains(capture.SignatureInput, `alg="ed25519"`) {
		t.Errorf("Signature-Input = %q, want it to contain alg=\"ed25519\"", capture.SignatureInput)
	}
	if capture.Signature == "" {
		t.Error("Signature header is empty")
	}
}

// T-CL-11: default output prints "claimed <claim_id>" on line 1 and "hash: <hash>" on line 2.
func TestClaimDefaultOutput(t *testing.T) {
	resetClaimFlags()

	validHash := base64.RawURLEncoding.EncodeToString(make([]byte, 32))

	server, _ := setupClaimServer(t, http.StatusOK, `{"claim_id":"claim-42","hash":"`+validHash+`"}`)
	oldBaseURL := apiBaseURL
	apiBaseURL = server.URL
	t.Cleanup(func() { apiBaseURL = oldBaseURL })

	dir := t.TempDir()
	homePath := setupClaimIdentity(t, dir, "testorg", "testbot")

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"claim", "--hash", validHash, "--home", homePath})

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("claim returned error: %v", err)
	}

	output := buf.String()
	lines := strings.Split(strings.TrimSpace(output), "\n")
	if len(lines) < 2 {
		t.Fatalf("expected 2 lines, got %d: %q", len(lines), output)
	}
	if lines[0] != "claimed claim-42" {
		t.Errorf("line 1 = %q, want %q", lines[0], "claimed claim-42")
	}
	if lines[1] != "hash: "+validHash {
		t.Errorf("line 2 = %q, want %q", lines[1], "hash: "+validHash)
	}
}

// T-CL-12: claim --json outputs the raw API response body.
func TestClaimJsonOutput(t *testing.T) {
	resetClaimFlags()

	validHash := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	rawResponse := `{"claim_id":"claim-json","hash":"` + validHash + `","extra":"field"}`

	server, _ := setupClaimServer(t, http.StatusOK, rawResponse)
	oldBaseURL := apiBaseURL
	apiBaseURL = server.URL
	t.Cleanup(func() { apiBaseURL = oldBaseURL })

	dir := t.TempDir()
	homePath := setupClaimIdentity(t, dir, "testorg", "testbot")

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"claim", "--hash", validHash, "--json", "--home", homePath})

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("claim --json returned error: %v", err)
	}

	output := strings.TrimSpace(buf.String())
	if output != rawResponse {
		t.Errorf("--json output = %q, want %q", output, rawResponse)
	}
}

// T-CL-13: claim maps 401, 404, 422, and generic non-2xx to documented errors.
func TestClaimHttpErrorMapping(t *testing.T) {
	cases := []struct {
		status      int
		body        string
		errContains string
	}{
		{http.StatusUnauthorized, `{"error":"unauthorized"}`, "authentication failed"},
		{http.StatusNotFound, `{"error":"not found"}`, "not found"},
		{http.StatusUnprocessableEntity, `invalid hash`, "invalid"},
		{http.StatusInternalServerError, `internal error`, "claim failed"},
	}

	validHash := base64.RawURLEncoding.EncodeToString(make([]byte, 32))

	for _, tc := range cases {
		t.Run(fmt.Sprintf("status_%d", tc.status), func(t *testing.T) {
			resetClaimFlags()

			server, _ := setupClaimServer(t, tc.status, tc.body)
			oldBaseURL := apiBaseURL
			apiBaseURL = server.URL
			t.Cleanup(func() { apiBaseURL = oldBaseURL })

			dir := t.TempDir()
			homePath := setupClaimIdentity(t, dir, "testorg", "testbot")

			buf := new(bytes.Buffer)
			rootCmd.SetOut(buf)
			rootCmd.SetErr(buf)
			rootCmd.SetArgs([]string{"claim", "--hash", validHash, "--home", homePath})

			err := rootCmd.Execute()
			if err == nil {
				t.Fatalf("claim should return error for HTTP %d", tc.status)
			}
			if !strings.Contains(err.Error(), tc.errContains) {
				t.Errorf("error = %q, want it to contain %q", err.Error(), tc.errContains)
			}
		})
	}
}
