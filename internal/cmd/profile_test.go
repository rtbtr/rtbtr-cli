package cmd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/rtbtr/rtbtr-cli/internal/config"
)

// resetProfileFlags resets all flag state between profile tests.
func resetProfileFlags() {
	homeFlag = ""
	profileNameFlag = ""
	profileDescriptionFlag = ""
	profileForceFlag = false

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

	for _, name := range []string{"name", "description", "force", "help"} {
		if flag := profileCmd.Flags().Lookup(name); flag != nil {
			if err := flag.Value.Set(flag.DefValue); err != nil {
				panic(err)
			}
			flag.Changed = false
		}
	}
}

// profileCapture captures the fields from a PATCH request to the profile endpoint.
type profileCapture struct {
	Method         string
	Path           string
	ContentType    string
	SignatureInput string
	Signature      string
	ContentDigest  string
	Body           []byte
}

// setupProfileServer creates a test server that handles PATCH /orgs/{org}/bots/{bot}
// and returns the given response. It captures the request details for assertions.
func setupProfileServer(t *testing.T, responseStatus int, responseBody string) (*httptest.Server, *profileCapture) {
	t.Helper()

	capture := &profileCapture{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capture.Method = r.Method
		capture.Path = r.URL.Path
		capture.ContentType = r.Header.Get("Content-Type")
		capture.SignatureInput = r.Header.Get("Signature-Input")
		capture.Signature = r.Header.Get("Signature")
		capture.ContentDigest = r.Header.Get("Content-Digest")

		body, _ := io.ReadAll(r.Body)
		capture.Body = body

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(responseStatus)
		w.Write([]byte(responseBody))
	}))

	return server, capture
}

// T-P01: profile is registered as a subcommand and produces help text.
func TestProfileCommandHelp(t *testing.T) {
	resetProfileFlags()

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetArgs([]string{"profile", "--help"})

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("profile --help returned error: %v", err)
	}

	output := buf.String()
	if len(output) == 0 {
		t.Fatal("profile --help produced no output")
	}
	if !strings.Contains(output, "profile") {
		t.Errorf("help output does not contain 'profile': %s", output)
	}
}

// T-P02: profile rejects when no flags are provided.
func TestProfileRejectsNoFlags(t *testing.T) {
	resetProfileFlags()

	dir := t.TempDir()
	homePath := setupInboxIdentity(t, dir, "testorg", "testbot")

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"profile", "--home", homePath})

	err := rootCmd.Execute()
	if err == nil {
		t.Fatal("profile should return error when no flags are provided")
	}
}

// T-P03: profile rejects when .rtbtr directory does not exist.
func TestProfileErrorOnMissingRtbtrDir(t *testing.T) {
	resetProfileFlags()

	dir := t.TempDir()
	t.Chdir(dir)

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"profile", "--description", "test desc"})

	err := rootCmd.Execute()
	if err == nil {
		t.Fatal("profile should return error when .rtbtr directory is not found")
	}
	if !strings.Contains(err.Error(), ".rtbtr") {
		t.Errorf("error = %q, want it to mention .rtbtr", err.Error())
	}
}

// T-P04: profile rejects when config.yaml is missing from .rtbtr.
func TestProfileErrorOnMissingConfig(t *testing.T) {
	resetProfileFlags()

	dir := t.TempDir()
	homePath := setupRtbtrDir(t, dir, map[string]string{
		"private_key": "dGVzdGtleQ", // dummy base64 key
	})

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"profile", "--description", "test desc", "--home", homePath})

	err := rootCmd.Execute()
	if err == nil {
		t.Fatal("profile should return error when config.yaml is missing")
	}
	if !strings.Contains(err.Error(), "not registered: run rtbtr register first") {
		t.Errorf("error = %q, want it to contain 'not registered: run rtbtr register first'", err.Error())
	}
}

// T-P04: profile rejects when org/bot are empty in config.yaml.
func TestProfileErrorOnEmptyOrgBot(t *testing.T) {
	resetProfileFlags()

	dir := t.TempDir()
	homePath := setupInboxIdentity(t, dir, "", "")

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"profile", "--description", "test desc", "--home", homePath})

	err := rootCmd.Execute()
	if err == nil {
		t.Fatal("profile should return error when org/bot are empty")
	}
	if !strings.Contains(err.Error(), "not registered") {
		t.Errorf("error = %q, want it to contain 'not registered'", err.Error())
	}
}

// T-P05: profile rejects when private_key is missing.
func TestProfileErrorOnMissingPrivateKey(t *testing.T) {
	resetProfileFlags()

	dir := t.TempDir()
	homePath := setupRtbtrDir(t, dir, map[string]string{
		"config.yaml": "org: testorg\nbot: testbot\n",
	})

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"profile", "--description", "test desc", "--home", homePath})

	err := rootCmd.Execute()
	if err == nil {
		t.Fatal("profile should return error when private_key is missing")
	}
	if !strings.Contains(err.Error(), "private key not found") {
		t.Errorf("error = %q, want it to contain 'private key not found'", err.Error())
	}
}

// T-P06: --description only sends PATCH with description field and prints updated profile.
func TestProfileDescriptionOnlySendsPatch(t *testing.T) {
	resetProfileFlags()

	server, capture := setupProfileServer(t, http.StatusOK,
		`{"name":"testbot","description":"Handles CI/CD","org":"testorg"}`)
	defer server.Close()

	oldBaseURL := apiBaseURL
	apiBaseURL = server.URL
	defer func() { apiBaseURL = oldBaseURL }()

	dir := t.TempDir()
	homePath := setupInboxIdentity(t, dir, "testorg", "testbot")

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"profile", "--description", "Handles CI/CD", "--home", homePath})

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("profile --description returned error: %v", err)
	}

	// Verify PATCH method.
	if capture.Method != "PATCH" {
		t.Errorf("request method = %q, want PATCH", capture.Method)
	}

	// Verify path.
	if capture.Path != "/orgs/testorg/bots/testbot" {
		t.Errorf("request path = %q, want /orgs/testorg/bots/testbot", capture.Path)
	}

	// Verify JSON body contains description.
	var body map[string]interface{}
	if err := json.Unmarshal(capture.Body, &body); err != nil {
		t.Fatalf("parsing PATCH body: %v", err)
	}
	if body["description"] != "Handles CI/CD" {
		t.Errorf("body description = %v, want 'Handles CI/CD'", body["description"])
	}

	// Verify name is not in the body when only description is set.
	if _, hasName := body["name"]; hasName {
		t.Errorf("body should not contain 'name' when only --description is set, got: %v", body)
	}

	// Verify output contains the updated profile.
	output := buf.String()
	if !strings.Contains(output, "testbot") {
		t.Errorf("output = %q, want it to contain bot name 'testbot'", output)
	}
	if !strings.Contains(output, "Handles CI/CD") {
		t.Errorf("output = %q, want it to contain description 'Handles CI/CD'", output)
	}
}

// T-P06b: --description "" (explicit empty) sends a PATCH body with the
// "description" key present and set to "" so existing descriptions can be cleared.
// This verifies that the JSON marshaling does NOT use omitempty on the description
// field, which would silently drop the empty value.
func TestProfileEmptyDescriptionClearsExisting(t *testing.T) {
	resetProfileFlags()

	server, capture := setupProfileServer(t, http.StatusOK,
		`{"name":"testbot","description":"","org":"testorg"}`)
	defer server.Close()

	oldBaseURL := apiBaseURL
	apiBaseURL = server.URL
	defer func() { apiBaseURL = oldBaseURL }()

	dir := t.TempDir()
	homePath := setupInboxIdentity(t, dir, "testorg", "testbot")

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"profile", "--description", "", "--home", homePath})

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("profile --description '' returned error: %v", err)
	}

	// Verify PATCH method.
	if capture.Method != "PATCH" {
		t.Errorf("request method = %q, want PATCH", capture.Method)
	}

	// The JSON body must contain the "description" key even when value is "".
	// We use json.Decoder with UseNumber to do a raw decode.
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(capture.Body, &raw); err != nil {
		t.Fatalf("parsing PATCH body: %v", err)
	}

	descRaw, hasDesc := raw["description"]
	if !hasDesc {
		t.Fatalf("PATCH body missing 'description' key; body = %s — cannot clear an existing description", string(capture.Body))
	}

	// The value should be the JSON string "" (serialized as `""`).
	var descVal string
	if err := json.Unmarshal(descRaw, &descVal); err != nil {
		t.Fatalf("description value is not a JSON string: %v", err)
	}
	if descVal != "" {
		t.Errorf("description = %q, want empty string", descVal)
	}

	// Verify name is absent (only description was set).
	if _, hasName := raw["name"]; hasName {
		t.Errorf("body should not contain 'name' when only --description is set, got: %s", string(capture.Body))
	}
}

// T-P07: --name only without --force prints warning and aborts.
func TestProfileNameWithoutForceAborts(t *testing.T) {
	resetProfileFlags()

	dir := t.TempDir()
	homePath := setupInboxIdentity(t, dir, "testorg", "testbot")

	// Simulate stdin as terminal (no confirmation available).
	oldStdin := stdinIsTerminal
	stdinIsTerminal = func() bool { return true }
	defer func() { stdinIsTerminal = oldStdin }()

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"profile", "--name", "new-bot-name", "--home", homePath})

	err := rootCmd.Execute()
	if err == nil {
		t.Fatal("profile --name without --force should return error or abort")
	}
}

// T-P08: --name with --force sends PATCH with name field and prints updated profile.
func TestProfileNameWithForceSendsPatch(t *testing.T) {
	resetProfileFlags()

	server, capture := setupProfileServer(t, http.StatusOK,
		`{"name":"new-bot-name","description":"existing desc","org":"testorg"}`)
	defer server.Close()

	oldBaseURL := apiBaseURL
	apiBaseURL = server.URL
	defer func() { apiBaseURL = oldBaseURL }()

	dir := t.TempDir()
	homePath := setupInboxIdentity(t, dir, "testorg", "testbot")

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"profile", "--name", "new-bot-name", "--force", "--home", homePath})

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("profile --name --force returned error: %v", err)
	}

	// Verify PATCH method.
	if capture.Method != "PATCH" {
		t.Errorf("request method = %q, want PATCH", capture.Method)
	}

	// Verify JSON body contains name.
	var body map[string]interface{}
	if err := json.Unmarshal(capture.Body, &body); err != nil {
		t.Fatalf("parsing PATCH body: %v", err)
	}
	if body["name"] != "new-bot-name" {
		t.Errorf("body name = %v, want 'new-bot-name'", body["name"])
	}

	// Verify description is not in the body when only name is set.
	if _, hasDesc := body["description"]; hasDesc {
		t.Errorf("body should not contain 'description' when only --name is set, got: %v", body)
	}

	// Verify output contains updated profile info.
	output := buf.String()
	if !strings.Contains(output, "new-bot-name") {
		t.Errorf("output = %q, want it to contain bot name 'new-bot-name'", output)
	}
}

// T-P09: Both --name and --description flags sends PATCH with both fields.
func TestProfileBothFlagsSendsPatch(t *testing.T) {
	resetProfileFlags()

	server, capture := setupProfileServer(t, http.StatusOK,
		`{"name":"new-name","description":"new desc","org":"testorg"}`)
	defer server.Close()

	oldBaseURL := apiBaseURL
	apiBaseURL = server.URL
	defer func() { apiBaseURL = oldBaseURL }()

	dir := t.TempDir()
	homePath := setupInboxIdentity(t, dir, "testorg", "testbot")

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"profile", "--name", "new-name", "--description", "new desc", "--force", "--home", homePath})

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("profile with both flags returned error: %v", err)
	}

	// Verify PATCH method.
	if capture.Method != "PATCH" {
		t.Errorf("request method = %q, want PATCH", capture.Method)
	}

	// Verify JSON body contains both fields.
	var body map[string]interface{}
	if err := json.Unmarshal(capture.Body, &body); err != nil {
		t.Fatalf("parsing PATCH body: %v", err)
	}
	if body["name"] != "new-name" {
		t.Errorf("body name = %v, want 'new-name'", body["name"])
	}
	if body["description"] != "new desc" {
		t.Errorf("body description = %v, want 'new desc'", body["description"])
	}
}

// T-P10: Description exceeding 500 characters (runes) is rejected.
func TestProfileRejectsDescriptionTooLong(t *testing.T) {
	resetProfileFlags()

	dir := t.TempDir()
	homePath := setupInboxIdentity(t, dir, "testorg", "testbot")

	longDesc := strings.Repeat("x", 501)

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"profile", "--description", longDesc, "--home", homePath})

	err := rootCmd.Execute()
	if err == nil {
		t.Fatal("profile should reject description longer than 500 characters")
	}
}

// T-P10b: A multi-byte Unicode description at exactly 500 characters (runes) must
// be accepted. This verifies the limit counts Unicode characters, not bytes.
// 500 × "é" (2 bytes each) = 1000 bytes but only 500 characters.
func TestProfileAcceptsMultiByteDescriptionAt500Runes(t *testing.T) {
	resetProfileFlags()

	server, _ := setupProfileServer(t, http.StatusOK,
		`{"name":"testbot","description":"ok","org":"testorg"}`)
	defer server.Close()

	oldBaseURL := apiBaseURL
	apiBaseURL = server.URL
	defer func() { apiBaseURL = oldBaseURL }()

	dir := t.TempDir()
	homePath := setupInboxIdentity(t, dir, "testorg", "testbot")

	// 500 runes of "é" (U+00E9) — each rune is 2 bytes, so total is 1000 bytes.
	multiByteDesc := strings.Repeat("é", 500)

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"profile", "--description", multiByteDesc, "--home", homePath})

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("profile should accept 500-rune multi-byte description (1000 bytes), got error: %v", err)
	}
}

// T-P10c: A multi-byte Unicode description at 501 characters (runes) must be
// rejected with an error that reports the correct character count (501, not
// the byte count 1002). This ensures the limit counts Unicode characters,
// not bytes, and that the error message reflects the actual character count.
func TestProfileRejectsMultiByteDescriptionAt501Runes(t *testing.T) {
	resetProfileFlags()

	dir := t.TempDir()
	homePath := setupInboxIdentity(t, dir, "testorg", "testbot")

	// 501 runes of "é" (U+00E9) — each rune is 2 bytes, so total is 1002 bytes.
	// A byte-counting implementation would see 1002 (wrong), not 501 (correct).
	multiByteDesc := strings.Repeat("é", 501)

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"profile", "--description", multiByteDesc, "--home", homePath})

	err := rootCmd.Execute()
	if err == nil {
		t.Fatal("profile should reject 501-rune multi-byte description")
	}

	// The error message must reference the actual character count (501),
	// proving the implementation counts runes, not bytes.
	// A byte-counting implementation would either use a static message
	// (missing "501") or report "1002" bytes instead.
	errMsg := err.Error()
	if !strings.Contains(errMsg, "501") {
		t.Errorf("error = %q, want it to contain the character count '501' (not byte count '1002')", errMsg)
	}
}

// T-P10: Description at exactly 500 characters is accepted.
func TestProfileAcceptsDescriptionAtMaxLength(t *testing.T) {
	resetProfileFlags()

	server, _ := setupProfileServer(t, http.StatusOK,
		`{"name":"testbot","description":"ok","org":"testorg"}`)
	defer server.Close()

	oldBaseURL := apiBaseURL
	apiBaseURL = server.URL
	defer func() { apiBaseURL = oldBaseURL }()

	dir := t.TempDir()
	homePath := setupInboxIdentity(t, dir, "testorg", "testbot")

	maxDesc := strings.Repeat("x", 500)

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"profile", "--description", maxDesc, "--home", homePath})

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("profile should accept description of exactly 500 chars, got error: %v", err)
	}
}

// T-P11: Name must match pattern (lowercase alphanumeric with hyphens, min 2 chars).
func TestProfileRejectsInvalidName(t *testing.T) {
	resetProfileFlags()

	dir := t.TempDir()
	homePath := setupInboxIdentity(t, dir, "testorg", "testbot")

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"profile", "--name", "Invalid Name!", "--force", "--home", homePath})

	err := rootCmd.Execute()
	if err == nil {
		t.Fatal("profile should reject name with invalid characters")
	}
}

// T-P11: Name with single character (below min 2) is rejected.
func TestProfileRejectsNameTooShort(t *testing.T) {
	resetProfileFlags()

	dir := t.TempDir()
	homePath := setupInboxIdentity(t, dir, "testorg", "testbot")

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"profile", "--name", "a", "--force", "--home", homePath})

	err := rootCmd.Execute()
	if err == nil {
		t.Fatal("profile should reject name shorter than 2 characters")
	}
}

// T-P11: Name starting or ending with hyphen is rejected.
func TestProfileRejectsNameStartingWithHyphen(t *testing.T) {
	resetProfileFlags()

	dir := t.TempDir()
	homePath := setupInboxIdentity(t, dir, "testorg", "testbot")

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"profile", "--name", "-botname", "--force", "--home", homePath})

	err := rootCmd.Execute()
	if err == nil {
		t.Fatal("profile should reject name starting with hyphen")
	}
}

// T-P11: Valid name with min 2 chars is accepted.
func TestProfileAcceptsValidName(t *testing.T) {
	resetProfileFlags()

	server, capture := setupProfileServer(t, http.StatusOK,
		`{"name":"ab","description":"","org":"testorg"}`)
	defer server.Close()

	oldBaseURL := apiBaseURL
	apiBaseURL = server.URL
	defer func() { apiBaseURL = oldBaseURL }()

	dir := t.TempDir()
	homePath := setupInboxIdentity(t, dir, "testorg", "testbot")

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"profile", "--name", "ab", "--force", "--home", homePath})

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("profile should accept valid 2-char name, got error: %v", err)
	}

	if capture.Method != "PATCH" {
		t.Errorf("request method = %q, want PATCH", capture.Method)
	}
}

// T-P12: PATCH request includes Signature-Input and Signature headers.
func TestProfileRequestIncludesSignatureHeaders(t *testing.T) {
	resetProfileFlags()

	server, capture := setupProfileServer(t, http.StatusOK,
		`{"name":"testbot","description":"updated desc","org":"testorg"}`)
	defer server.Close()

	oldBaseURL := apiBaseURL
	apiBaseURL = server.URL
	defer func() { apiBaseURL = oldBaseURL }()

	dir := t.TempDir()
	homePath := setupInboxIdentity(t, dir, "testorg", "testbot")

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"profile", "--description", "updated desc", "--home", homePath})

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("profile returned error: %v", err)
	}

	if capture.SignatureInput == "" {
		t.Error("Signature-Input header is empty")
	}
	if capture.Signature == "" {
		t.Error("Signature header is empty")
	}
}

// T-P12: Signature uses correct keyID {platformBaseURL}/o/{org}/{bot}.
func TestProfileSigningUsesCorrectKeyID(t *testing.T) {
	resetProfileFlags()

	server, capture := setupProfileServer(t, http.StatusOK,
		`{"name":"testbot","description":"updated desc","org":"testorg"}`)
	defer server.Close()

	oldBaseURL := apiBaseURL
	apiBaseURL = server.URL
	defer func() { apiBaseURL = oldBaseURL }()

	dir := t.TempDir()
	homePath := setupInboxIdentity(t, dir, "testorg", "testbot")

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"profile", "--description", "updated desc", "--home", homePath})

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("profile returned error: %v", err)
	}

	expectedKeyID := fmt.Sprintf(`keyid="%s/o/testorg/testbot"`, platformBaseURL)
	if !strings.Contains(capture.SignatureInput, expectedKeyID) {
		t.Errorf("Signature-Input = %q, want it to contain %s", capture.SignatureInput, expectedKeyID)
	}
}

// T-P13: PATCH body is covered by Content-Digest in the signature, consistent
// with other body-bearing commands (send, reply) that pass bodyBytes to Sign().
func TestProfileSigningIncludesContentDigest(t *testing.T) {
	resetProfileFlags()

	server, capture := setupProfileServer(t, http.StatusOK,
		`{"name":"testbot","description":"test","org":"testorg"}`)
	defer server.Close()

	oldBaseURL := apiBaseURL
	apiBaseURL = server.URL
	defer func() { apiBaseURL = oldBaseURL }()

	dir := t.TempDir()
	homePath := setupInboxIdentity(t, dir, "testorg", "testbot")

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"profile", "--description", "test", "--home", homePath})

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("profile returned error: %v", err)
	}

	// Content-Digest header must be present because the PATCH has a JSON body.
	if capture.ContentDigest == "" {
		t.Error("Content-Digest header is empty; body-bearing requests must include Content-Digest")
	}
	if !strings.HasPrefix(capture.ContentDigest, "sha-256=:") {
		t.Errorf("Content-Digest = %q, want it to start with 'sha-256=:'", capture.ContentDigest)
	}

	// Verify content-digest IS in Signature-Input covered components.
	if !strings.Contains(capture.SignatureInput, "content-digest") {
		t.Errorf("Signature-Input = %q, must contain 'content-digest' for body-bearing requests", capture.SignatureInput)
	}
}

// T-P14: PATCH request includes Content-Type application/json.
func TestProfileRequestContentType(t *testing.T) {
	resetProfileFlags()

	server, capture := setupProfileServer(t, http.StatusOK,
		`{"name":"testbot","description":"test","org":"testorg"}`)
	defer server.Close()

	oldBaseURL := apiBaseURL
	apiBaseURL = server.URL
	defer func() { apiBaseURL = oldBaseURL }()

	dir := t.TempDir()
	homePath := setupInboxIdentity(t, dir, "testorg", "testbot")

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"profile", "--description", "test", "--home", homePath})

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("profile returned error: %v", err)
	}

	if capture.ContentType != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", capture.ContentType)
	}
}

// T-P15: HTTP 401 maps to "authentication failed: signature rejected".
func TestProfileMaps401Error(t *testing.T) {
	resetProfileFlags()

	server, _ := setupProfileServer(t, http.StatusUnauthorized, `{"error":"unauthorized"}`)
	defer server.Close()

	oldBaseURL := apiBaseURL
	apiBaseURL = server.URL
	defer func() { apiBaseURL = oldBaseURL }()

	dir := t.TempDir()
	homePath := setupInboxIdentity(t, dir, "testorg", "testbot")

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"profile", "--description", "test", "--home", homePath})

	err := rootCmd.Execute()
	if err == nil {
		t.Fatal("profile should return error for HTTP 401")
	}
	if !strings.Contains(err.Error(), "authentication failed: signature rejected") {
		t.Errorf("error = %q, want it to contain 'authentication failed: signature rejected'", err.Error())
	}
}

// T-P16: HTTP 403 maps to "cannot update another bot".
func TestProfileMaps403Error(t *testing.T) {
	resetProfileFlags()

	server, _ := setupProfileServer(t, http.StatusForbidden, `{"error":"forbidden"}`)
	defer server.Close()

	oldBaseURL := apiBaseURL
	apiBaseURL = server.URL
	defer func() { apiBaseURL = oldBaseURL }()

	dir := t.TempDir()
	homePath := setupInboxIdentity(t, dir, "testorg", "testbot")

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"profile", "--description", "test", "--home", homePath})

	err := rootCmd.Execute()
	if err == nil {
		t.Fatal("profile should return error for HTTP 403")
	}
	if !strings.Contains(err.Error(), "cannot update another bot") {
		t.Errorf("error = %q, want it to contain 'cannot update another bot'", err.Error())
	}
}

// T-P17: HTTP 404 maps to "bot not found".
func TestProfileMaps404Error(t *testing.T) {
	resetProfileFlags()

	server, _ := setupProfileServer(t, http.StatusNotFound, `{"error":"not found"}`)
	defer server.Close()

	oldBaseURL := apiBaseURL
	apiBaseURL = server.URL
	defer func() { apiBaseURL = oldBaseURL }()

	dir := t.TempDir()
	homePath := setupInboxIdentity(t, dir, "testorg", "testbot")

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"profile", "--description", "test", "--home", homePath})

	err := rootCmd.Execute()
	if err == nil {
		t.Fatal("profile should return error for HTTP 404")
	}
	if !strings.Contains(err.Error(), "bot not found") {
		t.Errorf("error = %q, want it to contain 'bot not found'", err.Error())
	}
}

// T-P18: HTTP 409 maps to name conflict error.
func TestProfileMaps409Error(t *testing.T) {
	resetProfileFlags()

	server, _ := setupProfileServer(t, http.StatusConflict, `{"error":"name taken"}`)
	defer server.Close()

	oldBaseURL := apiBaseURL
	apiBaseURL = server.URL
	defer func() { apiBaseURL = oldBaseURL }()

	dir := t.TempDir()
	homePath := setupInboxIdentity(t, dir, "testorg", "testbot")

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"profile", "--name", "taken-name", "--force", "--home", homePath})

	err := rootCmd.Execute()
	if err == nil {
		t.Fatal("profile should return error for HTTP 409")
	}
	// 409 should indicate a name conflict.
	errMsg := err.Error()
	if !strings.Contains(errMsg, "conflict") && !strings.Contains(errMsg, "name") {
		t.Errorf("error = %q, want it to indicate name conflict", errMsg)
	}
}

// T-P19: HTTP 422 maps to validation error with response details.
func TestProfileMaps422Error(t *testing.T) {
	resetProfileFlags()

	server, _ := setupProfileServer(t, http.StatusUnprocessableEntity, `{"detail":"name must be lowercase"}`)
	defer server.Close()

	oldBaseURL := apiBaseURL
	apiBaseURL = server.URL
	defer func() { apiBaseURL = oldBaseURL }()

	dir := t.TempDir()
	homePath := setupInboxIdentity(t, dir, "testorg", "testbot")

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"profile", "--description", "test", "--home", homePath})

	err := rootCmd.Execute()
	if err == nil {
		t.Fatal("profile should return error for HTTP 422")
	}
	errMsg := err.Error()
	if !strings.Contains(errMsg, "name must be lowercase") {
		t.Errorf("error = %q, want it to contain validation detail 'name must be lowercase'", errMsg)
	}
}

// T-P20: Non-2xx (e.g. 500) maps to generic "profile failed: {status}: {body}".
func TestProfileMaps500GenericError(t *testing.T) {
	resetProfileFlags()

	server, _ := setupProfileServer(t, http.StatusInternalServerError, `{"error":"internal"}`)
	defer server.Close()

	oldBaseURL := apiBaseURL
	apiBaseURL = server.URL
	defer func() { apiBaseURL = oldBaseURL }()

	dir := t.TempDir()
	homePath := setupInboxIdentity(t, dir, "testorg", "testbot")

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"profile", "--description", "test", "--home", homePath})

	err := rootCmd.Execute()
	if err == nil {
		t.Fatal("profile should return error for HTTP 500")
	}
	errMsg := err.Error()
	if !strings.Contains(errMsg, "profile failed") {
		t.Errorf("error = %q, want it to contain 'profile failed'", errMsg)
	}
	if !strings.Contains(errMsg, "500") {
		t.Errorf("error = %q, want it to contain status code '500'", errMsg)
	}
}

// T-P06: PATCH endpoint path uses org/bot from config.
func TestProfilePatchEndpointUsesConfigIdentity(t *testing.T) {
	resetProfileFlags()

	server, capture := setupProfileServer(t, http.StatusOK,
		`{"name":"mybot","description":"desc","org":"myorg"}`)
	defer server.Close()

	oldBaseURL := apiBaseURL
	apiBaseURL = server.URL
	defer func() { apiBaseURL = oldBaseURL }()

	dir := t.TempDir()
	homePath := setupInboxIdentity(t, dir, "myorg", "mybot")

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"profile", "--description", "desc", "--home", homePath})

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("profile returned error: %v", err)
	}

	expectedPath := "/orgs/myorg/bots/mybot"
	if capture.Path != expectedPath {
		t.Errorf("request path = %q, want %q", capture.Path, expectedPath)
	}
}

// T-P21: After a successful rename (--name with --force), local config.yaml
// must be updated with the new bot name so that subsequent CLI commands
// (which derive API path and RFC 9421 keyID from config) address/sign
// as the new identity, not the stale old name.
func TestProfileRenameUpdatesLocalConfig(t *testing.T) {
	resetProfileFlags()

	server, _ := setupProfileServer(t, http.StatusOK,
		`{"name":"renamed-bot","description":"existing desc","org":"testorg"}`)
	defer server.Close()

	oldBaseURL := apiBaseURL
	apiBaseURL = server.URL
	defer func() { apiBaseURL = oldBaseURL }()

	dir := t.TempDir()
	homePath := setupInboxIdentity(t, dir, "testorg", "old-bot")

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"profile", "--name", "renamed-bot", "--force", "--home", homePath})

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("profile --name --force returned error: %v", err)
	}

	// Read back config.yaml and verify bot name was updated.
	cfg, err := config.Load(homePath)
	if err != nil {
		t.Fatalf("loading config after rename: %v", err)
	}
	if cfg.Bot != "renamed-bot" {
		t.Errorf("config.Bot = %q after rename, want %q — stale local identity will cause subsequent commands to address/sign as the old bot name", cfg.Bot, "renamed-bot")
	}
}

// T-P21b: After a successful rename, the org field in config.yaml must remain
// unchanged — only the bot name should be updated.
func TestProfileRenamePreservesOrg(t *testing.T) {
	resetProfileFlags()

	server, _ := setupProfileServer(t, http.StatusOK,
		`{"name":"new-name","description":"","org":"myorg"}`)
	defer server.Close()

	oldBaseURL := apiBaseURL
	apiBaseURL = server.URL
	defer func() { apiBaseURL = oldBaseURL }()

	dir := t.TempDir()
	homePath := setupInboxIdentity(t, dir, "myorg", "old-name")

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"profile", "--name", "new-name", "--force", "--home", homePath})

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("profile --name --force returned error: %v", err)
	}

	cfg, err := config.Load(homePath)
	if err != nil {
		t.Fatalf("loading config after rename: %v", err)
	}
	if cfg.Org != "myorg" {
		t.Errorf("config.Org = %q after rename, want %q — org must not change during bot rename", cfg.Org, "myorg")
	}
	if cfg.Bot != "new-name" {
		t.Errorf("config.Bot = %q after rename, want %q", cfg.Bot, "new-name")
	}
}

// T-P21c: A description-only update (no --name) must NOT change the bot name
// in config.yaml — only rename operations should trigger config rewrite.
func TestProfileDescriptionOnlyDoesNotChangeBotName(t *testing.T) {
	resetProfileFlags()

	server, _ := setupProfileServer(t, http.StatusOK,
		`{"name":"testbot","description":"new desc","org":"testorg"}`)
	defer server.Close()

	oldBaseURL := apiBaseURL
	apiBaseURL = server.URL
	defer func() { apiBaseURL = oldBaseURL }()

	dir := t.TempDir()
	homePath := setupInboxIdentity(t, dir, "testorg", "testbot")

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"profile", "--description", "new desc", "--home", homePath})

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("profile --description returned error: %v", err)
	}

	cfg, err := config.Load(homePath)
	if err != nil {
		t.Fatalf("loading config after description update: %v", err)
	}
	if cfg.Bot != "testbot" {
		t.Errorf("config.Bot = %q after description-only update, want %q — bot name should not change", cfg.Bot, "testbot")
	}
	if cfg.Org != "testorg" {
		t.Errorf("config.Org = %q after description-only update, want %q", cfg.Org, "testorg")
	}
}

// T-P21d: When rename fails (server returns non-2xx), local config.yaml must NOT
// be modified — partial rename must not corrupt local state.
func TestProfileRenameFailureDoesNotUpdateConfig(t *testing.T) {
	resetProfileFlags()

	// Server returns 409 Conflict — name is taken.
	server, _ := setupProfileServer(t, http.StatusConflict, `{"error":"name taken"}`)
	defer server.Close()

	oldBaseURL := apiBaseURL
	apiBaseURL = server.URL
	defer func() { apiBaseURL = oldBaseURL }()

	dir := t.TempDir()
	homePath := setupInboxIdentity(t, dir, "testorg", "original-bot")

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"profile", "--name", "taken-name", "--force", "--home", homePath})

	err := rootCmd.Execute()
	if err == nil {
		t.Fatal("profile --name --force with 409 should return error")
	}

	// Config must still have the original bot name.
	cfg, loadErr := config.Load(homePath)
	if loadErr != nil {
		t.Fatalf("loading config after failed rename: %v", loadErr)
	}
	if cfg.Bot != "original-bot" {
		t.Errorf("config.Bot = %q after failed rename, want %q — failed rename must not change local config", cfg.Bot, "original-bot")
	}
}
