package cmd

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// resetSendFlags resets all flag state between send tests.
func resetSendFlags() {
	homeFlag = ""
	sendToFlag = ""
	sendMessageFlag = ""
	sendJSONFlag = false

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

	for _, name := range []string{"to", "message", "json", "help"} {
		if flag := sendCmd.Flags().Lookup(name); flag != nil {
			if err := flag.Value.Set(flag.DefValue); err != nil {
				panic(err)
			}
			flag.Changed = false
		}
	}
}

// setupSendRecipientAndInbox creates a test server that returns a valid recipient
// profile on GET and captures POST to inbox. Returns the server, captured fields,
// and the Ed25519 public key used for the recipient.
func setupSendServer(t *testing.T, inboxStatus int, inboxResponse string) (*httptest.Server, *sendCapture) {
	t.Helper()

	// Generate a recipient Ed25519 keypair.
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating recipient key: %v", err)
	}
	encodedPub := base64.RawURLEncoding.EncodeToString([]byte(pub))

	capture := &sendCapture{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Route: GET /orgs/{org}/bots/{bot} — recipient profile.
		if r.Method == "GET" && strings.Count(r.URL.Path, "/") == 4 && !strings.Contains(r.URL.Path, "inbox") {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			fmt.Fprintf(w, `{"name":"bot","public_key":"%s"}`, encodedPub)
			return
		}

		// Route: POST /orgs/{org}/bots/{bot}/inbox — inbox POST.
		if r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/inbox") {
			capture.Method = r.Method
			capture.Path = r.URL.Path
			capture.ContentType = r.Header.Get("Content-Type")
			capture.ContentDigest = r.Header.Get("Content-Digest")
			capture.SignatureInput = r.Header.Get("Signature-Input")
			capture.Signature = r.Header.Get("Signature")

			body, _ := io.ReadAll(r.Body)
			capture.Body = body

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(inboxStatus)
			w.Write([]byte(inboxResponse))
			return
		}

		w.WriteHeader(http.StatusNotFound)
	}))

	return server, capture
}

type sendCapture struct {
	Method         string
	Path           string
	ContentType    string
	ContentDigest  string
	SignatureInput string
	Signature      string
	Body           []byte
}

// T-SEND01: send is registered as a root subcommand and --help succeeds.
func TestSendCommandHelp(t *testing.T) {
	resetSendFlags()

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetArgs([]string{"send", "--help"})

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("send --help returned error: %v", err)
	}

	output := buf.String()
	if len(output) == 0 {
		t.Fatal("send --help produced no output")
	}
	if !strings.Contains(output, "send") {
		t.Errorf("help output does not contain 'send': %s", output)
	}
}

// T-SEND02: send rejects missing --to flag.
func TestSendRejectsMissingTo(t *testing.T) {
	resetSendFlags()

	dir := t.TempDir()
	homePath := setupInboxIdentity(t, dir, "testorg", "testbot")

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"send", "--message", "hello", "--home", homePath})

	err := rootCmd.Execute()
	if err == nil {
		t.Fatal("send should return error when --to is missing")
	}
}

// T-SEND02: send rejects --to without slash.
func TestSendRejectsToWithoutSlash(t *testing.T) {
	resetSendFlags()

	dir := t.TempDir()
	homePath := setupInboxIdentity(t, dir, "testorg", "testbot")

	oldStdin := stdinIsTerminal
	stdinIsTerminal = func() bool { return false }
	defer func() { stdinIsTerminal = oldStdin }()

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetIn(strings.NewReader("hello"))
	rootCmd.SetArgs([]string{"send", "--to", "orgonly", "--message", "test", "--home", homePath})

	err := rootCmd.Execute()
	if err == nil {
		t.Fatal("send should reject --to without slash")
	}
}

// T-SEND02: send rejects --to with extra slash.
func TestSendRejectsToWithExtraSlash(t *testing.T) {
	resetSendFlags()

	dir := t.TempDir()
	homePath := setupInboxIdentity(t, dir, "testorg", "testbot")

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"send", "--to", "a/b/c", "--message", "test", "--home", homePath})

	err := rootCmd.Execute()
	if err == nil {
		t.Fatal("send should reject --to with extra slash")
	}
}

// T-SEND02: send rejects --to with empty org part.
func TestSendRejectsToWithEmptyOrg(t *testing.T) {
	resetSendFlags()

	dir := t.TempDir()
	homePath := setupInboxIdentity(t, dir, "testorg", "testbot")

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"send", "--to", "/bot", "--message", "test", "--home", homePath})

	err := rootCmd.Execute()
	if err == nil {
		t.Fatal("send should reject --to with empty org")
	}
}

// T-SEND02: send rejects --to with empty bot part.
func TestSendRejectsToWithEmptyBot(t *testing.T) {
	resetSendFlags()

	dir := t.TempDir()
	homePath := setupInboxIdentity(t, dir, "testorg", "testbot")

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"send", "--to", "org/", "--message", "test", "--home", homePath})

	err := rootCmd.Execute()
	if err == nil {
		t.Fatal("send should reject --to with empty bot")
	}
}

// T-SEND03: send resolves message from --message flag with priority over stdin.
func TestSendMessageFlagPriority(t *testing.T) {
	resetSendFlags()

	server, capture := setupSendServer(t, http.StatusOK, `{"message_id":"msg-1"}`)
	defer server.Close()

	oldBaseURL := apiBaseURL
	apiBaseURL = server.URL
	defer func() { apiBaseURL = oldBaseURL }()

	dir := t.TempDir()
	homePath := setupInboxIdentity(t, dir, "senderorg", "senderbot")

	oldStdin := stdinIsTerminal
	stdinIsTerminal = func() bool { return false }
	defer func() { stdinIsTerminal = oldStdin }()

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetIn(strings.NewReader("stdin content"))
	rootCmd.SetArgs([]string{"send", "--to", "reciporg/recipbot", "--message", "flag content", "--home", homePath})

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("send returned error: %v", err)
	}

	// The POST body should contain encrypted content — we can't check the plaintext
	// but we can verify a POST was made.
	if capture.Method != "POST" {
		t.Errorf("expected POST request, got %q", capture.Method)
	}
}

// T-SEND03: send reads from stdin when --message is not provided.
func TestSendReadsFromStdin(t *testing.T) {
	resetSendFlags()

	server, capture := setupSendServer(t, http.StatusOK, `{"message_id":"msg-1"}`)
	defer server.Close()

	oldBaseURL := apiBaseURL
	apiBaseURL = server.URL
	defer func() { apiBaseURL = oldBaseURL }()

	dir := t.TempDir()
	homePath := setupInboxIdentity(t, dir, "senderorg", "senderbot")

	oldStdin := stdinIsTerminal
	stdinIsTerminal = func() bool { return false }
	defer func() { stdinIsTerminal = oldStdin }()

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetIn(strings.NewReader("piped message"))
	rootCmd.SetArgs([]string{"send", "--to", "reciporg/recipbot", "--home", homePath})

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("send returned error: %v", err)
	}

	if capture.Method != "POST" {
		t.Errorf("expected POST request, got %q", capture.Method)
	}
}

// T-SEND03: send rejects terminal stdin without --message.
func TestSendRejectsTerminalStdinWithoutMessage(t *testing.T) {
	resetSendFlags()

	dir := t.TempDir()
	homePath := setupInboxIdentity(t, dir, "testorg", "testbot")

	oldStdin := stdinIsTerminal
	stdinIsTerminal = func() bool { return true }
	defer func() { stdinIsTerminal = oldStdin }()

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"send", "--to", "reciporg/recipbot", "--home", homePath})

	err := rootCmd.Execute()
	if err == nil {
		t.Fatal("send should reject when stdin is terminal and --message is absent")
	}
	if !strings.Contains(err.Error(), "message required: use --message or pipe to stdin") {
		t.Errorf("error = %q, want it to contain 'message required: use --message or pipe to stdin'", err.Error())
	}
}

// T-SEND03: send rejects empty message content.
func TestSendRejectsEmptyMessage(t *testing.T) {
	resetSendFlags()

	dir := t.TempDir()
	homePath := setupInboxIdentity(t, dir, "testorg", "testbot")

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"send", "--to", "reciporg/recipbot", "--message", "", "--home", homePath})

	err := rootCmd.Execute()
	if err == nil {
		t.Fatal("send should reject empty message")
	}
}

// T-SEND04: send rejects when .rtbtr directory is missing.
func TestSendRejectsMissingRtbtrDir(t *testing.T) {
	resetSendFlags()

	dir := t.TempDir()
	t.Chdir(dir)

	oldStdin := stdinIsTerminal
	stdinIsTerminal = func() bool { return false }
	defer func() { stdinIsTerminal = oldStdin }()

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetIn(strings.NewReader("hello"))
	rootCmd.SetArgs([]string{"send", "--to", "org/bot", "--message", "test"})

	err := rootCmd.Execute()
	if err == nil {
		t.Fatal("send should return error when .rtbtr directory is missing")
	}
	if !strings.Contains(err.Error(), ".rtbtr") {
		t.Errorf("error = %q, want it to mention .rtbtr", err.Error())
	}
}

// T-SEND05: send rejects when config.yaml is missing.
func TestSendRejectsMissingConfig(t *testing.T) {
	resetSendFlags()

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
	rootCmd.SetArgs([]string{"send", "--to", "org/bot", "--message", "test", "--home", homePath})

	err = rootCmd.Execute()
	if err == nil {
		t.Fatal("send should return error when config.yaml is missing")
	}
	if !strings.Contains(err.Error(), "not registered: run rtbtr register first") {
		t.Errorf("error = %q, want it to contain 'not registered: run rtbtr register first'", err.Error())
	}
}

// T-SEND05: send rejects when org/bot are empty in config.yaml.
func TestSendRejectsEmptyOrgBot(t *testing.T) {
	resetSendFlags()

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
	rootCmd.SetArgs([]string{"send", "--to", "org/bot", "--message", "test", "--home", homePath})

	err = rootCmd.Execute()
	if err == nil {
		t.Fatal("send should return error when org/bot are empty")
	}
	if !strings.Contains(err.Error(), "not registered") {
		t.Errorf("error = %q, want it to contain 'not registered'", err.Error())
	}
}

// T-SEND06: send rejects when private_key file is absent.
func TestSendRejectsMissingPrivateKey(t *testing.T) {
	resetSendFlags()

	dir := t.TempDir()
	homePath := setupRtbtrDir(t, dir, map[string]string{
		"config.yaml": "org: testorg\nbot: testbot\n",
	})

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"send", "--to", "org/bot", "--message", "test", "--home", homePath})

	err := rootCmd.Execute()
	if err == nil {
		t.Fatal("send should return error when private_key is missing")
	}
	if !strings.Contains(err.Error(), "private key not found") {
		t.Errorf("error = %q, want it to contain 'private key not found'", err.Error())
	}
}

// T-SEND07: send maps recipient profile 404 to "recipient not found".
func TestSendRecipientNotFound(t *testing.T) {
	resetSendFlags()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`{"error":"not found"}`))
	}))
	defer server.Close()

	oldBaseURL := apiBaseURL
	apiBaseURL = server.URL
	defer func() { apiBaseURL = oldBaseURL }()

	dir := t.TempDir()
	homePath := setupInboxIdentity(t, dir, "senderorg", "senderbot")

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"send", "--to", "missingorg/missingbot", "--message", "test", "--home", homePath})

	err := rootCmd.Execute()
	if err == nil {
		t.Fatal("send should return error when recipient is not found")
	}
	if !strings.Contains(err.Error(), "recipient not found") {
		t.Errorf("error = %q, want it to contain 'recipient not found'", err.Error())
	}
}

// T-SEND09: send rejects plaintext > 1MB with "message too large (max 1MB)".
func TestSendRejectsMessageTooLarge(t *testing.T) {
	resetSendFlags()

	dir := t.TempDir()
	homePath := setupInboxIdentity(t, dir, "testorg", "testbot")

	// 1MB + 1 byte message.
	largeMsg := strings.Repeat("x", 1<<20+1)

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"send", "--to", "org/bot", "--message", largeMsg, "--home", homePath})

	err := rootCmd.Execute()
	if err == nil {
		t.Fatal("send should reject message larger than 1MB")
	}
	if !strings.Contains(err.Error(), "message too large (max 1MB)") {
		t.Errorf("error = %q, want it to contain 'message too large (max 1MB)'", err.Error())
	}
}

// T-SEND10: send POSTs to correct inbox endpoint with JSON body containing encrypted_payload and encryption metadata.
func TestSendPostsToCorrectEndpoint(t *testing.T) {
	resetSendFlags()

	server, capture := setupSendServer(t, http.StatusOK, `{"message_id":"msg-1"}`)
	defer server.Close()

	oldBaseURL := apiBaseURL
	apiBaseURL = server.URL
	defer func() { apiBaseURL = oldBaseURL }()

	dir := t.TempDir()
	homePath := setupInboxIdentity(t, dir, "senderorg", "senderbot")

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"send", "--to", "reciporg/recipbot", "--message", "hello", "--home", homePath})

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("send returned error: %v", err)
	}

	// Verify POST path.
	if capture.Path != "/orgs/reciporg/bots/recipbot/inbox" {
		t.Errorf("POST path = %q, want /orgs/reciporg/bots/recipbot/inbox", capture.Path)
	}

	// Parse the JSON body.
	var body map[string]interface{}
	if err := json.Unmarshal(capture.Body, &body); err != nil {
		t.Fatalf("parsing POST body: %v", err)
	}

	// Verify encrypted_payload is valid standard base64.
	payload, ok := body["encrypted_payload"].(string)
	if !ok || payload == "" {
		t.Fatal("POST body missing or empty encrypted_payload")
	}
	if _, err := base64.StdEncoding.DecodeString(payload); err != nil {
		t.Errorf("encrypted_payload is not valid standard base64: %v", err)
	}

	// Verify encryption metadata.
	enc, ok := body["encryption"].(map[string]interface{})
	if !ok {
		t.Fatal("POST body missing encryption object")
	}
	if enc["algorithm"] == nil || enc["algorithm"] == "" {
		t.Error("encryption.algorithm is missing or empty")
	}
	if enc["recipient_public_key"] == nil || enc["recipient_public_key"] == "" {
		t.Error("encryption.recipient_public_key is missing or empty")
	}
	if enc["ephemeral_public_key"] == nil || enc["ephemeral_public_key"] == "" {
		t.Error("encryption.ephemeral_public_key is missing or empty")
	}
}

// T-SEND11: send POST includes Content-Type, Content-Digest, and HTTP signature headers.
func TestSendPostHeaders(t *testing.T) {
	resetSendFlags()

	server, capture := setupSendServer(t, http.StatusOK, `{"message_id":"msg-1"}`)
	defer server.Close()

	oldBaseURL := apiBaseURL
	apiBaseURL = server.URL
	defer func() { apiBaseURL = oldBaseURL }()

	dir := t.TempDir()
	homePath := setupInboxIdentity(t, dir, "senderorg", "senderbot")

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"send", "--to", "reciporg/recipbot", "--message", "hello", "--home", homePath})

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("send returned error: %v", err)
	}

	if capture.ContentType != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", capture.ContentType)
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
	if capture.Signature == "" {
		t.Error("Signature header is empty")
	}
}

// T-SEND12: send signs with key ID {platformBaseURL}/o/{sender_org}/{sender_bot}.
func TestSendSigningKeyID(t *testing.T) {
	resetSendFlags()

	server, capture := setupSendServer(t, http.StatusOK, `{"message_id":"msg-1"}`)
	defer server.Close()

	oldBaseURL := apiBaseURL
	apiBaseURL = server.URL
	defer func() { apiBaseURL = oldBaseURL }()

	dir := t.TempDir()
	homePath := setupInboxIdentity(t, dir, "senderorg", "senderbot")

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"send", "--to", "reciporg/recipbot", "--message", "hello", "--home", homePath})

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("send returned error: %v", err)
	}

	expectedKeyID := fmt.Sprintf(`keyid="%s/o/senderorg/senderbot"`, platformBaseURL)
	if !strings.Contains(capture.SignatureInput, expectedKeyID) {
		t.Errorf("Signature-Input = %q, want it to contain %s", capture.SignatureInput, expectedKeyID)
	}
}

// T-SEND13: On success, send prints "sent <message_id>".
func TestSendPrintsSentMessageID(t *testing.T) {
	resetSendFlags()

	server, _ := setupSendServer(t, http.StatusOK, `{"message_id":"test-msg-id"}`)
	defer server.Close()

	oldBaseURL := apiBaseURL
	apiBaseURL = server.URL
	defer func() { apiBaseURL = oldBaseURL }()

	dir := t.TempDir()
	homePath := setupInboxIdentity(t, dir, "senderorg", "senderbot")

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"send", "--to", "reciporg/recipbot", "--message", "hello", "--home", homePath})

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("send returned error: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "sent test-msg-id") {
		t.Errorf("stdout = %q, want it to contain 'sent test-msg-id'", output)
	}
}

// T-SEND14: send --json outputs raw API response JSON.
func TestSendJsonOutputsRawResponse(t *testing.T) {
	resetSendFlags()

	server, _ := setupSendServer(t, http.StatusOK, `{"message_id":"msg-json-1","status":"delivered"}`)
	defer server.Close()

	oldBaseURL := apiBaseURL
	apiBaseURL = server.URL
	defer func() { apiBaseURL = oldBaseURL }()

	dir := t.TempDir()
	homePath := setupInboxIdentity(t, dir, "senderorg", "senderbot")

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"send", "--to", "reciporg/recipbot", "--message", "hello", "--json", "--home", homePath})

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("send --json returned error: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "msg-json-1") {
		t.Errorf("--json output missing id: %q", output)
	}
	if !strings.Contains(output, "delivered") {
		t.Errorf("--json output missing status: %q", output)
	}
}

// T-SEND15: send maps HTTP 401 to "authentication failed: signature rejected".
func TestSendMaps401Error(t *testing.T) {
	resetSendFlags()

	server, _ := setupSendServer(t, http.StatusUnauthorized, `{"error":"unauthorized"}`)
	defer server.Close()

	oldBaseURL := apiBaseURL
	apiBaseURL = server.URL
	defer func() { apiBaseURL = oldBaseURL }()

	dir := t.TempDir()
	homePath := setupInboxIdentity(t, dir, "senderorg", "senderbot")

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"send", "--to", "reciporg/recipbot", "--message", "hello", "--home", homePath})

	err := rootCmd.Execute()
	if err == nil {
		t.Fatal("send should return error for HTTP 401")
	}
	if !strings.Contains(err.Error(), "authentication failed: signature rejected") {
		t.Errorf("error = %q, want it to contain 'authentication failed: signature rejected'", err.Error())
	}
}

// T-SEND15: send maps HTTP 404 on inbox POST to "recipient not found".
func TestSendMaps404InboxError(t *testing.T) {
	resetSendFlags()

	server, _ := setupSendServer(t, http.StatusNotFound, `{"error":"not found"}`)
	defer server.Close()

	oldBaseURL := apiBaseURL
	apiBaseURL = server.URL
	defer func() { apiBaseURL = oldBaseURL }()

	dir := t.TempDir()
	homePath := setupInboxIdentity(t, dir, "senderorg", "senderbot")

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"send", "--to", "reciporg/recipbot", "--message", "hello", "--home", homePath})

	err := rootCmd.Execute()
	if err == nil {
		t.Fatal("send should return error for HTTP 404 on inbox POST")
	}
	if !strings.Contains(err.Error(), "recipient not found") {
		t.Errorf("error = %q, want it to contain 'recipient not found'", err.Error())
	}
}

// T-SEND15: send maps HTTP 422 to "invalid message: {body}".
func TestSendMaps422Error(t *testing.T) {
	resetSendFlags()

	server, _ := setupSendServer(t, http.StatusUnprocessableEntity, `bad payload`)
	defer server.Close()

	oldBaseURL := apiBaseURL
	apiBaseURL = server.URL
	defer func() { apiBaseURL = oldBaseURL }()

	dir := t.TempDir()
	homePath := setupInboxIdentity(t, dir, "senderorg", "senderbot")

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"send", "--to", "reciporg/recipbot", "--message", "hello", "--home", homePath})

	err := rootCmd.Execute()
	if err == nil {
		t.Fatal("send should return error for HTTP 422")
	}
	if !strings.Contains(err.Error(), "invalid message:") {
		t.Errorf("error = %q, want it to contain 'invalid message:'", err.Error())
	}
	if !strings.Contains(err.Error(), "bad payload") {
		t.Errorf("error = %q, want it to contain response body 'bad payload'", err.Error())
	}
}

// T-SEND15: send maps HTTP 500 to "send failed: {status}: {body}".
func TestSendMaps500Error(t *testing.T) {
	resetSendFlags()

	server, _ := setupSendServer(t, http.StatusInternalServerError, `internal error`)
	defer server.Close()

	oldBaseURL := apiBaseURL
	apiBaseURL = server.URL
	defer func() { apiBaseURL = oldBaseURL }()

	dir := t.TempDir()
	homePath := setupInboxIdentity(t, dir, "senderorg", "senderbot")

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"send", "--to", "reciporg/recipbot", "--message", "hello", "--home", homePath})

	err := rootCmd.Execute()
	if err == nil {
		t.Fatal("send should return error for HTTP 500")
	}
	errMsg := err.Error()
	if !strings.Contains(errMsg, "send failed") {
		t.Errorf("error = %q, want it to contain 'send failed'", errMsg)
	}
}
