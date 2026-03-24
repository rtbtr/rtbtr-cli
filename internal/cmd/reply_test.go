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

// resetReplyFlags resets all flag state between reply tests.
func resetReplyFlags() {
	homeFlag = ""
	replyMessageFlag = ""
	replyJsonFlag = false

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

	for _, name := range []string{"message", "json", "help"} {
		if flag := replyCmd.Flags().Lookup(name); flag != nil {
			if err := flag.Value.Set(flag.DefValue); err != nil {
				panic(err)
			}
			flag.Changed = false
		}
	}
}

// setupReplyServer creates a test server that returns a message detail on GET
// and captures POST to sender's inbox. Returns the server and capture.
func setupReplyServer(t *testing.T, msgJSON string, postStatus int, postResponse string) (*httptest.Server, *replyCapture) {
	t.Helper()

	capture := &replyCapture{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Route: GET /orgs/{org}/bots/{bot}/inbox/{msg_id} — read original message.
		if r.Method == "GET" && strings.Contains(r.URL.Path, "/inbox/") {
			capture.GetMethod = r.Method
			capture.GetPath = r.URL.Path
			capture.GetSigInput = r.Header.Get("Signature-Input")
			capture.GetSig = r.Header.Get("Signature")

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(msgJSON))
			return
		}

		// Route: POST /orgs/{org}/bots/{bot}/inbox — send reply.
		if r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/inbox") {
			capture.PostMethod = r.Method
			capture.PostPath = r.URL.Path
			capture.PostContentType = r.Header.Get("Content-Type")
			capture.PostContentDigest = r.Header.Get("Content-Digest")
			capture.PostSigInput = r.Header.Get("Signature-Input")
			capture.PostSig = r.Header.Get("Signature")

			body, _ := io.ReadAll(r.Body)
			capture.PostBody = body

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(postStatus)
			w.Write([]byte(postResponse))
			return
		}

		w.WriteHeader(http.StatusNotFound)
	}))

	return server, capture
}

// setupReplyServerWithGetStatus creates a test server where the GET returns a
// specific HTTP status code (for testing GET-step error mappings).
func setupReplyServerWithGetStatus(t *testing.T, getStatus int, getBody string) *httptest.Server {
	t.Helper()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(getStatus)
		w.Write([]byte(getBody))
	}))

	return server
}

type replyCapture struct {
	GetMethod  string
	GetPath    string
	GetSigInput string
	GetSig     string

	PostMethod         string
	PostPath           string
	PostContentType    string
	PostContentDigest  string
	PostSigInput       string
	PostSig            string
	PostBody           []byte
}

// buildReplyMessageJSON builds a mock original message JSON with sender info.
func buildReplyMessageJSON(t *testing.T, senderOrg, senderBot string, senderPubKey *string) string {
	t.Helper()

	// Generate a recipient keypair for the encrypted payload (the reader's key).
	_, readerPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating reader key: %v", err)
	}

	plaintext := []byte("original message")
	encPayload, ephPub := encryptForTestWithSeed(t, plaintext, readerPriv.Seed())

	sender := map[string]interface{}{
		"org": senderOrg,
		"bot": senderBot,
	}
	if senderPubKey != nil {
		sender["public_key"] = *senderPubKey
	} else {
		sender["public_key"] = nil
	}

	msg := map[string]interface{}{
		"id":                "orig-msg-uuid",
		"encrypted_payload": encPayload,
		"status":            "delivered",
		"created_at":        "2026-03-20T12:00:00Z",
		"sender":            sender,
		"recipient":         "myorg/mybot",
		"encryption": map[string]interface{}{
			"algorithm":            "x25519-aes256gcm",
			"recipient_public_key": "ignored",
			"ephemeral_public_key": ephPub,
		},
	}

	data, err := json.Marshal(msg)
	if err != nil {
		t.Fatalf("marshaling reply message JSON: %v", err)
	}
	return string(data)
}

// T-REPLY01: reply is registered as a root subcommand and --help succeeds.
func TestReplyCommandHelp(t *testing.T) {
	resetReplyFlags()

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetArgs([]string{"reply", "--help"})

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("reply --help returned error: %v", err)
	}

	output := buf.String()
	if len(output) == 0 {
		t.Fatal("reply --help produced no output")
	}
	if !strings.Contains(output, "reply") {
		t.Errorf("help output does not contain 'reply': %s", output)
	}
}

// T-REPLY02: reply rejects missing message_id argument.
func TestReplyRejectsMissingMessageID(t *testing.T) {
	resetReplyFlags()

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"reply", "--message", "hi"})

	err := rootCmd.Execute()
	if err == nil {
		t.Fatal("reply should return error when message_id is missing")
	}
}

// T-REPLY02: reply rejects invalid UUID format.
func TestReplyRejectsInvalidUUID(t *testing.T) {
	resetReplyFlags()

	dir := t.TempDir()
	homePath := setupInboxIdentity(t, dir, "testorg", "testbot")

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"reply", "bad-id", "--message", "hi", "--home", homePath})

	err := rootCmd.Execute()
	if err == nil {
		t.Fatal("reply should return error for invalid UUID")
	}
}

// T-REPLY03: reply rejects terminal stdin without --message flag.
func TestReplyRejectsTerminalStdin(t *testing.T) {
	resetReplyFlags()

	dir := t.TempDir()
	homePath := setupInboxIdentity(t, dir, "testorg", "testbot")

	oldStdin := stdinIsTerminal
	stdinIsTerminal = func() bool { return true }
	defer func() { stdinIsTerminal = oldStdin }()

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"reply", "11111111-2222-3333-4444-555555555555", "--home", homePath})

	err := rootCmd.Execute()
	if err == nil {
		t.Fatal("reply should reject when stdin is terminal and --message is absent")
	}
	if !strings.Contains(err.Error(), "message required") {
		t.Errorf("error = %q, want it to contain 'message required'", err.Error())
	}
}

// T-REPLY03: reply accepts --message flag.
func TestReplyAcceptsMessageFlag(t *testing.T) {
	resetReplyFlags()

	// Generate a sender keypair for the original message.
	senderPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating sender key: %v", err)
	}
	senderPubB64 := base64.RawURLEncoding.EncodeToString([]byte(senderPub))

	msgJSON := buildReplyMessageJSON(t, "sender-org", "sender-bot", &senderPubB64)

	server, _ := setupReplyServer(t, msgJSON, http.StatusOK, `{"id":"new-msg-id"}`)
	defer server.Close()

	oldBaseURL := apiBaseURL
	apiBaseURL = server.URL
	defer func() { apiBaseURL = oldBaseURL }()

	dir := t.TempDir()
	homePath := setupInboxIdentity(t, dir, "testorg", "testbot")

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"reply", "11111111-2222-3333-4444-555555555555", "--message", "hello reply", "--home", homePath})

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("reply returned error: %v", err)
	}
}

// T-REPLY03: reply rejects empty message.
func TestReplyRejectsEmptyMessage(t *testing.T) {
	resetReplyFlags()

	dir := t.TempDir()
	homePath := setupInboxIdentity(t, dir, "testorg", "testbot")

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"reply", "11111111-2222-3333-4444-555555555555", "--message", "", "--home", homePath})

	err := rootCmd.Execute()
	if err == nil {
		t.Fatal("reply should reject empty message")
	}
}

// T-REPLY05: reply reads original message via signed GET to correct inbox endpoint.
func TestReplyReadsOriginalMessageViaSig(t *testing.T) {
	resetReplyFlags()

	senderPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating sender key: %v", err)
	}
	senderPubB64 := base64.RawURLEncoding.EncodeToString([]byte(senderPub))

	msgJSON := buildReplyMessageJSON(t, "sender-org", "sender-bot", &senderPubB64)

	server, capture := setupReplyServer(t, msgJSON, http.StatusOK, `{"id":"new-msg-id"}`)
	defer server.Close()

	oldBaseURL := apiBaseURL
	apiBaseURL = server.URL
	defer func() { apiBaseURL = oldBaseURL }()

	dir := t.TempDir()
	homePath := setupInboxIdentity(t, dir, "testorg", "testbot")

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"reply", "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", "--message", "hi", "--home", homePath})

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("reply returned error: %v", err)
	}

	// Verify GET was made to the correct path.
	if !strings.Contains(capture.GetPath, "/inbox/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee") {
		t.Errorf("GET path = %q, want it to contain /inbox/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", capture.GetPath)
	}

	// Verify Signature headers present on GET.
	if capture.GetSigInput == "" {
		t.Error("GET Signature-Input header is empty")
	}
	if capture.GetSig == "" {
		t.Error("GET Signature header is empty")
	}
}

// T-REPLY06: reply rejects with "cannot reply: sender's key has been revoked" when public_key is null.
func TestReplyRejectsSenderKeyRevoked(t *testing.T) {
	resetReplyFlags()

	msgJSON := buildReplyMessageJSON(t, "sender-org", "sender-bot", nil)

	server, _ := setupReplyServer(t, msgJSON, http.StatusOK, `{}`)
	defer server.Close()

	oldBaseURL := apiBaseURL
	apiBaseURL = server.URL
	defer func() { apiBaseURL = oldBaseURL }()

	dir := t.TempDir()
	homePath := setupInboxIdentity(t, dir, "testorg", "testbot")

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"reply", "11111111-2222-3333-4444-555555555555", "--message", "hi", "--home", homePath})

	err := rootCmd.Execute()
	if err == nil {
		t.Fatal("reply should reject when sender's key is revoked (null)")
	}
	if !strings.Contains(err.Error(), "cannot reply: sender's key has been revoked") {
		t.Errorf("error = %q, want it to contain 'cannot reply: sender's key has been revoked'", err.Error())
	}
}

// T-REPLY07: reply rejects with "cannot reply: sender no longer exists" when sender is unknown/unknown.
func TestReplyRejectsSenderUnknown(t *testing.T) {
	resetReplyFlags()

	// Sender is unknown/unknown but has a non-null public key.
	senderPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating sender key: %v", err)
	}
	senderPubB64 := base64.RawURLEncoding.EncodeToString([]byte(senderPub))

	msgJSON := buildReplyMessageJSON(t, "unknown", "unknown", &senderPubB64)

	server, _ := setupReplyServer(t, msgJSON, http.StatusOK, `{}`)
	defer server.Close()

	oldBaseURL := apiBaseURL
	apiBaseURL = server.URL
	defer func() { apiBaseURL = oldBaseURL }()

	dir := t.TempDir()
	homePath := setupInboxIdentity(t, dir, "testorg", "testbot")

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"reply", "11111111-2222-3333-4444-555555555555", "--message", "hi", "--home", homePath})

	err = rootCmd.Execute()
	if err == nil {
		t.Fatal("reply should reject when sender is unknown/unknown")
	}
	if !strings.Contains(err.Error(), "cannot reply: sender no longer exists") {
		t.Errorf("error = %q, want it to contain 'cannot reply: sender no longer exists'", err.Error())
	}
}

// T-REPLY08: reply encrypts for original sender and POSTs to sender's inbox with Content-Digest and HTTP signature.
func TestReplyPostsToSenderInbox(t *testing.T) {
	resetReplyFlags()

	senderPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating sender key: %v", err)
	}
	senderPubB64 := base64.RawURLEncoding.EncodeToString([]byte(senderPub))

	msgJSON := buildReplyMessageJSON(t, "sender-org", "sender-bot", &senderPubB64)

	server, capture := setupReplyServer(t, msgJSON, http.StatusOK, `{"id":"new-reply-id"}`)
	defer server.Close()

	oldBaseURL := apiBaseURL
	apiBaseURL = server.URL
	defer func() { apiBaseURL = oldBaseURL }()

	dir := t.TempDir()
	homePath := setupInboxIdentity(t, dir, "testorg", "testbot")

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"reply", "11111111-2222-3333-4444-555555555555", "--message", "reply content", "--home", homePath})

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("reply returned error: %v", err)
	}

	// Verify POST goes to sender's inbox.
	if capture.PostPath != "/orgs/sender-org/bots/sender-bot/inbox" {
		t.Errorf("POST path = %q, want /orgs/sender-org/bots/sender-bot/inbox", capture.PostPath)
	}

	// Verify headers.
	if capture.PostContentType != "application/json" {
		t.Errorf("POST Content-Type = %q, want application/json", capture.PostContentType)
	}
	if capture.PostContentDigest == "" {
		t.Error("POST Content-Digest header is empty")
	}
	if capture.PostSigInput == "" {
		t.Error("POST Signature-Input header is empty")
	}
	if capture.PostSig == "" {
		t.Error("POST Signature header is empty")
	}

	// Verify POST body has encryption metadata.
	var body map[string]interface{}
	if err := json.Unmarshal(capture.PostBody, &body); err != nil {
		t.Fatalf("parsing POST body: %v", err)
	}

	payload, ok := body["encrypted_payload"].(string)
	if !ok || payload == "" {
		t.Error("POST body missing encrypted_payload")
	}

	enc, ok := body["encryption"].(map[string]interface{})
	if !ok {
		t.Fatal("POST body missing encryption object")
	}
	if enc["algorithm"] == nil || enc["algorithm"] == "" {
		t.Error("encryption.algorithm missing or empty")
	}
	if enc["ephemeral_public_key"] == nil || enc["ephemeral_public_key"] == "" {
		t.Error("encryption.ephemeral_public_key missing or empty")
	}
}

// T-REPLY09: On success, reply prints "replied to <message_id> -> sent <new_message_id>".
func TestReplyPrintsSuccessMessage(t *testing.T) {
	resetReplyFlags()

	senderPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating sender key: %v", err)
	}
	senderPubB64 := base64.RawURLEncoding.EncodeToString([]byte(senderPub))

	msgJSON := buildReplyMessageJSON(t, "sender-org", "sender-bot", &senderPubB64)

	server, _ := setupReplyServer(t, msgJSON, http.StatusOK, `{"id":"new-msg-id"}`)
	defer server.Close()

	oldBaseURL := apiBaseURL
	apiBaseURL = server.URL
	defer func() { apiBaseURL = oldBaseURL }()

	dir := t.TempDir()
	homePath := setupInboxIdentity(t, dir, "testorg", "testbot")

	msgID := "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"reply", msgID, "--message", "hi", "--home", homePath})

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("reply returned error: %v", err)
	}

	output := buf.String()
	expected := fmt.Sprintf("replied to %s -> sent new-msg-id", msgID)
	if !strings.Contains(output, expected) {
		t.Errorf("stdout = %q, want it to contain %q", output, expected)
	}
}

// T-REPLY10: reply --json outputs raw send API response JSON.
func TestReplyJsonOutputsRawResponse(t *testing.T) {
	resetReplyFlags()

	senderPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating sender key: %v", err)
	}
	senderPubB64 := base64.RawURLEncoding.EncodeToString([]byte(senderPub))

	msgJSON := buildReplyMessageJSON(t, "sender-org", "sender-bot", &senderPubB64)

	server, _ := setupReplyServer(t, msgJSON, http.StatusOK, `{"id":"json-reply-id","status":"delivered"}`)
	defer server.Close()

	oldBaseURL := apiBaseURL
	apiBaseURL = server.URL
	defer func() { apiBaseURL = oldBaseURL }()

	dir := t.TempDir()
	homePath := setupInboxIdentity(t, dir, "testorg", "testbot")

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"reply", "11111111-2222-3333-4444-555555555555", "--message", "hi", "--json", "--home", homePath})

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("reply --json returned error: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "json-reply-id") {
		t.Errorf("--json output missing id: %q", output)
	}
	if !strings.Contains(output, "delivered") {
		t.Errorf("--json output missing status: %q", output)
	}
}

// T-REPLY11: reply uses read error mappings for GET step — test 401.
func TestReplyGetStep401Error(t *testing.T) {
	resetReplyFlags()

	server := setupReplyServerWithGetStatus(t, http.StatusUnauthorized, `{"error":"unauthorized"}`)
	defer server.Close()

	oldBaseURL := apiBaseURL
	apiBaseURL = server.URL
	defer func() { apiBaseURL = oldBaseURL }()

	dir := t.TempDir()
	homePath := setupInboxIdentity(t, dir, "testorg", "testbot")

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"reply", "11111111-2222-3333-4444-555555555555", "--message", "hi", "--home", homePath})

	err := rootCmd.Execute()
	if err == nil {
		t.Fatal("reply should return error for GET 401")
	}
	if !strings.Contains(err.Error(), "authentication failed: signature rejected") {
		t.Errorf("error = %q, want it to contain 'authentication failed: signature rejected'", err.Error())
	}
}

// T-REPLY11: reply uses read error mappings for GET step — test 404.
func TestReplyGetStep404Error(t *testing.T) {
	resetReplyFlags()

	server := setupReplyServerWithGetStatus(t, http.StatusNotFound, `{"error":"not found"}`)
	defer server.Close()

	oldBaseURL := apiBaseURL
	apiBaseURL = server.URL
	defer func() { apiBaseURL = oldBaseURL }()

	dir := t.TempDir()
	homePath := setupInboxIdentity(t, dir, "testorg", "testbot")

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"reply", "11111111-2222-3333-4444-555555555555", "--message", "hi", "--home", homePath})

	err := rootCmd.Execute()
	if err == nil {
		t.Fatal("reply should return error for GET 404")
	}
	if !strings.Contains(err.Error(), "message not found") {
		t.Errorf("error = %q, want it to contain 'message not found'", err.Error())
	}
}

// T-REPLY11: reply uses read error mappings for GET step — test 403.
func TestReplyGetStep403Error(t *testing.T) {
	resetReplyFlags()

	server := setupReplyServerWithGetStatus(t, http.StatusForbidden, `{"error":"forbidden"}`)
	defer server.Close()

	oldBaseURL := apiBaseURL
	apiBaseURL = server.URL
	defer func() { apiBaseURL = oldBaseURL }()

	dir := t.TempDir()
	homePath := setupInboxIdentity(t, dir, "testorg", "testbot")

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"reply", "11111111-2222-3333-4444-555555555555", "--message", "hi", "--home", homePath})

	err := rootCmd.Execute()
	if err == nil {
		t.Fatal("reply should return error for GET 403")
	}
	if !strings.Contains(err.Error(), "not authorized to read this message") {
		t.Errorf("error = %q, want it to contain 'not authorized to read this message'", err.Error())
	}
}

// T-REPLY11: reply uses send error mappings for POST step — test 401.
func TestReplyPostStep401Error(t *testing.T) {
	resetReplyFlags()

	senderPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating sender key: %v", err)
	}
	senderPubB64 := base64.RawURLEncoding.EncodeToString([]byte(senderPub))

	msgJSON := buildReplyMessageJSON(t, "sender-org", "sender-bot", &senderPubB64)

	server, _ := setupReplyServer(t, msgJSON, http.StatusUnauthorized, `{"error":"unauthorized"}`)
	defer server.Close()

	oldBaseURL := apiBaseURL
	apiBaseURL = server.URL
	defer func() { apiBaseURL = oldBaseURL }()

	dir := t.TempDir()
	homePath := setupInboxIdentity(t, dir, "testorg", "testbot")

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"reply", "11111111-2222-3333-4444-555555555555", "--message", "hi", "--home", homePath})

	err = rootCmd.Execute()
	if err == nil {
		t.Fatal("reply should return error for POST 401")
	}
	if !strings.Contains(err.Error(), "authentication failed: signature rejected") {
		t.Errorf("error = %q, want it to contain 'authentication failed: signature rejected'", err.Error())
	}
}

// T-REPLY11: reply uses send error mappings for POST step — test 422.
func TestReplyPostStep422Error(t *testing.T) {
	resetReplyFlags()

	senderPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating sender key: %v", err)
	}
	senderPubB64 := base64.RawURLEncoding.EncodeToString([]byte(senderPub))

	msgJSON := buildReplyMessageJSON(t, "sender-org", "sender-bot", &senderPubB64)

	server, _ := setupReplyServer(t, msgJSON, http.StatusUnprocessableEntity, `bad reply payload`)
	defer server.Close()

	oldBaseURL := apiBaseURL
	apiBaseURL = server.URL
	defer func() { apiBaseURL = oldBaseURL }()

	dir := t.TempDir()
	homePath := setupInboxIdentity(t, dir, "testorg", "testbot")

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"reply", "11111111-2222-3333-4444-555555555555", "--message", "hi", "--home", homePath})

	err = rootCmd.Execute()
	if err == nil {
		t.Fatal("reply should return error for POST 422")
	}
	if !strings.Contains(err.Error(), "invalid message:") {
		t.Errorf("error = %q, want it to contain 'invalid message:'", err.Error())
	}
}
