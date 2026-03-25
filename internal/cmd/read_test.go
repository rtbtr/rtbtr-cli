package cmd

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	rtbtrcrypto "github.com/rtbtr/rtbtr-cli/internal/crypto"
)

// resetReadFlags resets all flag state between read tests.
func resetReadFlags() {
	homeFlag = ""
	readJSONFlag = false

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
		if flag := readCmd.Flags().Lookup(name); flag != nil {
			if err := flag.Value.Set(flag.DefValue); err != nil {
				panic(err)
			}
			flag.Changed = false
		}
	}
}

// encryptForTestWithSeed encrypts plaintext using the crypto package's
// Encrypt function, given an Ed25519 seed. Returns standard-base64
// encrypted payload and URL-safe-base64 ephemeral public key.
func encryptForTestWithSeed(t *testing.T, plaintext []byte, recipientEd25519Seed []byte) (encPayloadB64, ephPubB64 string) {
	t.Helper()

	// Derive X25519 public key from the Ed25519 seed.
	_, x25519Pub, err := rtbtrcrypto.DeriveX25519KeyPair(recipientEd25519Seed)
	if err != nil {
		t.Fatalf("DeriveX25519KeyPair: %v", err)
	}

	// Encrypt using the crypto package.
	ciphertext, ephPub, err := rtbtrcrypto.Encrypt(plaintext, x25519Pub)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	return base64.StdEncoding.EncodeToString(ciphertext),
		base64.RawURLEncoding.EncodeToString(ephPub)
}

// buildReadMessageJSON builds a mock message detail JSON response.
func buildReadMessageJSON(t *testing.T, id, senderOrg, senderBot, senderPubKey, encPayload, ephPubKey string) string {
	t.Helper()

	msg := map[string]interface{}{
		"id":                id,
		"encrypted_payload": encPayload,
		"status":            "delivered",
		"created_at":        "2026-03-20T12:00:00Z",
		"sender": map[string]interface{}{
			"org":        senderOrg,
			"name":       senderBot,
			"public_key": senderPubKey,
		},
		"recipient": "myorg/mybot",
		"encryption": map[string]interface{}{
			"algorithm":            "x25519-aes256gcm",
			"recipient_public_key": "ignored",
			"ephemeral_public_key": ephPubKey,
		},
	}

	data, err := json.Marshal(msg)
	if err != nil {
		t.Fatalf("marshaling message JSON: %v", err)
	}
	return string(data)
}

// T-READ01: read is registered as a root subcommand and --help succeeds.
func TestReadCommandHelp(t *testing.T) {
	resetReadFlags()

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetArgs([]string{"read", "--help"})

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("read --help returned error: %v", err)
	}

	output := buf.String()
	if len(output) == 0 {
		t.Fatal("read --help produced no output")
	}
	if !strings.Contains(output, "read") {
		t.Errorf("help output does not contain 'read': %s", output)
	}
}

// T-READ02: read rejects missing message_id argument.
func TestReadRejectsMissingMessageID(t *testing.T) {
	resetReadFlags()

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"read"})

	err := rootCmd.Execute()
	if err == nil {
		t.Fatal("read should return error when message_id is missing")
	}
}

// T-READ02: read rejects invalid UUID format.
func TestReadRejectsInvalidUUID(t *testing.T) {
	resetReadFlags()

	dir := t.TempDir()
	homePath := setupInboxIdentity(t, dir, "testorg", "testbot")

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"read", "not-a-uuid", "--home", homePath})

	err := rootCmd.Execute()
	if err == nil {
		t.Fatal("read should return error for invalid UUID")
	}
}

// T-READ02: read accepts valid UUID format.
func TestReadAcceptsValidUUID(t *testing.T) {
	resetReadFlags()

	// Set up a mock server that returns a valid message.
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	seed := priv.Seed()

	plaintext := []byte("test message")
	encPayload, ephPub := encryptForTestWithSeed(t, plaintext, seed)

	senderPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating sender key: %v", err)
	}
	senderPubB64 := base64.RawURLEncoding.EncodeToString([]byte(senderPub))

	msgJSON := buildReadMessageJSON(t, "12345678-1234-1234-1234-123456789abc",
		"sender", "bot", senderPubB64, encPayload, ephPub)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(msgJSON))
	}))
	defer server.Close()

	oldBaseURL := apiBaseURL
	apiBaseURL = server.URL
	defer func() { apiBaseURL = oldBaseURL }()

	dir := t.TempDir()
	encodedSeed := base64.RawURLEncoding.EncodeToString(seed)
	homePath := setupRtbtrDir(t, dir, map[string]string{
		"config.yaml": "org: testorg\nbot: testbot\n",
		"private_key": encodedSeed,
	})

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"read", "12345678-1234-1234-1234-123456789abc", "--home", homePath})

	// Should not fail on UUID validation (may fail for other reasons but not UUID).
	err = rootCmd.Execute()
	// If there's an error, it should not be about UUID format.
	if err != nil && strings.Contains(err.Error(), "invalid message ID") {
		t.Errorf("read rejected a valid UUID: %v", err)
	}
}

// T-READ04: read sends signed GET with Signature headers present and Content-Digest absent.
func TestReadSendsSignedGetWithoutContentDigest(t *testing.T) {
	resetReadFlags()

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	seed := priv.Seed()

	plaintext := []byte("read test")
	encPayload, ephPub := encryptForTestWithSeed(t, plaintext, seed)

	senderPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating sender key: %v", err)
	}
	senderPubB64 := base64.RawURLEncoding.EncodeToString([]byte(senderPub))

	msgJSON := buildReadMessageJSON(t, "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
		"sender", "bot", senderPubB64, encPayload, ephPub)

	var capturedMethod string
	var capturedPath string
	var capturedSigInput string
	var capturedSig string
	var capturedContentDigest string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedMethod = r.Method
		capturedPath = r.URL.Path
		capturedSigInput = r.Header.Get("Signature-Input")
		capturedSig = r.Header.Get("Signature")
		capturedContentDigest = r.Header.Get("Content-Digest")

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(msgJSON))
	}))
	defer server.Close()

	oldBaseURL := apiBaseURL
	apiBaseURL = server.URL
	defer func() { apiBaseURL = oldBaseURL }()

	dir := t.TempDir()
	encodedSeed := base64.RawURLEncoding.EncodeToString(seed)
	homePath := setupRtbtrDir(t, dir, map[string]string{
		"config.yaml": "org: testorg\nbot: testbot\n",
		"private_key": encodedSeed,
	})

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"read", "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", "--home", homePath})

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("read returned error: %v", err)
	}

	if capturedMethod != "GET" {
		t.Errorf("method = %q, want GET", capturedMethod)
	}
	if capturedPath != "/orgs/testorg/bots/testbot/inbox/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee" {
		t.Errorf("path = %q, want /orgs/testorg/bots/testbot/inbox/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", capturedPath)
	}
	if capturedSigInput == "" {
		t.Error("Signature-Input header is empty")
	}
	if capturedSig == "" {
		t.Error("Signature header is empty")
	}
	if capturedContentDigest != "" {
		t.Errorf("Content-Digest should be absent for GET request, got %q", capturedContentDigest)
	}
}

// T-READ05: read successfully decrypts and emits plaintext.
func TestReadDecryptsAndEmitsPlaintext(t *testing.T) {
	resetReadFlags()

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	seed := priv.Seed()

	plaintext := []byte("hello encrypted world!")
	encPayload, ephPub := encryptForTestWithSeed(t, plaintext, seed)

	senderPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating sender key: %v", err)
	}
	senderPubB64 := base64.RawURLEncoding.EncodeToString([]byte(senderPub))

	msgJSON := buildReadMessageJSON(t, "11111111-2222-3333-4444-555555555555",
		"sender-org", "sender-bot", senderPubB64, encPayload, ephPub)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(msgJSON))
	}))
	defer server.Close()

	oldBaseURL := apiBaseURL
	apiBaseURL = server.URL
	defer func() { apiBaseURL = oldBaseURL }()

	dir := t.TempDir()
	encodedSeed := base64.RawURLEncoding.EncodeToString(seed)
	homePath := setupRtbtrDir(t, dir, map[string]string{
		"config.yaml": "org: testorg\nbot: testbot\n",
		"private_key": encodedSeed,
	})

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"read", "11111111-2222-3333-4444-555555555555", "--home", homePath})

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("read returned error: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "hello encrypted world!") {
		t.Errorf("stdout = %q, want it to contain decrypted plaintext 'hello encrypted world!'", output)
	}
}

// T-READ06: On decryption failure, read prints error to stderr, metadata to stdout, exits non-zero.
func TestReadDecryptionFailureShowsMetadata(t *testing.T) {
	resetReadFlags()

	// Use a corrupted payload that cannot be decrypted.
	corruptPayload := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0xAB}, 100))
	ephPub := base64.RawURLEncoding.EncodeToString(make([]byte, 32))

	senderPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating sender key: %v", err)
	}
	senderPubB64 := base64.RawURLEncoding.EncodeToString([]byte(senderPub))

	msgJSON := buildReadMessageJSON(t, "11111111-2222-3333-4444-555555555555",
		"sender-org", "sender-bot", senderPubB64, corruptPayload, ephPub)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(msgJSON))
	}))
	defer server.Close()

	oldBaseURL := apiBaseURL
	apiBaseURL = server.URL
	defer func() { apiBaseURL = oldBaseURL }()

	dir := t.TempDir()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	encodedSeed := base64.RawURLEncoding.EncodeToString(priv.Seed())
	homePath := setupRtbtrDir(t, dir, map[string]string{
		"config.yaml": "org: testorg\nbot: testbot\n",
		"private_key": encodedSeed,
	})

	stdout := new(bytes.Buffer)
	stderr := new(bytes.Buffer)
	rootCmd.SetOut(stdout)
	rootCmd.SetErr(stderr)
	rootCmd.SetArgs([]string{"read", "11111111-2222-3333-4444-555555555555", "--home", homePath})

	err = rootCmd.Execute()
	if err == nil {
		t.Fatal("read should return non-zero exit on decryption failure")
	}

	// Stderr should contain decryption error.
	errOutput := stderr.String()
	if errOutput == "" {
		t.Error("stderr should contain decryption error message")
	}

	// Stdout should still contain metadata (From:, Date:, or Status:).
	stdOutput := stdout.String()
	hasMetadata := strings.Contains(stdOutput, "From:") ||
		strings.Contains(stdOutput, "Date:") ||
		strings.Contains(stdOutput, "Status:")
	if !hasMetadata {
		t.Errorf("stdout should contain message metadata on decryption failure, got: %q", stdOutput)
	}
}

// T-READ07: Default read output prints From:, Date:, Status: and decrypted content.
func TestReadDefaultOutputFormat(t *testing.T) {
	resetReadFlags()

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	seed := priv.Seed()

	plaintext := []byte("decrypted content here")
	encPayload, ephPub := encryptForTestWithSeed(t, plaintext, seed)

	senderPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating sender key: %v", err)
	}
	senderPubB64 := base64.RawURLEncoding.EncodeToString([]byte(senderPub))

	msgJSON := buildReadMessageJSON(t, "11111111-2222-3333-4444-555555555555",
		"sender-org", "sender-bot", senderPubB64, encPayload, ephPub)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(msgJSON))
	}))
	defer server.Close()

	oldBaseURL := apiBaseURL
	apiBaseURL = server.URL
	defer func() { apiBaseURL = oldBaseURL }()

	dir := t.TempDir()
	encodedSeed := base64.RawURLEncoding.EncodeToString(seed)
	homePath := setupRtbtrDir(t, dir, map[string]string{
		"config.yaml": "org: testorg\nbot: testbot\n",
		"private_key": encodedSeed,
	})

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"read", "11111111-2222-3333-4444-555555555555", "--home", homePath})

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("read returned error: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "From:") {
		t.Errorf("output missing 'From:' header: %q", output)
	}
	if !strings.Contains(output, "sender-org/sender-bot") {
		t.Errorf("output missing sender identity: %q", output)
	}
	if !strings.Contains(output, "Date:") {
		t.Errorf("output missing 'Date:' header: %q", output)
	}
	if !strings.Contains(output, "Status:") {
		t.Errorf("output missing 'Status:' header: %q", output)
	}
	if !strings.Contains(output, "decrypted content here") {
		t.Errorf("output missing decrypted content: %q", output)
	}
}

// T-READ08: read --json outputs JSON with content field; on decryption failure content is null and decrypt_error is present.
func TestReadJsonOutputSuccess(t *testing.T) {
	resetReadFlags()

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	seed := priv.Seed()

	plaintext := []byte("json content test")
	encPayload, ephPub := encryptForTestWithSeed(t, plaintext, seed)

	senderPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating sender key: %v", err)
	}
	senderPubB64 := base64.RawURLEncoding.EncodeToString([]byte(senderPub))

	msgJSON := buildReadMessageJSON(t, "11111111-2222-3333-4444-555555555555",
		"sender-org", "sender-bot", senderPubB64, encPayload, ephPub)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(msgJSON))
	}))
	defer server.Close()

	oldBaseURL := apiBaseURL
	apiBaseURL = server.URL
	defer func() { apiBaseURL = oldBaseURL }()

	dir := t.TempDir()
	encodedSeed := base64.RawURLEncoding.EncodeToString(seed)
	homePath := setupRtbtrDir(t, dir, map[string]string{
		"config.yaml": "org: testorg\nbot: testbot\n",
		"private_key": encodedSeed,
	})

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"read", "11111111-2222-3333-4444-555555555555", "--json", "--home", homePath})

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("read --json returned error: %v", err)
	}

	output := buf.String()

	// Parse as JSON.
	var parsed map[string]interface{}
	if err := json.Unmarshal([]byte(output), &parsed); err != nil {
		t.Fatalf("output is not valid JSON: %v\noutput: %q", err, output)
	}

	// content should match decrypted plaintext.
	content, ok := parsed["content"].(string)
	if !ok {
		t.Fatalf("content field is not a string: %v", parsed["content"])
	}
	if content != "json content test" {
		t.Errorf("content = %q, want %q", content, "json content test")
	}

	// encrypted_payload should be absent.
	if _, exists := parsed["encrypted_payload"]; exists {
		t.Error("encrypted_payload should be absent from --json output")
	}
}

// T-READ08: read --json on decryption failure has null content and decrypt_error.
func TestReadJsonOutputDecryptFailure(t *testing.T) {
	resetReadFlags()

	corruptPayload := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0xAB}, 100))
	ephPub := base64.RawURLEncoding.EncodeToString(make([]byte, 32))

	senderPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating sender key: %v", err)
	}
	senderPubB64 := base64.RawURLEncoding.EncodeToString([]byte(senderPub))

	msgJSON := buildReadMessageJSON(t, "11111111-2222-3333-4444-555555555555",
		"sender-org", "sender-bot", senderPubB64, corruptPayload, ephPub)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(msgJSON))
	}))
	defer server.Close()

	oldBaseURL := apiBaseURL
	apiBaseURL = server.URL
	defer func() { apiBaseURL = oldBaseURL }()

	dir := t.TempDir()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	encodedSeed := base64.RawURLEncoding.EncodeToString(priv.Seed())
	homePath := setupRtbtrDir(t, dir, map[string]string{
		"config.yaml": "org: testorg\nbot: testbot\n",
		"private_key": encodedSeed,
	})

	stdout := new(bytes.Buffer)
	stderr := new(bytes.Buffer)
	rootCmd.SetOut(stdout)
	rootCmd.SetErr(stderr)
	rootCmd.SetArgs([]string{"read", "11111111-2222-3333-4444-555555555555", "--json", "--home", homePath})

	_ = rootCmd.Execute() // May return error (expected for decrypt failure)

	output := stdout.String()
	if output == "" {
		t.Fatal("stdout should have JSON output even on decrypt failure")
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal([]byte(output), &parsed); err != nil {
		t.Fatalf("output is not valid JSON: %v\noutput: %q", err, output)
	}

	// content should be null.
	if parsed["content"] != nil {
		t.Errorf("content should be null on decrypt failure, got %v", parsed["content"])
	}

	// decrypt_error should be present and non-empty.
	decryptErr, ok := parsed["decrypt_error"].(string)
	if !ok || decryptErr == "" {
		t.Errorf("decrypt_error should be a non-empty string, got %v", parsed["decrypt_error"])
	}
}

// T-READ09: read maps HTTP 401 to "authentication failed: signature rejected".
func TestReadMaps401Error(t *testing.T) {
	resetReadFlags()

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
	rootCmd.SetArgs([]string{"read", "11111111-2222-3333-4444-555555555555", "--home", homePath})

	err := rootCmd.Execute()
	if err == nil {
		t.Fatal("read should return error for HTTP 401")
	}
	if !strings.Contains(err.Error(), "authentication failed: signature rejected") {
		t.Errorf("error = %q, want it to contain 'authentication failed: signature rejected'", err.Error())
	}
}

// T-READ09: read maps HTTP 403 to "not authorized to read this message".
func TestReadMaps403Error(t *testing.T) {
	resetReadFlags()

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
	rootCmd.SetArgs([]string{"read", "11111111-2222-3333-4444-555555555555", "--home", homePath})

	err := rootCmd.Execute()
	if err == nil {
		t.Fatal("read should return error for HTTP 403")
	}
	if !strings.Contains(err.Error(), "not authorized to read this message") {
		t.Errorf("error = %q, want it to contain 'not authorized to read this message'", err.Error())
	}
}

// T-READ09: read maps HTTP 404 to "message not found".
func TestReadMaps404Error(t *testing.T) {
	resetReadFlags()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`{"error":"not found"}`))
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
	rootCmd.SetArgs([]string{"read", "11111111-2222-3333-4444-555555555555", "--home", homePath})

	err := rootCmd.Execute()
	if err == nil {
		t.Fatal("read should return error for HTTP 404")
	}
	if !strings.Contains(err.Error(), "message not found") {
		t.Errorf("error = %q, want it to contain 'message not found'", err.Error())
	}
}

// T-READ09: read maps HTTP 500 to "read failed: {status}: {body}".
func TestReadMaps500Error(t *testing.T) {
	resetReadFlags()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`internal error`))
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
	rootCmd.SetArgs([]string{"read", "11111111-2222-3333-4444-555555555555", "--home", homePath})

	err := rootCmd.Execute()
	if err == nil {
		t.Fatal("read should return error for HTTP 500")
	}
	errMsg := err.Error()
	if !strings.Contains(errMsg, "read failed") {
		t.Errorf("error = %q, want it to contain 'read failed'", errMsg)
	}
}
