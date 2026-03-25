package cmd

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func resetEncryptFlags() {
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

	if cmd, _, err := rootCmd.Find([]string{"encrypt"}); err == nil && cmd.Name() == "encrypt" {
		for _, name := range []string{"to", "message", "help"} {
			if flag := cmd.Flags().Lookup(name); flag != nil {
				if err := flag.Value.Set(flag.DefValue); err != nil {
					panic(err)
				}
				flag.Changed = false
			}
		}
	}
}

func requireEncryptCommand(t *testing.T) {
	t.Helper()
	cmd, _, err := rootCmd.Find([]string{"encrypt"})
	if err != nil || cmd.Name() != "encrypt" {
		t.Fatal("encrypt command is not registered as a subcommand of rtbtr")
	}
}

// mockBotProfileServer starts an HTTP server that returns a bot profile
// with the given Ed25519 public key. Returns the server and a cleanup func.
func mockBotProfileServer(t *testing.T, pubKeyB64 string) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"bot_id":"test-id","org":"test-org","public_key":"%s","description":"","created_at":"2026-01-01T00:00:00Z"}`, pubKeyB64)
	}))
	t.Cleanup(server.Close)
	return server
}

// setupEncryptWithMock generates a keypair, starts a mock server, overrides
// apiBaseURL, and returns the public key bytes and a cleanup func.
func setupEncryptWithMock(t *testing.T) ed25519.PublicKey {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating keypair: %v", err)
	}
	pubB64 := base64.RawURLEncoding.EncodeToString([]byte(pub))
	server := mockBotProfileServer(t, pubB64)
	oldBaseURL := apiBaseURL
	apiBaseURL = server.URL
	t.Cleanup(func() { apiBaseURL = oldBaseURL })
	return pub
}

func TestEncryptCommandHelp(t *testing.T) {
	resetEncryptFlags()
	requireEncryptCommand(t)

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetArgs([]string{"encrypt", "--help"})

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("encrypt --help returned error: %v", err)
	}

	output := buf.String()
	if len(output) == 0 {
		t.Fatal("encrypt --help produced no output")
	}
}

func TestEncryptProducesValidEnvelope(t *testing.T) {
	resetEncryptFlags()
	setupEncryptWithMock(t)

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(new(bytes.Buffer))
	rootCmd.SetArgs([]string{"encrypt", "--to", "test-org/test-bot", "--message", "hello world"})

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("encrypt returned error: %v", err)
	}

	var envelope map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &envelope); err != nil {
		t.Fatalf("output is not valid JSON: %v\noutput: %q", err, buf.String())
	}

	ct, ok := envelope["ciphertext"].(string)
	if !ok || ct == "" {
		t.Fatal("envelope missing or empty ciphertext field")
	}
	if _, err := base64.StdEncoding.DecodeString(ct); err != nil {
		t.Errorf("ciphertext is not valid base64: %v", err)
	}

	ephPub, ok := envelope["ephemeral_public_key"].(string)
	if !ok || ephPub == "" {
		t.Fatal("envelope missing or empty ephemeral_public_key field")
	}
	ephPubBytes, err := base64.RawURLEncoding.DecodeString(ephPub)
	if err != nil {
		t.Fatalf("ephemeral_public_key is not valid URL-safe base64: %v", err)
	}
	if len(ephPubBytes) != 32 {
		t.Errorf("ephemeral_public_key decoded length = %d, want 32", len(ephPubBytes))
	}

	algo, ok := envelope["algorithm"].(string)
	if !ok || algo != "x25519-aes256gcm" {
		t.Errorf("algorithm = %q, want %q", algo, "x25519-aes256gcm")
	}
}

func TestEncryptFromStdin(t *testing.T) {
	resetEncryptFlags()
	setupEncryptWithMock(t)

	oldStdin := stdinIsTerminal
	stdinIsTerminal = func() bool { return false }
	defer func() { stdinIsTerminal = oldStdin }()

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(new(bytes.Buffer))
	rootCmd.SetIn(strings.NewReader("stdin message"))
	rootCmd.SetArgs([]string{"encrypt", "--to", "test-org/test-bot"})

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("encrypt from stdin returned error: %v", err)
	}

	var envelope map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &envelope); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
}

func TestEncryptRejectsEmptyMessage(t *testing.T) {
	resetEncryptFlags()
	setupEncryptWithMock(t)

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"encrypt", "--to", "test-org/test-bot", "--message", ""})

	err := rootCmd.Execute()
	if err == nil {
		t.Fatal("encrypt should reject empty message")
	}
}

func TestEncryptRejectsInvalidRecipient(t *testing.T) {
	resetEncryptFlags()

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"encrypt", "--to", "noslash", "--message", "hello"})

	err := rootCmd.Execute()
	if err == nil {
		t.Fatal("encrypt should reject recipient without slash")
	}
	if !strings.Contains(err.Error(), "org/bot") {
		t.Errorf("error = %q, want it to mention org/bot format", err.Error())
	}
}

func TestEncryptRejectsOversizedInput(t *testing.T) {
	resetEncryptFlags()
	setupEncryptWithMock(t)

	largeMsg := strings.Repeat("x", 1<<20+1)

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"encrypt", "--to", "test-org/test-bot", "--message", largeMsg})

	err := rootCmd.Execute()
	if err == nil {
		t.Fatal("encrypt should reject message larger than 1MB")
	}
	if !strings.Contains(err.Error(), "too large") {
		t.Errorf("error = %q, want it to mention size limit", err.Error())
	}
}

func TestEncryptRejectsMissingTo(t *testing.T) {
	resetEncryptFlags()

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"encrypt", "--message", "hello"})

	err := rootCmd.Execute()
	if err == nil {
		t.Fatal("encrypt should return error when --to is missing")
	}
}

func TestEncryptNonDeterministic(t *testing.T) {
	requireEncryptCommand(t)

	outputs := make([]string, 2)
	for i := range outputs {
		resetEncryptFlags()
		setupEncryptWithMock(t)

		buf := new(bytes.Buffer)
		rootCmd.SetOut(buf)
		rootCmd.SetErr(new(bytes.Buffer))
		rootCmd.SetArgs([]string{"encrypt", "--to", "test-org/test-bot", "--message", "same message"})

		if err := rootCmd.Execute(); err != nil {
			t.Fatalf("encrypt run %d returned error: %v", i+1, err)
		}
		outputs[i] = buf.String()
	}

	if outputs[0] == outputs[1] {
		t.Error("encrypt should produce different output for same input (non-deterministic)")
	}
}

func TestEncryptRejectsTerminalStdinWithoutMessage(t *testing.T) {
	resetEncryptFlags()
	setupEncryptWithMock(t)

	oldStdin := stdinIsTerminal
	stdinIsTerminal = func() bool { return true }
	defer func() { stdinIsTerminal = oldStdin }()

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"encrypt", "--to", "test-org/test-bot"})

	err := rootCmd.Execute()
	if err == nil {
		t.Fatal("encrypt should reject when stdin is terminal and --message is absent")
	}
}

func TestEncryptAcceptsExactly1MB(t *testing.T) {
	resetEncryptFlags()
	setupEncryptWithMock(t)

	exactMsg := strings.Repeat("x", 1<<20)

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(new(bytes.Buffer))
	rootCmd.SetArgs([]string{"encrypt", "--to", "test-org/test-bot", "--message", exactMsg})

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("encrypt should accept exactly 1MB message: %v", err)
	}

	var envelope map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &envelope); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
}

func TestEncryptMessageFlagPriority(t *testing.T) {
	resetEncryptFlags()
	setupEncryptWithMock(t)

	oldStdin := stdinIsTerminal
	stdinIsTerminal = func() bool { return false }
	defer func() { stdinIsTerminal = oldStdin }()

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(new(bytes.Buffer))
	rootCmd.SetIn(strings.NewReader("stdin content"))
	rootCmd.SetArgs([]string{"encrypt", "--to", "test-org/test-bot", "--message", "flag content"})

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("encrypt returned error: %v", err)
	}

	var envelope map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &envelope); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
}

func TestEncryptRejectsWhitespaceOnlyMessage(t *testing.T) {
	resetEncryptFlags()
	setupEncryptWithMock(t)

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"encrypt", "--to", "test-org/test-bot", "--message", "   \n\t  "})

	err := rootCmd.Execute()
	if err == nil {
		t.Fatal("encrypt should reject whitespace-only message")
	}
}

func TestEncryptRejectsOversizedStdinInput(t *testing.T) {
	resetEncryptFlags()
	setupEncryptWithMock(t)

	oldStdin := stdinIsTerminal
	stdinIsTerminal = func() bool { return false }
	defer func() { stdinIsTerminal = oldStdin }()

	largeInput := strings.Repeat("x", 1<<20+1)

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetIn(strings.NewReader(largeInput))
	rootCmd.SetArgs([]string{"encrypt", "--to", "test-org/test-bot"})

	err := rootCmd.Execute()
	if err == nil {
		t.Fatal("encrypt should reject stdin input larger than 1MB")
	}
}

func TestEncryptRejectsPositionalArgs(t *testing.T) {
	resetEncryptFlags()

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"encrypt", "--to", "test-org/test-bot", "--message", "hello", "extra-arg"})

	err := rootCmd.Execute()
	if err == nil {
		t.Fatal("encrypt should reject unexpected positional arguments")
	}
}

func TestEncryptRecipientNotFound(t *testing.T) {
	resetEncryptFlags()

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
	rootCmd.SetArgs([]string{"encrypt", "--to", "no-org/no-bot", "--message", "hello"})

	err := rootCmd.Execute()
	if err == nil {
		t.Fatal("encrypt should return error for unknown recipient")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("error = %q, want it to mention not found", err.Error())
	}
}

func TestEncryptDecryptCLIRoundtrip(t *testing.T) {
	requireEncryptCommand(t)
	requireDecryptCommand(t)

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating Ed25519 keypair: %v", err)
	}
	pubB64 := base64.RawURLEncoding.EncodeToString([]byte(pub))
	seed := priv.Seed()

	server := mockBotProfileServer(t, pubB64)
	oldBaseURL := apiBaseURL
	apiBaseURL = server.URL
	defer func() { apiBaseURL = oldBaseURL }()

	originalMessage := "roundtrip through encrypt→decrypt CLI"

	// Step 1: encrypt
	resetEncryptFlags()
	encBuf := new(bytes.Buffer)
	rootCmd.SetOut(encBuf)
	rootCmd.SetErr(new(bytes.Buffer))
	rootCmd.SetArgs([]string{"encrypt", "--to", "test-org/test-bot", "--message", originalMessage})

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("encrypt returned error: %v", err)
	}

	envelope := strings.TrimSpace(encBuf.String())

	// Step 2: decrypt
	dir := t.TempDir()
	homePath := filepath.Join(dir, ".rtbtr")
	if err := os.MkdirAll(homePath, 0o755); err != nil {
		t.Fatalf("creating home: %v", err)
	}
	if err := os.WriteFile(filepath.Join(homePath, "private_key"), []byte(base64.RawURLEncoding.EncodeToString(seed)), 0o600); err != nil {
		t.Fatalf("writing private_key: %v", err)
	}

	resetDecryptFlags()
	decBuf := new(bytes.Buffer)
	rootCmd.SetOut(decBuf)
	rootCmd.SetErr(new(bytes.Buffer))
	rootCmd.SetArgs([]string{"decrypt", "--payload", envelope, "--home", homePath})

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("decrypt returned error: %v", err)
	}

	got := decBuf.Bytes()
	want := []byte(originalMessage)
	if !bytes.Equal(got, want) {
		t.Errorf("roundtrip failed: decrypted = %q, want %q", got, want)
	}
}

func TestEncryptDecryptStdinRoundtrip(t *testing.T) {
	requireEncryptCommand(t)
	requireDecryptCommand(t)

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating Ed25519 keypair: %v", err)
	}
	pubB64 := base64.RawURLEncoding.EncodeToString([]byte(pub))
	seed := priv.Seed()

	server := mockBotProfileServer(t, pubB64)
	oldBaseURL := apiBaseURL
	apiBaseURL = server.URL
	defer func() { apiBaseURL = oldBaseURL }()

	originalMessage := "piped roundtrip message"

	oldStdin := stdinIsTerminal
	stdinIsTerminal = func() bool { return false }
	defer func() { stdinIsTerminal = oldStdin }()

	// Step 1: encrypt from stdin
	resetEncryptFlags()
	encBuf := new(bytes.Buffer)
	rootCmd.SetOut(encBuf)
	rootCmd.SetErr(new(bytes.Buffer))
	rootCmd.SetIn(strings.NewReader(originalMessage))
	rootCmd.SetArgs([]string{"encrypt", "--to", "test-org/test-bot"})

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("encrypt from stdin returned error: %v", err)
	}

	envelope := strings.TrimSpace(encBuf.String())

	// Step 2: decrypt from stdin
	dir := t.TempDir()
	homePath := filepath.Join(dir, ".rtbtr")
	if err := os.MkdirAll(homePath, 0o755); err != nil {
		t.Fatalf("creating home: %v", err)
	}
	if err := os.WriteFile(filepath.Join(homePath, "private_key"), []byte(base64.RawURLEncoding.EncodeToString(seed)), 0o600); err != nil {
		t.Fatalf("writing private_key: %v", err)
	}

	resetDecryptFlags()
	decBuf := new(bytes.Buffer)
	rootCmd.SetOut(decBuf)
	rootCmd.SetErr(new(bytes.Buffer))
	rootCmd.SetIn(strings.NewReader(envelope))
	rootCmd.SetArgs([]string{"decrypt", "--home", homePath})

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("decrypt from stdin returned error: %v", err)
	}

	got := decBuf.Bytes()
	want := []byte(originalMessage)
	if !bytes.Equal(got, want) {
		t.Errorf("stdin roundtrip failed: decrypted = %q, want %q", got, want)
	}
}
