package cmd

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	rtbtrcrypto "github.com/rtbtr/rtbtr-cli/internal/crypto"
)

// resetDecryptFlags resets all flag state between decrypt tests.
func resetDecryptFlags() {
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

	for _, name := range []string{"payload", "help"} {
		if flag := decryptCmd.Flags().Lookup(name); flag != nil {
			if err := flag.Value.Set(flag.DefValue); err != nil {
				panic(err)
			}
			flag.Changed = false
		}
	}
}

// buildEncryptEnvelope encrypts plaintext for the given Ed25519 seed and
// returns a JSON envelope string matching the encrypt command output format.
func buildEncryptEnvelope(t *testing.T, plaintext []byte, recipientSeed []byte) string {
	t.Helper()

	_, x25519Pub, err := rtbtrcrypto.DeriveX25519KeyPair(recipientSeed)
	if err != nil {
		t.Fatalf("DeriveX25519KeyPair: %v", err)
	}

	ciphertext, ephPub, err := rtbtrcrypto.Encrypt(plaintext, x25519Pub)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	envelope := map[string]string{
		"ciphertext":           base64.StdEncoding.EncodeToString(ciphertext),
		"ephemeral_public_key": base64.RawURLEncoding.EncodeToString(ephPub),
		"algorithm":            "x25519-aes256gcm",
	}

	data, err := json.Marshal(envelope)
	if err != nil {
		t.Fatalf("marshaling envelope: %v", err)
	}
	return string(data)
}

// T-DEC01: decrypt is registered as a root subcommand and --help succeeds.
func TestDecryptCommandHelp(t *testing.T) {
	resetDecryptFlags()

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetArgs([]string{"decrypt", "--help"})

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("decrypt --help returned error: %v", err)
	}

	output := buf.String()
	if len(output) == 0 {
		t.Fatal("decrypt --help produced no output")
	}
	if !strings.Contains(output, "decrypt") {
		t.Errorf("help output does not contain 'decrypt': %s", output)
	}
}

// T-DEC02: decrypt roundtrip — encrypting then decrypting recovers the original plaintext.
func TestDecryptRoundtrip(t *testing.T) {
	resetDecryptFlags()

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	seed := priv.Seed()

	originalText := "hello, encrypted world!"
	envelope := buildEncryptEnvelope(t, []byte(originalText), seed)

	dir := t.TempDir()
	encodedSeed := base64.RawURLEncoding.EncodeToString(seed)
	homePath := setupRtbtrDir(t, dir, map[string]string{
		"config.yaml": "org: testorg\nbot: testbot\n",
		"private_key": encodedSeed,
	})

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(new(bytes.Buffer))
	rootCmd.SetArgs([]string{"decrypt", "--payload", envelope, "--home", homePath})

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("decrypt returned error: %v", err)
	}

	output := strings.TrimSpace(buf.String())
	if output != originalText {
		t.Errorf("decrypted output = %q, want %q", output, originalText)
	}
}

// T-DEC02: decrypt roundtrip with binary-like content.
func TestDecryptRoundtripBinaryContent(t *testing.T) {
	resetDecryptFlags()

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	seed := priv.Seed()

	// Content with special characters, unicode, and edge cases.
	originalText := "Hello 🌍!\x00\x01\x02 tabs\there"
	envelope := buildEncryptEnvelope(t, []byte(originalText), seed)

	dir := t.TempDir()
	encodedSeed := base64.RawURLEncoding.EncodeToString(seed)
	homePath := setupRtbtrDir(t, dir, map[string]string{
		"config.yaml": "org: testorg\nbot: testbot\n",
		"private_key": encodedSeed,
	})

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(new(bytes.Buffer))
	rootCmd.SetArgs([]string{"decrypt", "--payload", envelope, "--home", homePath})

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("decrypt returned error: %v", err)
	}

	// The output should contain the original text.
	output := buf.String()
	if !strings.Contains(output, "Hello 🌍!") {
		t.Errorf("decrypted output = %q, want it to contain original content", output)
	}
}

// T-DEC03: decrypt reads payload from stdin when --payload is absent.
func TestDecryptFromStdin(t *testing.T) {
	resetDecryptFlags()

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	seed := priv.Seed()

	originalText := "stdin decryption test"
	envelope := buildEncryptEnvelope(t, []byte(originalText), seed)

	dir := t.TempDir()
	encodedSeed := base64.RawURLEncoding.EncodeToString(seed)
	homePath := setupRtbtrDir(t, dir, map[string]string{
		"config.yaml": "org: testorg\nbot: testbot\n",
		"private_key": encodedSeed,
	})

	oldStdin := stdinIsTerminal
	stdinIsTerminal = func() bool { return false }
	defer func() { stdinIsTerminal = oldStdin }()

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(new(bytes.Buffer))
	rootCmd.SetIn(strings.NewReader(envelope))
	rootCmd.SetArgs([]string{"decrypt", "--home", homePath})

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("decrypt from stdin returned error: %v", err)
	}

	output := strings.TrimSpace(buf.String())
	if output != originalText {
		t.Errorf("decrypted output = %q, want %q", output, originalText)
	}
}

// T-DEC04: decrypt rejects invalid (malformed) JSON payload.
func TestDecryptRejectsInvalidPayload(t *testing.T) {
	resetDecryptFlags()

	dir := t.TempDir()
	homePath := setupInboxIdentity(t, dir, "testorg", "testbot")

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"decrypt", "--payload", "not-valid-json{{{", "--home", homePath})

	err := rootCmd.Execute()
	if err == nil {
		t.Fatal("decrypt should reject invalid JSON payload")
	}
}

// T-DEC04: decrypt rejects JSON with missing ciphertext field.
func TestDecryptRejectsMissingCiphertextField(t *testing.T) {
	resetDecryptFlags()

	dir := t.TempDir()
	homePath := setupInboxIdentity(t, dir, "testorg", "testbot")

	// Valid JSON but missing ciphertext.
	payload := `{"ephemeral_public_key":"AAAA","algorithm":"x25519-aes256gcm"}`

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"decrypt", "--payload", payload, "--home", homePath})

	err := rootCmd.Execute()
	if err == nil {
		t.Fatal("decrypt should reject payload with missing ciphertext field")
	}
}

// T-DEC04: decrypt rejects JSON with missing ephemeral_public_key field.
func TestDecryptRejectsMissingEphemeralKey(t *testing.T) {
	resetDecryptFlags()

	dir := t.TempDir()
	homePath := setupInboxIdentity(t, dir, "testorg", "testbot")

	// Valid JSON but missing ephemeral_public_key.
	payload := `{"ciphertext":"AAAA","algorithm":"x25519-aes256gcm"}`

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"decrypt", "--payload", payload, "--home", homePath})

	err := rootCmd.Execute()
	if err == nil {
		t.Fatal("decrypt should reject payload with missing ephemeral_public_key field")
	}
}

// T-DEC05: decrypt requires private key — errors when private_key file is absent.
func TestDecryptRequiresPrivateKey(t *testing.T) {
	resetDecryptFlags()

	dir := t.TempDir()
	homePath := setupRtbtrDir(t, dir, map[string]string{
		"config.yaml": "org: testorg\nbot: testbot\n",
	})

	// Build a valid envelope (we won't be able to decrypt, but want to
	// verify the error is about the missing private key, not the payload).
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	envelope := buildEncryptEnvelope(t, []byte("test"), priv.Seed())

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"decrypt", "--payload", envelope, "--home", homePath})

	err = rootCmd.Execute()
	if err == nil {
		t.Fatal("decrypt should return error when private_key is missing")
	}
	if !strings.Contains(err.Error(), "private key") {
		t.Errorf("error = %q, want it to mention 'private key'", err.Error())
	}
}

// T-DEC06: decrypt with wrong private key returns an error (cannot decrypt).
func TestDecryptWrongKey(t *testing.T) {
	resetDecryptFlags()

	// Generate two keypairs — encrypt for key A, try to decrypt with key B.
	_, privA, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating key A: %v", err)
	}
	_, privB, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating key B: %v", err)
	}

	// Encrypt using key A's seed.
	envelope := buildEncryptEnvelope(t, []byte("secret message"), privA.Seed())

	// Set up home with key B's seed.
	dir := t.TempDir()
	encodedSeedB := base64.RawURLEncoding.EncodeToString(privB.Seed())
	homePath := setupRtbtrDir(t, dir, map[string]string{
		"config.yaml": "org: testorg\nbot: testbot\n",
		"private_key": encodedSeedB,
	})

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"decrypt", "--payload", envelope, "--home", homePath})

	err = rootCmd.Execute()
	if err == nil {
		t.Fatal("decrypt should fail when using wrong private key")
	}
}

// T-DEC07: decrypt rejects when .rtbtr directory is missing.
func TestDecryptRejectsMissingRtbtrDir(t *testing.T) {
	resetDecryptFlags()

	dir := t.TempDir()
	t.Chdir(dir)

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	envelope := buildEncryptEnvelope(t, []byte("test"), priv.Seed())

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"decrypt", "--payload", envelope})

	err = rootCmd.Execute()
	if err == nil {
		t.Fatal("decrypt should return error when .rtbtr directory is missing")
	}
	if !strings.Contains(err.Error(), ".rtbtr") {
		t.Errorf("error = %q, want it to mention .rtbtr", err.Error())
	}
}

// T-DEC08: decrypt output is clean for piping — raw plaintext on stdout.
func TestDecryptOutputIsCleanForPiping(t *testing.T) {
	resetDecryptFlags()

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	seed := priv.Seed()

	originalText := "clean output for piping"
	envelope := buildEncryptEnvelope(t, []byte(originalText), seed)

	dir := t.TempDir()
	encodedSeed := base64.RawURLEncoding.EncodeToString(seed)
	homePath := setupRtbtrDir(t, dir, map[string]string{
		"config.yaml": "org: testorg\nbot: testbot\n",
		"private_key": encodedSeed,
	})

	stdout := new(bytes.Buffer)
	stderr := new(bytes.Buffer)
	rootCmd.SetOut(stdout)
	rootCmd.SetErr(stderr)
	rootCmd.SetArgs([]string{"decrypt", "--payload", envelope, "--home", homePath})

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("decrypt returned error: %v", err)
	}

	output := stdout.String()
	// Output should be raw plaintext, not JSON, not prefixed with metadata.
	if strings.Contains(output, "{") || strings.Contains(output, "From:") {
		t.Errorf("stdout should be raw plaintext, got: %q", output)
	}
	if !strings.Contains(output, originalText) {
		t.Errorf("stdout = %q, want it to contain %q", output, originalText)
	}

	// Stderr should be empty on success.
	if stderr.Len() > 0 {
		t.Errorf("stderr should be empty on success, got: %q", stderr.String())
	}
}

// T-DEC09: decrypt roundtrip with large payload (near 1MB boundary).
func TestDecryptRoundtripLargePayload(t *testing.T) {
	resetDecryptFlags()

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	seed := priv.Seed()

	// Use a payload close to 1MB.
	originalText := strings.Repeat("A", 1<<20-1)
	envelope := buildEncryptEnvelope(t, []byte(originalText), seed)

	dir := t.TempDir()
	encodedSeed := base64.RawURLEncoding.EncodeToString(seed)
	homePath := setupRtbtrDir(t, dir, map[string]string{
		"config.yaml": "org: testorg\nbot: testbot\n",
		"private_key": encodedSeed,
	})

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(new(bytes.Buffer))
	rootCmd.SetArgs([]string{"decrypt", "--payload", envelope, "--home", homePath})

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("decrypt returned error for large payload: %v", err)
	}

	output := strings.TrimSpace(buf.String())
	if len(output) != len(originalText) {
		t.Errorf("decrypted output length = %d, want %d", len(output), len(originalText))
	}
}

// T-DEC10: decrypt rejects payload with tampered ciphertext.
func TestDecryptRejectsTamperedCiphertext(t *testing.T) {
	resetDecryptFlags()

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	seed := priv.Seed()

	_, x25519Pub, err := rtbtrcrypto.DeriveX25519KeyPair(seed)
	if err != nil {
		t.Fatalf("DeriveX25519KeyPair: %v", err)
	}

	ciphertext, ephPub, err := rtbtrcrypto.Encrypt([]byte("secret"), x25519Pub)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	// Tamper with ciphertext — flip a byte in the middle.
	tampered := make([]byte, len(ciphertext))
	copy(tampered, ciphertext)
	tampered[len(tampered)/2] ^= 0xFF

	envelope := map[string]string{
		"ciphertext":           base64.StdEncoding.EncodeToString(tampered),
		"ephemeral_public_key": base64.RawURLEncoding.EncodeToString(ephPub),
		"algorithm":            "x25519-aes256gcm",
	}
	data, _ := json.Marshal(envelope)

	dir := t.TempDir()
	encodedSeed := base64.RawURLEncoding.EncodeToString(seed)
	homePath := setupRtbtrDir(t, dir, map[string]string{
		"config.yaml": "org: testorg\nbot: testbot\n",
		"private_key": encodedSeed,
	})

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"decrypt", "--payload", string(data), "--home", homePath})

	err = rootCmd.Execute()
	if err == nil {
		t.Fatal("decrypt should fail with tampered ciphertext")
	}
}

// T-DEC11: decrypt rejects empty payload string.
func TestDecryptRejectsEmptyPayload(t *testing.T) {
	resetDecryptFlags()

	dir := t.TempDir()
	homePath := setupInboxIdentity(t, dir, "testorg", "testbot")

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"decrypt", "--payload", "", "--home", homePath})

	err := rootCmd.Execute()
	if err == nil {
		t.Fatal("decrypt should reject empty payload")
	}
}

// T-DEC12: decrypt does not accept positional arguments.
func TestDecryptRejectsPositionalArgs(t *testing.T) {
	resetDecryptFlags()

	dir := t.TempDir()
	homePath := setupInboxIdentity(t, dir, "testorg", "testbot")

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"decrypt", "--home", homePath, "extra-arg"})

	err := rootCmd.Execute()
	if err == nil {
		t.Fatal("decrypt should reject unexpected positional arguments")
	}
}

// T-DEC13: decrypt roundtrip with empty-string plaintext (after encryption).
func TestDecryptRoundtripEmptyPlaintext(t *testing.T) {
	resetDecryptFlags()

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	seed := priv.Seed()

	// Encrypt a single space (not empty to avoid empty-message rejection,
	// but minimal content).
	originalText := " "
	envelope := buildEncryptEnvelope(t, []byte(originalText), seed)

	dir := t.TempDir()
	encodedSeed := base64.RawURLEncoding.EncodeToString(seed)
	homePath := setupRtbtrDir(t, dir, map[string]string{
		"config.yaml": "org: testorg\nbot: testbot\n",
		"private_key": encodedSeed,
	})

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(new(bytes.Buffer))
	rootCmd.SetArgs([]string{"decrypt", "--payload", envelope, "--home", homePath})

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("decrypt returned error: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, originalText) {
		t.Errorf("decrypted output = %q, want it to contain %q", output, originalText)
	}
}
