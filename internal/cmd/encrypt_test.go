package cmd

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

// resetEncryptFlags resets all flag state between encrypt tests.
// Uses command lookup so tests compile regardless of whether the
// implementation file exists.
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

// requireEncryptCommand fails the test immediately if the encrypt
// subcommand is not registered, ensuring all tests are red until
// the implementation wires the command.
func requireEncryptCommand(t *testing.T) {
	t.Helper()
	cmd, _, err := rootCmd.Find([]string{"encrypt"})
	if err != nil || cmd.Name() != "encrypt" {
		t.Fatal("encrypt command is not registered as a subcommand of rtbtr")
	}
}

// generateTestEd25519PublicKey creates a random Ed25519 keypair and returns
// the public key as URL-safe base64 (no padding).
func generateTestEd25519PublicKey(t *testing.T) string {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating Ed25519 keypair: %v", err)
	}
	return base64.RawURLEncoding.EncodeToString([]byte(pub))
}

// T-ENC01: encrypt is registered as a root subcommand and --help succeeds.
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
	if !strings.Contains(output, "encrypt") {
		t.Errorf("help output does not contain 'encrypt': %s", output)
	}
}

// T-ENC02: encrypt produces a valid JSON envelope with ciphertext,
// ephemeral_public_key, and algorithm fields.
func TestEncryptProducesValidEnvelope(t *testing.T) {
	resetEncryptFlags()
	requireEncryptCommand(t)

	pubB64 := generateTestEd25519PublicKey(t)

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(new(bytes.Buffer))
	rootCmd.SetArgs([]string{"encrypt", "--to", pubB64, "--message", "hello world"})

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("encrypt returned error: %v", err)
	}

	output := buf.String()

	// Parse as JSON.
	var envelope map[string]interface{}
	if err := json.Unmarshal([]byte(output), &envelope); err != nil {
		t.Fatalf("output is not valid JSON: %v\noutput: %q", err, output)
	}

	// Verify ciphertext field exists and is valid base64.
	ct, ok := envelope["ciphertext"].(string)
	if !ok || ct == "" {
		t.Fatal("envelope missing or empty ciphertext field")
	}
	if _, err := base64.StdEncoding.DecodeString(ct); err != nil {
		// Try URL-safe base64 as well.
		if _, err2 := base64.RawURLEncoding.DecodeString(ct); err2 != nil {
			t.Errorf("ciphertext is not valid base64: std=%v, url=%v", err, err2)
		}
	}

	// Verify ephemeral_public_key field exists and decodes to 32 bytes.
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

	// Verify algorithm field.
	algo, ok := envelope["algorithm"].(string)
	if !ok || algo == "" {
		t.Fatal("envelope missing or empty algorithm field")
	}
	if algo != "x25519-aes256gcm" {
		t.Errorf("algorithm = %q, want %q", algo, "x25519-aes256gcm")
	}
}

// T-ENC03: encrypt reads plaintext from stdin when --message is absent.
func TestEncryptFromStdin(t *testing.T) {
	resetEncryptFlags()
	requireEncryptCommand(t)

	pubB64 := generateTestEd25519PublicKey(t)

	oldStdin := stdinIsTerminal
	stdinIsTerminal = func() bool { return false }
	defer func() { stdinIsTerminal = oldStdin }()

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(new(bytes.Buffer))
	rootCmd.SetIn(strings.NewReader("stdin message"))
	rootCmd.SetArgs([]string{"encrypt", "--to", pubB64})

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("encrypt from stdin returned error: %v", err)
	}

	output := buf.String()

	// Should produce valid JSON envelope.
	var envelope map[string]interface{}
	if err := json.Unmarshal([]byte(output), &envelope); err != nil {
		t.Fatalf("output is not valid JSON: %v\noutput: %q", err, output)
	}

	if _, ok := envelope["ciphertext"].(string); !ok {
		t.Fatal("envelope missing ciphertext field")
	}
}

// T-ENC04: encrypt rejects empty message content.
func TestEncryptRejectsEmptyMessage(t *testing.T) {
	resetEncryptFlags()
	requireEncryptCommand(t)

	pubB64 := generateTestEd25519PublicKey(t)

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"encrypt", "--to", pubB64, "--message", ""})

	err := rootCmd.Execute()
	if err == nil {
		t.Fatal("encrypt should reject empty message")
	}
}

// T-ENC05: encrypt rejects invalid (malformed) Ed25519 public key.
func TestEncryptRejectsInvalidKey(t *testing.T) {
	resetEncryptFlags()
	requireEncryptCommand(t)

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"encrypt", "--to", "not-a-valid-key!!!", "--message", "hello"})

	err := rootCmd.Execute()
	if err == nil {
		t.Fatal("encrypt should reject invalid public key")
	}
}

// T-ENC05: encrypt rejects a key of wrong length (valid base64 but not 32 bytes).
func TestEncryptRejectsWrongLengthKey(t *testing.T) {
	resetEncryptFlags()
	requireEncryptCommand(t)

	// 16 bytes encoded as URL-safe base64 (should be 32 bytes for Ed25519).
	shortKey := base64.RawURLEncoding.EncodeToString(make([]byte, 16))

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"encrypt", "--to", shortKey, "--message", "hello"})

	err := rootCmd.Execute()
	if err == nil {
		t.Fatal("encrypt should reject key of wrong length")
	}
}

// T-ENC06: encrypt rejects input larger than 1MB.
func TestEncryptRejectsOversizedInput(t *testing.T) {
	resetEncryptFlags()
	requireEncryptCommand(t)

	pubB64 := generateTestEd25519PublicKey(t)

	// 1MB + 1 byte.
	largeMsg := strings.Repeat("x", 1<<20+1)

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"encrypt", "--to", pubB64, "--message", largeMsg})

	err := rootCmd.Execute()
	if err == nil {
		t.Fatal("encrypt should reject message larger than 1MB")
	}
	if !strings.Contains(err.Error(), "too large") && !strings.Contains(err.Error(), "1MB") {
		t.Errorf("error = %q, want it to mention size limit", err.Error())
	}
}

// T-ENC07: encrypt rejects missing --to flag.
func TestEncryptRejectsMissingTo(t *testing.T) {
	resetEncryptFlags()
	requireEncryptCommand(t)

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"encrypt", "--message", "hello"})

	err := rootCmd.Execute()
	if err == nil {
		t.Fatal("encrypt should return error when --to is missing")
	}
}

// T-ENC08: encrypt works without --home (fully offline, no private key needed).
func TestEncryptDoesNotRequireHome(t *testing.T) {
	resetEncryptFlags()
	requireEncryptCommand(t)

	pubB64 := generateTestEd25519PublicKey(t)

	// Change to a directory with no .rtbtr to prove encrypt doesn't need it.
	dir := t.TempDir()
	t.Chdir(dir)

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(new(bytes.Buffer))
	rootCmd.SetArgs([]string{"encrypt", "--to", pubB64, "--message", "offline encryption"})

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("encrypt should work without .rtbtr home directory: %v", err)
	}

	// Verify output is valid JSON.
	var envelope map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &envelope); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
}

// T-ENC09: encrypt is non-deterministic — same input produces different ciphertext.
func TestEncryptNonDeterministic(t *testing.T) {
	requireEncryptCommand(t)

	pubB64 := generateTestEd25519PublicKey(t)
	message := "same message"

	outputs := make([]string, 2)
	for i := range outputs {
		resetEncryptFlags()

		buf := new(bytes.Buffer)
		rootCmd.SetOut(buf)
		rootCmd.SetErr(new(bytes.Buffer))
		rootCmd.SetArgs([]string{"encrypt", "--to", pubB64, "--message", message})

		if err := rootCmd.Execute(); err != nil {
			t.Fatalf("encrypt run %d returned error: %v", i+1, err)
		}
		outputs[i] = buf.String()
	}

	if outputs[0] == outputs[1] {
		t.Error("encrypt should produce different output for same input (non-deterministic)")
	}
}

// T-ENC10: encrypt rejects terminal stdin without --message.
func TestEncryptRejectsTerminalStdinWithoutMessage(t *testing.T) {
	resetEncryptFlags()
	requireEncryptCommand(t)

	pubB64 := generateTestEd25519PublicKey(t)

	oldStdin := stdinIsTerminal
	stdinIsTerminal = func() bool { return true }
	defer func() { stdinIsTerminal = oldStdin }()

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"encrypt", "--to", pubB64})

	err := rootCmd.Execute()
	if err == nil {
		t.Fatal("encrypt should reject when stdin is terminal and --message is absent")
	}
}

// T-ENC11: encrypt at exactly 1MB boundary succeeds.
func TestEncryptAcceptsExactly1MB(t *testing.T) {
	resetEncryptFlags()
	requireEncryptCommand(t)

	pubB64 := generateTestEd25519PublicKey(t)

	// Exactly 1MB message.
	exactMsg := strings.Repeat("x", 1<<20)

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(new(bytes.Buffer))
	rootCmd.SetArgs([]string{"encrypt", "--to", pubB64, "--message", exactMsg})

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("encrypt should accept exactly 1MB message: %v", err)
	}

	// Verify output is valid JSON.
	var envelope map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &envelope); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
}

// T-ENC12: encrypt with --message flag takes priority over stdin content.
func TestEncryptMessageFlagPriority(t *testing.T) {
	resetEncryptFlags()
	requireEncryptCommand(t)

	pubB64 := generateTestEd25519PublicKey(t)

	oldStdin := stdinIsTerminal
	stdinIsTerminal = func() bool { return false }
	defer func() { stdinIsTerminal = oldStdin }()

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(new(bytes.Buffer))
	rootCmd.SetIn(strings.NewReader("stdin content"))
	rootCmd.SetArgs([]string{"encrypt", "--to", pubB64, "--message", "flag content"})

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("encrypt returned error: %v", err)
	}

	// Should produce valid JSON output — we can't verify which plaintext
	// was used since it's encrypted, but the command should succeed.
	var envelope map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &envelope); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
}

// T-ENC13: encrypt handles whitespace-only message as empty and rejects it.
func TestEncryptRejectsWhitespaceOnlyMessage(t *testing.T) {
	resetEncryptFlags()
	requireEncryptCommand(t)

	pubB64 := generateTestEd25519PublicKey(t)

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"encrypt", "--to", pubB64, "--message", "   \n\t  "})

	err := rootCmd.Execute()
	if err == nil {
		t.Fatal("encrypt should reject whitespace-only message")
	}
}

// T-ENC14: encrypt stdin with oversized input (>1MB) is rejected.
func TestEncryptRejectsOversizedStdinInput(t *testing.T) {
	resetEncryptFlags()
	requireEncryptCommand(t)

	pubB64 := generateTestEd25519PublicKey(t)

	oldStdin := stdinIsTerminal
	stdinIsTerminal = func() bool { return false }
	defer func() { stdinIsTerminal = oldStdin }()

	largeInput := strings.Repeat("x", 1<<20+1)

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetIn(strings.NewReader(largeInput))
	rootCmd.SetArgs([]string{"encrypt", "--to", pubB64})

	err := rootCmd.Execute()
	if err == nil {
		t.Fatal("encrypt should reject stdin input larger than 1MB")
	}
}

// T-ENC15: encrypt does not accept positional arguments.
func TestEncryptRejectsPositionalArgs(t *testing.T) {
	resetEncryptFlags()
	requireEncryptCommand(t)

	pubB64 := generateTestEd25519PublicKey(t)

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"encrypt", "--to", pubB64, "--message", "hello", "extra-arg"})

	err := rootCmd.Execute()
	if err == nil {
		t.Fatal("encrypt should reject unexpected positional arguments")
	}
}

// T-ENC16: encrypt→decrypt CLI roundtrip — the JSON envelope produced by
// encrypt can be directly consumed by decrypt to recover the original message.
func TestEncryptDecryptCLIRoundtrip(t *testing.T) {
	requireEncryptCommand(t)
	requireDecryptCommand(t)

	// Generate a recipient Ed25519 keypair.
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating Ed25519 keypair: %v", err)
	}
	pubB64 := base64.RawURLEncoding.EncodeToString([]byte(pub))
	seed := priv.Seed()

	originalMessage := "roundtrip through encrypt→decrypt CLI"

	// Step 1: encrypt
	resetEncryptFlags()
	encBuf := new(bytes.Buffer)
	rootCmd.SetOut(encBuf)
	rootCmd.SetErr(new(bytes.Buffer))
	rootCmd.SetArgs([]string{"encrypt", "--to", pubB64, "--message", originalMessage})

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("encrypt returned error: %v", err)
	}

	envelope := strings.TrimSpace(encBuf.String())
	// Sanity: verify it's valid JSON.
	var parsed map[string]interface{}
	if err := json.Unmarshal([]byte(envelope), &parsed); err != nil {
		t.Fatalf("encrypt output is not valid JSON: %v", err)
	}

	// Step 2: decrypt using the matching private key.
	dir := t.TempDir()
	encodedSeed := base64.RawURLEncoding.EncodeToString(seed)
	homePath := setupRtbtrDir(t, dir, map[string]string{
		"config.yaml": "org: testorg\nbot: testbot\n",
		"private_key": encodedSeed,
	})

	resetDecryptFlags()
	decBuf := new(bytes.Buffer)
	rootCmd.SetOut(decBuf)
	rootCmd.SetErr(new(bytes.Buffer))
	rootCmd.SetArgs([]string{"decrypt", "--payload", envelope, "--home", homePath})

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("decrypt returned error: %v", err)
	}

	decrypted := strings.TrimSpace(decBuf.String())
	if decrypted != originalMessage {
		t.Errorf("roundtrip failed: decrypted = %q, want %q", decrypted, originalMessage)
	}
}

// T-ENC17: encrypt→decrypt roundtrip with stdin pipe — encrypt from stdin,
// decrypt from stdin, verifying the full pipe-friendly workflow.
func TestEncryptDecryptStdinRoundtrip(t *testing.T) {
	requireEncryptCommand(t)
	requireDecryptCommand(t)

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating Ed25519 keypair: %v", err)
	}
	pubB64 := base64.RawURLEncoding.EncodeToString([]byte(pub))
	seed := priv.Seed()

	originalMessage := "piped roundtrip message"

	// Step 1: encrypt from stdin.
	oldStdin := stdinIsTerminal
	stdinIsTerminal = func() bool { return false }
	defer func() { stdinIsTerminal = oldStdin }()

	resetEncryptFlags()
	encBuf := new(bytes.Buffer)
	rootCmd.SetOut(encBuf)
	rootCmd.SetErr(new(bytes.Buffer))
	rootCmd.SetIn(strings.NewReader(originalMessage))
	rootCmd.SetArgs([]string{"encrypt", "--to", pubB64})

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("encrypt from stdin returned error: %v", err)
	}

	envelope := strings.TrimSpace(encBuf.String())

	// Step 2: decrypt from stdin.
	dir := t.TempDir()
	encodedSeed := base64.RawURLEncoding.EncodeToString(seed)
	homePath := setupRtbtrDir(t, dir, map[string]string{
		"config.yaml": "org: testorg\nbot: testbot\n",
		"private_key": encodedSeed,
	})

	resetDecryptFlags()
	decBuf := new(bytes.Buffer)
	rootCmd.SetOut(decBuf)
	rootCmd.SetErr(new(bytes.Buffer))
	rootCmd.SetIn(strings.NewReader(envelope))
	rootCmd.SetArgs([]string{"decrypt", "--home", homePath})

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("decrypt from stdin returned error: %v", err)
	}

	decrypted := strings.TrimSpace(decBuf.String())
	if decrypted != originalMessage {
		t.Errorf("stdin roundtrip failed: decrypted = %q, want %q", decrypted, originalMessage)
	}
}
