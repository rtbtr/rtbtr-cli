package cmd

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func resetSignFlags() {
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

	if flag := signCmd.Flags().Lookup("help"); flag != nil {
		if err := flag.Value.Set(flag.DefValue); err != nil {
			panic(err)
		}
		flag.Changed = false
	}
}

// setupSignHome creates a .rtbtr directory with a valid Ed25519 keypair
// and returns the home path, public key bytes, and seed bytes.
func setupSignHome(t *testing.T) (string, ed25519.PublicKey, []byte) {
	t.Helper()

	dir := t.TempDir()
	homePath := filepath.Join(dir, ".rtbtr")
	if err := os.MkdirAll(homePath, 0o755); err != nil {
		t.Fatalf("creating home directory: %v", err)
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating keypair: %v", err)
	}

	seed := priv.Seed()
	if err := os.WriteFile(filepath.Join(homePath, "private_key"), []byte(base64.RawURLEncoding.EncodeToString(seed)), 0o600); err != nil {
		t.Fatalf("writing private_key: %v", err)
	}
	if err := os.WriteFile(filepath.Join(homePath, "public_key"), []byte(base64.RawURLEncoding.EncodeToString(pub)), 0o600); err != nil {
		t.Fatalf("writing public_key: %v", err)
	}

	return homePath, pub, seed
}

func TestSignProducesValidSignature(t *testing.T) {
	resetSignFlags()

	homePath, pub, _ := setupSignHome(t)
	message := []byte("deploy v2.3.0\n")

	stdin := bytes.NewReader(message)
	stdout := new(bytes.Buffer)
	rootCmd.SetIn(stdin)
	rootCmd.SetOut(stdout)
	rootCmd.SetArgs([]string{"sign", "--home", homePath})

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("sign returned error: %v", err)
	}

	sigB64 := stdout.String()
	sigBytes, err := base64.RawURLEncoding.DecodeString(sigB64)
	if err != nil {
		t.Fatalf("decoding signature: %v", err)
	}
	if len(sigBytes) != ed25519.SignatureSize {
		t.Errorf("signature is %d bytes, want %d", len(sigBytes), ed25519.SignatureSize)
	}

	if !ed25519.Verify(pub, message, sigBytes) {
		t.Errorf("signature verification failed with the corresponding public key")
	}
}

func TestSignRequiresPrivateKey(t *testing.T) {
	resetSignFlags()

	dir := t.TempDir()
	homePath := filepath.Join(dir, ".rtbtr")
	if err := os.MkdirAll(homePath, 0o755); err != nil {
		t.Fatalf("creating home directory: %v", err)
	}
	// No private_key file

	stdin := bytes.NewReader([]byte("some data"))
	stdout := new(bytes.Buffer)
	rootCmd.SetIn(stdin)
	rootCmd.SetOut(stdout)
	rootCmd.SetArgs([]string{"sign", "--home", homePath})

	err := rootCmd.Execute()
	if err == nil {
		t.Fatal("sign should return error when private key not found")
	}
	if !strings.Contains(err.Error(), "private key not found") {
		t.Errorf("error = %q, want it to mention 'private key not found'", err.Error())
	}
}

func TestSignRejectsEmptyStdin(t *testing.T) {
	resetSignFlags()

	homePath, _, _ := setupSignHome(t)

	stdin := bytes.NewReader([]byte{})
	stdout := new(bytes.Buffer)
	rootCmd.SetIn(stdin)
	rootCmd.SetOut(stdout)
	rootCmd.SetArgs([]string{"sign", "--home", homePath})

	err := rootCmd.Execute()
	if err == nil {
		t.Fatal("sign should return error on empty stdin")
	}
	if !strings.Contains(err.Error(), "empty input") {
		t.Errorf("error = %q, want it to mention 'empty input'", err.Error())
	}
}

func TestSignRejectsOversizedInput(t *testing.T) {
	resetSignFlags()

	homePath, _, _ := setupSignHome(t)

	oversized := make([]byte, maxSignInputBytes+1)
	for i := range oversized {
		oversized[i] = 'x'
	}

	stdin := bytes.NewReader(oversized)
	stdout := new(bytes.Buffer)
	rootCmd.SetIn(stdin)
	rootCmd.SetOut(stdout)
	rootCmd.SetArgs([]string{"sign", "--home", homePath})

	err := rootCmd.Execute()
	if err == nil {
		t.Fatal("sign should return error on oversized input")
	}
	if !strings.Contains(err.Error(), "too large") {
		t.Errorf("error = %q, want it to mention 'too large'", err.Error())
	}
}

func TestSignOutputIsURLSafeBase64(t *testing.T) {
	resetSignFlags()

	homePath, _, _ := setupSignHome(t)

	stdin := bytes.NewReader([]byte("test payload"))
	stdout := new(bytes.Buffer)
	rootCmd.SetIn(stdin)
	rootCmd.SetOut(stdout)
	rootCmd.SetArgs([]string{"sign", "--home", homePath})

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("sign returned error: %v", err)
	}

	output := stdout.String()
	if strings.ContainsAny(output, "+/=") {
		t.Errorf("output contains standard base64 characters: %q", output)
	}
	if strings.ContainsAny(output, "\n\r \t") {
		t.Errorf("output contains whitespace: %q", output)
	}
}
