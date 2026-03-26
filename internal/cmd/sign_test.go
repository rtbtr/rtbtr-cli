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
// and returns the home path and public key bytes.
func setupSignHome(t *testing.T) (string, ed25519.PublicKey) {
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

	return homePath, pub
}

func TestSignProducesValidSignature(t *testing.T) {
	resetSignFlags()

	homePath, pub := setupSignHome(t)
	message := []byte("deploy v2.3.0\n")

	stdin := bytes.NewReader(message)
	stdout := new(bytes.Buffer)
	rootCmd.SetIn(stdin)
	rootCmd.SetOut(stdout)
	rootCmd.SetArgs([]string{"sign", "--home", homePath})

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("sign returned error: %v", err)
	}

	sigB64 := strings.TrimSpace(stdout.String())
	sigBytes, err := base64.StdEncoding.DecodeString(sigB64)
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

	homePath, _ := setupSignHome(t)

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

	homePath, _ := setupSignHome(t)

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

func TestSignRejectsMalformedPrivateKey(t *testing.T) {
	// A private_key file that is valid base64 but decodes to the wrong
	// number of bytes (not ed25519.SeedSize == 32) must produce a
	// user-facing error, not a panic from ed25519.NewKeyFromSeed.
	tests := []struct {
		name    string
		seedLen int
	}{
		{"too_short_16_bytes", 16},
		{"too_long_64_bytes", 64},
		{"single_byte", 1},
		{"zero_bytes", 0},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			resetSignFlags()

			dir := t.TempDir()
			homePath := filepath.Join(dir, ".rtbtr")
			if err := os.MkdirAll(homePath, 0o755); err != nil {
				t.Fatalf("creating home directory: %v", err)
			}

			// Write a private_key file with valid base64 but wrong seed length.
			badSeed := make([]byte, tc.seedLen)
			for i := range badSeed {
				badSeed[i] = byte(i)
			}
			encoded := base64.RawURLEncoding.EncodeToString(badSeed)
			if err := os.WriteFile(filepath.Join(homePath, "private_key"), []byte(encoded), 0o600); err != nil {
				t.Fatalf("writing private_key: %v", err)
			}

			stdin := bytes.NewReader([]byte("payload to sign"))
			stdout := new(bytes.Buffer)
			rootCmd.SetIn(stdin)
			rootCmd.SetOut(stdout)
			rootCmd.SetArgs([]string{"sign", "--home", homePath})

			err := rootCmd.Execute()
			if err == nil {
				t.Fatalf("sign should return error for malformed private key (%d bytes seed), got nil", tc.seedLen)
			}
			// The error should mention the private key issue, not be a panic.
			errMsg := err.Error()
			if !strings.Contains(errMsg, "private key") && !strings.Contains(errMsg, "seed") && !strings.Contains(errMsg, "invalid") {
				t.Errorf("error = %q, want it to mention private key / seed / invalid", errMsg)
			}
		})
	}
}

func TestSignOutputIsStdBase64(t *testing.T) {
	resetSignFlags()

	homePath, _ := setupSignHome(t)

	stdin := bytes.NewReader([]byte("test payload"))
	stdout := new(bytes.Buffer)
	rootCmd.SetIn(stdin)
	rootCmd.SetOut(stdout)
	rootCmd.SetArgs([]string{"sign", "--home", homePath})

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("sign returned error: %v", err)
	}

	output := strings.TrimSuffix(stdout.String(), "\n")
	if _, err := base64.StdEncoding.DecodeString(output); err != nil {
		t.Errorf("output is not valid standard base64: %v; output = %q", err, output)
	}
	if strings.ContainsAny(output, "\n\r \t") {
		t.Errorf("output contains unexpected whitespace: %q", output)
	}
}
