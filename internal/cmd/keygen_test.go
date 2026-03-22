package cmd

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func resetKeygenFlags() {
	homeFlag = ""
	forceFlag = false

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

	if flag := keygenCmd.Flags().Lookup("force"); flag != nil {
		if err := flag.Value.Set(flag.DefValue); err != nil {
			panic(err)
		}
		flag.Changed = false
	}

	if flag := keygenCmd.Flags().Lookup("help"); flag != nil {
		if err := flag.Value.Set(flag.DefValue); err != nil {
			panic(err)
		}
		flag.Changed = false
	}
}

func TestKeygenCreatesKeypair(t *testing.T) {
	resetKeygenFlags()

	dir := t.TempDir()
	homePath := filepath.Join(dir, ".rtbtr")

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetArgs([]string{"keygen", "--home", homePath})

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("keygen returned error: %v", err)
	}

	privContent, err := os.ReadFile(filepath.Join(homePath, "private_key"))
	if err != nil {
		t.Fatalf("reading private_key: %v", err)
	}

	seed, err := base64.RawURLEncoding.DecodeString(string(privContent))
	if err != nil {
		t.Fatalf("decoding private_key: %v", err)
	}
	if len(seed) != 32 {
		t.Errorf("decoded private key is %d bytes, want 32", len(seed))
	}

	pubContent, err := os.ReadFile(filepath.Join(homePath, "public_key"))
	if err != nil {
		t.Fatalf("reading public_key: %v", err)
	}

	pubBytes, err := base64.RawURLEncoding.DecodeString(string(pubContent))
	if err != nil {
		t.Fatalf("decoding public_key: %v", err)
	}
	if len(pubBytes) != 32 {
		t.Errorf("decoded public key is %d bytes, want 32", len(pubBytes))
	}

	derivedPub := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
	if string(derivedPub) != string(pubBytes) {
		t.Errorf("derived public key does not match stored public key")
	}
}

func TestKeygenWritesPrivateKey(t *testing.T) {
	resetKeygenFlags()

	dir := t.TempDir()
	homePath := filepath.Join(dir, ".rtbtr")

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetArgs([]string{"keygen", "--home", homePath})

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("keygen returned error: %v", err)
	}

	content, err := os.ReadFile(filepath.Join(homePath, "private_key"))
	if err != nil {
		t.Fatalf("reading private_key: %v", err)
	}

	s := string(content)
	if strings.ContainsAny(s, "+/=") {
		t.Errorf("private_key contains standard base64 characters: %q", s)
	}
	if strings.ContainsAny(s, "\n\r \t") {
		t.Errorf("private_key contains whitespace: %q", s)
	}

	decoded, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		t.Fatalf("decoding private_key: %v", err)
	}
	if len(decoded) != 32 {
		t.Errorf("decoded private key is %d bytes, want 32", len(decoded))
	}
}

func TestKeygenWritesPublicKey(t *testing.T) {
	resetKeygenFlags()

	dir := t.TempDir()
	homePath := filepath.Join(dir, ".rtbtr")

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetArgs([]string{"keygen", "--home", homePath})

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("keygen returned error: %v", err)
	}

	content, err := os.ReadFile(filepath.Join(homePath, "public_key"))
	if err != nil {
		t.Fatalf("reading public_key: %v", err)
	}

	s := string(content)
	if strings.ContainsAny(s, "+/=") {
		t.Errorf("public_key contains standard base64 characters: %q", s)
	}
	if strings.ContainsAny(s, "\n\r \t") {
		t.Errorf("public_key contains whitespace: %q", s)
	}

	decoded, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		t.Fatalf("decoding public_key: %v", err)
	}
	if len(decoded) != 32 {
		t.Errorf("decoded public key is %d bytes, want 32", len(decoded))
	}
}

func TestKeygenRefusesOverwrite(t *testing.T) {
	resetKeygenFlags()

	dir := t.TempDir()
	homePath := filepath.Join(dir, ".rtbtr")
	if err := os.MkdirAll(homePath, 0o755); err != nil {
		t.Fatalf("creating home directory: %v", err)
	}
	if err := os.WriteFile(filepath.Join(homePath, "private_key"), []byte("existing-private"), 0o600); err != nil {
		t.Fatalf("writing existing private_key: %v", err)
	}
	if err := os.WriteFile(filepath.Join(homePath, "public_key"), []byte("existing-public"), 0o600); err != nil {
		t.Fatalf("writing existing public_key: %v", err)
	}

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetArgs([]string{"keygen", "--home", homePath})

	err := rootCmd.Execute()
	if err == nil {
		t.Fatal("keygen should return error when keys exist without --force")
	}
	if !strings.Contains(err.Error(), "already exist") {
		t.Errorf("error = %q, want it to mention 'already exist'", err.Error())
	}

	privateKey, err := os.ReadFile(filepath.Join(homePath, "private_key"))
	if err != nil {
		t.Fatalf("reading private_key: %v", err)
	}
	if string(privateKey) != "existing-private" {
		t.Errorf("private_key = %q, want %q", string(privateKey), "existing-private")
	}

	publicKey, err := os.ReadFile(filepath.Join(homePath, "public_key"))
	if err != nil {
		t.Fatalf("reading public_key: %v", err)
	}
	if string(publicKey) != "existing-public" {
		t.Errorf("public_key = %q, want %q", string(publicKey), "existing-public")
	}
}

func TestKeygenForceOverwrite(t *testing.T) {
	resetKeygenFlags()

	dir := t.TempDir()
	homePath := filepath.Join(dir, ".rtbtr")
	if err := os.MkdirAll(homePath, 0o755); err != nil {
		t.Fatalf("creating home directory: %v", err)
	}
	if err := os.WriteFile(filepath.Join(homePath, "private_key"), []byte("old-private"), 0o600); err != nil {
		t.Fatalf("writing old private_key: %v", err)
	}
	if err := os.WriteFile(filepath.Join(homePath, "public_key"), []byte("old-public"), 0o600); err != nil {
		t.Fatalf("writing old public_key: %v", err)
	}

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetArgs([]string{"keygen", "--force", "--home", homePath})

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("keygen returned error: %v", err)
	}

	privateKey, err := os.ReadFile(filepath.Join(homePath, "private_key"))
	if err != nil {
		t.Fatalf("reading private_key: %v", err)
	}
	if string(privateKey) == "old-private" {
		t.Errorf("private_key was not overwritten")
	}

	seed, err := base64.RawURLEncoding.DecodeString(string(privateKey))
	if err != nil {
		t.Fatalf("decoding private_key: %v", err)
	}
	if len(seed) != 32 {
		t.Errorf("decoded private key is %d bytes, want 32", len(seed))
	}

	publicKey, err := os.ReadFile(filepath.Join(homePath, "public_key"))
	if err != nil {
		t.Fatalf("reading public_key: %v", err)
	}
	if string(publicKey) == "old-public" {
		t.Errorf("public_key was not overwritten")
	}

	pubBytes, err := base64.RawURLEncoding.DecodeString(string(publicKey))
	if err != nil {
		t.Fatalf("decoding public_key: %v", err)
	}
	if len(pubBytes) != 32 {
		t.Errorf("decoded public key is %d bytes, want 32", len(pubBytes))
	}

	derivedPub := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
	if string(derivedPub) != string(pubBytes) {
		t.Errorf("derived public key does not match stored public key")
	}
}

func TestKeygenPrintsPubkeyStdout(t *testing.T) {
	resetKeygenFlags()

	dir := t.TempDir()
	homePath := filepath.Join(dir, ".rtbtr")

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetArgs([]string{"keygen", "--home", homePath})

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("keygen returned error: %v", err)
	}

	output := strings.TrimSpace(buf.String())
	if output == "" {
		t.Fatal("stdout output is empty")
	}
	if _, err := base64.RawURLEncoding.DecodeString(output); err != nil {
		t.Errorf("stdout is not valid base64: %v", err)
	}

	pubContent, err := os.ReadFile(filepath.Join(homePath, "public_key"))
	if err != nil {
		t.Fatalf("reading public_key: %v", err)
	}
	if output != string(pubContent) {
		t.Errorf("stdout = %q, public_key file = %q, want match", output, string(pubContent))
	}
}

func TestKeygenCreatesRtbtrDir(t *testing.T) {
	resetKeygenFlags()

	dir := t.TempDir()
	homePath := filepath.Join(dir, ".rtbtr")

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetArgs([]string{"keygen", "--home", homePath})

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("keygen returned error: %v", err)
	}

	info, err := os.Stat(homePath)
	if err != nil {
		t.Fatalf("homePath does not exist: %v", err)
	}
	if !info.IsDir() {
		t.Errorf("homePath is not a directory")
	}

	if _, err := os.Stat(filepath.Join(homePath, "private_key")); err != nil {
		t.Errorf("private_key not found: %v", err)
	}
	if _, err := os.Stat(filepath.Join(homePath, "public_key")); err != nil {
		t.Errorf("public_key not found: %v", err)
	}
}

func TestKeygenSubcommandRegistered(t *testing.T) {
	resetKeygenFlags()

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetArgs([]string{"keygen", "--help"})

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("keygen --help returned error: %v", err)
	}

	output := buf.String()
	if len(output) == 0 {
		t.Fatal("keygen --help produced no output")
	}
	if !strings.Contains(output, "keygen") {
		t.Errorf("help output does not contain 'keygen': %s", output)
	}
	if !strings.Contains(output, "Ed25519") {
		t.Errorf("help output does not mention 'Ed25519': %s", output)
	}
}

func TestKeygenPublicKeyFormat(t *testing.T) {
	resetKeygenFlags()

	dir := t.TempDir()
	homePath := filepath.Join(dir, ".rtbtr")

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetArgs([]string{"keygen", "--home", homePath})

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("keygen returned error: %v", err)
	}

	pubContent, err := os.ReadFile(filepath.Join(homePath, "public_key"))
	if err != nil {
		t.Fatalf("reading public_key: %v", err)
	}
	pubB64 := string(pubContent)
	if strings.ContainsAny(pubB64, "+/") {
		t.Errorf("public_key contains standard base64 characters: %q", pubB64)
	}
	if strings.Contains(pubB64, "=") {
		t.Errorf("public_key contains padding: %q", pubB64)
	}

	pubBytes, err := base64.RawURLEncoding.DecodeString(pubB64)
	if err != nil {
		t.Fatalf("decoding public_key: %v", err)
	}
	if len(pubBytes) != 32 {
		t.Errorf("decoded public key is %d bytes, want 32", len(pubBytes))
	}

	privContent, err := os.ReadFile(filepath.Join(homePath, "private_key"))
	if err != nil {
		t.Fatalf("reading private_key: %v", err)
	}
	privB64 := string(privContent)
	if strings.ContainsAny(privB64, "+/") {
		t.Errorf("private_key contains standard base64 characters: %q", privB64)
	}
	if strings.Contains(privB64, "=") {
		t.Errorf("private_key contains padding: %q", privB64)
	}

	seed, err := base64.RawURLEncoding.DecodeString(privB64)
	if err != nil {
		t.Fatalf("decoding private_key: %v", err)
	}
	if len(seed) != 32 {
		t.Errorf("decoded private key is %d bytes, want 32", len(seed))
	}

	privateKey := ed25519.NewKeyFromSeed(seed)
	sig := ed25519.Sign(privateKey, []byte("test message"))
	pubKey := ed25519.PublicKey(pubBytes)
	if !ed25519.Verify(pubKey, []byte("test message"), sig) {
		t.Errorf("sign-verify roundtrip failed: keys are not a valid Ed25519 pair")
	}
}
