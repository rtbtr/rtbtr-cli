package cmd

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func resetVerifyFlags() {
	homeFlag = ""
	verifyKeyFlag = ""
	verifySignatureFlag = ""

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

	if flag := verifyCmd.Flags().Lookup("key"); flag != nil {
		if err := flag.Value.Set(flag.DefValue); err != nil {
			panic(err)
		}
		flag.Changed = false
	}

	if flag := verifyCmd.Flags().Lookup("signature"); flag != nil {
		if err := flag.Value.Set(flag.DefValue); err != nil {
			panic(err)
		}
		flag.Changed = false
	}

	if flag := verifyCmd.Flags().Lookup("help"); flag != nil {
		if err := flag.Value.Set(flag.DefValue); err != nil {
			panic(err)
		}
		flag.Changed = false
	}
}

// setupVerifyMock starts a mock server returning the given public key and
// overrides apiBaseURL. Returns cleanup via t.Cleanup.
func setupVerifyMock(t *testing.T, pub ed25519.PublicKey) {
	t.Helper()
	pubB64 := base64.RawURLEncoding.EncodeToString([]byte(pub))
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"bot_id":"test-id","org":"test-org","public_key":"%s","description":"","created_at":"2026-01-01T00:00:00Z"}`, pubB64)
	}))
	t.Cleanup(server.Close)
	oldBaseURL := apiBaseURL
	apiBaseURL = server.URL
	t.Cleanup(func() { apiBaseURL = oldBaseURL })
}

func TestVerifyValidSignature(t *testing.T) {
	resetVerifyFlags()

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating keypair: %v", err)
	}
	setupVerifyMock(t, pub)

	message := []byte("deploy v2.3.0\n")
	sig := ed25519.Sign(priv, message)
	sigB64 := base64.StdEncoding.EncodeToString(sig)

	stdin := bytes.NewReader(message)
	stdout := new(bytes.Buffer)
	rootCmd.SetIn(stdin)
	rootCmd.SetOut(stdout)
	rootCmd.SetArgs([]string{"verify", "--key", "test-org/test-bot", "--signature", sigB64})

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("verify returned error: %v", err)
	}

	output := strings.TrimSpace(stdout.String())
	if output != "valid" {
		t.Errorf("stdout = %q, want %q", output, "valid")
	}
}

func TestVerifyInvalidSignature(t *testing.T) {
	resetVerifyFlags()

	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating keypair: %v", err)
	}
	setupVerifyMock(t, pub)

	message := []byte("deploy v2.3.0\n")
	fakeSig := make([]byte, ed25519.SignatureSize)
	for i := range fakeSig {
		fakeSig[i] = byte(i)
	}
	sigB64 := base64.StdEncoding.EncodeToString(fakeSig)

	stdin := bytes.NewReader(message)
	stdout := new(bytes.Buffer)
	rootCmd.SetIn(stdin)
	rootCmd.SetOut(stdout)
	rootCmd.SetArgs([]string{"verify", "--key", "test-org/test-bot", "--signature", sigB64})

	err = rootCmd.Execute()
	if !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("verify should return ErrInvalidSignature, got: %v", err)
	}

	output := strings.TrimSpace(stdout.String())
	if output != "invalid" {
		t.Errorf("stdout = %q, want %q", output, "invalid")
	}
}

func TestVerifyRejectsInvalidKeyFormat(t *testing.T) {
	resetVerifyFlags()

	sigB64 := base64.StdEncoding.EncodeToString(make([]byte, ed25519.SignatureSize))

	stdin := bytes.NewReader([]byte("some data"))
	stdout := new(bytes.Buffer)
	rootCmd.SetIn(stdin)
	rootCmd.SetOut(stdout)
	rootCmd.SetArgs([]string{"verify", "--key", "noslash", "--signature", sigB64})

	err := rootCmd.Execute()
	if err == nil {
		t.Fatal("verify should return error for key without org/bot format")
	}
	if !strings.Contains(err.Error(), "org/bot") {
		t.Errorf("error = %q, want it to mention org/bot", err.Error())
	}
}

func TestVerifyRejectsInvalidSignature(t *testing.T) {
	resetVerifyFlags()

	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating keypair: %v", err)
	}
	setupVerifyMock(t, pub)

	badSig := "not-valid-base64!@#$%"

	stdin := bytes.NewReader([]byte("some data"))
	stdout := new(bytes.Buffer)
	rootCmd.SetIn(stdin)
	rootCmd.SetOut(stdout)
	rootCmd.SetArgs([]string{"verify", "--key", "test-org/test-bot", "--signature", badSig})

	err = rootCmd.Execute()
	if err == nil {
		t.Fatal("verify should return error for malformed signature")
	}
	if !strings.Contains(err.Error(), "signature") {
		t.Errorf("error = %q, want it to mention 'signature'", err.Error())
	}
}

func TestVerifyRejectsOversizedInput(t *testing.T) {
	resetVerifyFlags()

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating keypair: %v", err)
	}
	setupVerifyMock(t, pub)

	message := []byte("small")
	sig := ed25519.Sign(priv, message)
	sigB64 := base64.StdEncoding.EncodeToString(sig)

	oversized := make([]byte, maxVerifyInputBytes+1)
	for i := range oversized {
		oversized[i] = 'x'
	}

	stdin := bytes.NewReader(oversized)
	stdout := new(bytes.Buffer)
	rootCmd.SetIn(stdin)
	rootCmd.SetOut(stdout)
	rootCmd.SetArgs([]string{"verify", "--key", "test-org/test-bot", "--signature", sigB64})

	err = rootCmd.Execute()
	if err == nil {
		t.Fatal("verify should return error on oversized input")
	}
	if !strings.Contains(err.Error(), "too large") {
		t.Errorf("error = %q, want it to mention 'too large'", err.Error())
	}
}

func TestSignVerifyRoundtrip(t *testing.T) {
	resetSignFlags()

	homePath, pub := setupSignHome(t)
	setupVerifyMock(t, pub)

	message := []byte("deploy v2.3.0\n")

	// Sign.
	signStdin := bytes.NewReader(message)
	signStdout := new(bytes.Buffer)
	rootCmd.SetIn(signStdin)
	rootCmd.SetOut(signStdout)
	rootCmd.SetArgs([]string{"sign", "--home", homePath})

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("sign returned error: %v", err)
	}

	sigB64 := strings.TrimSpace(signStdout.String())

	// Verify.
	resetVerifyFlags()

	verifyStdin := bytes.NewReader(message)
	verifyStdout := new(bytes.Buffer)
	rootCmd.SetIn(verifyStdin)
	rootCmd.SetOut(verifyStdout)
	rootCmd.SetArgs([]string{"verify", "--key", "test-org/test-bot", "--signature", sigB64})

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("verify returned error: %v", err)
	}

	output := strings.TrimSpace(verifyStdout.String())
	if output != "valid" {
		t.Errorf("roundtrip verify stdout = %q, want %q", output, "valid")
	}
}

func TestVerifyWrongKey(t *testing.T) {
	resetVerifyFlags()

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating signer keypair: %v", err)
	}

	wrongPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating wrong keypair: %v", err)
	}
	setupVerifyMock(t, wrongPub)

	message := []byte("deploy v2.3.0\n")
	sig := ed25519.Sign(priv, message)
	sigB64 := base64.StdEncoding.EncodeToString(sig)

	stdin := bytes.NewReader(message)
	stdout := new(bytes.Buffer)
	rootCmd.SetIn(stdin)
	rootCmd.SetOut(stdout)
	rootCmd.SetArgs([]string{"verify", "--key", "test-org/test-bot", "--signature", sigB64})

	err = rootCmd.Execute()
	if !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("verify should return ErrInvalidSignature, got: %v", err)
	}

	output := strings.TrimSpace(stdout.String())
	if output != "invalid" {
		t.Errorf("stdout = %q, want %q", output, "invalid")
	}
}

func TestVerifyRejectsEmptyStdin(t *testing.T) {
	resetVerifyFlags()

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating keypair: %v", err)
	}
	setupVerifyMock(t, pub)

	sig := ed25519.Sign(priv, []byte("data"))
	sigB64 := base64.StdEncoding.EncodeToString(sig)

	stdin := bytes.NewReader([]byte{})
	stdout := new(bytes.Buffer)
	rootCmd.SetIn(stdin)
	rootCmd.SetOut(stdout)
	rootCmd.SetArgs([]string{"verify", "--key", "test-org/test-bot", "--signature", sigB64})

	err = rootCmd.Execute()
	if err == nil {
		t.Fatal("verify should return error on empty stdin")
	}
	if !strings.Contains(err.Error(), "empty input") {
		t.Errorf("error = %q, want it to mention 'empty input'", err.Error())
	}
}

func TestVerifySignerNotFound(t *testing.T) {
	resetVerifyFlags()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`{"error":"not found"}`))
	}))
	defer server.Close()
	oldBaseURL := apiBaseURL
	apiBaseURL = server.URL
	defer func() { apiBaseURL = oldBaseURL }()

	sigB64 := base64.StdEncoding.EncodeToString(make([]byte, ed25519.SignatureSize))

	stdin := bytes.NewReader([]byte("some data"))
	stdout := new(bytes.Buffer)
	rootCmd.SetIn(stdin)
	rootCmd.SetOut(stdout)
	rootCmd.SetArgs([]string{"verify", "--key", "no-org/no-bot", "--signature", sigB64})

	err := rootCmd.Execute()
	if err == nil {
		t.Fatal("verify should return error for unknown signer")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("error = %q, want it to mention not found", err.Error())
	}
}

func TestVerifyRejectsWrongLengthSignature(t *testing.T) {
	resetVerifyFlags()

	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating keypair: %v", err)
	}
	setupVerifyMock(t, pub)

	shortSig := make([]byte, 32)
	sigB64 := base64.StdEncoding.EncodeToString(shortSig)

	stdin := bytes.NewReader([]byte("some data"))
	stdout := new(bytes.Buffer)
	rootCmd.SetIn(stdin)
	rootCmd.SetOut(stdout)
	rootCmd.SetArgs([]string{"verify", "--key", "test-org/test-bot", "--signature", sigB64})

	err = rootCmd.Execute()
	if err == nil {
		t.Fatal("verify should return error for wrong-length signature")
	}
	if !strings.Contains(err.Error(), "invalid signature length") {
		t.Errorf("error = %q, want it to mention 'invalid signature length'", err.Error())
	}
}
