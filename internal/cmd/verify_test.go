package cmd

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
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

func TestVerifyValidSignature(t *testing.T) {
	resetVerifyFlags()

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating keypair: %v", err)
	}

	message := []byte("deploy v2.3.0\n")
	sig := ed25519.Sign(priv, message)

	keyB64 := base64.RawURLEncoding.EncodeToString(pub)
	sigB64 := base64.RawURLEncoding.EncodeToString(sig)

	stdin := bytes.NewReader(message)
	stdout := new(bytes.Buffer)
	rootCmd.SetIn(stdin)
	rootCmd.SetOut(stdout)
	rootCmd.SetArgs([]string{"verify", "--key", keyB64, "--signature", sigB64})

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

	message := []byte("deploy v2.3.0\n")
	fakeSig := make([]byte, ed25519.SignatureSize)
	for i := range fakeSig {
		fakeSig[i] = byte(i)
	}

	keyB64 := base64.RawURLEncoding.EncodeToString(pub)
	sigB64 := base64.RawURLEncoding.EncodeToString(fakeSig)

	stdin := bytes.NewReader(message)
	stdout := new(bytes.Buffer)
	rootCmd.SetIn(stdin)
	rootCmd.SetOut(stdout)
	rootCmd.SetArgs([]string{"verify", "--key", keyB64, "--signature", sigB64})

	err = rootCmd.Execute()
	if !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("verify should return ErrInvalidSignature, got: %v", err)
	}

	output := strings.TrimSpace(stdout.String())
	if output != "invalid" {
		t.Errorf("stdout = %q, want %q", output, "invalid")
	}
}

func TestVerifyRejectsInvalidKey(t *testing.T) {
	resetVerifyFlags()

	badKey := "not-valid-base64!@#$%"
	sigB64 := base64.RawURLEncoding.EncodeToString(make([]byte, ed25519.SignatureSize))

	stdin := bytes.NewReader([]byte("some data"))
	stdout := new(bytes.Buffer)
	rootCmd.SetIn(stdin)
	rootCmd.SetOut(stdout)
	rootCmd.SetArgs([]string{"verify", "--key", badKey, "--signature", sigB64})

	err := rootCmd.Execute()
	if err == nil {
		t.Fatal("verify should return error for malformed public key")
	}
	if !strings.Contains(err.Error(), "public key") {
		t.Errorf("error = %q, want it to mention 'public key'", err.Error())
	}
}

func TestVerifyRejectsInvalidSignature(t *testing.T) {
	resetVerifyFlags()

	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating keypair: %v", err)
	}
	keyB64 := base64.RawURLEncoding.EncodeToString(pub)

	badSig := "not-valid-base64!@#$%"

	stdin := bytes.NewReader([]byte("some data"))
	stdout := new(bytes.Buffer)
	rootCmd.SetIn(stdin)
	rootCmd.SetOut(stdout)
	rootCmd.SetArgs([]string{"verify", "--key", keyB64, "--signature", badSig})

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

	message := []byte("small")
	sig := ed25519.Sign(priv, message)

	keyB64 := base64.RawURLEncoding.EncodeToString(pub)
	sigB64 := base64.RawURLEncoding.EncodeToString(sig)

	oversized := make([]byte, maxVerifyInputBytes+1)
	for i := range oversized {
		oversized[i] = 'x'
	}

	stdin := bytes.NewReader(oversized)
	stdout := new(bytes.Buffer)
	rootCmd.SetIn(stdin)
	rootCmd.SetOut(stdout)
	rootCmd.SetArgs([]string{"verify", "--key", keyB64, "--signature", sigB64})

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
	keyB64 := base64.RawURLEncoding.EncodeToString(pub)

	verifyStdin := bytes.NewReader(message)
	verifyStdout := new(bytes.Buffer)
	rootCmd.SetIn(verifyStdin)
	rootCmd.SetOut(verifyStdout)
	rootCmd.SetArgs([]string{"verify", "--key", keyB64, "--signature", sigB64})

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

	message := []byte("deploy v2.3.0\n")
	sig := ed25519.Sign(priv, message)

	keyB64 := base64.RawURLEncoding.EncodeToString(wrongPub)
	sigB64 := base64.RawURLEncoding.EncodeToString(sig)

	stdin := bytes.NewReader(message)
	stdout := new(bytes.Buffer)
	rootCmd.SetIn(stdin)
	rootCmd.SetOut(stdout)
	rootCmd.SetArgs([]string{"verify", "--key", keyB64, "--signature", sigB64})

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

	sig := ed25519.Sign(priv, []byte("data"))
	keyB64 := base64.RawURLEncoding.EncodeToString(pub)
	sigB64 := base64.RawURLEncoding.EncodeToString(sig)

	stdin := bytes.NewReader([]byte{})
	stdout := new(bytes.Buffer)
	rootCmd.SetIn(stdin)
	rootCmd.SetOut(stdout)
	rootCmd.SetArgs([]string{"verify", "--key", keyB64, "--signature", sigB64})

	err = rootCmd.Execute()
	if err == nil {
		t.Fatal("verify should return error on empty stdin")
	}
	if !strings.Contains(err.Error(), "empty input") {
		t.Errorf("error = %q, want it to mention 'empty input'", err.Error())
	}
}

func TestVerifyRejectsWrongLengthKey(t *testing.T) {
	resetVerifyFlags()

	shortKey := make([]byte, 16)
	keyB64 := base64.RawURLEncoding.EncodeToString(shortKey)
	sigB64 := base64.RawURLEncoding.EncodeToString(make([]byte, ed25519.SignatureSize))

	stdin := bytes.NewReader([]byte("some data"))
	stdout := new(bytes.Buffer)
	rootCmd.SetIn(stdin)
	rootCmd.SetOut(stdout)
	rootCmd.SetArgs([]string{"verify", "--key", keyB64, "--signature", sigB64})

	err := rootCmd.Execute()
	if err == nil {
		t.Fatal("verify should return error for wrong-length public key")
	}
	if !strings.Contains(err.Error(), "invalid public key length") {
		t.Errorf("error = %q, want it to mention 'invalid public key length'", err.Error())
	}
}

func TestVerifyRejectsWrongLengthSignature(t *testing.T) {
	resetVerifyFlags()

	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating keypair: %v", err)
	}
	keyB64 := base64.RawURLEncoding.EncodeToString(pub)

	shortSig := make([]byte, 32)
	sigB64 := base64.RawURLEncoding.EncodeToString(shortSig)

	stdin := bytes.NewReader([]byte("some data"))
	stdout := new(bytes.Buffer)
	rootCmd.SetIn(stdin)
	rootCmd.SetOut(stdout)
	rootCmd.SetArgs([]string{"verify", "--key", keyB64, "--signature", sigB64})

	err = rootCmd.Execute()
	if err == nil {
		t.Fatal("verify should return error for wrong-length signature")
	}
	if !strings.Contains(err.Error(), "invalid signature length") {
		t.Errorf("error = %q, want it to mention 'invalid signature length'", err.Error())
	}
}
