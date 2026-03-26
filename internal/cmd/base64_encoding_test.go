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

// ---------------------------------------------------------------------------
// Sign: output must be standard base64 with padding (RFC 4648 section 4).
// Ed25519 signatures are always 64 bytes, so standard base64 encoding
// produces exactly 88 characters ending with "==".
// ---------------------------------------------------------------------------

// TestSignOutputIsStdBase64WithPadding verifies that `rtbtr sign` encodes
// the signature using standard base64 (alphabet A-Z a-z 0-9 + /) with
// padding, so that the output is directly usable in RFC 8941 Signature
// headers.
func TestSignOutputIsStdBase64WithPadding(t *testing.T) {
	resetSignFlags()

	homePath, _ := setupSignHome(t)

	stdin := bytes.NewReader([]byte("test payload for base64 encoding"))
	stdout := new(bytes.Buffer)
	rootCmd.SetIn(stdin)
	rootCmd.SetOut(stdout)
	rootCmd.SetArgs([]string{"sign", "--home", homePath})

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("sign returned error: %v", err)
	}

	output := strings.TrimSpace(stdout.String())

	// Standard base64 for 64 bytes: ceil(64/3)*4 = 88 characters with "==" padding.
	if len(output) != 88 {
		t.Errorf("sign output length = %d, want 88 (standard base64 of 64 bytes); output = %q", len(output), output)
	}

	// Must end with "==" because 64 % 3 == 1.
	if !strings.HasSuffix(output, "==") {
		t.Errorf("sign output does not end with '==': %q", output)
	}

	// Must be decodable with standard base64 (StdEncoding).
	decoded, err := base64.StdEncoding.DecodeString(output)
	if err != nil {
		t.Fatalf("sign output is not valid standard base64: %v; output = %q", err, output)
	}

	if len(decoded) != ed25519.SignatureSize {
		t.Errorf("decoded signature length = %d, want %d", len(decoded), ed25519.SignatureSize)
	}
}

// TestSignOutputDoesNotUseURLSafeAlphabet ensures the sign output never
// uses the URL-safe base64 characters '-' and '_'. Standard base64 uses
// '+' and '/' instead.
func TestSignOutputDoesNotUseURLSafeAlphabet(t *testing.T) {
	// Generate multiple signatures to increase the chance of hitting
	// base64 positions 62 and 63 in the encoded output.
	for i := 0; i < 20; i++ {
		resetSignFlags()

		homePath, _ := setupSignHome(t)

		msg := fmt.Sprintf("payload iteration %d for base64 alphabet check", i)
		stdin := bytes.NewReader([]byte(msg))
		stdout := new(bytes.Buffer)
		rootCmd.SetIn(stdin)
		rootCmd.SetOut(stdout)
		rootCmd.SetArgs([]string{"sign", "--home", homePath})

		if err := rootCmd.Execute(); err != nil {
			t.Fatalf("sign returned error on iteration %d: %v", i, err)
		}

		output := strings.TrimSpace(stdout.String())

		// URL-safe base64 uses '-' and '_'; standard uses '+' and '/'.
		// The output must not contain URL-safe-only characters.
		if strings.ContainsAny(output, "-_") {
			t.Errorf("iteration %d: sign output contains URL-safe character(s): %q", i, output)
		}
	}
}

// TestSignOutputDecodesToValidEd25519Signature ensures that decoding the
// sign output with base64.StdEncoding produces a valid Ed25519 signature
// that verifies against the corresponding public key.
func TestSignOutputDecodesToValidEd25519Signature(t *testing.T) {
	resetSignFlags()

	homePath, pub := setupSignHome(t)
	message := []byte("message to sign and verify via standard base64")

	stdin := bytes.NewReader(message)
	stdout := new(bytes.Buffer)
	rootCmd.SetIn(stdin)
	rootCmd.SetOut(stdout)
	rootCmd.SetArgs([]string{"sign", "--home", homePath})

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("sign returned error: %v", err)
	}

	output := strings.TrimSpace(stdout.String())

	// Decode using standard base64 (with padding).
	sigBytes, err := base64.StdEncoding.DecodeString(output)
	if err != nil {
		t.Fatalf("cannot decode sign output as standard base64: %v; output = %q", err, output)
	}

	// Cryptographically verify the signature.
	if !ed25519.Verify(pub, message, sigBytes) {
		t.Errorf("signature decoded via StdEncoding does not verify against the public key")
	}
}

// ---------------------------------------------------------------------------
// Verify: --signature flag must accept standard base64 with padding.
// ---------------------------------------------------------------------------

// setupVerifyMockStd is like setupVerifyMock but uses standard base64 for
// the public key in the mock response (matching the server's encoding).
func setupVerifyMockStd(t *testing.T, pub ed25519.PublicKey) {
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

// TestVerifyAcceptsStdBase64Signature checks that `rtbtr verify` correctly
// accepts a signature encoded with standard base64 (with padding).
func TestVerifyAcceptsStdBase64Signature(t *testing.T) {
	resetVerifyFlags()

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating keypair: %v", err)
	}
	setupVerifyMockStd(t, pub)

	message := []byte("deploy v2.3.0\n")
	sig := ed25519.Sign(priv, message)

	// Encode the signature as standard base64 WITH padding.
	sigB64 := base64.StdEncoding.EncodeToString(sig)

	stdin := bytes.NewReader(message)
	stdout := new(bytes.Buffer)
	rootCmd.SetIn(stdin)
	rootCmd.SetOut(stdout)
	rootCmd.SetArgs([]string{"verify", "--key", "test-org/test-bot", "--signature", sigB64})

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("verify returned error for standard base64 signature: %v", err)
	}

	output := strings.TrimSpace(stdout.String())
	if output != "valid" {
		t.Errorf("stdout = %q, want %q", output, "valid")
	}
}

// TestVerifyRejectsInvalidStdBase64Signature ensures verify returns
// ErrInvalidSignature when a standard-base64-encoded but cryptographically
// wrong signature is supplied.
func TestVerifyRejectsInvalidStdBase64Signature(t *testing.T) {
	resetVerifyFlags()

	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating keypair: %v", err)
	}
	setupVerifyMockStd(t, pub)

	message := []byte("deploy v2.3.0\n")
	fakeSig := make([]byte, ed25519.SignatureSize)
	for i := range fakeSig {
		fakeSig[i] = byte(i)
	}
	// Standard base64 encoding with padding.
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

// TestVerifyStdBase64WrongLengthSignature ensures verify rejects a
// standard-base64-encoded value whose decoded length is not 64 bytes.
func TestVerifyStdBase64WrongLengthSignature(t *testing.T) {
	resetVerifyFlags()

	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating keypair: %v", err)
	}
	setupVerifyMockStd(t, pub)

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

// ---------------------------------------------------------------------------
// Sign -> Verify roundtrip: sign output must be directly usable as verify
// --signature input without any re-encoding.
// ---------------------------------------------------------------------------

// TestSignVerifyRoundtripStdBase64 verifies that the standard-base64 output
// of `rtbtr sign` can be passed directly to `rtbtr verify --signature`
// without manual encoding conversion.
func TestSignVerifyRoundtripStdBase64(t *testing.T) {
	resetSignFlags()

	homePath, pub := setupSignHome(t)
	setupVerifyMockStd(t, pub)

	message := []byte("roundtrip with standard base64\n")

	// Step 1: Sign.
	signStdin := bytes.NewReader(message)
	signStdout := new(bytes.Buffer)
	rootCmd.SetIn(signStdin)
	rootCmd.SetOut(signStdout)
	rootCmd.SetArgs([]string{"sign", "--home", homePath})

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("sign returned error: %v", err)
	}

	sigB64 := strings.TrimSpace(signStdout.String())

	// Sanity check: output must be valid standard base64 with padding.
	if _, err := base64.StdEncoding.DecodeString(sigB64); err != nil {
		t.Fatalf("sign output is not valid standard base64: %v; output = %q", err, sigB64)
	}

	// Step 2: Verify using the raw sign output as --signature value.
	resetVerifyFlags()

	verifyStdin := bytes.NewReader(message)
	verifyStdout := new(bytes.Buffer)
	rootCmd.SetIn(verifyStdin)
	rootCmd.SetOut(verifyStdout)
	rootCmd.SetArgs([]string{"verify", "--key", "test-org/test-bot", "--signature", sigB64})

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("verify returned error on roundtrip: %v", err)
	}

	output := strings.TrimSpace(verifyStdout.String())
	if output != "valid" {
		t.Errorf("roundtrip verify stdout = %q, want %q", output, "valid")
	}
}

// TestSignVerifyRoundtripMultipleMessages runs the sign->verify roundtrip
// for several different messages to ensure consistency across payloads.
func TestSignVerifyRoundtripMultipleMessages(t *testing.T) {
	messages := []string{
		"hello world",
		"deploy v2.3.0\n",
		"binary-ish: \x00\x01\x02\xff",
		strings.Repeat("a", 1024),
		"RFC 8941 Structured Fields header test",
	}

	for _, msg := range messages {
		t.Run(fmt.Sprintf("msg_%d_bytes", len(msg)), func(t *testing.T) {
			resetSignFlags()

			homePath, pub := setupSignHome(t)
			setupVerifyMockStd(t, pub)

			// Sign.
			signStdin := bytes.NewReader([]byte(msg))
			signStdout := new(bytes.Buffer)
			rootCmd.SetIn(signStdin)
			rootCmd.SetOut(signStdout)
			rootCmd.SetArgs([]string{"sign", "--home", homePath})

			if err := rootCmd.Execute(); err != nil {
				t.Fatalf("sign error: %v", err)
			}

			sigB64 := strings.TrimSpace(signStdout.String())

			// Output must be valid standard base64.
			if _, err := base64.StdEncoding.DecodeString(sigB64); err != nil {
				t.Fatalf("sign output not valid StdEncoding base64: %v; output = %q", err, sigB64)
			}

			// Must have exactly 88 characters with "==" suffix.
			if len(sigB64) != 88 {
				t.Errorf("sign output length = %d, want 88; output = %q", len(sigB64), sigB64)
			}

			// Verify.
			resetVerifyFlags()

			verifyStdin := bytes.NewReader([]byte(msg))
			verifyStdout := new(bytes.Buffer)
			rootCmd.SetIn(verifyStdin)
			rootCmd.SetOut(verifyStdout)
			rootCmd.SetArgs([]string{"verify", "--key", "test-org/test-bot", "--signature", sigB64})

			if err := rootCmd.Execute(); err != nil {
				t.Fatalf("verify error: %v", err)
			}

			output := strings.TrimSpace(verifyStdout.String())
			if output != "valid" {
				t.Errorf("verify output = %q, want %q", output, "valid")
			}
		})
	}
}

// ---------------------------------------------------------------------------
// RFC 8941 compatibility: the sign output must be directly embeddable in
// an RFC 8941 Structured Fields byte-sequence item (`:base64:` syntax).
// RFC 8941 section 3.3.5 requires standard base64 (RFC 4648 section 4).
// ---------------------------------------------------------------------------

// TestSignOutputIsRFC8941Compatible verifies that the sign output can be
// wrapped in RFC 8941 byte-sequence delimiters (colons) and decoded using
// standard base64, just like the Signature header in HTTP message signatures.
func TestSignOutputIsRFC8941Compatible(t *testing.T) {
	resetSignFlags()

	homePath, _ := setupSignHome(t)

	stdin := bytes.NewReader([]byte("rfc 8941 byte sequence test"))
	stdout := new(bytes.Buffer)
	rootCmd.SetIn(stdin)
	rootCmd.SetOut(stdout)
	rootCmd.SetArgs([]string{"sign", "--home", homePath})

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("sign returned error: %v", err)
	}

	rawOutput := strings.TrimSpace(stdout.String())

	// Wrap in RFC 8941 byte-sequence syntax: sig1=:<base64>:
	rfc8941Value := "sig1=:" + rawOutput + ":"

	// Extract and decode — this is exactly what a server would do.
	inner := strings.TrimPrefix(rfc8941Value, "sig1=:")
	inner = strings.TrimSuffix(inner, ":")

	decoded, err := base64.StdEncoding.DecodeString(inner)
	if err != nil {
		t.Fatalf("cannot decode sign output as standard base64 for RFC 8941: %v; value = %q", err, inner)
	}

	if len(decoded) != ed25519.SignatureSize {
		t.Errorf("decoded length = %d, want %d", len(decoded), ed25519.SignatureSize)
	}
}

// TestSignOutputContainsPaddingCharacters asserts that Ed25519 signatures
// (64 bytes) always produce standard base64 output with padding characters,
// confirming the encoding is NOT raw/unpadded.
func TestSignOutputContainsPaddingCharacters(t *testing.T) {
	// Run multiple iterations with different keys and messages to be thorough.
	for i := 0; i < 10; i++ {
		resetSignFlags()

		homePath, _ := setupSignHome(t)
		msg := fmt.Sprintf("padding check iteration %d", i)

		stdin := bytes.NewReader([]byte(msg))
		stdout := new(bytes.Buffer)
		rootCmd.SetIn(stdin)
		rootCmd.SetOut(stdout)
		rootCmd.SetArgs([]string{"sign", "--home", homePath})

		if err := rootCmd.Execute(); err != nil {
			t.Fatalf("sign returned error on iteration %d: %v", i, err)
		}

		output := strings.TrimSpace(stdout.String())

		// 64 bytes % 3 == 1, so standard base64 always ends with "==".
		if !strings.Contains(output, "=") {
			t.Errorf("iteration %d: sign output has no padding character '=': %q", i, output)
		}
		if !strings.HasSuffix(output, "==") {
			t.Errorf("iteration %d: sign output does not end with '==': %q", i, output)
		}
	}
}
