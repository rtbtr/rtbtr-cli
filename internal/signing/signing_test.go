package signing

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"strings"
	"testing"
	"time"
)

// T-S01: Sign adds Signature-Input and Signature headers conforming to RFC 9421.
func TestSignAddsHeaders(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	_ = pub

	oldNow := nowFunc
	nowFunc = func() time.Time { return time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC) }
	defer func() { nowFunc = oldNow }()

	req, err := http.NewRequest("GET", "https://example.com/test?foo=bar", nil)
	if err != nil {
		t.Fatalf("creating request: %v", err)
	}

	if err := Sign(req, priv.Seed(), "testorg/testbot"); err != nil {
		t.Fatalf("Sign returned error: %v", err)
	}

	sigInput := req.Header.Get("Signature-Input")
	if sigInput == "" {
		t.Fatal("Signature-Input header is empty")
	}
	if !strings.HasPrefix(sigInput, "sig1=(") {
		t.Errorf("Signature-Input = %q, want prefix 'sig1=('", sigInput)
	}
	if !strings.Contains(sigInput, "\"@method\"") {
		t.Errorf("Signature-Input missing @method: %q", sigInput)
	}
	if !strings.Contains(sigInput, "\"@target-uri\"") {
		t.Errorf("Signature-Input missing @target-uri: %q", sigInput)
	}
	if !strings.Contains(sigInput, "\"@authority\"") {
		t.Errorf("Signature-Input missing @authority: %q", sigInput)
	}
	if !strings.Contains(sigInput, "created=") {
		t.Errorf("Signature-Input missing created parameter: %q", sigInput)
	}
	if !strings.Contains(sigInput, "keyid=") {
		t.Errorf("Signature-Input missing keyid parameter: %q", sigInput)
	}
	if !strings.Contains(sigInput, `alg="ed25519"`) {
		t.Errorf("Signature-Input missing alg parameter: %q", sigInput)
	}
	if !strings.Contains(sigInput, `keyid="testorg/testbot"`) {
		t.Errorf("Signature-Input missing correct keyid value: %q", sigInput)
	}

	sig := req.Header.Get("Signature")
	if sig == "" {
		t.Fatal("Signature header is empty")
	}
	if !strings.HasPrefix(sig, "sig1=:") {
		t.Errorf("Signature = %q, want prefix 'sig1=:'", sig)
	}
	if !strings.HasSuffix(sig, ":") {
		t.Errorf("Signature = %q, want suffix ':'", sig)
	}

	// Verify the base64 content between the colons is valid.
	inner := strings.TrimPrefix(sig, "sig1=:")
	inner = strings.TrimSuffix(inner, ":")
	if _, err := base64.StdEncoding.DecodeString(inner); err != nil {
		t.Errorf("Signature base64 decode failed: %v (value: %q)", err, inner)
	}
}

// T-S01: Verify the created timestamp uses the injected time.
func TestSignUsesInjectedTime(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}

	fixedTime := time.Date(2026, 6, 15, 12, 30, 0, 0, time.UTC)
	oldNow := nowFunc
	nowFunc = func() time.Time { return fixedTime }
	defer func() { nowFunc = oldNow }()

	req, err := http.NewRequest("GET", "https://example.com/path", nil)
	if err != nil {
		t.Fatalf("creating request: %v", err)
	}

	if err := Sign(req, priv.Seed(), "org/bot"); err != nil {
		t.Fatalf("Sign returned error: %v", err)
	}

	sigInput := req.Header.Get("Signature-Input")
	expectedCreated := "created=1781526600"
	if !strings.Contains(sigInput, expectedCreated) {
		t.Errorf("Signature-Input = %q, want it to contain %q", sigInput, expectedCreated)
	}
}

// T-S02: Sign rejects seed with incorrect length.
func TestSignRejectsInvalidSeedLength(t *testing.T) {
	req, err := http.NewRequest("GET", "https://example.com/test", nil)
	if err != nil {
		t.Fatalf("creating request: %v", err)
	}

	shortSeed := make([]byte, 16)
	err = Sign(req, shortSeed, "testorg/testbot")
	if err == nil {
		t.Fatal("Sign should return error for 16-byte seed")
	}

	longSeed := make([]byte, 64)
	err = Sign(req, longSeed, "testorg/testbot")
	if err == nil {
		t.Fatal("Sign should return error for 64-byte seed")
	}

	emptySeed := make([]byte, 0)
	err = Sign(req, emptySeed, "testorg/testbot")
	if err == nil {
		t.Fatal("Sign should return error for empty seed")
	}
}

// T-S02: Verify that valid 32-byte seed does not return an error.
func TestSignAcceptsValid32ByteSeed(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}

	oldNow := nowFunc
	nowFunc = func() time.Time { return time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC) }
	defer func() { nowFunc = oldNow }()

	req, err := http.NewRequest("GET", "https://example.com/test", nil)
	if err != nil {
		t.Fatalf("creating request: %v", err)
	}

	seed := priv.Seed()
	if len(seed) != 32 {
		t.Fatalf("expected 32-byte seed, got %d", len(seed))
	}

	if err := Sign(req, seed, "org/bot"); err != nil {
		t.Errorf("Sign returned unexpected error for valid 32-byte seed: %v", err)
	}
}

// T-S03: The Ed25519 signature produced by Sign is cryptographically verifiable.
func TestSignProducesVerifiableSignature(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}

	oldNow := nowFunc
	nowFunc = func() time.Time { return time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC) }
	defer func() { nowFunc = oldNow }()

	req, err := http.NewRequest("GET", "https://example.com/path?q=1", nil)
	if err != nil {
		t.Fatalf("creating request: %v", err)
	}

	if err := Sign(req, priv.Seed(), "org/bot"); err != nil {
		t.Fatalf("Sign returned error: %v", err)
	}

	// Extract the raw signature bytes from the Signature header.
	sigHeader := req.Header.Get("Signature")
	if sigHeader == "" {
		t.Fatal("Signature header is empty")
	}
	inner := strings.TrimPrefix(sigHeader, "sig1=:")
	inner = strings.TrimSuffix(inner, ":")
	sigBytes, err := base64.StdEncoding.DecodeString(inner)
	if err != nil {
		t.Fatalf("decoding signature base64: %v", err)
	}

	// Extract the sigParams from Signature-Input header.
	sigInputHeader := req.Header.Get("Signature-Input")
	if sigInputHeader == "" {
		t.Fatal("Signature-Input header is empty")
	}
	sigParams := strings.TrimPrefix(sigInputHeader, "sig1=")

	// Rebuild the signature base using the same algorithm as defined in RFC 9421.
	sigBase := "\"@method\": " + req.Method + "\n" +
		"\"@target-uri\": " + req.URL.String() + "\n" +
		"\"@authority\": " + req.URL.Host + "\n" +
		"\"@signature-params\": " + sigParams

	// Verify the signature.
	if !ed25519.Verify(pub, []byte(sigBase), sigBytes) {
		t.Errorf("ed25519.Verify failed: signature is not valid for the reconstructed signature base")
	}
}

// T-S03: Verify that modifying the request after signing invalidates the signature.
func TestSignSignatureInvalidAfterRequestChange(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}

	oldNow := nowFunc
	nowFunc = func() time.Time { return time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC) }
	defer func() { nowFunc = oldNow }()

	req, err := http.NewRequest("GET", "https://example.com/path?q=1", nil)
	if err != nil {
		t.Fatalf("creating request: %v", err)
	}

	if err := Sign(req, priv.Seed(), "org/bot"); err != nil {
		t.Fatalf("Sign returned error: %v", err)
	}

	// Extract the raw signature bytes.
	sigHeader := req.Header.Get("Signature")
	inner := strings.TrimPrefix(sigHeader, "sig1=:")
	inner = strings.TrimSuffix(inner, ":")
	sigBytes, err := base64.StdEncoding.DecodeString(inner)
	if err != nil {
		t.Fatalf("decoding signature base64: %v", err)
	}

	// Extract the sigParams from Signature-Input.
	sigInputHeader := req.Header.Get("Signature-Input")
	sigParams := strings.TrimPrefix(sigInputHeader, "sig1=")

	// Rebuild signature base with a DIFFERENT method (POST instead of GET).
	tamperedBase := "\"@method\": POST\n" +
		"\"@target-uri\": " + req.URL.String() + "\n" +
		"\"@authority\": " + req.URL.Host + "\n" +
		"\"@signature-params\": " + sigParams

	if ed25519.Verify(pub, []byte(tamperedBase), sigBytes) {
		t.Errorf("signature should not verify against tampered signature base")
	}
}

// T-S01: Verify signature base covers @method, @target-uri, @authority.
func TestSignCoversCorrectComponents(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}

	oldNow := nowFunc
	nowFunc = func() time.Time { return time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC) }
	defer func() { nowFunc = oldNow }()

	req, err := http.NewRequest("POST", "https://api.example.com/v1/resource?key=value", nil)
	if err != nil {
		t.Fatalf("creating request: %v", err)
	}

	if err := Sign(req, priv.Seed(), "myorg/mybot"); err != nil {
		t.Fatalf("Sign returned error: %v", err)
	}

	sigInput := req.Header.Get("Signature-Input")

	// The Signature-Input should declare all three derived components.
	if !strings.Contains(sigInput, "\"@method\"") {
		t.Errorf("Signature-Input missing @method component")
	}
	if !strings.Contains(sigInput, "\"@target-uri\"") {
		t.Errorf("Signature-Input missing @target-uri component")
	}
	if !strings.Contains(sigInput, "\"@authority\"") {
		t.Errorf("Signature-Input missing @authority component")
	}
}
