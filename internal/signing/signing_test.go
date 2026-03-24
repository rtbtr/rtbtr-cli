package signing

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"
)

// T-S01: Sign sets Signature-Input header with correct RFC 9421 structure.
func TestSignSetsSignatureInputWithRFC9421Format(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}

	oldNow := nowFunc
	nowFunc = func() time.Time { return time.Date(2026, 3, 15, 10, 0, 0, 0, time.UTC) }
	defer func() { nowFunc = oldNow }()

	req, err := http.NewRequestWithContext(context.Background(), "GET", "https://api.example.com/inbox?page=1", nil)
	if err != nil {
		t.Fatalf("creating request: %v", err)
	}

	if signErr := Sign(req, priv.Seed(), "myorg/mybot"); signErr != nil {
		t.Fatalf("Sign returned error: %v", signErr)
	}

	sigInput := req.Header.Get("Signature-Input")
	if sigInput == "" {
		t.Fatal("Signature-Input header is empty")
	}

	// Must start with "sig1=" followed by the covered components list.
	if !strings.HasPrefix(sigInput, "sig1=(") {
		t.Errorf("Signature-Input = %q, want prefix 'sig1=('", sigInput)
	}

	// Must declare all three derived components.
	for _, component := range []string{`"@method"`, `"@target-uri"`, `"@authority"`} {
		if !strings.Contains(sigInput, component) {
			t.Errorf("Signature-Input missing component %s: %q", component, sigInput)
		}
	}

	// Must include created parameter with a Unix timestamp.
	if !strings.Contains(sigInput, "created=") {
		t.Errorf("Signature-Input missing 'created=' parameter: %q", sigInput)
	}

	// Must include the correct keyid.
	if !strings.Contains(sigInput, `keyid="myorg/mybot"`) {
		t.Errorf("Signature-Input missing keyid=\"myorg/mybot\": %q", sigInput)
	}

	// Must include the alg parameter as ed25519.
	if !strings.Contains(sigInput, `alg="ed25519"`) {
		t.Errorf("Signature-Input missing alg=\"ed25519\": %q", sigInput)
	}
}

// T-S01: Sign sets Signature header with byte-sequence syntax wrapping.
func TestSignSetsSignatureWithColonWrappedBase64(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}

	oldNow := nowFunc
	nowFunc = func() time.Time { return time.Date(2026, 3, 15, 10, 0, 0, 0, time.UTC) }
	defer func() { nowFunc = oldNow }()

	req, err := http.NewRequestWithContext(context.Background(), "GET", "https://api.example.com/test", nil)
	if err != nil {
		t.Fatalf("creating request: %v", err)
	}

	if signErr := Sign(req, priv.Seed(), "org/bot"); signErr != nil {
		t.Fatalf("Sign returned error: %v", signErr)
	}

	sig := req.Header.Get("Signature")
	if sig == "" {
		t.Fatal("Signature header is empty")
	}

	// Must start with "sig1=:" (Structured Fields byte-sequence prefix).
	if !strings.HasPrefix(sig, "sig1=:") {
		t.Errorf("Signature = %q, want prefix 'sig1=:'", sig)
	}

	// Must end with ":" (Structured Fields byte-sequence suffix).
	if !strings.HasSuffix(sig, ":") {
		t.Errorf("Signature = %q, want suffix ':'", sig)
	}

	// The content between the colons must be valid standard base64.
	inner := strings.TrimPrefix(sig, "sig1=:")
	inner = strings.TrimSuffix(inner, ":")
	decoded, decErr := base64.StdEncoding.DecodeString(inner)
	if decErr != nil {
		t.Fatalf("Signature base64 decode failed: %v (raw: %q)", decErr, inner)
	}

	// Ed25519 signatures are 64 bytes.
	if len(decoded) != ed25519.SignatureSize {
		t.Errorf("decoded signature length = %d, want %d", len(decoded), ed25519.SignatureSize)
	}
}

// T-S01: Sign uses injected timestamp in the Signature-Input created parameter.
func TestSignCreatedTimestampReflectsInjectedTime(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}

	fixedTime := time.Date(2026, 7, 4, 18, 30, 0, 0, time.UTC)
	expectedUnix := fixedTime.Unix()

	oldNow := nowFunc
	nowFunc = func() time.Time { return fixedTime }
	defer func() { nowFunc = oldNow }()

	req, err := http.NewRequestWithContext(context.Background(), "GET", "https://example.com/path", nil)
	if err != nil {
		t.Fatalf("creating request: %v", err)
	}

	if signErr := Sign(req, priv.Seed(), "org/bot"); signErr != nil {
		t.Fatalf("Sign returned error: %v", signErr)
	}

	sigInput := req.Header.Get("Signature-Input")
	expectedCreated := fmt.Sprintf("created=%d", expectedUnix)
	if !strings.Contains(sigInput, expectedCreated) {
		t.Errorf("Signature-Input = %q, want it to contain %q", sigInput, expectedCreated)
	}
}

// T-S02: Sign returns error for seed with incorrect length.
func TestSignReturnsErrorForWrongSeedLength(t *testing.T) {
	req, err := http.NewRequestWithContext(context.Background(), "GET", "https://example.com/test", nil)
	if err != nil {
		t.Fatalf("creating request: %v", err)
	}

	// 16-byte seed (too short).
	shortSeed := make([]byte, 16)
	if signErr := Sign(req, shortSeed, "org/bot"); signErr == nil {
		t.Error("Sign should return error for 16-byte seed, got nil")
	}

	// 64-byte seed (too long).
	longSeed := make([]byte, 64)
	if signErr := Sign(req, longSeed, "org/bot"); signErr == nil {
		t.Error("Sign should return error for 64-byte seed, got nil")
	}

	// Empty seed.
	if signErr := Sign(req, []byte{}, "org/bot"); signErr == nil {
		t.Error("Sign should return error for empty seed, got nil")
	}

	// Nil seed.
	if signErr := Sign(req, nil, "org/bot"); signErr == nil {
		t.Error("Sign should return error for nil seed, got nil")
	}
}

// T-S02: Sign succeeds for exactly 32-byte seed.
func TestSignSucceedsForValid32ByteSeed(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}

	oldNow := nowFunc
	nowFunc = func() time.Time { return time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC) }
	defer func() { nowFunc = oldNow }()

	req, err := http.NewRequestWithContext(context.Background(), "GET", "https://example.com/test", nil)
	if err != nil {
		t.Fatalf("creating request: %v", err)
	}

	seed := priv.Seed()
	if len(seed) != 32 {
		t.Fatalf("expected 32-byte seed, got %d", len(seed))
	}

	if signErr := Sign(req, seed, "org/bot"); signErr != nil {
		t.Errorf("Sign returned unexpected error for 32-byte seed: %v", signErr)
	}
}

// T-S02: Sign does not set headers on the request when seed is invalid.
func TestSignDoesNotSetHeadersOnInvalidSeed(t *testing.T) {
	req, err := http.NewRequestWithContext(context.Background(), "GET", "https://example.com/test", nil)
	if err != nil {
		t.Fatalf("creating request: %v", err)
	}

	badSeed := make([]byte, 10)
	_ = Sign(req, badSeed, "org/bot")

	if h := req.Header.Get("Signature-Input"); h != "" {
		t.Errorf("Signature-Input header should be empty after failed Sign, got %q", h)
	}
	if h := req.Header.Get("Signature"); h != "" {
		t.Errorf("Signature header should be empty after failed Sign, got %q", h)
	}
}

// T-S03: The signature produced by Sign is cryptographically verifiable.
func TestSignProducesVerifiableEd25519Signature(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}

	oldNow := nowFunc
	nowFunc = func() time.Time { return time.Date(2026, 2, 14, 12, 0, 0, 0, time.UTC) }
	defer func() { nowFunc = oldNow }()

	req, err := http.NewRequestWithContext(context.Background(), "GET", "https://api.example.com/orgs/org1/bots/bot1/inbox?page=1&limit=20", nil)
	if err != nil {
		t.Fatalf("creating request: %v", err)
	}

	if signErr := Sign(req, priv.Seed(), "org1/bot1"); signErr != nil {
		t.Fatalf("Sign returned error: %v", signErr)
	}

	// Extract the base64-encoded signature from the Signature header.
	sigHeader := req.Header.Get("Signature")
	if sigHeader == "" {
		t.Fatal("Signature header is empty")
	}
	inner := strings.TrimPrefix(sigHeader, "sig1=:")
	inner = strings.TrimSuffix(inner, ":")
	sigBytes, decErr := base64.StdEncoding.DecodeString(inner)
	if decErr != nil {
		t.Fatalf("decoding signature base64: %v", decErr)
	}

	// Extract sigParams from Signature-Input header.
	sigInputHeader := req.Header.Get("Signature-Input")
	if sigInputHeader == "" {
		t.Fatal("Signature-Input header is empty")
	}
	sigParams := strings.TrimPrefix(sigInputHeader, "sig1=")

	// Rebuild the signature base per RFC 9421.
	sigBase := "\"@method\": " + req.Method + "\n" +
		"\"@target-uri\": " + req.URL.String() + "\n" +
		"\"@authority\": " + req.URL.Host + "\n" +
		"\"@signature-params\": " + sigParams

	if !ed25519.Verify(pub, []byte(sigBase), sigBytes) {
		t.Errorf("ed25519.Verify failed: signature is not valid for the reconstructed signature base")
	}
}

// T-S03: The signature is invalid when the request is tampered with after signing.
func TestSignSignatureInvalidWhenRequestTampered(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}

	oldNow := nowFunc
	nowFunc = func() time.Time { return time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC) }
	defer func() { nowFunc = oldNow }()

	req, err := http.NewRequestWithContext(context.Background(), "GET", "https://example.com/path?q=1", nil)
	if err != nil {
		t.Fatalf("creating request: %v", err)
	}

	if signErr := Sign(req, priv.Seed(), "org/bot"); signErr != nil {
		t.Fatalf("Sign returned error: %v", signErr)
	}

	// Extract signature bytes.
	sigHeader := req.Header.Get("Signature")
	inner := strings.TrimPrefix(sigHeader, "sig1=:")
	inner = strings.TrimSuffix(inner, ":")
	sigBytes, decErr := base64.StdEncoding.DecodeString(inner)
	if decErr != nil {
		t.Fatalf("decoding signature base64: %v", decErr)
	}

	// Extract sigParams from Signature-Input.
	sigInputHeader := req.Header.Get("Signature-Input")
	sigParams := strings.TrimPrefix(sigInputHeader, "sig1=")

	// Rebuild signature base with tampered method (POST instead of GET).
	tamperedBase := "\"@method\": POST\n" +
		"\"@target-uri\": " + req.URL.String() + "\n" +
		"\"@authority\": " + req.URL.Host + "\n" +
		"\"@signature-params\": " + sigParams

	if ed25519.Verify(pub, []byte(tamperedBase), sigBytes) {
		t.Errorf("signature should not verify against tampered signature base")
	}
}

// T-S03: Signing with a different key does not verify with the original public key.
func TestSignDifferentKeyDoesNotVerify(t *testing.T) {
	pub1, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating key 1: %v", err)
	}
	_, priv2, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating key 2: %v", err)
	}

	oldNow := nowFunc
	nowFunc = func() time.Time { return time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC) }
	defer func() { nowFunc = oldNow }()

	req, err := http.NewRequestWithContext(context.Background(), "GET", "https://example.com/test", nil)
	if err != nil {
		t.Fatalf("creating request: %v", err)
	}

	// Sign with key 2.
	if signErr := Sign(req, priv2.Seed(), "org/bot"); signErr != nil {
		t.Fatalf("Sign returned error: %v", signErr)
	}

	// Extract the signature.
	sigHeader := req.Header.Get("Signature")
	inner := strings.TrimPrefix(sigHeader, "sig1=:")
	inner = strings.TrimSuffix(inner, ":")
	sigBytes, decErr := base64.StdEncoding.DecodeString(inner)
	if decErr != nil {
		t.Fatalf("decoding signature: %v", decErr)
	}

	// Reconstruct the signature base.
	sigInputHeader := req.Header.Get("Signature-Input")
	sigParams := strings.TrimPrefix(sigInputHeader, "sig1=")
	sigBase := "\"@method\": " + req.Method + "\n" +
		"\"@target-uri\": " + req.URL.String() + "\n" +
		"\"@authority\": " + req.URL.Host + "\n" +
		"\"@signature-params\": " + sigParams

	// Verify with key 1's public key should fail.
	if ed25519.Verify(pub1, []byte(sigBase), sigBytes) {
		t.Errorf("signature signed with key 2 should not verify with key 1's public key")
	}
}

// T-S01: Sign covers @method, @target-uri, and @authority with a non-GET method.
func TestSignCoversMethodTargetUriAuthority(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}

	oldNow := nowFunc
	nowFunc = func() time.Time { return time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC) }
	defer func() { nowFunc = oldNow }()

	req, err := http.NewRequestWithContext(context.Background(), "POST", "https://api.example.com/v2/resource?key=value", nil)
	if err != nil {
		t.Fatalf("creating request: %v", err)
	}

	if signErr := Sign(req, priv.Seed(), "testorg/testbot"); signErr != nil {
		t.Fatalf("Sign returned error: %v", signErr)
	}

	sigInput := req.Header.Get("Signature-Input")
	if !strings.Contains(sigInput, `"@method"`) {
		t.Errorf("Signature-Input missing @method component: %q", sigInput)
	}
	if !strings.Contains(sigInput, `"@target-uri"`) {
		t.Errorf("Signature-Input missing @target-uri component: %q", sigInput)
	}
	if !strings.Contains(sigInput, `"@authority"`) {
		t.Errorf("Signature-Input missing @authority component: %q", sigInput)
	}
}
