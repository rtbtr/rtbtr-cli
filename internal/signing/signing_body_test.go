package signing

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"
)

// T-S04: Sign with nil body preserves prior behavior — no Content-Digest header,
// and covered components include only @method, @target-uri, @authority.
func TestSignNilBodyNoContentDigest(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}

	oldNow := nowFunc
	nowFunc = func() time.Time { return time.Date(2026, 3, 20, 12, 0, 0, 0, time.UTC) }
	defer func() { nowFunc = oldNow }()

	req, err := http.NewRequestWithContext(context.Background(), "GET", "https://api.example.com/inbox?page=1", nil)
	if err != nil {
		t.Fatalf("creating request: %v", err)
	}

	if signErr := Sign(req, priv.Seed(), "org/bot", nil); signErr != nil {
		t.Fatalf("Sign returned error: %v", signErr)
	}

	// Content-Digest header must be absent when body is nil.
	if cd := req.Header.Get("Content-Digest"); cd != "" {
		t.Errorf("Content-Digest should be absent for nil body, got %q", cd)
	}

	// Signature-Input must NOT include "content-digest" in covered components.
	sigInput := req.Header.Get("Signature-Input")
	if sigInput == "" {
		t.Fatal("Signature-Input header is empty")
	}
	if strings.Contains(sigInput, "content-digest") {
		t.Errorf("Signature-Input should not contain content-digest for nil body: %q", sigInput)
	}

	// Signature must still include @method, @target-uri, @authority.
	for _, component := range []string{`"@method"`, `"@target-uri"`, `"@authority"`} {
		if !strings.Contains(sigInput, component) {
			t.Errorf("Signature-Input missing component %s: %q", component, sigInput)
		}
	}

	// Signature must be cryptographically valid.
	sigHeader := req.Header.Get("Signature")
	if sigHeader == "" {
		t.Fatal("Signature header is empty")
	}
	inner := strings.TrimPrefix(sigHeader, "sig1=:")
	inner = strings.TrimSuffix(inner, ":")
	sigBytes, decErr := base64.StdEncoding.DecodeString(inner)
	if decErr != nil {
		t.Fatalf("decoding signature: %v", decErr)
	}

	sigParams := strings.TrimPrefix(sigInput, "sig1=")
	sigBase := "\"@method\": " + req.Method + "\n" +
		"\"@target-uri\": " + req.URL.String() + "\n" +
		"\"@authority\": " + req.URL.Host + "\n" +
		"\"@signature-params\": " + sigParams

	if !ed25519.Verify(pub, []byte(sigBase), sigBytes) {
		t.Error("ed25519.Verify failed for nil-body signature")
	}
}

// T-S04: Sign with non-nil body sets Content-Digest header in sha-256=:<base64>: format.
func TestSignWithBodySetsContentDigest(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}

	oldNow := nowFunc
	nowFunc = func() time.Time { return time.Date(2026, 3, 20, 12, 0, 0, 0, time.UTC) }
	defer func() { nowFunc = oldNow }()

	body := []byte("hello")
	req, err := http.NewRequestWithContext(context.Background(), "POST", "https://api.example.com/orgs/o/bots/b/inbox", nil)
	if err != nil {
		t.Fatalf("creating request: %v", err)
	}

	if signErr := Sign(req, priv.Seed(), "org/bot", body); signErr != nil {
		t.Fatalf("Sign returned error: %v", signErr)
	}

	// Content-Digest header must be present.
	cd := req.Header.Get("Content-Digest")
	if cd == "" {
		t.Fatal("Content-Digest header is empty for non-nil body")
	}

	// Verify the Content-Digest format: sha-256=:<standard-base64(SHA-256(body))>:
	digest := sha256.Sum256(body)
	expectedDigest := fmt.Sprintf("sha-256=:%s:", base64.StdEncoding.EncodeToString(digest[:]))
	if cd != expectedDigest {
		t.Errorf("Content-Digest = %q, want %q", cd, expectedDigest)
	}
}

// T-S04: Sign with non-nil body includes "content-digest" in covered RFC 9421 components.
func TestSignWithBodyIncludesContentDigestInSignatureComponents(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}

	oldNow := nowFunc
	nowFunc = func() time.Time { return time.Date(2026, 3, 20, 12, 0, 0, 0, time.UTC) }
	defer func() { nowFunc = oldNow }()

	body := []byte(`{"message":"test"}`)
	req, err := http.NewRequestWithContext(context.Background(), "POST", "https://api.example.com/inbox", nil)
	if err != nil {
		t.Fatalf("creating request: %v", err)
	}

	if signErr := Sign(req, priv.Seed(), "org/bot", body); signErr != nil {
		t.Fatalf("Sign returned error: %v", signErr)
	}

	sigInput := req.Header.Get("Signature-Input")
	if sigInput == "" {
		t.Fatal("Signature-Input header is empty")
	}

	// Must include "content-digest" in covered components along with the standard three.
	for _, component := range []string{`"@method"`, `"@target-uri"`, `"@authority"`, `"content-digest"`} {
		if !strings.Contains(sigInput, component) {
			t.Errorf("Signature-Input missing component %s: %q", component, sigInput)
		}
	}
}

// T-S04: Sign with non-nil body produces a verifiable signature over the base including content-digest.
func TestSignWithBodyProducesVerifiableSignature(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}

	oldNow := nowFunc
	nowFunc = func() time.Time { return time.Date(2026, 3, 20, 12, 0, 0, 0, time.UTC) }
	defer func() { nowFunc = oldNow }()

	body := []byte(`{"encrypted_payload":"abc"}`)
	req, err := http.NewRequestWithContext(context.Background(), "POST", "https://api.example.com/orgs/org1/bots/bot1/inbox", nil)
	if err != nil {
		t.Fatalf("creating request: %v", err)
	}

	if signErr := Sign(req, priv.Seed(), "org1/bot1", body); signErr != nil {
		t.Fatalf("Sign returned error: %v", signErr)
	}

	// Extract signature bytes.
	sigHeader := req.Header.Get("Signature")
	inner := strings.TrimPrefix(sigHeader, "sig1=:")
	inner = strings.TrimSuffix(inner, ":")
	sigBytes, decErr := base64.StdEncoding.DecodeString(inner)
	if decErr != nil {
		t.Fatalf("decoding signature: %v", decErr)
	}

	// Extract Content-Digest.
	cd := req.Header.Get("Content-Digest")
	if cd == "" {
		t.Fatal("Content-Digest is empty")
	}

	// Extract sigParams.
	sigInput := req.Header.Get("Signature-Input")
	sigParams := strings.TrimPrefix(sigInput, "sig1=")

	// Reconstruct signature base including content-digest line.
	sigBase := "\"@method\": " + req.Method + "\n" +
		"\"@target-uri\": " + req.URL.String() + "\n" +
		"\"@authority\": " + req.URL.Host + "\n" +
		"\"content-digest\": " + cd + "\n" +
		"\"@signature-params\": " + sigParams

	if !ed25519.Verify(pub, []byte(sigBase), sigBytes) {
		t.Error("ed25519.Verify failed for body-signed request")
	}
}

// T-S04: Sign with empty body (non-nil but zero-length) still sets Content-Digest.
func TestSignWithEmptyBodySetsContentDigest(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}

	oldNow := nowFunc
	nowFunc = func() time.Time { return time.Date(2026, 3, 20, 12, 0, 0, 0, time.UTC) }
	defer func() { nowFunc = oldNow }()

	body := []byte{} // non-nil but empty
	req, err := http.NewRequestWithContext(context.Background(), "POST", "https://api.example.com/test", nil)
	if err != nil {
		t.Fatalf("creating request: %v", err)
	}

	if signErr := Sign(req, priv.Seed(), "org/bot", body); signErr != nil {
		t.Fatalf("Sign returned error: %v", signErr)
	}

	cd := req.Header.Get("Content-Digest")
	if cd == "" {
		t.Fatal("Content-Digest should be present for non-nil empty body")
	}

	// Verify the digest value is the SHA-256 of an empty byte slice.
	digest := sha256.Sum256(body)
	expectedDigest := fmt.Sprintf("sha-256=:%s:", base64.StdEncoding.EncodeToString(digest[:]))
	if cd != expectedDigest {
		t.Errorf("Content-Digest = %q, want %q", cd, expectedDigest)
	}

	// "content-digest" must be in covered components.
	sigInput := req.Header.Get("Signature-Input")
	if !strings.Contains(sigInput, `"content-digest"`) {
		t.Errorf("Signature-Input missing content-digest for non-nil empty body: %q", sigInput)
	}
}
