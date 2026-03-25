// Package signing implements RFC 9421 HTTP message signature helpers.
package signing

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/http"
	"time"
)

// nowFunc returns the current time. Overridden in tests for deterministic timestamps.
var nowFunc = time.Now

// Sign adds RFC 9421 Signature-Input and Signature headers to req.
func Sign(req *http.Request, seed []byte, keyID string, body []byte) error {
	if len(seed) != ed25519.SeedSize {
		return fmt.Errorf("invalid Ed25519 seed length: got %d, want %d", len(seed), ed25519.SeedSize)
	}

	privKey := ed25519.NewKeyFromSeed(seed)
	created := nowFunc().Unix()
	nonce, err := generateNonce()
	if err != nil {
		return fmt.Errorf("generating nonce: %w", err)
	}

	coveredComponents := "\"@method\" \"@target-uri\" \"@authority\""
	contentDigest := ""
	if body != nil {
		digest := sha256.Sum256(body)
		contentDigest = fmt.Sprintf("sha-256=:%s:", base64.StdEncoding.EncodeToString(digest[:]))
		req.Header.Set("Content-Digest", contentDigest)
		coveredComponents += " \"content-digest\""
	}

	sigParams := fmt.Sprintf("(%s);created=%d;nonce=%q;keyid=%q;alg=%q", coveredComponents, created, nonce, keyID, "ed25519")
	sigBase := buildSignatureBase(req, sigParams, contentDigest)
	sig := ed25519.Sign(privKey, []byte(sigBase))

	req.Header.Set("Signature-Input", "sig1="+sigParams)
	req.Header.Set("Signature", "sig1=:"+base64.StdEncoding.EncodeToString(sig)+":")

	return nil
}

func generateNonce() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func buildSignatureBase(req *http.Request, sigParams, contentDigest string) string {
	sigBase := fmt.Sprintf("\"@method\": %s\n\"@target-uri\": %s\n\"@authority\": %s\n", req.Method, req.URL.String(), req.URL.Host)
	if contentDigest != "" {
		sigBase += fmt.Sprintf("\"content-digest\": %s\n", contentDigest)
	}
	return sigBase + fmt.Sprintf("\"@signature-params\": %s", sigParams)
}
