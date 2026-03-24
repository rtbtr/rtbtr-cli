// Package signing implements RFC 9421 HTTP message signature helpers.
package signing

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"net/http"
	"time"
)

var nowFunc = time.Now

// Sign adds RFC 9421 Signature-Input and Signature headers to req.
func Sign(req *http.Request, seed []byte, keyID string) error {
	if len(seed) != ed25519.SeedSize {
		return fmt.Errorf("invalid Ed25519 seed length: got %d, want %d", len(seed), ed25519.SeedSize)
	}

	privKey := ed25519.NewKeyFromSeed(seed)
	created := nowFunc().Unix()
	sigParams := fmt.Sprintf("(\"@method\" \"@target-uri\" \"@authority\");created=%d;keyid=%q;alg=%q", created, keyID, "ed25519")
	sigBase := buildSignatureBase(req, sigParams)
	sig := ed25519.Sign(privKey, []byte(sigBase))

	req.Header.Set("Signature-Input", "sig1="+sigParams)
	req.Header.Set("Signature", "sig1=:"+base64.StdEncoding.EncodeToString(sig)+":")

	return nil
}

func buildSignatureBase(req *http.Request, sigParams string) string {
	return fmt.Sprintf("\"@method\": %s\n\"@target-uri\": %s\n\"@authority\": %s\n\"@signature-params\": %s", req.Method, req.URL.String(), req.URL.Host, sigParams)
}
