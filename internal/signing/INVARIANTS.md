# Signing Invariants

- [untested] S-01: signing.Sign(req *http.Request, seed []byte, keyID string) error adds Signature-Input and Signature headers to req conforming to RFC 9421. The signature base covers the @method, @target-uri, and @authority derived components. The Signature-Input header uses parameters created (Unix timestamp), keyid (the provided keyID), and alg ("ed25519"). The Signature header value is a standard base64-encoded Ed25519 signature of the signature base, wrapped in colons per Structured Fields byte-sequence syntax.
- [untested] S-02: signing.Sign returns a non-nil error if the seed length is not exactly 32 bytes (ed25519.SeedSize).
- [untested] S-03: The Ed25519 signature produced by signing.Sign is verifiable: given the same request and the corresponding public key, reconstructing the signature base from the Signature-Input header and verifying with ed25519.Verify succeeds.
