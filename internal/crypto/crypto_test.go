package crypto

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"testing"
)

// T-C01: DeriveX25519KeyPair accepts 32-byte Ed25519 seed and returns 32-byte keys.
func TestDeriveX25519KeyPairValidSeed(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	seed := priv.Seed()

	privKey, pubKey, err := DeriveX25519KeyPair(seed)
	if err != nil {
		t.Fatalf("DeriveX25519KeyPair returned error: %v", err)
	}

	if len(privKey) != 32 {
		t.Errorf("private key length = %d, want 32", len(privKey))
	}
	if len(pubKey) != 32 {
		t.Errorf("public key length = %d, want 32", len(pubKey))
	}
}

// T-C01: DeriveX25519KeyPair is deterministic — same seed yields same output.
func TestDeriveX25519KeyPairDeterministic(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	seed := priv.Seed()

	priv1, pub1, err := DeriveX25519KeyPair(seed)
	if err != nil {
		t.Fatalf("first call: %v", err)
	}

	priv2, pub2, err := DeriveX25519KeyPair(seed)
	if err != nil {
		t.Fatalf("second call: %v", err)
	}

	if !bytes.Equal(priv1, priv2) {
		t.Error("private keys differ for same seed")
	}
	if !bytes.Equal(pub1, pub2) {
		t.Error("public keys differ for same seed")
	}
}

// T-C01: DeriveX25519KeyPair clamps private key bits per RFC 7748.
func TestDeriveX25519KeyPairClamping(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	seed := priv.Seed()

	privKey, _, err := DeriveX25519KeyPair(seed)
	if err != nil {
		t.Fatalf("DeriveX25519KeyPair returned error: %v", err)
	}

	// RFC 7748 clamping: bits 0-2 of first byte are cleared.
	if privKey[0]&7 != 0 {
		t.Errorf("private key byte[0] = 0x%02x, bits 0-2 should be cleared (val & 7 == 0)", privKey[0])
	}

	// Bit 7 of last byte is cleared.
	if privKey[31]&128 != 0 {
		t.Errorf("private key byte[31] = 0x%02x, bit 7 should be cleared", privKey[31])
	}

	// Bit 6 of last byte is set.
	if privKey[31]&64 == 0 {
		t.Errorf("private key byte[31] = 0x%02x, bit 6 should be set", privKey[31])
	}
}

// T-C01: DeriveX25519KeyPair rejects invalid seed lengths.
func TestDeriveX25519KeyPairRejectsInvalidLength(t *testing.T) {
	// Too short.
	_, _, err := DeriveX25519KeyPair(make([]byte, 16))
	if err == nil {
		t.Error("expected error for 16-byte seed, got nil")
	}

	// Empty.
	_, _, err = DeriveX25519KeyPair([]byte{})
	if err == nil {
		t.Error("expected error for empty seed, got nil")
	}

	// Nil.
	_, _, err = DeriveX25519KeyPair(nil)
	if err == nil {
		t.Error("expected error for nil seed, got nil")
	}

	// Too long.
	_, _, err = DeriveX25519KeyPair(make([]byte, 64))
	if err == nil {
		t.Error("expected error for 64-byte seed, got nil")
	}
}

// T-C03: Encrypt produces non-empty ciphertext and 32-byte ephemeral key.
func TestEncryptProducesValidOutput(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}

	_, pubKey, err := DeriveX25519KeyPair(priv.Seed())
	if err != nil {
		t.Fatalf("DeriveX25519KeyPair: %v", err)
	}

	plaintext := []byte("hello, encrypted world")
	ciphertext, ephPub, err := Encrypt(plaintext, pubKey)
	if err != nil {
		t.Fatalf("Encrypt returned error: %v", err)
	}

	// Ciphertext must include at least 12-byte nonce + 16-byte tag = 28 bytes minimum.
	if len(ciphertext) < 28 {
		t.Errorf("ciphertext length = %d, want >= 28", len(ciphertext))
	}

	// Ephemeral public key must be 32 bytes.
	if len(ephPub) != 32 {
		t.Errorf("ephemeral public key length = %d, want 32", len(ephPub))
	}
}

// T-C03: Encrypt output is decryptable.
func TestEncryptDecryptRoundtrip(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}

	privKey, pubKey, err := DeriveX25519KeyPair(priv.Seed())
	if err != nil {
		t.Fatalf("DeriveX25519KeyPair: %v", err)
	}

	plaintext := []byte("roundtrip test message")
	ciphertext, ephPub, err := Encrypt(plaintext, pubKey)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	decrypted, err := Decrypt(ciphertext, ephPub, privKey)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}

	if !bytes.Equal(decrypted, plaintext) {
		t.Errorf("decrypted = %q, want %q", decrypted, plaintext)
	}
}

// T-C03: Encrypt is non-deterministic — same plaintext yields different ciphertext.
func TestEncryptNonDeterministic(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}

	_, pubKey, err := DeriveX25519KeyPair(priv.Seed())
	if err != nil {
		t.Fatalf("DeriveX25519KeyPair: %v", err)
	}

	plaintext := []byte("same message")

	ct1, eph1, err := Encrypt(plaintext, pubKey)
	if err != nil {
		t.Fatalf("first Encrypt: %v", err)
	}

	ct2, eph2, err := Encrypt(plaintext, pubKey)
	if err != nil {
		t.Fatalf("second Encrypt: %v", err)
	}

	if bytes.Equal(ct1, ct2) {
		t.Error("two encryptions of same plaintext produced identical ciphertext")
	}

	if bytes.Equal(eph1, eph2) {
		t.Error("two encryptions produced identical ephemeral public keys")
	}
}

// T-C03: Encrypt rejects invalid-length recipient key.
func TestEncryptRejectsInvalidRecipientKey(t *testing.T) {
	_, _, err := Encrypt([]byte("test"), make([]byte, 16))
	if err == nil {
		t.Error("expected error for invalid-length recipient key, got nil")
	}
}

// T-C04: Decrypt correctly decrypts valid ciphertext.
func TestDecryptValidCiphertext(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}

	privKey, pubKey, err := DeriveX25519KeyPair(priv.Seed())
	if err != nil {
		t.Fatalf("DeriveX25519KeyPair: %v", err)
	}

	plaintext := []byte("decrypt test")
	ciphertext, ephPub, err := Encrypt(plaintext, pubKey)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	result, err := Decrypt(ciphertext, ephPub, privKey)
	if err != nil {
		t.Fatalf("Decrypt returned error: %v", err)
	}

	if !bytes.Equal(result, plaintext) {
		t.Errorf("decrypted = %q, want %q", result, plaintext)
	}
}

// T-C04: Decrypt rejects ciphertext shorter than 28 bytes.
func TestDecryptRejectsShortCiphertext(t *testing.T) {
	_, err := Decrypt(make([]byte, 27), make([]byte, 32), make([]byte, 32))
	if err == nil {
		t.Error("expected error for short ciphertext (27 bytes), got nil")
	}

	_, err = Decrypt(make([]byte, 10), make([]byte, 32), make([]byte, 32))
	if err == nil {
		t.Error("expected error for short ciphertext (10 bytes), got nil")
	}

	_, err = Decrypt(nil, make([]byte, 32), make([]byte, 32))
	if err == nil {
		t.Error("expected error for nil ciphertext, got nil")
	}
}

// T-C04: Decrypt rejects when wrong private key is used.
func TestDecryptRejectsWrongPrivateKey(t *testing.T) {
	_, priv1, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating key 1: %v", err)
	}
	_, pubKey1, err := DeriveX25519KeyPair(priv1.Seed())
	if err != nil {
		t.Fatalf("DeriveX25519KeyPair 1: %v", err)
	}

	_, priv2, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating key 2: %v", err)
	}
	privKey2, _, err := DeriveX25519KeyPair(priv2.Seed())
	if err != nil {
		t.Fatalf("DeriveX25519KeyPair 2: %v", err)
	}

	plaintext := []byte("secret for key 1")
	ciphertext, ephPub, err := Encrypt(plaintext, pubKey1)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	// Attempt decryption with key 2's private key.
	_, err = Decrypt(ciphertext, ephPub, privKey2)
	if err == nil {
		t.Error("expected error when decrypting with wrong private key, got nil")
	}
}

// T-C04: Decrypt rejects tampered ciphertext.
func TestDecryptRejectsTamperedCiphertext(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}

	privKey, pubKey, err := DeriveX25519KeyPair(priv.Seed())
	if err != nil {
		t.Fatalf("DeriveX25519KeyPair: %v", err)
	}

	plaintext := []byte("tamper test message")
	ciphertext, ephPub, err := Encrypt(plaintext, pubKey)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	// Flip a byte in the middle of the ciphertext.
	tampered := make([]byte, len(ciphertext))
	copy(tampered, ciphertext)
	midpoint := len(tampered) / 2
	tampered[midpoint] ^= 0xFF

	_, err = Decrypt(tampered, ephPub, privKey)
	if err == nil {
		t.Error("expected error for tampered ciphertext, got nil")
	}
}

// T-C04: Decrypt rejects wrong ephemeral public key.
func TestDecryptRejectsWrongEphemeralKey(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}

	privKey, pubKey, err := DeriveX25519KeyPair(priv.Seed())
	if err != nil {
		t.Fatalf("DeriveX25519KeyPair: %v", err)
	}

	plaintext := []byte("wrong eph key test")
	ciphertext, _, err := Encrypt(plaintext, pubKey)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	// Use a random 32-byte value as the wrong ephemeral public key.
	wrongEph := make([]byte, 32)
	if _, randErr := rand.Read(wrongEph); randErr != nil {
		t.Fatalf("generating random bytes: %v", randErr)
	}

	_, err = Decrypt(ciphertext, wrongEph, privKey)
	if err == nil {
		t.Error("expected error when decrypting with wrong ephemeral public key, got nil")
	}
}

// T-C05: Ed25519PublicToX25519 converts 32-byte Ed25519 public key to 32-byte X25519 key.
func TestEd25519PublicToX25519ValidKey(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}

	x25519Pub, err := Ed25519PublicToX25519([]byte(pub))
	if err != nil {
		t.Fatalf("Ed25519PublicToX25519 returned error: %v", err)
	}

	if len(x25519Pub) != 32 {
		t.Errorf("X25519 public key length = %d, want 32", len(x25519Pub))
	}
}

// T-C05: Ed25519PublicToX25519 result matches DeriveX25519KeyPair's public key for the same seed.
func TestEd25519PublicToX25519ConsistentWithDeriveKeyPair(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}

	// Convert Ed25519 public key to X25519.
	x25519FromEd, err := Ed25519PublicToX25519([]byte(pub))
	if err != nil {
		t.Fatalf("Ed25519PublicToX25519: %v", err)
	}

	// Derive X25519 key pair from the same seed.
	_, x25519FromSeed, err := DeriveX25519KeyPair(priv.Seed())
	if err != nil {
		t.Fatalf("DeriveX25519KeyPair: %v", err)
	}

	if !bytes.Equal(x25519FromEd, x25519FromSeed) {
		t.Errorf("Ed25519PublicToX25519 result does not match DeriveX25519KeyPair public key")
	}
}

// T-C05: Ed25519PublicToX25519 rejects invalid input length.
func TestEd25519PublicToX25519RejectsInvalidLength(t *testing.T) {
	_, err := Ed25519PublicToX25519(make([]byte, 16))
	if err == nil {
		t.Error("expected error for 16-byte input, got nil")
	}

	_, err = Ed25519PublicToX25519([]byte{})
	if err == nil {
		t.Error("expected error for empty input, got nil")
	}

	_, err = Ed25519PublicToX25519(nil)
	if err == nil {
		t.Error("expected error for nil input, got nil")
	}
}

// T-C03/C04: Encrypt/Decrypt roundtrip with large payload.
func TestEncryptDecryptLargePayload(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}

	privKey, pubKey, err := DeriveX25519KeyPair(priv.Seed())
	if err != nil {
		t.Fatalf("DeriveX25519KeyPair: %v", err)
	}

	// 1MB payload.
	plaintext := make([]byte, 1<<20)
	if _, randErr := rand.Read(plaintext); randErr != nil {
		t.Fatalf("generating random plaintext: %v", randErr)
	}

	ciphertext, ephPub, err := Encrypt(plaintext, pubKey)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	decrypted, err := Decrypt(ciphertext, ephPub, privKey)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}

	if !bytes.Equal(decrypted, plaintext) {
		t.Error("decrypted large payload does not match original")
	}
}
