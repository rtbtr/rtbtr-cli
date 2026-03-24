// Package crypto provides X25519 key derivation, Ed25519-to-X25519 conversion,
// and envelope encryption/decryption for rtbtr messaging.
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"io"

	"filippo.io/edwards25519"
	"golang.org/x/crypto/hkdf"
)

const (
	x25519KeySize  = 32
	aeadNonceSize  = 12
	aeadTagSize    = 16
	hkdfInfoString = "rtbtr-v1"
)

// DeriveX25519KeyPair deterministically derives an X25519 keypair from a
// 32-byte Ed25519 seed.
func DeriveX25519KeyPair(ed25519Seed []byte) (privateKey, publicKey []byte, err error) {
	if len(ed25519Seed) != x25519KeySize {
		return nil, nil, fmt.Errorf("invalid Ed25519 seed length: got %d, want %d", len(ed25519Seed), x25519KeySize)
	}

	h := sha512.Sum512(ed25519Seed)
	h[0] &= 248
	h[31] &= 127
	h[31] |= 64

	priv, err := ecdh.X25519().NewPrivateKey(h[:32])
	if err != nil {
		return nil, nil, fmt.Errorf("creating X25519 private key: %w", err)
	}

	return priv.Bytes(), priv.PublicKey().Bytes(), nil
}

// Ed25519PublicToX25519 converts a 32-byte Ed25519 public key to the
// corresponding X25519 public key.
func Ed25519PublicToX25519(ed25519Public []byte) ([]byte, error) {
	if len(ed25519Public) != x25519KeySize {
		return nil, fmt.Errorf("invalid Ed25519 public key length: got %d, want %d", len(ed25519Public), x25519KeySize)
	}

	point, err := new(edwards25519.Point).SetBytes(ed25519Public)
	if err != nil {
		return nil, fmt.Errorf("parsing Ed25519 public key: %w", err)
	}

	return point.BytesMontgomery(), nil
}

// Encrypt performs X25519 ECDH + HKDF-SHA256 key agreement and seals plaintext
// with AES-256-GCM. The returned ciphertext is nonce || ciphertext || tag.
func Encrypt(plaintext, recipientX25519Public []byte) (ciphertext, ephemeralPublic []byte, err error) {
	recipientPub, err := ecdh.X25519().NewPublicKey(recipientX25519Public)
	if err != nil {
		return nil, nil, fmt.Errorf("parsing recipient X25519 public key: %w", err)
	}

	eph, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generating ephemeral X25519 key: %w", err)
	}

	shared, err := eph.ECDH(recipientPub)
	if err != nil {
		return nil, nil, fmt.Errorf("performing X25519 ECDH: %w", err)
	}

	key, err := deriveAEADKey(shared)
	if err != nil {
		return nil, nil, err
	}

	gcm, err := newGCM(key)
	if err != nil {
		return nil, nil, err
	}

	nonce := make([]byte, aeadNonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, fmt.Errorf("generating AES-GCM nonce: %w", err)
	}

	sealed := gcm.Seal(nonce, nonce, plaintext, nil)
	return sealed, eph.PublicKey().Bytes(), nil
}

// Decrypt reverses Encrypt using the recipient's X25519 private key.
func Decrypt(ciphertext, ephemeralPublic, recipientX25519Private []byte) ([]byte, error) {
	if len(ciphertext) < aeadNonceSize+aeadTagSize {
		return nil, fmt.Errorf("ciphertext too short: got %d bytes, want at least %d", len(ciphertext), aeadNonceSize+aeadTagSize)
	}

	ephPub, err := ecdh.X25519().NewPublicKey(ephemeralPublic)
	if err != nil {
		return nil, fmt.Errorf("parsing ephemeral X25519 public key: %w", err)
	}

	priv, err := ecdh.X25519().NewPrivateKey(recipientX25519Private)
	if err != nil {
		return nil, fmt.Errorf("parsing recipient X25519 private key: %w", err)
	}

	shared, err := priv.ECDH(ephPub)
	if err != nil {
		return nil, fmt.Errorf("performing X25519 ECDH: %w", err)
	}

	key, err := deriveAEADKey(shared)
	if err != nil {
		return nil, err
	}

	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}

	nonce := ciphertext[:aeadNonceSize]
	sealed := ciphertext[aeadNonceSize:]
	plaintext, err := gcm.Open(nil, nonce, sealed, nil)
	if err != nil {
		return nil, fmt.Errorf("decrypting payload: %w", err)
	}

	return plaintext, nil
}

func deriveAEADKey(shared []byte) ([]byte, error) {
	key := make([]byte, 32)
	if _, err := io.ReadFull(hkdf.New(sha256.New, shared, nil, []byte(hkdfInfoString)), key); err != nil {
		return nil, fmt.Errorf("deriving AES-256-GCM key: %w", err)
	}
	return key, nil
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("creating AES-256 block cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("creating AES-GCM cipher: %w", err)
	}

	return gcm, nil
}
