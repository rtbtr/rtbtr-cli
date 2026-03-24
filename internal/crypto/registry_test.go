package crypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// T-C02: FetchRecipientKey sends GET to correct path and returns decoded 32-byte public key.
func TestFetchRecipientKeySuccess(t *testing.T) {
	// Generate a real Ed25519 keypair for the response.
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	encodedPub := base64.RawURLEncoding.EncodeToString([]byte(pub))

	var capturedPath string
	var capturedMethod string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedPath = r.URL.Path
		capturedMethod = r.Method

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, `{"public_key":"%s","name":"testbot"}`, encodedPub)
	}))
	defer server.Close()

	result, err := FetchRecipientKey(server.URL, "testorg", "testbot")
	if err != nil {
		t.Fatalf("FetchRecipientKey returned error: %v", err)
	}

	// Verify the request path.
	if capturedMethod != "GET" {
		t.Errorf("method = %q, want GET", capturedMethod)
	}
	if capturedPath != "/orgs/testorg/bots/testbot" {
		t.Errorf("path = %q, want /orgs/testorg/bots/testbot", capturedPath)
	}

	// Verify the returned key matches the original 32-byte public key.
	if len(result) != 32 {
		t.Errorf("returned key length = %d, want 32", len(result))
	}
	if string(result) != string(pub) {
		t.Error("returned key does not match the expected Ed25519 public key")
	}
}

// T-C02: FetchRecipientKey returns error with "not found" on 404.
func TestFetchRecipientKey404(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`{"error":"not found"}`))
	}))
	defer server.Close()

	_, err := FetchRecipientKey(server.URL, "missingorg", "missingbot")
	if err == nil {
		t.Fatal("expected error for 404, got nil")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("error = %q, want it to contain 'not found'", err.Error())
	}
}

// T-C02: FetchRecipientKey returns error with "not found" when public_key field is missing.
func TestFetchRecipientKeyMissingPublicKeyField(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"name":"testbot"}`))
	}))
	defer server.Close()

	_, err := FetchRecipientKey(server.URL, "testorg", "testbot")
	if err == nil {
		t.Fatal("expected error when public_key field is missing, got nil")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("error = %q, want it to contain 'not found'", err.Error())
	}
}

// T-C02: FetchRecipientKey returns error when public_key is empty string.
func TestFetchRecipientKeyEmptyPublicKey(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"public_key":"","name":"testbot"}`))
	}))
	defer server.Close()

	_, err := FetchRecipientKey(server.URL, "testorg", "testbot")
	if err == nil {
		t.Fatal("expected error for empty public_key, got nil")
	}
}

// T-C02: FetchRecipientKey correctly URL-safe base64 decodes the public_key.
func TestFetchRecipientKeyBase64Decoding(t *testing.T) {
	// Create a key with characters that differ between standard and URL-safe base64.
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}

	// Encode with URL-safe no-padding encoding.
	encoded := base64.RawURLEncoding.EncodeToString([]byte(pub))

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, `{"public_key":"%s"}`, encoded)
	}))
	defer server.Close()

	result, err := FetchRecipientKey(server.URL, "org1", "bot1")
	if err != nil {
		t.Fatalf("FetchRecipientKey returned error: %v", err)
	}

	if len(result) != 32 {
		t.Errorf("decoded key length = %d, want 32", len(result))
	}
}

// T-C02: FetchRecipientKey handles server errors (non-404, non-200).
func TestFetchRecipientKeyServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`internal error`))
	}))
	defer server.Close()

	_, err := FetchRecipientKey(server.URL, "org", "bot")
	if err == nil {
		t.Fatal("expected error for 500 response, got nil")
	}
}
