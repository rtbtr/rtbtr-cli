package crypto

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

var httpClient = &http.Client{Timeout: 30 * time.Second}

type recipientProfile struct {
	PublicKey string `json:"public_key"`
}

// FetchRecipientKey fetches a bot profile and returns its Ed25519 public key.
func FetchRecipientKey(baseURL, org, bot string) ([]byte, error) {
	requestURL := fmt.Sprintf("%s/orgs/%s/bots/%s", strings.TrimRight(baseURL, "/"), org, bot)
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, requestURL, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetching recipient profile: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("recipient %s/%s not found", org, bot)
	}
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return nil, fmt.Errorf("fetch recipient key failed: %s", resp.Status)
	}

	var profile recipientProfile
	if decodeErr := json.NewDecoder(resp.Body).Decode(&profile); decodeErr != nil {
		return nil, fmt.Errorf("decoding recipient profile: %w", decodeErr)
	}
	if profile.PublicKey == "" {
		return nil, fmt.Errorf("recipient %s/%s not found: public_key missing", org, bot)
	}

	key, err := base64.RawURLEncoding.DecodeString(profile.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("decoding recipient public key: %w", err)
	}
	if len(key) != x25519KeySize {
		return nil, fmt.Errorf("invalid recipient public key length: got %d, want %d", len(key), x25519KeySize)
	}

	return key, nil
}
