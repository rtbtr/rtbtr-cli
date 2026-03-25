package selfupdate

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCheckForUpdateReturnsNilForDev(t *testing.T) {
	if info := CheckForUpdate(context.Background(), "dev"); info != nil {
		t.Errorf("expected nil for dev version, got %+v", info)
	}
}

func TestCheckForUpdateReturnsNilForInvalidSemver(t *testing.T) {
	if info := CheckForUpdate(context.Background(), "abc123"); info != nil {
		t.Errorf("expected nil for invalid semver, got %+v", info)
	}
}

func TestCheckForUpdateReturnsNilWhenUpToDate(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"tag_name":"v1.0.0"}`)
	}))
	defer server.Close()
	defer SetLatestReleaseURLForTesting(server.URL)()

	if info := CheckForUpdate(context.Background(), "v1.0.0"); info != nil {
		t.Errorf("expected nil when up to date, got %+v", info)
	}
}

func TestCheckForUpdateReturnsInfoWhenNewer(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"tag_name":"v2.0.0"}`)
	}))
	defer server.Close()
	defer SetLatestReleaseURLForTesting(server.URL)()

	info := CheckForUpdate(context.Background(), "v1.0.0")
	if info == nil {
		t.Fatal("expected UpdateInfo, got nil")
	}
	if info.CurrentVersion != "v1.0.0" {
		t.Errorf("CurrentVersion = %q, want %q", info.CurrentVersion, "v1.0.0")
	}
	if info.LatestVersion != "v2.0.0" {
		t.Errorf("LatestVersion = %q, want %q", info.LatestVersion, "v2.0.0")
	}
}

func TestCheckForUpdateReturnsNilOnHTTPError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()
	defer SetLatestReleaseURLForTesting(server.URL)()

	if info := CheckForUpdate(context.Background(), "v1.0.0"); info != nil {
		t.Errorf("expected nil on HTTP error, got %+v", info)
	}
}

func TestCheckForUpdateReturnsNilOnInvalidJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `not json`)
	}))
	defer server.Close()
	defer SetLatestReleaseURLForTesting(server.URL)()

	if info := CheckForUpdate(context.Background(), "v1.0.0"); info != nil {
		t.Errorf("expected nil on invalid JSON, got %+v", info)
	}
}

func TestCheckForUpdateReturnsNilOnInvalidTagSemver(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"tag_name":"not-semver"}`)
	}))
	defer server.Close()
	defer SetLatestReleaseURLForTesting(server.URL)()

	if info := CheckForUpdate(context.Background(), "v1.0.0"); info != nil {
		t.Errorf("expected nil on invalid tag semver, got %+v", info)
	}
}

func TestCheckForUpdateReturnsNilOnCanceledContext(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"tag_name":"v2.0.0"}`)
	}))
	defer server.Close()
	defer SetLatestReleaseURLForTesting(server.URL)()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if info := CheckForUpdate(ctx, "v1.0.0"); info != nil {
		t.Errorf("expected nil on canceled context, got %+v", info)
	}
}

func TestGithubTokenPrefersGITHUB_TOKEN(t *testing.T) {
	t.Setenv("GITHUB_TOKEN", "gh-tok")
	t.Setenv("GH_TOKEN", "cli-tok")

	if got := githubToken(); got != "gh-tok" {
		t.Errorf("githubToken() = %q, want %q", got, "gh-tok")
	}
}

func TestGithubTokenFallsBackToGH_TOKEN(t *testing.T) {
	t.Setenv("GITHUB_TOKEN", "")
	t.Setenv("GH_TOKEN", "cli-tok")

	if got := githubToken(); got != "cli-tok" {
		t.Errorf("githubToken() = %q, want %q", got, "cli-tok")
	}
}

func TestGithubTokenReturnsEmptyWhenUnset(t *testing.T) {
	t.Setenv("GITHUB_TOKEN", "")
	t.Setenv("GH_TOKEN", "")

	if got := githubToken(); got != "" {
		t.Errorf("githubToken() = %q, want empty", got)
	}
}

func TestCheckForUpdateSendsAuthHeader(t *testing.T) {
	t.Setenv("GITHUB_TOKEN", "test-token")

	var gotAuth string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"tag_name":"v2.0.0"}`)
	}))
	defer server.Close()
	defer SetLatestReleaseURLForTesting(server.URL)()

	CheckForUpdate(context.Background(), "v1.0.0")

	if gotAuth != "Bearer test-token" {
		t.Errorf("Authorization = %q, want %q", gotAuth, "Bearer test-token")
	}
}

func TestCheckForUpdateNoAuthHeaderWithoutToken(t *testing.T) {
	t.Setenv("GITHUB_TOKEN", "")
	t.Setenv("GH_TOKEN", "")

	var gotAuth string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"tag_name":"v2.0.0"}`)
	}))
	defer server.Close()
	defer SetLatestReleaseURLForTesting(server.URL)()

	CheckForUpdate(context.Background(), "v1.0.0")

	if gotAuth != "" {
		t.Errorf("Authorization = %q, want empty", gotAuth)
	}
}

func TestDetectUpgradeRejectsInvalidSemver(t *testing.T) {
	if _, err := DetectUpgrade(context.Background(), "abc123"); err == nil {
		t.Fatal("expected error for invalid semver")
	}
}

func TestDetectUpgradeRejectsCommitHash(t *testing.T) {
	if _, err := DetectUpgrade(context.Background(), "a1b2c3d"); err == nil {
		t.Fatal("expected error for commit hash version")
	}
}
