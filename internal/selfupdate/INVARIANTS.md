# Selfupdate Invariants

## CheckForUpdate

- [tested] SU-01: `CheckForUpdate` returns nil for non-semver version strings (e.g. "dev", "abc123") — no error is surfaced.
- [tested] SU-02: `CheckForUpdate` returns nil when the latest release tag equals the current version (already up to date).
- [tested] SU-03: `CheckForUpdate` returns an `UpdateInfo` with `CurrentVersion` and `LatestVersion` when the remote tag is newer.
- [tested] SU-04: `CheckForUpdate` returns nil on all failure modes (HTTP errors, invalid JSON, invalid tag semver, canceled context) — it never disrupts CLI usage.
- [tested] SU-05: `CheckForUpdate` sends `Authorization: Bearer {token}` when `GITHUB_TOKEN` or `GH_TOKEN` is set; sends no Authorization header when both are unset.

## githubToken

- [tested] SU-06: `githubToken()` prefers `GITHUB_TOKEN` over `GH_TOKEN`; falls back to `GH_TOKEN` when `GITHUB_TOKEN` is empty; returns empty when both are unset.

## DetectUpgrade

- [tested] SU-07: `DetectUpgrade` rejects non-semver version strings (e.g. "abc123", commit hashes) with an error.
