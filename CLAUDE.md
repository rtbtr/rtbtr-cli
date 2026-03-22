# rtbtr CLI

Multiplatform CLI for cryptographic identity management and encrypted messaging on the rtbtr platform.

## What This Is

End-user tool for:
- Generating Ed25519/X25519 key pairs
- Encrypting and decrypting messages
- Signing and verifying payloads
- Interacting with the rtbtr registry and mailbox APIs

## Development Setup

Requires Go 1.24+ and [golangci-lint](https://golangci-lint.run/welcome/install/).

```bash
make build   # Build binary
make test    # Run tests
make lint    # Run linter
make check   # Run all quality checks (fmt + lint + vet + test)
```

Git hooks: `git config core.hooksPath .githooks` (pre-push runs `make check`).

## Project Structure

```
rtbtr-cli/
├── cmd/rtbtr/main.go              # Entry point
├── internal/
│   ├── cmd/                       # Cobra commands
│   │   ├── root.go                # Root command
│   │   └── version.go             # Version command
│   └── version/                   # Build-time version injection
├── .github/workflows/
│   ├── ci.yml                     # Lint + vet + test on PR/push
│   └── release.yml                # Cross-compile + GitHub release on tag
├── .githooks/pre-push             # Pre-push hook (runs make check)
├── Makefile                       # Build commands
└── .golangci.yml                  # Linter config
```

## Code Style

- **Imports:** three groups — stdlib, third-party, local — separated by blank lines
- **Naming:** PascalCase exported, camelCase unexported, no stuttering (`cmd.Version` not `cmd.CmdVersion`)
- **Errors:** return early, wrap with `fmt.Errorf("context: %w", err)`
- **Functions:** small, single-purpose, max ~40 lines
- **Comments:** package-level doc on every package, exported symbols documented
- **No TODO/FIXME:** fix it or don't merge it

## Adding New Commands

1. Create a new file in `internal/cmd/` (e.g., `internal/cmd/keygen.go`)
2. Define the cobra command
3. Register it in `internal/cmd/root.go` via `rootCmd.AddCommand()`

## Build & Release

- `make build` — Build for current platform
- `make release` — Cross-compile for linux/darwin/windows (amd64 + arm64)
- Push a tag (e.g., `v1.0.0`) to trigger GitHub release workflow

## Git Policy

**NEVER commit without explicit user approval.**
**NEVER merge PRs without explicit user approval.**
