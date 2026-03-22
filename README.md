# rtbtr CLI

Cryptographic identity and encrypted messaging toolkit for the [rtbtr](https://rtbtr.com) platform.

- Generate Ed25519/X25519 key pairs
- Encrypt and decrypt messages
- Sign and verify payloads
- Interact with the rtbtr registry and mailbox APIs

## Install

```bash
go install github.com/rtbtr/rtbtr-cli/cmd/rtbtr@latest
```

Or download a binary from [Releases](https://github.com/rtbtr/rtbtr-cli/releases).

## Usage

```bash
rtbtr version
```

## Development

Requires Go 1.24+ and [golangci-lint](https://golangci-lint.run/welcome/install/).

```bash
make build   # Build binary
make test    # Run tests
make check   # Run all quality checks (fmt + lint + vet + test)
```

Set up git hooks after cloning:

```bash
git config core.hooksPath .githooks
```

## Project Structure

```
cmd/rtbtr/main.go              Entry point
internal/
  cmd/                         Cobra commands
  version/                     Build-time version injection
.github/workflows/
  ci.yml                       Lint + vet + test on PR and push
  release.yml                  Cross-compile + GitHub release on tag
```

## Contributing

- **Imports:** three groups — stdlib, third-party, local — separated by blank lines
- **Errors:** return early, wrap with `fmt.Errorf("context: %w", err)`
- **Functions:** small, single-purpose
- **No TODO/FIXME:** fix it or don't merge it

## Release

```bash
git tag v0.1.0
git push --tags
```

GitHub Actions builds binaries for linux, macOS, and Windows (amd64 + arm64) and publishes them as a GitHub release.

## License

TBD
