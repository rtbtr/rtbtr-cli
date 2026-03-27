# Home Invariants

## Resolve

- [tested] H-01: `Resolve(explicitHome, _)` returns `explicitHome` as-is when non-empty, regardless of `allowCreate` or working directory.
- [tested] H-02: `Resolve("", false)` walks up from the current working directory looking for a `.rtbtr/` subdirectory; returns the first match found.
- [tested] H-03: `Resolve("", false)` returns an error containing ".rtbtr directory not found" when no `.rtbtr/` exists in any ancestor. No directory is created.
- [tested] H-04: `Resolve("", true)` creates `.rtbtr/` in the current working directory when no existing `.rtbtr/` is found in any ancestor, and returns the new path.

## FindDirUp

- [tested] H-05: `FindDirUp(startDir, name)` walks up from `startDir` and returns the first directory named `name`; returns `("", false)` if the root is reached without a match.

## LoadPrivateKey

- [tested] H-06: `LoadPrivateKey(dir)` reads `private_key` from `dir`, trims whitespace, decodes URL-safe base64 (no padding), validates the result is exactly 32 bytes (ed25519.SeedSize), and returns the seed bytes.
- [tested] H-07: `LoadPrivateKey` returns "private key not found, run rtbtr keygen first" when the `private_key` file does not exist.
- [tested] H-08: `LoadPrivateKey` returns an error for invalid base64 encoding or wrong decoded length (not 32 bytes) — no panic.
