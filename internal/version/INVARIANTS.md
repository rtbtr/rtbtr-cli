# Version Invariants

- [tested] V-01: `Info()` returns a string containing `Version`, `Commit`, and `BuildTime`.
- [tested] V-02: `IsDev()` returns true when `Version == "dev"` and false otherwise.
- [tested] V-03: `Version`, `Commit`, and `BuildTime` are package-level variables intended for build-time injection via ldflags; they default to "dev", "unknown", and "unknown" respectively.
