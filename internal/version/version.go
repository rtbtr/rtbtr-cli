// Package version provides build-time version information.
package version

// Build-time variables injected via ldflags.
var (
	// Version is the semantic version (e.g., "v1.0.0" or "dev").
	Version = "dev"

	// Commit is the git commit SHA.
	Commit = "unknown"

	// BuildTime is the UTC timestamp of the build.
	BuildTime = "unknown"
)

// Info returns formatted version information.
func Info() string {
	return Version + " (commit: " + Commit + ", built: " + BuildTime + ")"
}
