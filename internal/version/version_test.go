package version

import (
	"strings"
	"testing"
)

func TestInfoContainsVersion(t *testing.T) {
	info := Info()
	if !strings.Contains(info, Version) {
		t.Errorf("Info() = %q, want it to contain Version %q", info, Version)
	}
}

func TestInfoContainsCommit(t *testing.T) {
	info := Info()
	if !strings.Contains(info, Commit) {
		t.Errorf("Info() = %q, want it to contain Commit %q", info, Commit)
	}
}

func TestInfoContainsBuildTime(t *testing.T) {
	info := Info()
	if !strings.Contains(info, BuildTime) {
		t.Errorf("Info() = %q, want it to contain BuildTime %q", info, BuildTime)
	}
}
