package ecosystem

import (
	"slices"
	"testing"

	"github.com/google/osv.dev/go/testutils"
)

// getTestProvider sets up an isolated Provider with a VCR client for testing.
func getTestProvider(t *testing.T) *Provider {
	t.Helper()
	rec := testutils.SetupVCR(t)

	return NewProvider(rec.GetDefaultClient())
}

// checkNextVersion verifies that expectedNext is the version immediately following current in the versions list.
// If current is "0", it expects expectedNext to be the first element.
func checkNextVersion(t *testing.T, versions []string, current, expectedNext string) {
	t.Helper()
	if len(versions) == 0 {
		t.Fatalf("expected versions, got empty list")
	}
	if current == "0" {
		if versions[0] != expectedNext {
			t.Errorf("expected %s to be the first version, got %s", expectedNext, versions[0])
		}

		return
	}

	idx := slices.Index(versions, current)
	if idx == -1 {
		t.Fatalf("version %s not found in versions list", current)
	}
	if idx+1 >= len(versions) {
		t.Fatalf("version %s is the last version, expected next version %s", current, expectedNext)
	}

	if versions[idx+1] != expectedNext {
		t.Errorf("expected next version after %s to be %s, got %s", current, expectedNext, versions[idx+1])
	}
}
