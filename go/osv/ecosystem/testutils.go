package ecosystem

import (
	"testing"

	"github.com/google/osv.dev/go/testutils"
)

// setupHTTPClientForTest sets up the global HTTPClient for testing.
// Tests requiring this cannot be run in parallel.
func setupHTTPClientForTest(t *testing.T) {
	t.Helper()
	rec := testutils.SetupVCR(t)
	var oldClient = HTTPClient
	t.Cleanup(func() {
		HTTPClient = oldClient
	})
	HTTPClient = rec.GetDefaultClient()
}
