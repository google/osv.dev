package git

import (
	"testing"
)

func TestVersionToCommit(t *testing.T) {
	var cache RepoTagsCache
	cache = make(RepoTagsCache)

	tests := []struct {
		description    string
		inputRepoURL   string
		cache          RepoTagsCache
		inputVersion   string
		expectedResult string
		expectedOk     bool
	}{
		{
			description:    "An exact match",
			inputRepoURL:   "https://github.com/ARMmbed/mbedtls",
			cache:          cache,
			inputVersion:   "3.0.0",
			expectedResult: "ecf535f6cb70c97beb7c44dceadc14423086ca0d",
			expectedOk:     true,
		},
	}

	for _, tc := range tests {
		normalizedTags, err := NormalizeRepoTags(tc.inputRepoURL, cache)
		if err != nil {
			t.Errorf("test %q: unexpected failure normalizing repo tags: %#v", tc.description, err)
		}
		got, err := VersionToCommit(tc.inputVersion, tc.inputRepoURL, normalizedTags)
		if err != nil && tc.expectedOk {
			t.Errorf("test %q: VersionToCommit(%q, %q) unexpectedly failed: %#v", tc.description, tc.inputVersion, tc.inputRepoURL, err)
		}
		if got.Commit != tc.expectedResult {
			t.Errorf("test %q: VersionToCommit(%q, %q) result incorrect, got: %q wanted: %q", tc.description, tc.inputVersion, tc.inputRepoURL, got.Commit, tc.expectedResult)
		}
	}
}
