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
			expectedResult: "8df2f8e7b9c7bb9390ac74bb7bace27edca81a2b",
			expectedOk:     true,
		},
		{
			description:    "A fuzzy version match",
			inputRepoURL:   "https://gitlab.com/gitlab-org/gitlab",
			cache:          cache,
			inputVersion:   "12.0",
			expectedResult: "3b13818e8330f68625d80d9bf5d8049c41fbe197",
			expectedOk:     true,
		},
		{
			description:    "A failed version match (non-existent version)",
			inputRepoURL:   "https://github.com/google/go-attestation",
			cache:          cache,
			inputVersion:   "0.3.3", // referred to in CVE-2022-0317
			expectedResult: "",
			expectedOk:     false,
		},
	}

	for _, tc := range tests {
		normalizedTags, err := NormalizeRepoTags(tc.inputRepoURL, cache)
		if err != nil {
			t.Errorf("test %q: unexpected failure normalizing repo tags: %#v", tc.description, err)
		}
		got, err := VersionToCommit(tc.inputVersion, tc.inputRepoURL, "Fixed", normalizedTags)
		if err != nil && tc.expectedOk {
			t.Errorf("test %q: VersionToCommit(%q, %q) unexpectedly failed: %#v", tc.description, tc.inputVersion, tc.inputRepoURL, err)
			continue
		}
		if got.Fixed != tc.expectedResult {
			t.Errorf("test %q: VersionToCommit(%q, %q) result incorrect, got: %q wanted: %q", tc.description, tc.inputVersion, tc.inputRepoURL, got.Fixed, tc.expectedResult)
		}
	}
}
