package git

import (
	"testing"
	"time"

	"github.com/google/osv/vulnfeeds/cves"
	"github.com/google/osv/vulnfeeds/internal/testutils"
)

func TestVersionToCommit(t *testing.T) {
	cache := make(RepoTagsCache)

	tests := []struct {
		description       string
		inputRepoURL      string
		cache             RepoTagsCache
		inputVersion      string
		expectedResult    string
		expectedOk        bool
		disableExpiryDate time.Time
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
			description:    "A fuzzy version match",
			inputRepoURL:   "https://github.com/eclipse-openj9/openj9",
			cache:          cache,
			inputVersion:   "0.38.0",
			expectedResult: "d57d05932008a14605bf6cd729bb22dd6f49162c",
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
		{
			description:    "A fuzzy version match for a tag with a different format to the others in the repo",
			inputRepoURL:   "https://github.com/yui/yui2",
			cache:          cache,
			inputVersion:   "2800",
			expectedResult: "159208465da41a4796716d8a5bf833c6778b3f61",
			expectedOk:     true,
		},
		{
			description:    "A version that should not fuzzy match to a release candidate",
			inputRepoURL:   "https://github.com/apache/inlong",
			cache:          cache,
			inputVersion:   "1.4.0",
			expectedResult: "",
			expectedOk:     false,
		},
		{
			description:    "An RC version that should match to one of many prefixed release candidates",
			inputRepoURL:   "https://github.com/apache/inlong",
			cache:          cache,
			inputVersion:   "1.8.0",
			expectedResult: "",
			expectedOk:     false,
		},
		{
			description:    "An RC version that should match to a (single) release candidate",
			inputRepoURL:   "https://github.com/apache/inlong",
			cache:          cache,
			inputVersion:   "1.4.0-RC0",
			expectedResult: "8c8145974548568a68bb81720cabdafbefe545be",
			expectedOk:     false,
		},
		{
			description:    "An RC version that should match to one of many prefixed release candidates",
			inputRepoURL:   "https://github.com/apache/inlong",
			cache:          cache,
			inputVersion:   "1.8.0-RC1",
			expectedResult: "91368c4b61d0dc4284092e497a1c1a2eceb5c2ad",
			expectedOk:     false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.description, func(t *testing.T) {
			testutils.SetupGitVCR(t)
			if time.Now().Before(tc.disableExpiryDate) {
				t.Skipf("test %q: VersionToCommit(%q, %q) has been skipped due to known outage and will be reenabled on %s.", tc.description, tc.inputVersion, tc.inputRepoURL, tc.disableExpiryDate)
			}
			if !tc.disableExpiryDate.IsZero() && time.Now().After(tc.disableExpiryDate) {
				t.Logf("test %q: VersionToCommit(%q, %q) has been enabled on %s.", tc.description, tc.inputVersion, tc.inputRepoURL, tc.disableExpiryDate)
			}
			normalizedTags, err := NormalizeRepoTags(tc.inputRepoURL, cache)
			if err != nil {
				t.Errorf("test %q: unexpected failure normalizing repo tags: %#v", tc.description, err)
			}
			got, err := VersionToCommit(tc.inputVersion, tc.inputRepoURL, cves.Fixed, normalizedTags)
			if err != nil && tc.expectedOk {
				t.Errorf("test %q: VersionToCommit(%q, %q) unexpectedly failed: %#v", tc.description, tc.inputVersion, tc.inputRepoURL, err)
				t.Skip()
			}
			if got.Fixed != tc.expectedResult {
				t.Errorf("test %q: VersionToCommit(%q, %q) result incorrect, got: %q wanted: %q", tc.description, tc.inputVersion, tc.inputRepoURL, got.Fixed, tc.expectedResult)
			}
		})
	}
}
