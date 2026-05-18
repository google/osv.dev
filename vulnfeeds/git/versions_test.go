package git

import (
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/google/osv/vulnfeeds/internal/testutils"
	"github.com/google/osv/vulnfeeds/models"
)

func TestVersionToAffectedCommit(t *testing.T) {
	cache := &InMemoryRepoTagsCache{}

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
				t.Skipf("test %q: VersionToAffectedCommit(%q, %q) has been skipped due to known outage and will be reenabled on %s.", tc.description, tc.inputVersion, tc.inputRepoURL, tc.disableExpiryDate)
			}
			if !tc.disableExpiryDate.IsZero() && time.Now().After(tc.disableExpiryDate) {
				t.Logf("test %q: VersionToAffectedCommit(%q, %q) has been enabled on %s.", tc.description, tc.inputVersion, tc.inputRepoURL, tc.disableExpiryDate)
			}
			normalizedTags, err := NormalizeRepoTags(tc.inputRepoURL, cache)
			if err != nil {
				t.Errorf("test %q: unexpected failure normalizing repo tags: %#v", tc.description, err)
			}
			got, err := VersionToAffectedCommit(tc.inputVersion, tc.inputRepoURL, models.Fixed, normalizedTags)
			if err != nil && tc.expectedOk {
				t.Errorf("test %q: VersionToAffectedCommit(%q, %q) unexpectedly failed: %#v", tc.description, tc.inputVersion, tc.inputRepoURL, err)
				t.Skip()
			}
			if got.Fixed != tc.expectedResult {
				t.Errorf("test %q: VersionToAffectedCommit(%q, %q) result incorrect, got: %q wanted: %q", tc.description, tc.inputVersion, tc.inputRepoURL, got.Fixed, tc.expectedResult)
			}
		})
	}
}
func TestNormalizeVersion(t *testing.T) {
	tests := []struct {
		description               string
		inputVersion              string
		expectedNormalizedVersion string
		expectedOk                bool
	}{
		{
			description:               "Empty string",
			inputVersion:              "",
			expectedNormalizedVersion: "",
			expectedOk:                false,
		},
		{
			description:               "Garbage version",
			inputVersion:              "hjlk;gfdhjkgf",
			expectedNormalizedVersion: "",
			expectedOk:                false,
		},
		{
			description:               "Valid supported version #1",
			inputVersion:              "1.0",
			expectedNormalizedVersion: "1-0",
			expectedOk:                true,
		},
		{
			description:               "Valid supported version #2",
			inputVersion:              "22.3rc1",
			expectedNormalizedVersion: "22-3-rc1",
			expectedOk:                true,
		},
		{
			description:               "Valid supported version #3",
			inputVersion:              "1.2.3.4.5-rc1",
			expectedNormalizedVersion: "1-2-3-4-5-rc1",
			expectedOk:                true,
		},
		{
			description:               "Valid supported version #4",
			inputVersion:              ".1",
			expectedNormalizedVersion: "0-1",
			expectedOk:                true,
		},
		{
			description:               "Valid supported version #5",
			inputVersion:              "0.1.11.1",
			expectedNormalizedVersion: "0-1-11-1",
			expectedOk:                true,
		},
		{
			description:               "Valid supported version #6",
			inputVersion:              "project-123-1",
			expectedNormalizedVersion: "123-1",
			expectedOk:                true,
		},
		{
			description:               "Valid supported version #7",
			inputVersion:              "project-123-1RC",
			expectedNormalizedVersion: "123-1-RC",
			expectedOk:                true,
		},
		{
			description:               "Valid supported version #8",
			inputVersion:              "project-123-1RC5",
			expectedNormalizedVersion: "123-1-RC5",
			expectedOk:                true,
		},
		{
			description:               "Valid supported version #9",
			inputVersion:              "arc-20200101",
			expectedNormalizedVersion: "20200101",
			expectedOk:                true,
		},
		{
			description:               "Valid supported version #10",
			inputVersion:              "php-8.0.0beta",
			expectedNormalizedVersion: "8-0-0-beta",
			expectedOk:                true,
		},
		{
			description:               "Valid supported version #11",
			inputVersion:              "php-8.0.0beta",
			expectedNormalizedVersion: "8-0-0-beta",
			expectedOk:                true,
		},
		{
			description:               "Valid supported version #12",
			inputVersion:              "v6.0.0-alpha1",
			expectedNormalizedVersion: "6-0-0-alpha1",
			expectedOk:                true,
		},
		{
			description:               "Valid supported version #13",
			inputVersion:              "android-10.0.0_r10",
			expectedNormalizedVersion: "10-0-0-10",
			expectedOk:                true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.description, func(t *testing.T) {
			t.Parallel()
			got, err := NormalizeVersion(tc.inputVersion)
			if err != nil && tc.expectedOk {
				t.Errorf("test %q: Normalize(%q) unexpectedly errored: %#v", tc.description, tc.inputVersion, err)
			}
			if !reflect.DeepEqual(got, tc.expectedNormalizedVersion) {
				t.Errorf("test %q: normalized version for %q was incorrect, got: %q, expected %q", tc.description, tc.inputVersion, got, tc.expectedNormalizedVersion)
			}
		})
	}
}

func TestParseVersionRange(t *testing.T) {
	tests := []struct {
		description    string
		input          string
		expectedResult models.AffectedVersion
		expectErr      bool
	}{
		{
			description: "Standard two-part range with <",
			input:       ">= 1.32.3, < 1.34.5",
			expectedResult: models.AffectedVersion{
				Introduced: "1.32.3",
				Fixed:      "1.34.5",
			},
			expectErr: false,
		},
		{
			description: "Two-part range with <=",
			input:       "  >= 1.32.3, <= 1.34.5  ", // Test with extra whitespace
			expectedResult: models.AffectedVersion{
				Introduced:   "1.32.3",
				LastAffected: "1.34.5",
			},
			expectErr: false,
		},
		{
			description: "Single constraint with <=",
			input:       "<= 2.0.0",
			expectedResult: models.AffectedVersion{
				Introduced:   "0",
				LastAffected: "2.0.0",
			},
			expectErr: false,
		},
		{
			description: "Single constraint with <",
			input:       "< 2.0.0",
			expectedResult: models.AffectedVersion{
				Introduced: "0",
				Fixed:      "2.0.0",
			},
			expectErr: false,
		},
		{
			description: "Single constraint with >",
			input:       "> 5.0",
			expectedResult: models.AffectedVersion{
				Introduced: "5.0",
			},
			expectErr: false,
		},
		{
			description: "Invalid format",
			input:       "this is not a valid range",
			expectErr:   true,
		},
		{
			description: "Invalid operator in second part",
			input:       ">= 1.0, > 2.0",
			expectErr:   true,
		},
		{
			description: "Invalid operator in first part",
			input:       "< 1.0, < 2.0",
			expectErr:   true,
		},
		{
			description: "too many spaces",
			input:       ">= 7.65.0 , < 7.71.0",
			expectedResult: models.AffectedVersion{
				Introduced: "7.65.0",
				Fixed:      "7.71.0",
			},
			expectErr: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.description, func(t *testing.T) {
			t.Parallel()
			got, err := ParseVersionRange(tc.input)

			if (err != nil) != tc.expectErr {
				t.Errorf("ParseVersionRange(%q) unexpected error state: got err = %v, wantErr = %v", tc.input, err, tc.expectErr)
			}

			if !reflect.DeepEqual(got, tc.expectedResult) {
				t.Errorf("ParseVersionRange(%q) got = %v, want %v", tc.input, got, tc.expectedResult)
			}
		})
	}
}

func TestValidateAndCanonicalizeLink(t *testing.T) {
	type args struct {
		link string
	}
	tests := []struct {
		name              string
		args              args
		wantCanonicalLink string
		wantErr           bool
		skipOnCloudBuild  bool
		disableExpiryDate time.Time // If test needs to be disabled due to known outage.
	}{
		{
			name: "A link that 404's",
			args: args{
				link: "https://github.com/WebKit/webkit/commit/6f9b511a115311b13c06eb58038ddc2c78da5531",
			},
			wantCanonicalLink: "https://github.com/WebKit/webkit/commit/6f9b511a115311b13c06eb58038ddc2c78da5531",
			wantErr:           true,
		},
		{
			name: "A functioning link",
			args: args{
				link: "https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=ee1fee900537b5d9560e9f937402de5ddc8412f3",
			},
			wantCanonicalLink: "https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=ee1fee900537b5d9560e9f937402de5ddc8412f3",
			wantErr:           false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := testutils.SetupVCR(t)
			client := r.GetDefaultClient()

			if time.Now().Before(tt.disableExpiryDate) {
				t.Skipf("test %q has been skipped due to known outage and will be reenabled on %s.", tt.name, tt.disableExpiryDate)
			}
			if _, ok := os.LookupEnv("BUILD_ID"); ok && tt.skipOnCloudBuild {
				t.Skipf("test %q: running on Cloud Build", tt.name)
			}
			gotCanonicalLink, err := ValidateAndCanonicalizeLink(tt.args.link, client)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateAndCanonicalizeLink() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if gotCanonicalLink != tt.wantCanonicalLink {
				t.Errorf("ValidateAndCanonicalizeLink() = %v, want %v", gotCanonicalLink, tt.wantCanonicalLink)
			}
		})
	}
}

func TestValidateAndCanonicalizeLink_429(t *testing.T) {
	requests := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests++
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer ts.Close()

	client := ts.Client()
	_, err := ValidateAndCanonicalizeLink(ts.URL, client)
	if err == nil {
		t.Errorf("ValidateAndCanonicalizeLink() expected error, got nil")
	}
}

func TestValidateAndCanonicalizeLink_Retries(t *testing.T) {
	requests := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests++
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer ts.Close()

	client := ts.Client()
	_, err := ValidateAndCanonicalizeLink(ts.URL, client)
	if err == nil {
		t.Errorf("ValidateAndCanonicalizeLink() expected error, got nil")
	}
	if requests != 4 {
		t.Errorf("ValidateAndCanonicalizeLink() expected 4 requests (1 initial + 3 retries), got %d", requests)
	}
}
