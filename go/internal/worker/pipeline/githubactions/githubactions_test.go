package githubactions

import (
	"context"
	"encoding/hex"
	"errors"
	"io"
	"testing"

	"github.com/google/osv.dev/go/internal/gitter"
	gitterpb "github.com/google/osv.dev/go/internal/gitter/pb/repository"
	"github.com/google/osv.dev/go/internal/worker/pipeline"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
)

type mockGitterClient struct {
	tagsByRepo map[string]*gitterpb.TagsResponse
	errByRepo  map[string]error
	callCount  map[string]int
}

var _ gitter.Client = (*mockGitterClient)(nil)

func (m *mockGitterClient) GetTags(_ context.Context, repoURL string) (*gitterpb.TagsResponse, error) {
	if m.callCount != nil {
		m.callCount[repoURL]++
	}
	if err, ok := m.errByRepo[repoURL]; ok && err != nil {
		return nil, err
	}
	if resp, ok := m.tagsByRepo[repoURL]; ok {
		return resp, nil
	}

	return &gitterpb.TagsResponse{}, nil
}

func (m *mockGitterClient) GetGit(_ context.Context, _ string, _ bool) (io.ReadCloser, error) {
	return nil, errors.New("not implemented")
}

func (m *mockGitterClient) Cache(_ context.Context, _ string) error {
	return errors.New("not implemented")
}

func (m *mockGitterClient) GetAffectedCommits(_ context.Context, _ *gitterpb.AffectedCommitsRequest) (*gitterpb.AffectedCommitsResponse, error) {
	return nil, errors.New("not implemented")
}

func (m *mockGitterClient) GetFileDiffs(_ context.Context, _ *gitterpb.FileDiffsRequest) (*gitterpb.FileDiffsResponse, error) {
	return nil, errors.New("not implemented")
}

func (m *mockGitterClient) GetFileContent(_ context.Context, _ *gitterpb.FileContentRequest) (*gitterpb.FileContentResponse, error) {
	return nil, errors.New("not implemented")
}

func makeRef(t *testing.T, label string, hashHex string) *gitterpb.Ref {
	t.Helper()
	b, err := hex.DecodeString(hashHex)
	if err != nil {
		t.Fatalf("invalid hex %q: %v", hashHex, err)
	}

	return &gitterpb.Ref{Label: label, Hash: b}
}

func TestExtractGitHubRepoURL(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		actionName string
		wantURL    string
		wantErr    bool
	}{
		{
			name:       "Standard action name",
			actionName: "actions/checkout",
			wantURL:    "https://github.com/actions/checkout",
			wantErr:    false,
		},
		{
			name:       "Standard action with whitespace",
			actionName: "  actions/checkout  ",
			wantURL:    "https://github.com/actions/checkout",
			wantErr:    false,
		},
		{
			name:       "Standard action with leading slash",
			actionName: "/actions/checkout/",
			wantURL:    "https://github.com/actions/checkout",
			wantErr:    false,
		},
		{
			name:       "Nested sub-action",
			actionName: "docker/build-push-action/v2",
			wantURL:    "https://github.com/docker/build-push-action",
			wantErr:    false,
		},
		{
			name:       "Deeply nested sub-action workflow",
			actionName: "slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml",
			wantURL:    "https://github.com/slsa-framework/slsa-github-generator",
			wantErr:    false,
		},
		{
			name:       "Action with git suffix",
			actionName: "actions/checkout.git",
			wantURL:    "https://github.com/actions/checkout",
			wantErr:    false,
		},
		{
			name:       "Action with embedded version tag",
			actionName: "actions/checkout@v4",
			wantURL:    "https://github.com/actions/checkout",
			wantErr:    false,
		},
		{
			name:       "Prefixed with github.com",
			actionName: "github.com/actions/setup-go",
			wantURL:    "https://github.com/actions/setup-go",
			wantErr:    false,
		},
		{
			name:       "Prefixed with https://github.com",
			actionName: "https://github.com/actions/setup-node",
			wantURL:    "https://github.com/actions/setup-node",
			wantErr:    false,
		},
		{
			name:       "Prefixed with http://github.com",
			actionName: "http://github.com/actions/cache",
			wantURL:    "https://github.com/actions/cache",
			wantErr:    false,
		},
		{
			name:       "Empty action name",
			actionName: "",
			wantErr:    true,
		},
		{
			name:       "Whitespace only",
			actionName: "   ",
			wantErr:    true,
		},
		{
			name:       "Single segment without slash",
			actionName: "singleaction",
			wantErr:    true,
		},
		{
			name:       "Path traversal dot-dot in owner",
			actionName: "../actions/checkout",
			wantErr:    true,
		},
		{
			name:       "Path traversal dot-dot in repo",
			actionName: "actions/../checkout",
			wantErr:    true,
		},
		{
			name:       "Path traversal single dot",
			actionName: "./actions",
			wantErr:    true,
		},
		{
			name:       "Path traversal double dot owner",
			actionName: "../malicious",
			wantErr:    true,
		},
		{
			name:       "Embedded dot-dot in owner name",
			actionName: "evil..org/repo",
			wantErr:    true,
		},
		{
			name:       "Embedded dot-dot in repo name",
			actionName: "owner/repo..evil",
			wantErr:    true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			gotURL, err := ExtractGitHubRepoURL(tc.actionName)
			if (err != nil) != tc.wantErr {
				t.Fatalf("ExtractGitHubRepoURL(%q) err = %v, wantErr = %v", tc.actionName, err, tc.wantErr)
			}
			if !tc.wantErr && gotURL != tc.wantURL {
				t.Errorf("ExtractGitHubRepoURL(%q) = %q, want %q", tc.actionName, gotURL, tc.wantURL)
			}
		})
	}
}

func TestEnricher_Enrich(t *testing.T) {
	t.Parallel()

	enricher := &Enricher{}
	ctx := context.Background()

	shaCheckoutV4Fixed := "b4ffde65f46336ab88eb53be808477a3936bae11"
	shaDockerV1Intro := "1111111111111111111111111111111111111111"
	shaDockerV2Fixed := "2222222222222222222222222222222222222222"
	shaUploadV1Intro := "3333333333333333333333333333333333333333"
	shaUploadV1Fixed := "4444444444444444444444444444444444444444"

	newMockClient := func(t *testing.T) *mockGitterClient {
		t.Helper()
		return &mockGitterClient{
			tagsByRepo: map[string]*gitterpb.TagsResponse{
				"https://github.com/actions/checkout": {
					Tags: []*gitterpb.Ref{
						makeRef(t, "v4.1.0", shaCheckoutV4Fixed),
						makeRef(t, "v4.0.0", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
					},
				},
				"https://github.com/docker/build-push-action": {
					Tags: []*gitterpb.Ref{
						makeRef(t, "v1.0.0", shaDockerV1Intro),
						makeRef(t, "v2.1.0", shaDockerV2Fixed),
					},
				},
				"https://github.com/actions/cache": {
					Tags: []*gitterpb.Ref{
						makeRef(t, "v3.0.0", "5555555555555555555555555555555555555555"),
					},
				},
				"https://github.com/actions/upload-artifact": {
					Tags: []*gitterpb.Ref{
						makeRef(t, "1.0.0", shaUploadV1Intro),
						makeRef(t, "1.2.0", shaUploadV1Fixed),
					},
				},
			},
			callCount: make(map[string]int),
		}
	}

	t.Run("Enrich GitHub Actions advisory with SEMVER range and commit resolution", func(t *testing.T) {
		t.Parallel()

		vuln := &osvschema.Vulnerability{
			Id: "GHSA-test-1234",
			Affected: []*osvschema.Affected{
				{
					Package: &osvschema.Package{
						Ecosystem: "GitHub Actions",
						Name:      "actions/checkout",
					},
					Ranges: []*osvschema.Range{
						{
							Type: osvschema.Range_SEMVER,
							Events: []*osvschema.Event{
								{Introduced: "0"},
								{Fixed: "4.1.0"},
							},
						},
					},
				},
			},
		}

		client := newMockClient(t)
		err := enricher.Enrich(ctx, vuln, &pipeline.EnrichParams{GitterClient: client})
		if err != nil {
			t.Fatalf("Enrich() returned unexpected error: %v", err)
		}

		affected := vuln.GetAffected()[0]
		if len(affected.GetRanges()) != 2 {
			t.Fatalf("expected 2 ranges (SEMVER + GIT), got %d", len(affected.GetRanges()))
		}

		// First range remains SEMVER
		if affected.GetRanges()[0].GetType() != osvschema.Range_SEMVER {
			t.Errorf("expected first range to be SEMVER, got %v", affected.GetRanges()[0].GetType())
		}

		// Injected range is GIT
		gitRange := affected.GetRanges()[1]
		if gitRange.GetType() != osvschema.Range_GIT {
			t.Errorf("expected second range to be GIT, got %v", gitRange.GetType())
		}
		if gitRange.GetRepo() != "https://github.com/actions/checkout" {
			t.Errorf("expected repo https://github.com/actions/checkout, got %s", gitRange.GetRepo())
		}
		if len(gitRange.GetEvents()) != 2 {
			t.Fatalf("expected 2 events in GIT range, got %d", len(gitRange.GetEvents()))
		}
		if gitRange.GetEvents()[0].GetIntroduced() != "0" || gitRange.GetEvents()[1].GetFixed() != shaCheckoutV4Fixed {
			t.Errorf("events in GIT range do not match expected introduced/fixed values: %+v", gitRange.GetEvents())
		}
	})

	t.Run("Enrich GitHub Actions advisory with ECOSYSTEM range and v-prefix matching", func(t *testing.T) {
		t.Parallel()

		vuln := &osvschema.Vulnerability{
			Id: "GHSA-test-eco",
			Affected: []*osvschema.Affected{
				{
					Package: &osvschema.Package{
						Ecosystem: "GitHub Actions",
						Name:      "docker/build-push-action/v2",
					},
					Ranges: []*osvschema.Range{
						{
							Type: osvschema.Range_ECOSYSTEM,
							Events: []*osvschema.Event{
								{Introduced: "1.0.0"},
								{Fixed: "2.1.0"},
							},
						},
					},
				},
			},
		}

		client := newMockClient(t)
		err := enricher.Enrich(ctx, vuln, &pipeline.EnrichParams{GitterClient: client})
		if err != nil {
			t.Fatalf("Enrich() returned error: %v", err)
		}

		affected := vuln.GetAffected()[0]
		if len(affected.GetRanges()) != 2 {
			t.Fatalf("expected 2 ranges, got %d", len(affected.GetRanges()))
		}

		gitRange := affected.GetRanges()[1]
		if gitRange.GetType() != osvschema.Range_GIT {
			t.Errorf("expected GIT range type, got %v", gitRange.GetType())
		}
		if gitRange.GetRepo() != "https://github.com/docker/build-push-action" {
			t.Errorf("expected repo https://github.com/docker/build-push-action, got %s", gitRange.GetRepo())
		}
		if gitRange.GetEvents()[0].GetIntroduced() != shaDockerV1Intro || gitRange.GetEvents()[1].GetFixed() != shaDockerV2Fixed {
			t.Errorf("events in GIT range do not match expected SHAs: %+v", gitRange.GetEvents())
		}
	})

	t.Run("Missing tag in repository gracefully skips GIT range without error", func(t *testing.T) {
		t.Parallel()

		vuln := &osvschema.Vulnerability{
			Id: "GHSA-missing-tag",
			Affected: []*osvschema.Affected{
				{
					Package: &osvschema.Package{
						Ecosystem: "GitHub Actions",
						Name:      "actions/checkout",
					},
					Ranges: []*osvschema.Range{
						{
							Type: osvschema.Range_SEMVER,
							Events: []*osvschema.Event{
								{Introduced: "0"},
								{Fixed: "99.99.99"}, // Non-existent tag
							},
						},
					},
				},
			},
		}

		client := newMockClient(t)
		err := enricher.Enrich(ctx, vuln, &pipeline.EnrichParams{GitterClient: client})
		if err != nil {
			t.Fatalf("expected nil error on missing tag, got %v", err)
		}

		affected := vuln.GetAffected()[0]
		if len(affected.GetRanges()) != 1 {
			t.Errorf("expected 1 range (unresolved GIT range skipped), got %d", len(affected.GetRanges()))
		}
	})

	t.Run("Gitter client error skips gracefully without failing worker", func(t *testing.T) {
		t.Parallel()

		vuln := &osvschema.Vulnerability{
			Id: "GHSA-gitter-err",
			Affected: []*osvschema.Affected{
				{
					Package: &osvschema.Package{
						Ecosystem: "GitHub Actions",
						Name:      "actions/checkout",
					},
					Ranges: []*osvschema.Range{
						{
							Type: osvschema.Range_SEMVER,
							Events: []*osvschema.Event{
								{Introduced: "0"},
								{Fixed: "4.1.0"},
							},
						},
					},
				},
			},
		}

		client := &mockGitterClient{
			errByRepo: map[string]error{
				"https://github.com/actions/checkout": gitter.ErrRepoInaccessible,
			},
		}

		err := enricher.Enrich(ctx, vuln, &pipeline.EnrichParams{GitterClient: client})
		if err != nil {
			t.Fatalf("expected nil error when gitter fails, got %v", err)
		}

		affected := vuln.GetAffected()[0]
		if len(affected.GetRanges()) != 1 {
			t.Errorf("expected 1 range, got %d", len(affected.GetRanges()))
		}
	})

	t.Run("Gitter client nil skips gracefully without error", func(t *testing.T) {
		t.Parallel()

		vuln := &osvschema.Vulnerability{
			Id: "GHSA-nil-client",
			Affected: []*osvschema.Affected{
				{
					Package: &osvschema.Package{
						Ecosystem: "GitHub Actions",
						Name:      "actions/checkout",
					},
					Ranges: []*osvschema.Range{
						{
							Type: osvschema.Range_SEMVER,
							Events: []*osvschema.Event{
								{Introduced: "0"},
								{Fixed: "4.1.0"},
							},
						},
					},
				},
			},
		}

		err := enricher.Enrich(ctx, vuln, &pipeline.EnrichParams{GitterClient: nil})
		if err != nil {
			t.Fatalf("expected nil error when GitterClient is nil, got %v", err)
		}

		affected := vuln.GetAffected()[0]
		if len(affected.GetRanges()) != 1 {
			t.Errorf("expected 1 range, got %d", len(affected.GetRanges()))
		}
	})

	t.Run("Ignore non-GitHub Actions ecosystem", func(t *testing.T) {
		t.Parallel()

		vuln := &osvschema.Vulnerability{
			Id: "PYPI-test-123",
			Affected: []*osvschema.Affected{
				{
					Package: &osvschema.Package{
						Ecosystem: "PyPI",
						Name:      "requests",
					},
					Ranges: []*osvschema.Range{
						{
							Type: osvschema.Range_ECOSYSTEM,
							Events: []*osvschema.Event{
								{Introduced: "0"},
								{Fixed: "2.31.0"},
							},
						},
					},
				},
			},
		}

		client := newMockClient(t)
		err := enricher.Enrich(ctx, vuln, &pipeline.EnrichParams{GitterClient: client})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		affected := vuln.GetAffected()[0]
		if len(affected.GetRanges()) != 1 {
			t.Errorf("expected exactly 1 range (unmodified), got %d", len(affected.GetRanges()))
		}
	})

	t.Run("Skip malformed action name gracefully without error", func(t *testing.T) {
		t.Parallel()

		vuln := &osvschema.Vulnerability{
			Id: "GHSA-malformed",
			Affected: []*osvschema.Affected{
				{
					Package: &osvschema.Package{
						Ecosystem: "GitHub Actions",
						Name:      "invalid-action-without-owner",
					},
					Ranges: []*osvschema.Range{
						{
							Type: osvschema.Range_SEMVER,
							Events: []*osvschema.Event{
								{Introduced: "0"},
							},
						},
					},
				},
			},
		}

		client := newMockClient(t)
		err := enricher.Enrich(ctx, vuln, &pipeline.EnrichParams{GitterClient: client})
		if err != nil {
			t.Fatalf("expected nil error on malformed package name, got %v", err)
		}

		affected := vuln.GetAffected()[0]
		if len(affected.GetRanges()) != 1 {
			t.Errorf("expected ranges to remain unmodified, got %d", len(affected.GetRanges()))
		}
	})

	t.Run("Idempotent - running Enrich twice does not duplicate GIT ranges", func(t *testing.T) {
		t.Parallel()

		vuln := &osvschema.Vulnerability{
			Id: "GHSA-idempotent",
			Affected: []*osvschema.Affected{
				{
					Package: &osvschema.Package{
						Ecosystem: "GitHub Actions",
						Name:      "actions/cache",
					},
					Ranges: []*osvschema.Range{
						{
							Type: osvschema.Range_SEMVER,
							Events: []*osvschema.Event{
								{Introduced: "0"},
								{Fixed: "3.0.0"},
							},
						},
					},
				},
			},
		}

		client := newMockClient(t)
		params := &pipeline.EnrichParams{GitterClient: client}

		// First invocation
		if err := enricher.Enrich(ctx, vuln, params); err != nil {
			t.Fatalf("first Enrich failed: %v", err)
		}
		if len(vuln.GetAffected()[0].GetRanges()) != 2 {
			t.Fatalf("expected 2 ranges after first enrich, got %d", len(vuln.GetAffected()[0].GetRanges()))
		}

		// Second invocation
		if err := enricher.Enrich(ctx, vuln, params); err != nil {
			t.Fatalf("second Enrich failed: %v", err)
		}
		if len(vuln.GetAffected()[0].GetRanges()) != 2 {
			t.Fatalf("expected still 2 ranges after second enrich (idempotency violated), got %d", len(vuln.GetAffected()[0].GetRanges()))
		}
	})

	t.Run("Deep copy events verification", func(t *testing.T) {
		t.Parallel()

		semverEvents := []*osvschema.Event{
			{Introduced: "1.0.0"},
			{Fixed: "1.2.0"},
		}
		vuln := &osvschema.Vulnerability{
			Id: "GHSA-deep-copy",
			Affected: []*osvschema.Affected{
				{
					Package: &osvschema.Package{
						Ecosystem: "GitHub Actions",
						Name:      "actions/upload-artifact",
					},
					Ranges: []*osvschema.Range{
						{
							Type:   osvschema.Range_SEMVER,
							Events: semverEvents,
						},
					},
				},
			},
		}

		client := newMockClient(t)
		if err := enricher.Enrich(ctx, vuln, &pipeline.EnrichParams{GitterClient: client}); err != nil {
			t.Fatalf("Enrich failed: %v", err)
		}

		gitRange := vuln.GetAffected()[0].GetRanges()[1]
		// Mutating gitRange event must not affect semverEvents
		gitRange.GetEvents()[0].Introduced = "mutated-sha"
		if semverEvents[0].GetIntroduced() != "1.0.0" {
			t.Errorf("SEMVER event was mutated through GIT range event: got %q, want '1.0.0'", semverEvents[0].GetIntroduced())
		}
	})

	t.Run("Multiple packages with same repo caches Gitter tag lookup", func(t *testing.T) {
		t.Parallel()

		vuln := &osvschema.Vulnerability{
			Id: "GHSA-multi-pkg",
			Affected: []*osvschema.Affected{
				{
					Package: &osvschema.Package{
						Ecosystem: "GitHub Actions",
						Name:      "docker/build-push-action/v2",
					},
					Ranges: []*osvschema.Range{
						{
							Type: osvschema.Range_ECOSYSTEM,
							Events: []*osvschema.Event{
								{Introduced: "1.0.0"},
								{Fixed: "2.1.0"},
							},
						},
					},
				},
				{
					Package: &osvschema.Package{
						Ecosystem: "GitHub Actions",
						Name:      "docker/build-push-action/v3",
					},
					Ranges: []*osvschema.Range{
						{
							Type: osvschema.Range_ECOSYSTEM,
							Events: []*osvschema.Event{
								{Introduced: "1.0.0"},
								{Fixed: "2.1.0"},
							},
						},
					},
				},
			},
		}

		client := newMockClient(t)
		if err := enricher.Enrich(ctx, vuln, &pipeline.EnrichParams{GitterClient: client}); err != nil {
			t.Fatalf("Enrich failed: %v", err)
		}

		if calls := client.callCount["https://github.com/docker/build-push-action"]; calls != 1 {
			t.Errorf("expected GetTags called exactly 1 time (cached), got %d", calls)
		}
	})
}
