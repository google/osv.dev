package githubactions

import (
	"context"
	"testing"

	"github.com/google/osv.dev/go/internal/worker/pipeline"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
)

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

	t.Run("Enrich GitHub Actions advisory with SEMVER range", func(t *testing.T) {
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

		err := enricher.Enrich(ctx, vuln, &pipeline.EnrichParams{})
		if err != nil {
			t.Fatalf("Enrich() returned unexpected error: %v", err)
		}

		affected := vuln.Affected[0]
		if len(affected.Ranges) != 2 {
			t.Fatalf("expected 2 ranges (SEMVER + GIT), got %d", len(affected.Ranges))
		}

		// First range remains SEMVER
		if affected.Ranges[0].Type != osvschema.Range_SEMVER {
			t.Errorf("expected first range to be SEMVER, got %v", affected.Ranges[0].Type)
		}

		// Injected range is GIT
		gitRange := affected.Ranges[1]
		if gitRange.Type != osvschema.Range_GIT {
			t.Errorf("expected second range to be GIT, got %v", gitRange.Type)
		}
		if gitRange.Repo != "https://github.com/actions/checkout" {
			t.Errorf("expected repo https://github.com/actions/checkout, got %s", gitRange.Repo)
		}
		if len(gitRange.Events) != 2 {
			t.Fatalf("expected 2 events in GIT range, got %d", len(gitRange.Events))
		}
		if gitRange.Events[0].Introduced != "0" || gitRange.Events[1].Fixed != "4.1.0" {
			t.Errorf("events in GIT range do not match expected introduced/fixed values: %+v", gitRange.Events)
		}
	})

	t.Run("Enrich GitHub Actions advisory with ECOSYSTEM range", func(t *testing.T) {
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

		err := enricher.Enrich(ctx, vuln, &pipeline.EnrichParams{})
		if err != nil {
			t.Fatalf("Enrich() returned error: %v", err)
		}

		affected := vuln.Affected[0]
		if len(affected.Ranges) != 2 {
			t.Fatalf("expected 2 ranges, got %d", len(affected.Ranges))
		}

		gitRange := affected.Ranges[1]
		if gitRange.Type != osvschema.Range_GIT {
			t.Errorf("expected GIT range type, got %v", gitRange.Type)
		}
		if gitRange.Repo != "https://github.com/docker/build-push-action" {
			t.Errorf("expected repo https://github.com/docker/build-push-action, got %s", gitRange.Repo)
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

		err := enricher.Enrich(ctx, vuln, &pipeline.EnrichParams{})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		affected := vuln.Affected[0]
		if len(affected.Ranges) != 1 {
			t.Errorf("expected exactly 1 range (unmodified), got %d", len(affected.Ranges))
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

		err := enricher.Enrich(ctx, vuln, &pipeline.EnrichParams{})
		if err != nil {
			t.Fatalf("expected nil error on malformed package name, got %v", err)
		}

		affected := vuln.Affected[0]
		if len(affected.Ranges) != 1 {
			t.Errorf("expected ranges to remain unmodified, got %d", len(affected.Ranges))
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

		// First invocation
		if err := enricher.Enrich(ctx, vuln, &pipeline.EnrichParams{}); err != nil {
			t.Fatalf("first Enrich failed: %v", err)
		}
		if len(vuln.Affected[0].Ranges) != 2 {
			t.Fatalf("expected 2 ranges after first enrich, got %d", len(vuln.Affected[0].Ranges))
		}

		// Second invocation
		if err := enricher.Enrich(ctx, vuln, &pipeline.EnrichParams{}); err != nil {
			t.Fatalf("second Enrich failed: %v", err)
		}
		if len(vuln.Affected[0].Ranges) != 2 {
			t.Fatalf("expected still 2 ranges after second enrich (idempotency violated), got %d", len(vuln.Affected[0].Ranges))
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

		if err := enricher.Enrich(ctx, vuln, &pipeline.EnrichParams{}); err != nil {
			t.Fatalf("Enrich failed: %v", err)
		}

		gitRange := vuln.Affected[0].Ranges[1]
		// Mutating gitRange event must not affect semverEvents
		gitRange.Events[0].Introduced = "mutated-sha"
		if semverEvents[0].Introduced != "1.0.0" {
			t.Errorf("SEMVER event was mutated through GIT range event: got %q, want '1.0.0'", semverEvents[0].Introduced)
		}
	})
}
