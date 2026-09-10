// Package githubactions implements an enricher that generates GIT ranges
// for GitHub Actions advisories from SemVer or Ecosystem ranges.
package githubactions

import (
	"context"
	"fmt"
	"log/slog"
	"slices"
	"strings"

	"github.com/google/osv.dev/go/internal/worker/pipeline"
	"github.com/google/osv.dev/go/logger"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
)

// EcosystemGitHubActions is the canonical OSV ecosystem name for GitHub Actions.
const EcosystemGitHubActions = "GitHub Actions"

type Enricher struct{}

var _ pipeline.Enricher = (*Enricher)(nil)

// ExtractGitHubRepoURL extracts the canonical "https://github.com/{owner}/{repo}" from action names.
// It handles standard action names (e.g. "actions/checkout"), nested sub-actions
// (e.g. "docker/build-push-action/v2"), and guards against path traversal.
func ExtractGitHubRepoURL(actionName string) (string, error) {
	trimmed := strings.TrimSpace(actionName)

	// Strip common prefixes if present.
	if strings.HasPrefix(trimmed, "https://github.com/") {
		trimmed = strings.TrimPrefix(trimmed, "https://github.com/")
	} else if strings.HasPrefix(trimmed, "http://github.com/") {
		trimmed = strings.TrimPrefix(trimmed, "http://github.com/")
	} else if strings.HasPrefix(trimmed, "github.com/") {
		trimmed = strings.TrimPrefix(trimmed, "github.com/")
	}

	trimmed = strings.Trim(trimmed, "/")
	parts := strings.Split(trimmed, "/")
	if len(parts) < 2 {
		return "", fmt.Errorf("invalid action name %q: expected owner/repo", actionName)
	}

	owner, repo := parts[0], parts[1]

	// Strip version tag suffix if embedded (e.g. "actions/checkout@v4")
	repo, _, _ = strings.Cut(repo, "@")

	// Strip .git suffix if present
	repo = strings.TrimSuffix(repo, ".git")

	if owner == "" || repo == "" {
		return "", fmt.Errorf("empty owner or repo segment in action %q", actionName)
	}

	if owner == "." || owner == ".." || repo == "." || repo == ".." ||
		strings.Contains(owner, "..") || strings.Contains(repo, "..") {
		return "", fmt.Errorf("invalid path traversal segment in action %q", actionName)
	}

	return fmt.Sprintf("https://github.com/%s/%s", owner, repo), nil
}

// Enrich inspects vulnerabilities for affected packages in the "GitHub Actions" ecosystem
// and injects a Range_GIT range for each SEMVER or ECOSYSTEM range.
func (*Enricher) Enrich(ctx context.Context, vuln *osvschema.Vulnerability, _ *pipeline.EnrichParams) error {
	for _, affected := range vuln.GetAffected() {
		pkg := affected.GetPackage()
		if pkg.GetEcosystem() != EcosystemGitHubActions {
			continue
		}

		repoURL, err := ExtractGitHubRepoURL(pkg.GetName())
		if err != nil {
			logger.WarnContext(ctx, "failed to extract GitHub repo URL for action",
				slog.String("vuln_id", vuln.GetId()),
				slog.String("ecosystem", pkg.GetEcosystem()),
				slog.String("name", pkg.GetName()),
				slog.Any("error", err),
			)
			continue
		}

		var gitRanges []*osvschema.Range
		for _, r := range affected.GetRanges() {
			if r.GetType() != osvschema.Range_SEMVER && r.GetType() != osvschema.Range_ECOSYSTEM {
				continue
			}

			// Check if duplicate GIT range already exists
			if gitRangeExists(affected.GetRanges(), repoURL, r.GetEvents()) ||
				gitRangeExists(gitRanges, repoURL, r.GetEvents()) {
				continue
			}

			eventsCopy := make([]*osvschema.Event, len(r.GetEvents()))
			for i, e := range r.GetEvents() {
				eventsCopy[i] = &osvschema.Event{
					Introduced:   e.GetIntroduced(),
					Fixed:        e.GetFixed(),
					LastAffected: e.GetLastAffected(),
					Limit:        e.GetLimit(),
				}
			}

			gitRanges = append(gitRanges, &osvschema.Range{
				Type:   osvschema.Range_GIT,
				Repo:   repoURL,
				Events: eventsCopy,
			})
		}
		affected.Ranges = append(affected.Ranges, gitRanges...)
	}

	return nil
}

func gitRangeExists(ranges []*osvschema.Range, repoURL string, events []*osvschema.Event) bool {
	return slices.ContainsFunc(ranges, func(r *osvschema.Range) bool {
		return r.GetType() == osvschema.Range_GIT && r.GetRepo() == repoURL && eventsEqual(r.GetEvents(), events)
	})
}

func eventsEqual(a, b []*osvschema.Event) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].GetIntroduced() != b[i].GetIntroduced() ||
			a[i].GetFixed() != b[i].GetFixed() ||
			a[i].GetLastAffected() != b[i].GetLastAffected() ||
			a[i].GetLimit() != b[i].GetLimit() {
			return false
		}
	}
	return true
}
