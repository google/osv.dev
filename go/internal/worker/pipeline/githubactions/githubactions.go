// Package githubactions implements an enricher that generates GIT ranges
// with resolved commit SHAs for GitHub Actions advisories from SemVer or Ecosystem ranges.
package githubactions

import (
	"context"
	"encoding/hex"
	"fmt"
	"log/slog"
	"slices"
	"strings"

	gitterpb "github.com/google/osv.dev/go/internal/gitter/pb/repository"
	"github.com/google/osv.dev/go/internal/worker/pipeline"
	"github.com/google/osv.dev/go/logger"
	"github.com/ossf/osv-schema/bindings/go/osvconstants"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
)

type Enricher struct{}

var _ pipeline.Enricher = (*Enricher)(nil)

// ExtractGitHubRepoURL extracts the canonical "https://github.com/{owner}/{repo}" from action names.
// It handles standard action names (e.g. "actions/checkout"), nested sub-actions
// (e.g. "docker/build-push-action/v2"), and guards against path traversal.
func ExtractGitHubRepoURL(actionName string) (string, error) {
	trimmed := strings.TrimSpace(actionName)

	// Strip common prefixes if present.
	if after, ok := strings.CutPrefix(trimmed, "https://github.com/"); ok {
		trimmed = after
	} else if after, ok := strings.CutPrefix(trimmed, "http://github.com/"); ok {
		trimmed = after
	} else if after, ok := strings.CutPrefix(trimmed, "github.com/"); ok {
		trimmed = after
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

	if owner == "." || repo == "." || strings.Contains(owner, "..") || strings.Contains(repo, "..") {
		return "", fmt.Errorf("invalid path traversal segment in action %q", actionName)
	}

	return fmt.Sprintf("https://github.com/%s/%s", owner, repo), nil
}

// Enrich inspects vulnerabilities for affected packages in the "GitHub Actions" ecosystem
// and injects a Range_GIT range with resolved commit SHAs for each SEMVER or ECOSYSTEM range.
func (*Enricher) Enrich(ctx context.Context, vuln *osvschema.Vulnerability, params *pipeline.EnrichParams) error {
	if params == nil || params.GitterClient == nil {
		logger.WarnContext(ctx, "Gitter client not provided, skipping GitHub Actions git range enrichment",
			slog.String("vuln_id", vuln.GetId()),
		)

		return nil
	}

	tagsCache := make(map[string]map[string]string)

	for _, affected := range vuln.GetAffected() {
		pkg := affected.GetPackage()
		if pkg.GetEcosystem() != string(osvconstants.EcosystemGitHubActions) {
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

		tagToCommit, ok := tagsCache[repoURL]
		if !ok {
			tagsResp, err := params.GitterClient.GetTags(ctx, repoURL)
			if err != nil {
				logger.WarnContext(ctx, "failed to get tags from gitter for action repo",
					slog.String("vuln_id", vuln.GetId()),
					slog.String("repo", repoURL),
					slog.Any("error", err),
				)

				continue
			}

			tagToCommit = buildTagCommitMap(tagsResp)
			tagsCache[repoURL] = tagToCommit
		}

		var gitRanges []*osvschema.Range
		for _, r := range affected.GetRanges() {
			if r.GetType() != osvschema.Range_SEMVER && r.GetType() != osvschema.Range_ECOSYSTEM {
				continue
			}

			resolvedEvents, ok := resolveRangeEvents(ctx, vuln.GetId(), repoURL, r.GetEvents(), tagToCommit)
			if !ok {
				continue
			}

			// Check if duplicate GIT range already exists
			if gitRangeExists(affected.GetRanges(), repoURL, resolvedEvents) ||
				gitRangeExists(gitRanges, repoURL, resolvedEvents) {
				continue
			}

			gitRanges = append(gitRanges, &osvschema.Range{
				Type:   osvschema.Range_GIT,
				Repo:   repoURL,
				Events: resolvedEvents,
			})
		}
		affected.Ranges = append(affected.Ranges, gitRanges...)
	}

	return nil
}

func buildTagCommitMap(tagsResp *gitterpb.TagsResponse) map[string]string {
	if tagsResp == nil {
		return nil
	}
	tagToCommit := make(map[string]string, len(tagsResp.GetTags())*2)
	for _, ref := range tagsResp.GetTags() {
		hash := hex.EncodeToString(ref.GetHash())
		if hash == "" {
			continue
		}
		label := strings.TrimPrefix(ref.GetLabel(), "refs/tags/")
		tagToCommit[label] = hash

		if trimmed, ok := strings.CutPrefix(label, "v"); ok {
			tagToCommit[trimmed] = hash
		} else {
			tagToCommit["v"+label] = hash
		}
	}

	return tagToCommit
}

func resolveRangeEvents(ctx context.Context, vulnID, repoURL string, events []*osvschema.Event, tagToCommit map[string]string) ([]*osvschema.Event, bool) {
	resolvedEvents := make([]*osvschema.Event, len(events))
	for i, e := range events {
		resolved := &osvschema.Event{}

		if intro := e.GetIntroduced(); intro != "" {
			sha, ok := resolveVersion(intro, tagToCommit)
			if !ok {
				logger.WarnContext(ctx, "unable to resolve introduced version tag to commit for action",
					slog.String("vuln_id", vulnID),
					slog.String("repo", repoURL),
					slog.String("version", intro),
				)

				return nil, false
			}
			resolved.Introduced = sha
		}

		if fixed := e.GetFixed(); fixed != "" {
			sha, ok := resolveVersion(fixed, tagToCommit)
			if !ok {
				logger.WarnContext(ctx, "unable to resolve fixed version tag to commit for action",
					slog.String("vuln_id", vulnID),
					slog.String("repo", repoURL),
					slog.String("version", fixed),
				)

				return nil, false
			}
			resolved.Fixed = sha
		}

		if lastAff := e.GetLastAffected(); lastAff != "" {
			sha, ok := resolveVersion(lastAff, tagToCommit)
			if !ok {
				logger.WarnContext(ctx, "unable to resolve last_affected version tag to commit for action",
					slog.String("vuln_id", vulnID),
					slog.String("repo", repoURL),
					slog.String("version", lastAff),
				)

				return nil, false
			}
			resolved.LastAffected = sha
		}

		if limit := e.GetLimit(); limit != "" {
			sha, ok := resolveVersion(limit, tagToCommit)
			if !ok {
				logger.WarnContext(ctx, "unable to resolve limit version tag to commit for action",
					slog.String("vuln_id", vulnID),
					slog.String("repo", repoURL),
					slog.String("version", limit),
				)

				return nil, false
			}
			resolved.Limit = sha
		}

		resolvedEvents[i] = resolved
	}

	return resolvedEvents, true
}

func resolveVersion(ver string, tagToCommit map[string]string) (string, bool) {
	if ver == "0" {
		return "0", true
	}
	if sha, ok := tagToCommit[ver]; ok {
		return sha, true
	}
	if isGitCommitSHA(ver) {
		return ver, true
	}

	return "", false
}

func isGitCommitSHA(s string) bool {
	if len(s) != 40 {
		return false
	}
	for _, c := range []byte(s) {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') && (c < 'A' || c > 'F') {
			return false
		}
	}

	return true
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
