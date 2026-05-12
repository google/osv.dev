// Package nvd converts NVD CVEs to OSV format.
package nvd

import (
	"cmp"
	"encoding/json"
	"errors"
	"log/slog"
	"maps"
	"net/http"
	"os"
	"path/filepath"
	"slices"

	c "github.com/google/osv/vulnfeeds/conversion"
	"github.com/google/osv/vulnfeeds/conversion/writer"
	"github.com/google/osv/vulnfeeds/git"
	"github.com/google/osv/vulnfeeds/models"
	"github.com/google/osv/vulnfeeds/utility"
	"github.com/google/osv/vulnfeeds/utility/logger"
	"github.com/google/osv/vulnfeeds/vulns"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
)

var ErrNoRanges = errors.New("no ranges")

var ErrUnresolvedFix = errors.New("fixes not resolved to commits")

// CVEToOSV Takes an NVD CVE record and returns an OSV Vulnerability object, ConversionMetrics, and the outcome.
func CVEToOSV(cve models.NVDCVE, repos []string, cache git.RepoTagsCache, metrics *models.ConversionMetrics) (*vulns.Vulnerability, *models.ConversionMetrics, models.ConversionOutcome) {
	CPEs := c.CPEs(cve)
	metrics.CPEs = CPEs
	refs := c.DeduplicateRefs(cve.References)
	// The vendor name and product name are used to construct the output `vulnDir` below, so need to be set to *something* to keep the output tidy.

	if len(CPEs) > 0 {
		_, err := c.ParseCPE(CPEs[0]) // For naming the subdirectory used for output.
		if err != nil {
			metrics.AddNote("Can't generate an OSV record without valid CPE data")
			return nil, metrics, models.ConversionUnknown
		}
	}

	// Create basic OSV record
	v := vulns.FromNVDCVE(cve.ID, cve)
	databaseSpecific, err := utility.NewStructpbFromMap(make(map[string]any))
	if err != nil {
		metrics.AddNote("Failed to convert database specific: %v", err)
	} else {
		v.DatabaseSpecific = databaseSpecific
	}

	// At the bare minimum, we want to attempt to extract the raw version information
	// from CPEs, whether or not they can resolve to commits.
	cpeRanges := c.ExtractVersionsFromCPEs(cve, nil, metrics)

	// If there are no repos, there are no commits from the refs either
	if len(cpeRanges) == 0 && len(repos) == 0 {
		metrics.SetOutcome(models.NoRepos)
		return v, metrics, models.NoRepos
	}

	successfulRepos := make(map[string]bool)
	var resolvedRanges []models.RangeWithMetadata
	var unresolvedRanges []models.RangeWithMetadata

	// Exit early if there are no repositories
	if len(repos) == 0 {
		metrics.SetOutcome(models.NoRepos)
		metrics.UnresolvedRangesCount += len(cpeRanges)

		unresolvedRangesList := c.CreateUnresolvedRanges(cpeRanges)
		if unresolvedRangesList != nil {
			if err := c.AddFieldToDatabaseSpecific(v.DatabaseSpecific, "unresolved_ranges", unresolvedRangesList); err != nil {
				logger.Warn("failed to add unresolved ranges to database specific: %v", err)
			}
		}

		// Exit early
		return v, metrics, models.NoRepos
	}

	// If we have ranges, try to resolve them
	r, un, sR := c.ProcessRanges(cpeRanges, repos, metrics, cache, models.VersionSourceCPE)
	if metrics.Outcome == models.Error {
		return nil, metrics, models.Error
	}
	resolvedRanges = append(resolvedRanges, r...)
	unresolvedRanges = append(unresolvedRanges, un...)
	for _, s := range sR {
		successfulRepos[s] = true
	}

	// Extract Commits
	commits, err := c.ExtractCommitsFromRefs(refs, http.DefaultClient)
	if err != nil {
		metrics.AddNote("Failed to extract commits from refs: %#v", err)
	}
	if len(commits) > 0 {
		metrics.AddNote("Extracted commits from refs: %v", commits)
		for _, commit := range commits {
			successfulRepos[commit.Repo] = true
		}
		metrics.SetOutcome(models.Successful)
		metrics.VersionSources = append(metrics.VersionSources, models.VersionSourceRefs)
	}

	// Extract Versions From Text if no CPE versions found
	if len(resolvedRanges) == 0 {
		textRanges := c.ExtractVersionsFromText(nil, models.EnglishDescription(cve.Descriptions), metrics, models.VersionSourceDescription)
		if len(textRanges) > 0 {
			metrics.AddNote("Extracted versions from description: %v", textRanges)
		}
		r, un, sR := c.ProcessRanges(textRanges, repos, metrics, cache, models.VersionSourceDescription)
		if metrics.Outcome == models.Error {
			return nil, metrics, models.Error
		}
		resolvedRanges = append(resolvedRanges, r...)
		unresolvedRanges = append(unresolvedRanges, un...)
		for _, s := range sR {
			successfulRepos[s] = true
		}
	}

	if len(resolvedRanges) == 0 && len(commits) == 0 {
		metrics.AddNote("No ranges detected")
		metrics.SetOutcome(models.NoRanges)
	}

	// Use the successful repos for more efficient merging.
	keys := slices.Collect(maps.Keys(successfulRepos))
	groupedRanges := c.GroupRanges(resolvedRanges)
	affected := c.MergeRangesAndCreateAffected(groupedRanges, commits, keys, metrics)
	if metrics.Outcome == models.Error {
		return nil, metrics, metrics.Outcome
	}

	v.Affected = append(v.Affected, affected...)

	// sort affected by repository name alphabetically to ensure deterministic output and caching hashes
	slices.SortFunc(v.Affected, func(a, b *osvschema.Affected) int {
		var repoA, repoB string
		if len(a.GetRanges()) > 0 {
			repoA = a.GetRanges()[0].GetRepo()
		}
		if len(b.GetRanges()) > 0 {
			repoB = b.GetRanges()[0].GetRepo()
		}

		return cmp.Compare(repoA, repoB)
	})

	unresolvedRangesList := c.CreateUnresolvedRanges(unresolvedRanges)
	if unresolvedRangesList != nil {
		if err := c.AddFieldToDatabaseSpecific(v.DatabaseSpecific, "unresolved_ranges", unresolvedRangesList); err != nil {
			logger.Warn("failed to add unresolved ranges to database specific: %v", err)
		}
	}

	return v, metrics, metrics.Outcome
}

// CVEToPackageInfo takes an NVD CVE record and outputs a PackageInfo struct in a file in the specified directory.
func CVEToPackageInfo(cve models.NVDCVE, repos []string, cache git.RepoTagsCache, directory string, metrics *models.ConversionMetrics) models.ConversionOutcome {
	CPEs := c.CPEs(cve)
	// The vendor name and product name are used to construct the output `vulnDir` below, so need to be set to *something* to keep the output tidy.
	maybeVendorName := "ENOCPE"
	maybeProductName := "ENOCPE"

	if len(CPEs) > 0 {
		CPE, err := c.ParseCPE(CPEs[0]) // For naming the subdirectory used for output.
		maybeVendorName = CPE.Vendor
		maybeProductName = CPE.Product
		if err != nil {
			return models.NoRanges
		}
	}

	// more often than not, this yields a VersionInfo with AffectedVersions and no AffectedCommits.
	versions := c.ExtractVersionInfo(cve, nil, http.DefaultClient, metrics)

	if len(versions.AffectedVersions) != 0 {
		// There are some AffectedVersions to try and resolve to AffectedCommits.
		if len(repos) == 0 {
			metrics.AddNote("No affected ranges for %q, and no repos to try and convert %+v to tags with", maybeProductName, versions.AffectedVersions)
			return models.NoRepos
		}
		logger.Info("Trying to convert version tags to commits", slog.String("cve", string(cve.ID)), slog.Any("versions", versions), slog.Any("repos", repos))
		c.VersionInfoToCommits(&versions, repos, cache, metrics)
		if metrics.Outcome == models.Error {
			return models.Error
		}
	}

	hasAnyFixedCommits := false
	for _, repo := range repos {
		if versions.HasFixedCommits(repo) {
			hasAnyFixedCommits = true
		}
	}

	if versions.HasFixedVersions() && !hasAnyFixedCommits {
		metrics.AddNote("Failed to convert fixed version tags to commits: %+v", versions)
		return models.NoCommitRanges
	}

	hasAnyLastAffectedCommits := false
	for _, repo := range repos {
		if versions.HasLastAffectedCommits(repo) {
			hasAnyLastAffectedCommits = true
		}
	}

	if versions.HasLastAffectedVersions() && !hasAnyLastAffectedCommits && !hasAnyFixedCommits {
		metrics.AddNote("Failed to convert last_affected version tags to commits: %+v", versions)
		return models.NoCommitRanges
	}

	if len(versions.AffectedCommits) == 0 {
		metrics.AddNote("No affected commit ranges determined for %q", maybeProductName)
		return models.NoCommitRanges
	}

	versions.AffectedVersions = nil // these have served their purpose and are not required in the resulting output.

	slices.SortStableFunc(versions.AffectedCommits, models.AffectedCommitCompare)

	if metrics.Outcome == models.Error {
		return metrics.Outcome
	}

	var pkgInfos []vulns.PackageInfo
	pi := vulns.PackageInfo{VersionInfo: versions}
	pkgInfos = append(pkgInfos, pi) // combine-to-osv expects a serialised *array* of PackageInfo

	vulnDir := filepath.Join(directory, maybeVendorName, maybeProductName)
	err := os.MkdirAll(vulnDir, 0755)
	if err != nil {
		logger.Warn("Failed to create dir", slog.Any("err", err))
	}

	outputFile := filepath.Join(vulnDir, string(cve.ID)+".nvd"+models.Extension)
	f, err := os.Create(outputFile)
	if err != nil {
		logger.Warn("Failed to open for writing", slog.String("path", outputFile), slog.Any("err", err))
	}
	defer f.Close()

	encoder := json.NewEncoder(f)
	encoder.SetIndent("", "  ")
	err = encoder.Encode(&pkgInfos)

	if err != nil {
		logger.Warn("Failed to encode PackageInfo", slog.String("path", outputFile), slog.Any("err", err))
	}

	logger.Info("Generated PackageInfo record", slog.String("cve", string(cve.ID)), slog.String("product", maybeProductName))

	metricsFile, err := writer.CreateMetricsFile(cve.ID, vulnDir)
	if err != nil {
		logger.Warn("Failed to create metrics file", slog.String("path", metricsFile.Name()), slog.Any("err", err))
	}
	err = writer.WriteMetricsFile(metrics, metricsFile)
	if err != nil {
		logger.Warn("Failed to write metrics file", slog.String("path", metricsFile.Name()), slog.Any("err", err))
	}

	return metrics.Outcome
}

// FindRepos attempts to find the source code repositories for a given CVE.
func FindRepos(cve models.NVDCVE, vpRepoCache *c.VPRepoCache, repoTagsCache git.RepoTagsCache, metrics *models.ConversionMetrics, httpClient *http.Client) []string {
	// Find repos
	refs := c.DeduplicateRefs(cve.References)
	CPEs := c.CPEs(cve)
	CVEID := cve.ID
	var reposForCVE []string

	if len(refs) == 0 && len(CPEs) == 0 {
		metrics.AddNote("Skipping due to lack of CPEs and lack of references")
		// 100% of these in 2022 were rejected CVEs
		metrics.SetOutcome(models.Rejected)

		return nil
	}

	if len(refs) > 0 && len(CPEs) == 0 {
		repos := c.ReposFromReferences(nil, nil, refs, c.RefTagDenyList, repoTagsCache, metrics, httpClient)
		if len(repos) == 0 {
			metrics.AddNote("Failed to derive any repos and there were no CPEs")
			return nil
		}
		metrics.AddNote("Derived repos for CVE with no CPEs: %v", repos)
		reposForCVE = repos
	}
	vendorProductCombinations := make(map[c.VendorProduct]bool)
	for _, CPEstr := range CPEs {
		CPE, err := c.ParseCPE(CPEstr)
		if err != nil {
			metrics.AddNote("Failed to parse CPE: %v", CPEstr)
			continue
		}
		if CPE.Part != "a" { // only care about application CPEs
			continue
		}
		vendorProductCombinations[c.VendorProduct{Vendor: CPE.Vendor, Product: CPE.Product}] = true
	}

	// If there wasn't a repo from the CPE Dictionary, try and derive one from the CVE references.
	for vendorProductKey := range vendorProductCombinations {
		if repos, ok := vpRepoCache.Get(vendorProductKey); ok {
			metrics.AddNote("Pre-references, derived repos using cache: %v", repos)
			if len(reposForCVE) == 0 {
				reposForCVE = repos
				continue
			}
			for _, repo := range repos {
				if !slices.Contains(reposForCVE, repo) {
					reposForCVE = append(reposForCVE, repo)
				}
			}
		}
		if len(reposForCVE) == 0 && len(refs) > 0 {
			if slices.Contains(c.VendorProductDenyList, vendorProductKey) {
				continue
			}
			repos := c.ReposFromReferences(vpRepoCache, &vendorProductKey, refs, c.RefTagDenyList, repoTagsCache, metrics, httpClient)
			if len(repos) == 0 {
				metrics.AddNote("Failed to derive any repos for %s/%s", vendorProductKey.Vendor, vendorProductKey.Product)
				continue
			}
			metrics.AddNote("Derived repos: %v", repos)
			reposForCVE = append(reposForCVE, repos...)
		}
	}

	if len(reposForCVE) == 0 {
		// We have nothing useful to work with, so we'll assume it's out of scope
		metrics.AddNote("Passing due to lack of viable repository")

		return nil
	}

	metrics.AddNote("Found Repos for CVE %s: %v", string(CVEID), reposForCVE)

	return reposForCVE
}
