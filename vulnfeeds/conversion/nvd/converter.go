// Package nvd converts NVD CVEs to OSV format.
package nvd

import (
	"encoding/json"
	"errors"
	"log/slog"
	"maps"
	"net/http"
	"os"
	"path/filepath"
	"slices"

	"github.com/google/osv/vulnfeeds/conversion"
	"github.com/google/osv/vulnfeeds/cves"
	"github.com/google/osv/vulnfeeds/git"
	"github.com/google/osv/vulnfeeds/models"
	"github.com/google/osv/vulnfeeds/utility"
	"github.com/google/osv/vulnfeeds/utility/logger"
	"github.com/google/osv/vulnfeeds/vulns"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
)

var ErrNoRanges = errors.New("no ranges")

var ErrUnresolvedFix = errors.New("fixes not resolved to commits")

// CVEToOSV Takes an NVD CVE record and outputs an OSV file in the specified directory.
func CVEToOSV(cve models.NVDCVE, repos []string, cache *git.RepoTagsCache, directory string, metrics *models.ConversionMetrics, rejectFailed bool, outputMetrics bool) models.ConversionOutcome {
	CPEs := cves.CPEs(cve)
	metrics.CPEs = CPEs
	// The vendor name and product name are used to construct the output `vulnDir` below, so need to be set to *something* to keep the output tidy.
	maybeVendorName := "ENOCPE"
	maybeProductName := "ENOCPE"

	if len(CPEs) > 0 {
		CPE, err := cves.ParseCPE(CPEs[0]) // For naming the subdirectory used for output.
		maybeVendorName = CPE.Vendor
		maybeProductName = CPE.Product
		if err != nil {
			metrics.AddNote("Can't generate an OSV record without valid CPE data")
			return models.ConversionUnknown
		}
	}

	// Create basic OSV record
	v := vulns.FromNVDCVE(cve.ID, cve)

	// At the bare minimum, we want to attempt to extract the raw version information
	// from CPEs, whether or not they can resolve to commits.
	cpeRanges := cves.ExtractVersionsFromCPEs(cve, nil, metrics)

	// If there are no repos, there are no commits from the refs either
	if len(cpeRanges) == 0 && len(repos) == 0 {
		metrics.SetOutcome(models.NoRepos)
		outputFiles(v, directory, maybeVendorName, maybeProductName, metrics, rejectFailed, outputMetrics)

		return models.NoRepos
	}

	successfulRepos := make(map[string]bool)
	var resolvedRanges, unresolvedRanges []*osvschema.Range

	// Exit early if there are no repositories
	if len(repos) == 0 {
		metrics.SetOutcome(models.NoRepos)
		metrics.UnresolvedRangesCount += len(cpeRanges)
		affected := MergeRangesAndCreateAffected(resolvedRanges, cpeRanges, nil, nil, metrics)
		v.Affected = append(v.Affected, affected)
		// Exit early
		outputFiles(v, directory, maybeVendorName, maybeProductName, metrics, rejectFailed, outputMetrics)

		return models.NoRepos
	}

	// If we have ranges, try to resolve them
	r, un, sR := processRanges(cpeRanges, repos, metrics, cache, models.VersionSourceCPE)
	if metrics.Outcome == models.Error {
		return models.Error
	}
	resolvedRanges = append(resolvedRanges, r...)
	unresolvedRanges = append(unresolvedRanges, un...)
	for _, s := range sR {
		successfulRepos[s] = true
	}

	// Extract Commits
	commits, err := cves.ExtractCommitsFromRefs(cve.References, http.DefaultClient)
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
		textRanges := cves.ExtractVersionsFromText(nil, models.EnglishDescription(cve.Descriptions), metrics)
		if len(textRanges) > 0 {
			metrics.AddNote("Extracted versions from description: %v", textRanges)
		}
		r, un, sR := processRanges(textRanges, repos, metrics, cache, models.VersionSourceDescription)
		if metrics.Outcome == models.Error {
			return models.Error
		}
		resolvedRanges = append(resolvedRanges, r...)
		unresolvedRanges = append(unresolvedRanges, un...)
		for _, s := range sR {
			successfulRepos[s] = true
		}
	}

	if len(resolvedRanges) == 0 && len(commits) == 0 {
		metrics.AddNote("No ranges detected for %q", maybeProductName)
		metrics.SetOutcome(models.NoRanges)
	}

	// Use the successful repos for more efficient merging.
	keys := slices.Collect(maps.Keys(successfulRepos))
	affected := MergeRangesAndCreateAffected(resolvedRanges, unresolvedRanges, commits, keys, metrics)
	v.Affected = append(v.Affected, affected)

	if metrics.Outcome == models.Error || (!outputMetrics && rejectFailed && metrics.Outcome != models.Successful) {
		return metrics.Outcome
	}

	outputFiles(v, directory, maybeVendorName, maybeProductName, metrics, rejectFailed, outputMetrics)

	return metrics.Outcome
}

// CVEToPackageInfo takes an NVD CVE record and outputs a PackageInfo struct in a file in the specified directory.
func CVEToPackageInfo(cve models.NVDCVE, repos []string, cache *git.RepoTagsCache, directory string, metrics *models.ConversionMetrics) models.ConversionOutcome {
	CPEs := cves.CPEs(cve)
	// The vendor name and product name are used to construct the output `vulnDir` below, so need to be set to *something* to keep the output tidy.
	maybeVendorName := "ENOCPE"
	maybeProductName := "ENOCPE"

	if len(CPEs) > 0 {
		CPE, err := cves.ParseCPE(CPEs[0]) // For naming the subdirectory used for output.
		maybeVendorName = CPE.Vendor
		maybeProductName = CPE.Product
		if err != nil {
			return models.NoRanges
		}
	}

	// more often than not, this yields a VersionInfo with AffectedVersions and no AffectedCommits.
	versions := cves.ExtractVersionInfo(cve, nil, http.DefaultClient, metrics)

	if len(versions.AffectedVersions) != 0 {
		// There are some AffectedVersions to try and resolve to AffectedCommits.
		if len(repos) == 0 {
			metrics.AddNote("No affected ranges for %q, and no repos to try and convert %+v to tags with", maybeProductName, versions.AffectedVersions)
			return models.NoRepos
		}
		logger.Info("Trying to convert version tags to commits", slog.String("cve", string(cve.ID)), slog.Any("versions", versions), slog.Any("repos", repos))
		cves.VersionInfoToCommits(&versions, repos, cache, metrics)
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

	metricsFile, err := conversion.CreateMetricsFile(cve.ID, vulnDir)
	if err != nil {
		logger.Warn("Failed to create metrics file", slog.String("path", metricsFile.Name()), slog.Any("err", err))
	}
	err = conversion.WriteMetricsFile(metrics, metricsFile)
	if err != nil {
		logger.Warn("Failed to write metrics file", slog.String("path", metricsFile.Name()), slog.Any("err", err))
	}

	return metrics.Outcome
}

// FindRepos attempts to find the source code repositories for a given CVE.
func FindRepos(cve models.NVDCVE, vpRepoCache *cves.VPRepoCache, repoTagsCache *git.RepoTagsCache, metrics *models.ConversionMetrics, httpClient *http.Client) []string {
	// Find repos
	refs := conversion.DeduplicateRefs(cve.References)
	CPEs := cves.CPEs(cve)
	CVEID := cve.ID
	var reposForCVE []string

	if len(refs) == 0 && len(CPEs) == 0 {
		metrics.AddNote("Skipping due to lack of CPEs and lack of references")
		// 100% of these in 2022 were rejected CVEs
		metrics.SetOutcome(models.Rejected)

		return nil
	}

	if len(refs) > 0 && len(CPEs) == 0 {
		repos := cves.ReposFromReferences(nil, nil, refs, cves.RefTagDenyList, repoTagsCache, metrics, httpClient)
		if len(repos) == 0 {
			metrics.AddNote("Failed to derive any repos and there were no CPEs")
			return nil
		}
		metrics.AddNote("Derived repos for CVE with no CPEs: %v", repos)
		reposForCVE = repos
	}
	vendorProductCombinations := make(map[cves.VendorProduct]bool)
	for _, CPEstr := range CPEs {
		CPE, err := cves.ParseCPE(CPEstr)
		if err != nil {
			metrics.AddNote("Failed to parse CPE: %v", CPEstr)
			continue
		}
		if CPE.Part != "a" { // only care about application CPEs
			continue
		}
		vendorProductCombinations[cves.VendorProduct{Vendor: CPE.Vendor, Product: CPE.Product}] = true
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
			if slices.Contains(cves.VendorProductDenyList, vendorProductKey) {
				continue
			}
			repos := cves.ReposFromReferences(vpRepoCache, &vendorProductKey, refs, cves.RefTagDenyList, repoTagsCache, metrics, httpClient)
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

// MergeRangesAndCreateAffected combines resolved and unresolved ranges with commits to create an OSV Affected object.
// It merges ranges for the same repository and adds commit events to the appropriate ranges at the end.
//
// Arguments:
//   - resolvedRanges: A slice of resolved OSV ranges to be merged.
//   - unresolvedRanges: A slice of unresolved OSV ranges to be included in the database specific field.
//   - commits: A slice of affected commits to be converted into events and added to ranges.
//   - successfulRepos: A slice of repository URLs that were successfully processed.
//   - metrics: A pointer to ConversionMetrics to track the outcome and notes.
func MergeRangesAndCreateAffected(resolvedRanges []*osvschema.Range, unresolvedRanges []*osvschema.Range, commits []models.AffectedCommit, successfulRepos []string, metrics *models.ConversionMetrics) *osvschema.Affected {
	var newResolvedRanges []*osvschema.Range
	// Combine the ranges appropriately
	if len(resolvedRanges) > 0 {
		slices.Sort(successfulRepos)
		successfulRepos = slices.Compact(successfulRepos)
		for _, repo := range successfulRepos {
			var mergedRange *osvschema.Range
			for _, vr := range resolvedRanges {
				if vr.GetRepo() == repo {
					if mergedRange == nil {
						mergedRange = vr
					} else {
						var err error
						mergedRange, err = conversion.MergeTwoRanges(mergedRange, vr)
						if err != nil {
							metrics.AddNote("Failed to merge ranges: %v", err)
						}
					}
				}
			}
			if len(commits) > 0 {
				for _, commit := range commits {
					if commit.Repo == repo {
						if mergedRange == nil {
							mergedRange = conversion.BuildVersionRange(commit.Introduced, commit.LastAffected, commit.Fixed)
							mergedRange.Repo = repo
						} else {
							event := convertCommitToEvent(commit)
							if event != nil {
								addEventToRange(mergedRange, event)
							}
						}
					}
				}
			}
			if mergedRange != nil {
				newResolvedRanges = append(newResolvedRanges, mergedRange)
			}
		}
	}

	// if there are no resolved version but there are commits, we should create a range for each commit
	if len(resolvedRanges) == 0 && len(commits) > 0 {
		for _, commit := range commits {
			newRange := conversion.BuildVersionRange(commit.Introduced, commit.LastAffected, commit.Fixed)
			newRange.Repo = commit.Repo
			newRange.Type = osvschema.Range_GIT
			newResolvedRanges = append(newResolvedRanges, newRange)
			metrics.ResolvedRangesCount++
		}
	}

	newAffected := &osvschema.Affected{
		Ranges: newResolvedRanges,
	}

	if len(unresolvedRanges) > 0 {
		databaseSpecific, err := utility.NewStructpbFromMap(map[string]any{"unresolved_ranges": unresolvedRanges})
		if err != nil {
			metrics.AddNote("failed to make database specific: %v", err)
		}
		newAffected.DatabaseSpecific = databaseSpecific
	}

	return newAffected
}

// addEventToRange adds an event to a version range, avoiding duplicates.
// Introduced events are prepended to the events list, while others are appended.
//
// Arguments:
//   - versionRange: The OSV range to which the event will be added.
//   - event: The OSV event (Introduced, Fixed, or LastAffected) to add.
func addEventToRange(versionRange *osvschema.Range, event *osvschema.Event) {
	// Handle duplicate events being added
	for _, e := range versionRange.GetEvents() {
		if e.GetIntroduced() != "" && e.GetIntroduced() == event.GetIntroduced() {
			return
		}
		if e.GetFixed() != "" && e.GetFixed() == event.GetFixed() {
			return
		}
		if e.GetLastAffected() != "" && e.GetLastAffected() == event.GetLastAffected() {
			return
		}
	}
	//TODO: maybe handle if the fixed event appears as an introduced event or similar.

	if event.GetIntroduced() != "" {
		versionRange.Events = append([]*osvschema.Event{{
			Introduced: event.GetIntroduced()}}, versionRange.GetEvents()...)
	} else {
		versionRange.Events = append(versionRange.Events, event)
	}
}

// convertCommitToEvent creates an OSV Event from an AffectedCommit.
// It returns an event with the Introduced, Fixed, or LastAffected value from the commit.
func convertCommitToEvent(commit models.AffectedCommit) *osvschema.Event {
	if commit.Introduced != "" {
		return &osvschema.Event{
			Introduced: commit.Introduced,
		}
	}
	if commit.Fixed != "" {
		return &osvschema.Event{
			Fixed: commit.Fixed,
		}
	}
	if commit.LastAffected != "" {
		return &osvschema.Event{
			LastAffected: commit.LastAffected,
		}
	}

	return nil
}

// outputFiles writes the OSV vulnerability record and conversion metrics to files in the specified directory.
// It creates the necessary subdirectories based on the vendor and product names and handles whether or not
// the files should be written based on the rejectFailed and outputMetrics flags.
//
// Arguments:
//   - v: The OSV Vulnerability object to be written to a file.
//   - dir: The base directory where the output files should be created.
//   - vendor: The vendor name used to create the subdirectory.
//   - product: The product name used to create the subdirectory.
//   - metrics: A pointer to ConversionMetrics to be written to a metrics file.
//   - rejectFailed: A boolean indicating whether to skip writing the OSV file if the conversion was not successful.
//   - outputMetrics: A boolean indicating whether to write the metrics file.
func outputFiles(v *vulns.Vulnerability, dir string, vendor string, product string, metrics *models.ConversionMetrics, rejectFailed bool, outputMetrics bool) {
	cveID := v.Id
	vulnDir := filepath.Join(dir, vendor, product)

	if err := os.MkdirAll(vulnDir, 0755); err != nil {
		logger.Info("Failed to create directory "+vulnDir, slog.String("cve", cveID), slog.String("path", vulnDir), slog.Any("err", err))
	}

	if metrics.Outcome == models.Error {
		return
	}

	if !rejectFailed || metrics.Outcome == models.Successful {
		osvFile, errCVE := conversion.CreateOSVFile(models.CVEID(cveID), vulnDir)
		if errCVE != nil {
			logger.Fatal("File failed to be created for CVE", slog.String("cve", cveID))
		}
		if err := v.ToJSON(osvFile); err != nil {
			logger.Error("Failed to write", slog.Any("err", err))
		}
		osvFile.Close()
	}
	if outputMetrics {
		metricsFile, errMetrics := conversion.CreateMetricsFile(models.CVEID(cveID), vulnDir)
		if errMetrics != nil {
			logger.Fatal("File failed to be created for CVE", slog.String("cve", cveID))
		}
		if err := conversion.WriteMetricsFile(metrics, metricsFile); err != nil {
			logger.Error("Failed to write metrics", slog.Any("err", err))
		}
		metricsFile.Close()
	}
}

// processRanges attempts to resolve the given ranges to commits and updates the metrics accordingly.
func processRanges(ranges []*osvschema.Range, repos []string, metrics *models.ConversionMetrics, cache *git.RepoTagsCache, source models.VersionSource) ([]*osvschema.Range, []*osvschema.Range, []string) {
	if len(ranges) == 0 {
		return nil, nil, nil
	}

	r, un, sR := conversion.GitVersionsToCommits(ranges, repos, metrics, cache)
	if len(r) > 0 {
		metrics.ResolvedRangesCount += len(r)
		metrics.SetOutcome(models.Successful)
	}

	if len(un) > 0 {
		metrics.UnresolvedRangesCount += len(un)
		if len(r) == 0 {
			metrics.SetOutcome(models.NoCommitRanges)
		}
	}

	metrics.VersionSources = append(metrics.VersionSources, source)

	return r, un, sR
}
