// Package nvd converts NVD CVEs to OSV format.
package nvd

import (
	"errors"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"slices"

	"github.com/google/osv/vulnfeeds/conversion"
	"github.com/google/osv/vulnfeeds/cves"
	"github.com/google/osv/vulnfeeds/git"
	"github.com/google/osv/vulnfeeds/models"
	"github.com/google/osv/vulnfeeds/utility/logger"
	"github.com/google/osv/vulnfeeds/vulns"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
)

var ErrNoRanges = errors.New("no ranges")

var ErrUnresolvedFix = errors.New("fixes not resolved to commits")

// CVEToOSV Takes an NVD CVE record and outputs an OSV file in the specified directory.
func CVEToOSV(cve models.NVDCVE, repos []string, cache *git.RepoTagsCache, directory string, metrics *models.ConversionMetrics, rejectFailed bool) models.ConversionOutcome {
	CPEs := cves.CPEs(cve)
	metrics.CPEs = CPEs
	// The vendor name and product name are used to construct the output `vulnDir` below, so need to be set to *something* to keep the output tidy.
	maybeVendorName := "ENOCPE"
	maybeProductName := "ENOCPE"

	if len(CPEs) > 0 {
		CPE, _ := cves.ParseCPE(CPEs[0]) // For naming the subdirectory used for output.
		maybeVendorName = CPE.Vendor
		maybeProductName = CPE.Product
	}

	// Create basic OSV record
	v := vulns.FromNVDCVE(cve.ID, cve)

	cpeRanges, commits, textRanges := cves.ExtractVersions(v, cve, nil, http.DefaultClient, metrics)
	
	if cpeRanges == nil && commits == nil && textRanges == nil {
		metrics.AddNote("No ranges detected for %q", maybeProductName)
		metrics.Outcome = models.NoRanges
		if rejectFailed {
			return metrics.Outcome
		}
	}
	
	var resolutionOutcome models.ConversionOutcome
	if len(cpeRanges) > 0 {
		outcome, affected := ResolveVersionsToCommits(cpeRanges, repos, cache, metrics)
		resolutionOutcome = outcome
		if outcome == models.Successful {
			conversion.AddAffected(v, affected, metrics)
		}
	}

	if len(commits) > 0 {
		var versionRanges []*osvschema.Range
		// handle commits as version ranges
		for _, commit := range commits {
			// if commit doesn't already 
			vr := conversion.BuildVersionRange(commit.Introduced,commit.LastAffected,  commit.Fixed)	
			vr.Repo = commit.Repo
			versionRanges = append(versionRanges, vr)
		}
		
		if len(versionRanges) > 0 {
			affected := osvschema.Affected{
				Ranges: versionRanges,
			}
			conversion.AddAffected(v, &affected, metrics)
			resolutionOutcome = models.Successful
		}
	}

	if len(textRanges) > 0 && resolutionOutcome != models.Successful {
		// handle text ranges as version ranges
		outcome, affected := ResolveVersionsToCommits(textRanges, repos, cache, metrics)
		resolutionOutcome = outcome
		if outcome == models.Successful {
			conversion.AddAffected(v, affected, metrics)
		}
	}

	for _, affected := range v.Affected {
		if len(affected.Ranges) != 0 {
			break
		}
		resolutionOutcome = models.NoCommitRanges
	}
	
	if rejectFailed && resolutionOutcome != models.Successful {
		return resolutionOutcome
	}
	metrics.Outcome = resolutionOutcome
	vulnDir := filepath.Join(directory, maybeVendorName, maybeProductName)

	if err := os.MkdirAll(vulnDir, 0755); err != nil {
		logger.Info("Failed to create directory "+vulnDir, slog.String("cve", string(cve.ID)), slog.String("path", vulnDir), slog.Any("err", err))
	}
	osvFile, errCVE := conversion.CreateOSVFile(cve.ID, vulnDir)
	metricsFile, errMetrics := conversion.CreateMetricsFile(cve.ID, vulnDir)
	if errCVE != nil || errMetrics != nil {
		logger.Fatal("File failed to be created for CVE", slog.String("cve", string(cve.ID)))
	}

	err := v.ToJSON(osvFile)
	if err != nil {
		logger.Error("Failed to write", slog.Any("err", err))
	}

	osvFile.Close()

	err = conversion.WriteMetricsFile(metrics, metricsFile)
	if err != nil {
		logger.Error("Failed to write metrics", slog.Any("err", err))
	}

	return metrics.Outcome
}

// CVEToPackageInfo takes an NVD CVE record and outputs a PackageInfo struct in a file in the specified directory.
// func CVEToPackageInfo(cve models.NVDCVE, repos []string, cache *git.RepoTagsCache, directory string, metrics *models.ConversionMetrics, rejectFailed bool) models.ConversionOutcome {
// 	CPEs := cves.CPEs(cve)
// 	// The vendor name and product name are used to construct the output `vulnDir` below, so need to be set to *something* to keep the output tidy.
// 	maybeVendorName := "ENOCPE"
// 	maybeProductName := "ENOCPE"

// 	if len(CPEs) > 0 {
// 		CPE, err := cves.ParseCPE(CPEs[0]) // For naming the subdirectory used for output.
// 		maybeVendorName = CPE.Vendor
// 		maybeProductName = CPE.Product
// 		if err != nil {
// 			return models.NoRanges
// 		}
// 	}

// 	// more often than not, this yields a VersionInfo with AffectedVersions and no AffectedCommits.
// 	// versions := cves.ExtractVersions(cve, nil, http.DefaultClient, metrics)

// 	// metrics.Outcome = ResolveVersionsToCommits(&versions, repos, cache, metrics)

// 	// if len(versions.AffectedCommits) == 0 {
// 	// 	metrics.AddNote("No affected commit ranges determined for %q", maybeProductName)
// 	// 	metrics.Outcome = models.NoCommitRanges
// 	// }

// 	// if rejectFailed && metrics.Outcome != models.Successful {
// 	// 	return metrics.Outcome
// 	// }

// 	// versions.AffectedVersions = nil // these have served their purpose and are not required in the resulting output.

// 	// slices.SortStableFunc(versions.AffectedCommits, models.AffectedCommitCompare)

// 	var pkgInfos []vulns.PackageInfo
// 	pi := vulns.PackageInfo{VersionInfo: versions}
// 	pkgInfos = append(pkgInfos, pi) // combine-to-osv expects a serialised *array* of PackageInfo

// 	vulnDir := filepath.Join(directory, maybeVendorName, maybeProductName)
// 	err := os.MkdirAll(vulnDir, 0755)
// 	if err != nil {
// 		logger.Warn("Failed to create dir", slog.Any("err", err))
// 	}

// 	outputFile := filepath.Join(vulnDir, string(cve.ID)+".nvd"+models.Extension)
// 	f, err := os.Create(outputFile)
// 	if err != nil {
// 		logger.Warn("Failed to open for writing", slog.String("path", outputFile), slog.Any("err", err))
// 	}
// 	defer f.Close()

// 	encoder := json.NewEncoder(f)
// 	encoder.SetIndent("", "  ")
// 	err = encoder.Encode(&pkgInfos)

// 	if err != nil {
// 		logger.Warn("Failed to encode PackageInfo", slog.String("path", outputFile), slog.Any("err", err))
// 	}

// 	logger.Info("Generated PackageInfo record", slog.String("cve", string(cve.ID)), slog.String("product", maybeProductName))

// 	metricsFile, err := conversion.CreateMetricsFile(cve.ID, vulnDir)
// 	if err != nil {
// 		logger.Warn("Failed to create metrics file", slog.String("path", metricsFile.Name()), slog.Any("err", err))
// 	}
// 	err = conversion.WriteMetricsFile(metrics, metricsFile)
// 	if err != nil {
// 		logger.Warn("Failed to write metrics file", slog.String("path", metricsFile.Name()), slog.Any("err", err))
// 	}

// 	return metrics.Outcome
// }

// FindRepos attempts to find the source code repositories for a given CVE.
func FindRepos(cve models.NVDCVE, vpRepoCache *cves.VPRepoCache, repoTagsCache *git.RepoTagsCache, metrics *models.ConversionMetrics, httpClient *http.Client) []string {
	// Find repos
	refs := cve.References
	conversion.DeduplicateRefs(refs)
	CPEs := cves.CPEs(cve)
	CVEID := cve.ID
	var reposForCVE []string

	if len(refs) == 0 && len(CPEs) == 0 {
		metrics.AddNote("Skipping due to lack of CPEs and lack of references")
		// 100% of these in 2022 were rejected CVEs
		metrics.Outcome = models.Rejected

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
		if CPE.Part != "a" && CPE.Part != "o" { // only care about application and operating system CPEs
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
		metrics.Outcome = models.NoRepos

		return nil
	}

	metrics.AddNote("Found Repos for CVE %s: %v", string(CVEID), reposForCVE)

	return reposForCVE
}

func ResolveVersionsToCommits(versions []*osvschema.Range, repos []string, cache *git.RepoTagsCache, metrics *models.ConversionMetrics) (models.ConversionOutcome, *osvschema.Affected) {
	if len(repos) == 0 && len(versions) == 0 {
		return models.NoRepos, nil
	}

	// There are some AffectedVersions to try and resolve to AffectedCommits.
	metrics.AddNote("Trying to convert version tags to commits: %v with repos: %v", versions, repos)
	affected, err := conversion.GitVersionsToCommits(versions, repos, metrics, cache)
	if err != nil {
		return models.FixUnresolvable, nil
	}

	return models.Successful, affected
}
