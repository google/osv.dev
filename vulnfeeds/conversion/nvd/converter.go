// Package nvd converts NVD CVEs to OSV format.
package nvd

import (
	"encoding/json"
	"errors"
	"fmt"
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
)

var ErrNoRanges = errors.New("no ranges")

var ErrUnresolvedFix = errors.New("fixes not resolved to commits")

// CVEToOSV Takes an NVD CVE record and outputs an OSV file in the specified directory.
func CVEToOSV(cve models.NVDCVE, repos []string, cache *git.RepoTagsCache, directory string, metrics *models.ConversionMetrics) error {
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
			return fmt.Errorf("[%s]: Can't generate an OSV record without valid CPE data", cve.ID)
		}
	}

	v := vulns.FromNVDCVE(cve.ID, cve)
	versions := cves.ExtractVersionInfo(cve, nil, http.DefaultClient, metrics)

	if len(versions.AffectedVersions) != 0 {
		var err error
		// There are some AffectedVersions to try and resolve to AffectedCommits.
		if len(repos) == 0 {
			metrics.AddNote("No affected ranges for %q, and no repos to try and convert %+v to tags with", maybeProductName, versions.AffectedVersions)
			return fmt.Errorf("[%s]: No affected ranges for %q, and no repos to try and convert %+v to tags with", cve.ID, maybeProductName, versions.AffectedVersions)
		}
		logger.Info("Trying to convert version tags to commits", slog.String("cve", string(cve.ID)), slog.Any("versions", versions), slog.Any("repos", repos))
		versions, err = cves.GitVersionsToCommits(cve.ID, versions, repos, cache)
		if err != nil {
			metrics.AddNote("Failed to convert version tags to commits: %#v", err)
			return fmt.Errorf("[%s]: Failed to convert version tags to commits: %#w", cve.ID, err)
		}
		hasAnyFixedCommits := false
		for _, repo := range repos {
			if versions.HasFixedCommits(repo) {
				hasAnyFixedCommits = true
				break
			}
		}

		if versions.HasFixedVersions() && !hasAnyFixedCommits {
			metrics.AddNote("Failed to convert fixed version tags to commits: %#v", versions)
			return fmt.Errorf("[%s]: Failed to convert fixed version tags to commits: %#v %w", cve.ID, versions, ErrUnresolvedFix)
		}

		hasAnyLastAffectedCommits := false
		for _, repo := range repos {
			if versions.HasLastAffectedCommits(repo) {
				hasAnyLastAffectedCommits = true
				break
			}
		}

		if versions.HasLastAffectedVersions() && !hasAnyLastAffectedCommits && !hasAnyFixedCommits {
			metrics.AddNote("Failed to convert last_affected version tags to commits: %#v", versions)
			return fmt.Errorf("[%s]: Failed to convert last_affected version tags to commits: %#v %w", cve.ID, versions, ErrUnresolvedFix)
		}
	}

	slices.SortStableFunc(versions.AffectedCommits, models.AffectedCommitCompare)

	vulns.AttachExtractedVersionInfo(v, versions)

	if len(v.Affected) == 0 {
		metrics.AddNote("No affected ranges detected for %q", maybeProductName)
		return fmt.Errorf("[%s]: No affected ranges detected for %q %w", cve.ID, maybeProductName, ErrNoRanges)
	}

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
		logger.Info("Failed to write", slog.Any("err", err))
		return err
	}
	
	logger.Info("Generated OSV record", slog.String("cve", string(cve.ID)), slog.String("product", maybeProductName))
	osvFile.Close()
	
	err = conversion.WriteMetricsFile(metrics, metricsFile)
	if err != nil {
		return err
	}

	
	return nil
}

// CVEToPackageInfo takes an NVD CVE record and outputs a PackageInfo struct in a file in the specified directory.
func CVEToPackageInfo(cve models.NVDCVE, repos []string, cache *git.RepoTagsCache, directory string, metrics *models.ConversionMetrics) error {
	CPEs := cves.CPEs(cve)
	// The vendor name and product name are used to construct the output `vulnDir` below, so need to be set to *something* to keep the output tidy.
	maybeVendorName := "ENOCPE"
	maybeProductName := "ENOCPE"

	if len(CPEs) > 0 {
		CPE, err := cves.ParseCPE(CPEs[0]) // For naming the subdirectory used for output.
		maybeVendorName = CPE.Vendor
		maybeProductName = CPE.Product
		if err != nil {
			return fmt.Errorf("[%s]: Can't generate an OSV record without valid CPE data", cve.ID)
		}
	}

	// more often than not, this yields a VersionInfo with AffectedVersions and no AffectedCommits.
	versions := cves.ExtractVersionInfo(cve, nil, http.DefaultClient, metrics)

	if len(versions.AffectedVersions) != 0 {
		var err error
		// There are some AffectedVersions to try and resolve to AffectedCommits.
		if len(repos) == 0 {
			metrics.AddNote("No affected ranges for %q, and no repos to try and convert %+v to tags with", maybeProductName, versions.AffectedVersions)
			return fmt.Errorf("[%s]: No affected ranges for %q, and no repos to try and convert %+v to tags with", cve.ID, maybeProductName, versions.AffectedVersions)
		}
		logger.Info("Trying to convert version tags to commits", slog.String("cve", string(cve.ID)), slog.Any("versions", versions), slog.Any("repos", repos))
		versions, err = cves.GitVersionsToCommits(cve.ID, versions, repos, cache)
		if err != nil {
			metrics.AddNote("Failed to convert version tags to commits: %#v", err)
			return fmt.Errorf("[%s]: Failed to convert version tags to commits: %#w", cve.ID, err)
		}
	}

	hasAnyFixedCommits := false
	for _, repo := range repos {
		if versions.HasFixedCommits(repo) {
			hasAnyFixedCommits = true
		}
	}

	if versions.HasFixedVersions() && !hasAnyFixedCommits {
		metrics.AddNote("Failed to convert fixed version tags to commits: %#v", versions)
		return fmt.Errorf("[%s]: Failed to convert fixed version tags to commits: %#v %w", cve.ID, versions, ErrUnresolvedFix)
	}

	hasAnyLastAffectedCommits := false
	for _, repo := range repos {
		if versions.HasLastAffectedCommits(repo) {
			hasAnyLastAffectedCommits = true
		}
	}

	if versions.HasLastAffectedVersions() && !hasAnyLastAffectedCommits && !hasAnyFixedCommits {
		metrics.AddNote("Failed to convert last_affected version tags to commits: %#v", versions)
		return fmt.Errorf("[%s]: Failed to convert last_affected version tags to commits: %#v %w", cve.ID, versions, ErrUnresolvedFix)
	}

	if len(versions.AffectedCommits) == 0 {
		metrics.AddNote("No affected commit ranges determined for %q", maybeProductName)
		return fmt.Errorf("[%s]: No affected commit ranges determined for %q %w", cve.ID, maybeProductName, ErrNoRanges)
	}

	versions.AffectedVersions = nil // these have served their purpose and are not required in the resulting output.

	slices.SortStableFunc(versions.AffectedCommits, models.AffectedCommitCompare)

	var pkgInfos []vulns.PackageInfo
	pi := vulns.PackageInfo{VersionInfo: versions}
	pkgInfos = append(pkgInfos, pi) // combine-to-osv expects a serialised *array* of PackageInfo

	vulnDir := filepath.Join(directory, maybeVendorName, maybeProductName)
	err := os.MkdirAll(vulnDir, 0755)
	if err != nil {
		logger.Warn("Failed to create dir", slog.Any("err", err))
		return fmt.Errorf("failed to create dir: %w", err)
	}

	outputFile := filepath.Join(vulnDir, string(cve.ID)+".nvd"+models.Extension)
	// notesFile := filepath.Join(vulnDir, string(cve.ID)+".nvd.notes")
	f, err := os.Create(outputFile)
	if err != nil {
		logger.Warn("Failed to open for writing", slog.String("path", outputFile), slog.Any("err", err))
		return fmt.Errorf("failed to open %s for writing: %w", outputFile, err)
	}
	defer f.Close()

	encoder := json.NewEncoder(f)
	encoder.SetIndent("", "  ")
	err = encoder.Encode(&pkgInfos)

	if err != nil {
		logger.Warn("Failed to encode PackageInfo", slog.String("path", outputFile), slog.Any("err", err))
		return fmt.Errorf("failed to encode PackageInfo to %s: %w", outputFile, err)
	}

	logger.Info("Generated PackageInfo record", slog.String("cve", string(cve.ID)), slog.String("product", maybeProductName))

	metricsFile, err := conversion.CreateMetricsFile(cve.ID, vulnDir)
	if err != nil {
		return err
	}
	err = conversion.WriteMetricsFile(metrics, metricsFile)
	if err != nil {
		return err
	}

	return nil
}

// FindRepos attempts to find the source code repositories for a given CVE.
func FindRepos(cve models.NVDCVE, vpRepoCache *cves.VPRepoCache, metrics *models.ConversionMetrics) []string {
	// Find repos
	refs := cve.References
	CPEs := cves.CPEs(cve)
	CVEID := cve.ID
	var reposForCVE []string

	if len(refs) == 0 && len(CPEs) == 0 {
		logger.Info("Skipping due to lack of CPEs and lack of references", slog.String("cve", string(CVEID)))
		// 100% of these in 2022 were rejected CVEs
		metrics.Outcome = models.Rejected

		return nil
	}

	// Edge case: No CPEs, but perhaps usable references.
	if len(refs) > 0 && len(CPEs) == 0 {
		repos := cves.ReposFromReferences(nil, nil, refs, cves.RefTagDenyList, metrics)
		if len(repos) == 0 {
			logger.Warn("Failed to derive any repos and there were no CPEs", slog.String("cve", string(CVEID)))
			return nil
		}
		logger.Info("Derived repos for CVE with no CPEs", slog.String("cve", string(CVEID)), slog.Any("repos", repos))
		reposForCVE = repos
	}

	// Does it have any application CPEs? Look for pre-computed repos based on VendorProduct.
	appCPECount := 0
	for _, CPEstr := range CPEs {
		CPE, err := cves.ParseCPE(CPEstr)
		if err != nil {
			logger.Warn("Failed to parse CPE", slog.String("cve", string(CVEID)), slog.String("cpe", CPEstr), slog.Any("err", err))
			metrics.Outcome = models.ConversionUnknown

			continue
		}
		if CPE.Part == "a" {
			appCPECount += 1
		}
		vendorProductKey := cves.VendorProduct{Vendor: CPE.Vendor, Product: CPE.Product}
		if repos, ok := vpRepoCache.Get(vendorProductKey); ok {
			logger.Info("Pre-references, derived repos using cache", slog.String("cve", string(CVEID)), slog.Any("repos", repos), slog.String("vendor", CPE.Vendor), slog.String("product", CPE.Product))
			if len(reposForCVE) == 0 {
				reposForCVE = repos
				continue
			}
			// Don't append duplicates.
			for _, repo := range repos {
				if !slices.Contains(reposForCVE, repo) {
					reposForCVE = append(reposForCVE, repo)
				}
			}
		}
	}

	if len(CPEs) > 0 && appCPECount == 0 {
		// This CVE is not for software (based on there being CPEs but not any application ones), skip.
		metrics.Outcome = models.NoSoftware
		return nil
	}

	// If there wasn't a repo from the CPE Dictionary, try and derive one from the CVE references.
	if len(reposForCVE) == 0 && len(refs) > 0 {
		for _, CPEstr := range cves.CPEs(cve) {
			CPE, err := cves.ParseCPE(CPEstr)
			if err != nil {
				logger.Warn("Failed to parse CPE", slog.String("cve", string(CVEID)), slog.String("cpe", CPEstr), slog.Any("err", err))
				continue
			}
			// Continue to only focus on application CPEs.
			if CPE.Part != "a" {
				continue
			}
			if slices.Contains(cves.VendorProductDenyList, cves.VendorProduct{Vendor: CPE.Vendor, Product: ""}) {
				continue
			}
			if slices.Contains(cves.VendorProductDenyList, cves.VendorProduct{Vendor: CPE.Vendor, Product: CPE.Product}) {
				continue
			}
			repos := cves.ReposFromReferences(vpRepoCache, &cves.VendorProduct{Vendor: CPE.Vendor, Product: CPE.Product}, refs, cves.RefTagDenyList, metrics)
			if len(repos) == 0 {
				logger.Warn("Failed to derive any repos", slog.String("cve", string(CVEID)), slog.String("vendor", CPE.Vendor), slog.String("product", CPE.Product))
				continue
			}
			logger.Info("Derived repos", slog.String("cve", string(CVEID)), slog.Any("repos", repos), slog.String("vendor", CPE.Vendor), slog.String("product", CPE.Product))
			reposForCVE = repos
		}
	}

	logger.Info("Finished processing "+string(CVEID),
		slog.String("cve", string(CVEID)),
		slog.Int("cpes", len(CPEs)),
		slog.Int("app_cpes", appCPECount),
		slog.Int("derived_repos", len(reposForCVE)))

	// If we've made it to here, we may have a CVE:
	// * that has Application-related CPEs (so applies to software)
	// * has a reference that is a known repository URL
	// OR
	// * a derived repository for the software package
	//
	// We do not yet have:
	// * any knowledge of the language used
	// * definitive version information

	if len(reposForCVE) == 0 {
		// We have nothing useful to work with, so we'll assume it's out of scope
		logger.Info("Passing due to lack of viable repository", slog.String("cve", string(CVEID)))
		metrics.Outcome = models.NoRepos

		return nil
	}

	logger.Info("Found Repos for CVE "+string(CVEID), slog.String("cve", string(CVEID)), slog.Any("repos", reposForCVE))

	return reposForCVE
}
