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
	"strings"

	"github.com/google/osv/vulnfeeds/cves"
	"github.com/google/osv/vulnfeeds/git"
	"github.com/google/osv/vulnfeeds/models"
	"github.com/google/osv/vulnfeeds/utility/logger"
	"github.com/google/osv/vulnfeeds/vulns"
)

var ErrNoRanges = errors.New("no ranges")

var ErrUnresolvedFix = errors.New("fixes not resolved to commits")

// CVEToOSV Takes an NVD CVE record and outputs an OSV file in the specified directory.
func CVEToOSV(cve models.NVDCVE, repos []string, cache git.RepoTagsCache, directory string) error {
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

	v := vulns.FromNVDCVE(cve.ID, cve)
	versions, notes := cves.ExtractVersionInfo(cve, nil, http.DefaultClient)

	if len(versions.AffectedVersions) != 0 {
		var err error
		// There are some AffectedVersions to try and resolve to AffectedCommits.
		if len(repos) == 0 {
			return fmt.Errorf("[%s]: No affected ranges for %q, and no repos to try and convert %+v to tags with", cve.ID, maybeProductName, versions.AffectedVersions)
		}
		logger.Info("Trying to convert version tags to commits", slog.String("cve", string(cve.ID)), slog.Any("versions", versions), slog.Any("repos", repos))
		versions, err = cves.GitVersionsToCommits(cve.ID, versions, repos, cache)
		if err != nil {
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
			return fmt.Errorf("[%s]: Failed to convert last_affected version tags to commits: %#v %w", cve.ID, versions, ErrUnresolvedFix)
		}
	}

	slices.SortStableFunc(versions.AffectedCommits, models.AffectedCommitCompare)

	vulns.AttachExtractedVersionInfo(v, versions)

	if len(v.Affected) == 0 {
		return fmt.Errorf("[%s]: No affected ranges detected for %q %w", cve.ID, maybeProductName, ErrNoRanges)
	}

	vulnDir := filepath.Join(directory, maybeVendorName, maybeProductName)
	err := os.MkdirAll(vulnDir, 0755)
	if err != nil {
		logger.Warn("Failed to create dir", slog.Any("err", err))
		return fmt.Errorf("failed to create dir: %w", err)
	}
	outputFile := filepath.Join(vulnDir, v.Id+models.Extension)
	notesFile := filepath.Join(vulnDir, v.Id+".notes")
	f, err := os.Create(outputFile)
	if err != nil {
		logger.Warn("Failed to open for writing", slog.String("path", outputFile), slog.Any("err", err))
		return fmt.Errorf("failed to open %s for writing: %w", outputFile, err)
	}
	defer f.Close()
	err = v.ToJSON(f)
	if err != nil {
		logger.Warn("Failed to write", slog.String("path", outputFile), slog.Any("err", err))
		return fmt.Errorf("failed to write %s: %w", outputFile, err)
	}
	logger.Info("Generated OSV record", slog.String("cve", string(cve.ID)), slog.String("product", maybeProductName))
	if len(notes) > 0 {
		err = os.WriteFile(notesFile, []byte(strings.Join(notes, "\n")), 0600)
		if err != nil {
			logger.Warn("Failed to write", slog.String("cve", string(cve.ID)), slog.String("path", notesFile), slog.Any("err", err))
		}
	}

	return nil
}

// CVEToPackageInfo takes an NVD CVE record and outputs a PackageInfo struct in a file in the specified directory.
func CVEToPackageInfo(cve models.NVDCVE, repos []string, cache git.RepoTagsCache, directory string) error {
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
	versions, notes := cves.ExtractVersionInfo(cve, nil, http.DefaultClient)

	if len(versions.AffectedVersions) != 0 {
		var err error
		// There are some AffectedVersions to try and resolve to AffectedCommits.
		if len(repos) == 0 {
			return fmt.Errorf("[%s]: No affected ranges for %q, and no repos to try and convert %+v to tags with", cve.ID, maybeProductName, versions.AffectedVersions)
		}
		logger.Info("Trying to convert version tags to commits", slog.String("cve", string(cve.ID)), slog.Any("versions", versions), slog.Any("repos", repos))
		versions, err = cves.GitVersionsToCommits(cve.ID, versions, repos, cache)
		if err != nil {
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
		return fmt.Errorf("[%s]: Failed to convert fixed version tags to commits: %#v %w", cve.ID, versions, ErrUnresolvedFix)
	}

	hasAnyLastAffectedCommits := false
	for _, repo := range repos {
		if versions.HasLastAffectedCommits(repo) {
			hasAnyLastAffectedCommits = true
		}
	}

	if versions.HasLastAffectedVersions() && !hasAnyLastAffectedCommits && !hasAnyFixedCommits {
		return fmt.Errorf("[%s]: Failed to convert last_affected version tags to commits: %#v %w", cve.ID, versions, ErrUnresolvedFix)
	}

	if len(versions.AffectedCommits) == 0 {
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
	notesFile := filepath.Join(vulnDir, string(cve.ID)+".nvd.notes")
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

	if len(notes) > 0 {
		err = os.WriteFile(notesFile, []byte(strings.Join(notes, "\n")), 0600)
		if err != nil {
			logger.Warn("Failed to write", slog.String("cve", string(cve.ID)), slog.String("path", notesFile), slog.Any("err", err))
		}
	}

	return nil
}
