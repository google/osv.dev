// Package main converts alpine records to OSV parts for combine-to-osv to consume
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/google/osv-scalibr/semantic"
	"github.com/google/osv.dev/vulnfeeds/conversion"
	"github.com/google/osv.dev/vulnfeeds/conversion/writer"
	"github.com/google/osv.dev/vulnfeeds/models"
	"github.com/google/osv.dev/vulnfeeds/utility/logger"
	"github.com/google/osv.dev/vulnfeeds/vulns"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const (
	alpineURLBase           = "https://secdb.alpinelinux.org/%s/%s.json"
	alpineIndexURL          = "https://secdb.alpinelinux.org/"
	alpineOutputPathDefault = "alpine"
	defaultCvePath          = "cve_jsons"
	outputBucketDefault     = "osv-test-cve-osv-conversion"
)

func main() {
	logger.InitGlobalLogger()
	defer logger.Close()

	alpineOutputPath := flag.String(
		"output-path",
		alpineOutputPathDefault,
		"path to output general alpine affected package information")
	outputBucketName := flag.String("output-bucket", outputBucketDefault, "The GCS bucket to write to.")
	numWorkers := flag.Int("workers", 64, "Number of workers to process records")
	uploadToGCS := flag.Bool("upload-to-gcs", false, "If true, do not write to GCS bucket and instead write to local disk.")
	syncDeletions := flag.Bool("sync-deletions", false, "If false, do not delete files in bucket that are not local")
	flag.Parse()

	err := os.MkdirAll(*alpineOutputPath, 0755)
	if err != nil {
		logger.Fatal("Can't create output path", slog.Any("err", err))
	}

	allAlpineSecDB := getAlpineSecDBData()

	targetCVEs := make(map[string]bool)
	for cveID := range allAlpineSecDB {
		if strings.HasPrefix(cveID, "CVE") {
			targetCVEs[cveID] = true
		}
	}

	allCVEs := vulns.LoadTargetCVEs(defaultCvePath, targetCVEs)
	osvVulnerabilities := generateAlpineOSV(allAlpineSecDB, allCVEs)

	vulnerabilities := make([]*osvschema.Vulnerability, 0, len(osvVulnerabilities))
	for _, v := range osvVulnerabilities {
		if len(v.Affected) == 0 {
			logger.Warn(fmt.Sprintf("Skipping %s as no affected versions found.", v.Id), slog.String("id", v.Id))
			continue
		}
		vulnerabilities = append(vulnerabilities, v.Vulnerability)
	}

	ctx := context.Background()
	writer.UploadVulnsToGCS(ctx, "Alpine CVEs", *uploadToGCS, *outputBucketName, "", *numWorkers, *alpineOutputPath, vulnerabilities, *syncDeletions)
	logger.Info("Alpine CVE conversion succeeded.")
}

// getAllAlpineVersions gets all available version name in alpine secdb
func getAllAlpineVersions() []string {
	res, err := http.Get(alpineIndexURL)
	if err != nil {
		logger.Fatal("Failed to get alpine index page", slog.Any("err", err))
	}
	defer res.Body.Close()
	buf := new(strings.Builder)
	_, err = io.Copy(buf, res.Body)
	if err != nil {
		logger.Fatal("Failed to get alpine index page", slog.Any("err", err))
	}

	exp := regexp.MustCompile(`href="(v[\d.]*)/"`)

	searchRes := exp.FindAllStringSubmatch(buf.String(), -1)
	alpineVersions := make([]string, 0, len(searchRes))

	for _, match := range searchRes {
		// The expression only has one capture that must always be there
		logger.Info("Found version", slog.String("version", match[1]))
		alpineVersions = append(alpineVersions, match[1])
	}

	return alpineVersions
}

type VersionAndPkg struct {
	Ver       string
	Pkg       string
	AlpineVer string
}

// getAlpineSecDBData Download from Alpine API
func getAlpineSecDBData() map[string][]VersionAndPkg {
	allAlpineSecDb := make(map[string][]VersionAndPkg)
	allAlpineVers := getAllAlpineVersions()
	for _, alpineVer := range allAlpineVers {
		for _, repo := range []string{"main", "community"} {
			secdb := downloadAlpine(alpineVer, repo)
			for _, pkg := range secdb.Packages {
				for version, cveIDs := range pkg.Pkg.SecFixes {
					for _, cveID := range cveIDs {
						cveID = strings.Split(cveID, " ")[0]

						if !validVersion(version) {
							logger.Warn(fmt.Sprintf("[%s] Invalid alpine version: '%s', on package: '%s', and alpine version: '%s'",
								cveID, version, pkg.Pkg.Name,
								alpineVer), slog.String("version", version),
								slog.String("package", pkg.Pkg.Name),
								slog.String("alpine_version", alpineVer),
							)

							continue
						}

						allAlpineSecDb[cveID] = append(allAlpineSecDb[cveID],
							VersionAndPkg{
								Pkg:       pkg.Pkg.Name,
								Ver:       version,
								AlpineVer: alpineVer,
							})
					}
				}
			}
		}
	}

	return allAlpineSecDb
}

// generateAlpineOSV generates the generic PackageInfo package from the information given by alpine advisory
func generateAlpineOSV(allAlpineSecDb map[string][]VersionAndPkg, allCVEs map[models.CVEID]models.Vulnerability) (osvVulnerabilities []*vulns.Vulnerability) {
	cveIDs := make([]string, 0, len(allAlpineSecDb))
	for cveID := range allAlpineSecDb {
		cveIDs = append(cveIDs, cveID)
	}
	sort.Strings(cveIDs)

	for _, cveID := range cveIDs {
		verPkgs := allAlpineSecDb[cveID]
		sort.Slice(verPkgs, func(i, j int) bool {
			if verPkgs[i].Pkg != verPkgs[j].Pkg {
				return verPkgs[i].Pkg < verPkgs[j].Pkg
			}
			if verPkgs[i].AlpineVer != verPkgs[j].AlpineVer {
				return verPkgs[i].AlpineVer < verPkgs[j].AlpineVer
			}

			return verPkgs[i].Ver < verPkgs[j].Ver
		})
		cve, ok := allCVEs[models.CVEID(cveID)]
		var published time.Time
		var details string
		if ok {
			published = cve.CVE.Published.Time
			if len(cve.CVE.Descriptions) > 0 {
				details = cve.CVE.Descriptions[0].Value
			}
		} else {
			// TODO: add support for non-CVE reports
			logger.Warn(fmt.Sprintf("CVE %s not found in cve_jsons", cveID), slog.String("cveID", cveID))
			continue
		}

		v := &vulns.Vulnerability{
			Vulnerability: &osvschema.Vulnerability{
				Id:        "ALPINE-" + cveID,
				Upstream:  []string{cveID},
				Published: timestamppb.New(published),
				Details:   details,
				References: []*osvschema.Reference{
					{
						Type: osvschema.Reference_ADVISORY,
						Url:  "https://security.alpinelinux.org/vuln/" + cveID,
					},
				},
			},
		}

		for _, verPkg := range verPkgs {
			// if the fixed version is 0, then it means that the vulnerability does
			// not affect this package on this alpine version.
			if verPkg.Ver == "0" {
				continue
			}

			introduced := findIntroducedVersion(cve.CVE, verPkg.Pkg, verPkg.Ver)
			pkgInfo := vulns.PackageInfo{
				PkgName: verPkg.Pkg,
				VersionInfo: models.VersionInfo{
					AffectedVersions: []models.AffectedVersion{{Introduced: introduced, Fixed: verPkg.Ver}},
				},
				Ecosystem: "Alpine:" + verPkg.AlpineVer,
				PURL:      "pkg:apk/alpine/" + verPkg.Pkg + "?arch=source",
			}
			v.AddPkgInfo(pkgInfo)
		}

		if len(v.Affected) == 0 {
			logger.Warn(fmt.Sprintf("Skipping %s as no affected versions found.", v.Id), slog.String("cveID", cveID))
			continue
		}
		if cve.CVE.Metrics != nil {
			v.AddSeverity(cve.CVE.Metrics)
		}

		osvVulnerabilities = append(osvVulnerabilities, v)
	}

	return osvVulnerabilities
}

// cpeMatchesAlpinePackage checks if a parsed CPE matches an Alpine package name
// using the same naming convention rules as the Alpine secfixes-tracker:
// language-specific prefixes (py3-, ruby-, perl-, lua-, vscode-) derived from
// the CPE target_sw field, plus direct name match for native packages.
func cpeMatchesAlpinePackage(parsed *models.CPEString, alpinePkg string) bool {
	product := strings.ToLower(parsed.Product)
	if product == alpinePkg {
		return true
	}
	product = strings.ReplaceAll(product, "_", "-")
	targetSW := strings.ToLower(parsed.TargetSW)
	var rewritten string
	switch {
	case strings.Contains(targetSW, "python"):
		rewritten = "py3-" + product
	case strings.Contains(targetSW, "ruby"):
		rewritten = "ruby-" + product
	case strings.Contains(targetSW, "perl"):
		rewritten = "perl-" + strings.ReplaceAll(product, "::", "-")
	case strings.Contains(targetSW, "lua"):
		rewritten = "lua-" + product
	case strings.Contains(targetSW, "visual_studio_code"):
		rewritten = "vscode-" + product
	default:
		return false
	}

	return rewritten == alpinePkg
}

// apkVersionLess reports whether Alpine version a sorts strictly before b
// according to osv-scalibr's APK version comparator.
func apkVersionLess(a, b string) bool {
	if !validVersion(a) || !validVersion(b) {
		return false
	}
	av, err := semantic.ParseAlpineVersion(a)
	if err != nil {
		return false
	}
	cmp, err := av.CompareStr(b)
	if err != nil {
		return false
	}

	return cmp < 0
}

// cpeInterval represents a vulnerable version interval extracted from an NVD CPEMatch.
type cpeInterval struct {
	bound        string // lower bound used for ordering ("0" when unbounded below)
	introduced   string // inclusive OSV introduced version ("0" when unbounded or exclusive)
	end          string // upper bound version ("" when unbounded above)
	endInclusive bool
}

// intervalsOverlap reports whether sorted intervals a and b (with a.bound <= b.bound) overlap.
func intervalsOverlap(a, b cpeInterval) bool {
	if a.end == "" {
		return true
	}
	if !validVersion(a.end) {
		return false
	}
	if b.bound == "0" {
		return true
	}
	if a.endInclusive {
		return !apkVersionLess(a.end, b.bound)
	}

	return apkVersionLess(b.bound, a.end)
}

// mergeEnd returns the higher upper bound of two overlapping intervals.
func mergeEnd(a, b cpeInterval) (string, bool) {
	if a.end == "" || b.end == "" {
		return "", false
	}
	if !validVersion(a.end) {
		return b.end, b.endInclusive
	}
	if !validVersion(b.end) {
		return a.end, a.endInclusive
	}
	if apkVersionLess(a.end, b.end) {
		return b.end, b.endInclusive
	}
	if apkVersionLess(b.end, a.end) {
		return a.end, a.endInclusive
	}

	return a.end, a.endInclusive || b.endInclusive
}

// findIntroducedVersion searches NVD CPE configurations for the introduced
// version corresponding to the given Alpine package on the branch fixed at
// fixedVersion.
//
// NVD CPE configurations can list both disjoint release branches (e.g. < 5.26.3
// and [5.28.0, 5.28.1)) and overlapping edition ranges on the same branch
// (e.g. ISC BIND [9.20.0, 9.20.24] alongside Supported Preview [9.20.9, 9.20.24]).
// Matching range intervals are therefore merged where they overlap first, and
// then the disjoint interval closest to (strictly below) fixedVersion is chosen.
func findIntroducedVersion(cve models.NVDCVE, alpinePkg, fixedVersion string) string {
	var intervals []cpeInterval

	for _, config := range cve.Configurations {
		if config.Negate {
			continue
		}
		for _, node := range config.Nodes {
			if node.Negate {
				continue
			}
			for _, match := range node.CPEMatch {
				if !match.Vulnerable {
					continue
				}
				hasRangeBound := match.VersionStartIncluding != nil ||
					match.VersionStartExcluding != nil ||
					match.VersionEndIncluding != nil ||
					match.VersionEndExcluding != nil
				if !hasRangeBound {
					continue
				}

				iv := cpeInterval{bound: "0", introduced: "0"}
				switch {
				case match.VersionStartIncluding != nil:
					start := *match.VersionStartIncluding
					if start != "0" && !validAPKVersion(start) {
						continue
					}
					iv.bound = start
					iv.introduced = start
				case match.VersionStartExcluding != nil:
					start := *match.VersionStartExcluding
					if start != "0" && !validAPKVersion(start) {
						continue
					}
					iv.bound = start
					iv.introduced = "0"
				}

				switch {
				case match.VersionEndExcluding != nil:
					iv.end = *match.VersionEndExcluding
				case match.VersionEndIncluding != nil:
					iv.end = *match.VersionEndIncluding
					iv.endInclusive = true
				}

				parsed, err := conversion.ParseCPE(match.Criteria)
				if err != nil || !cpeMatchesAlpinePackage(parsed, alpinePkg) {
					continue
				}
				intervals = append(intervals, iv)
			}
		}
	}

	if len(intervals) == 0 {
		return "0"
	}

	slices.SortFunc(intervals, func(a, b cpeInterval) int {
		if a.bound != b.bound {
			if a.bound == "0" {
				return -1
			}
			if b.bound == "0" {
				return 1
			}
			if apkVersionLess(a.bound, b.bound) {
				return -1
			}
			if apkVersionLess(b.bound, a.bound) {
				return 1
			}
		}
		if a.introduced != b.introduced {
			if a.introduced == "0" {
				return -1
			}
			if b.introduced == "0" {
				return 1
			}
		}

		return 0
	})

	merged := make([]cpeInterval, 0, len(intervals))
	for _, iv := range intervals {
		if len(merged) == 0 {
			merged = append(merged, iv)
			continue
		}
		last := &merged[len(merged)-1]
		if intervalsOverlap(*last, iv) {
			last.end, last.endInclusive = mergeEnd(*last, iv)
			continue
		}
		merged = append(merged, iv)
	}

	bestIntroduced := "0"
	for _, iv := range merged {
		if iv.bound == "0" {
			if apkVersionLess("0", fixedVersion) {
				bestIntroduced = "0"
			}

			continue
		}
		if apkVersionLess(iv.bound, fixedVersion) {
			bestIntroduced = iv.introduced
		}
	}

	return bestIntroduced
}

// downloadAlpine downloads Alpine SecDB data from their API
func downloadAlpine(version, repo string) AlpineSecDB {
	res, err := http.Get(fmt.Sprintf(alpineURLBase, version, repo))
	if err != nil {
		logger.Fatal("Failed to get alpine file", slog.String("version", version), slog.Any("err", err))
	}
	defer res.Body.Close()

	var decodedSecdb AlpineSecDB
	if res.StatusCode == http.StatusNotFound {
		return decodedSecdb
	}

	if err := json.NewDecoder(res.Body).Decode(&decodedSecdb); err != nil {
		logger.Fatal("Failed to parse alpine json", slog.Any("err", err))
	}

	return decodedSecdb
}
