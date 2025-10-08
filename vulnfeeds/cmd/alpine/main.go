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
	"sort"
	"strings"
	"time"

	"github.com/google/osv/vulnfeeds/cves"
	"github.com/google/osv/vulnfeeds/models"
	"github.com/google/osv/vulnfeeds/utility/logger"
	"github.com/google/osv/vulnfeeds/vulns"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
)

const (
	alpineURLBase           = "https://secdb.alpinelinux.org/%s/main.json"
	alpineIndexURL          = "https://secdb.alpinelinux.org/"
	alpineOutputPathDefault = "alpine"
	defaultCvePath          = "cve_jsons"
	outputBucketDefault     = "osv-test-cve-osv-conversion"
)

func main() {
	logger.InitGlobalLogger()

	alpineOutputPath := flag.String(
		"output_path",
		alpineOutputPathDefault,
		"path to output general alpine affected package information")
	outputBucketName := flag.String("output_bucket", outputBucketDefault, "The GCS bucket to write to.")
	numWorkers := flag.Int("num_workers", 64, "Number of workers to process records")
	uploadToGCS := flag.Bool("uploadToGCS", false, "If true, do not write to GCS bucket and instead write to local disk.")
	flag.Parse()

	err := os.MkdirAll(*alpineOutputPath, 0755)
	if err != nil {
		logger.Fatal("Can't create output path", slog.Any("err", err))
	}

	allCVEs := vulns.LoadAllCVEs(defaultCvePath)
	allAlpineSecDB := getAlpineSecDBData()
	osvVulnerabilities := generateAlpineOSV(allAlpineSecDB, allCVEs)

	var vulnerabilities []*osvschema.Vulnerability //nolint:prealloc
	for _, v := range osvVulnerabilities {
		if len(v.Affected) == 0 {
			logger.Warn(fmt.Sprintf("Skipping %s as no affected versions found.", v.ID), slog.String("id", v.ID))
			continue
		}
		vulnerabilities = append(vulnerabilities, &v.Vulnerability)
	}

	ctx := context.Background()
	vulns.Run(ctx, "Alpine CVEs", *uploadToGCS, *outputBucketName, "", *numWorkers, *alpineOutputPath, vulnerabilities)
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
		secdb := downloadAlpine(alpineVer)
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

	return allAlpineSecDb
}

// generateAlpineOSV generates the generic PackageInfo package from the information given by alpine advisory
func generateAlpineOSV(allAlpineSecDb map[string][]VersionAndPkg, allCVEs map[cves.CVEID]cves.Vulnerability) (osvVulnerabilities []*vulns.Vulnerability) {
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
		cve, ok := allCVEs[cves.CVEID(cveID)]
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
			Vulnerability: osvschema.Vulnerability{
				ID:        "ALPINE-" + cveID,
				Upstream:  []string{cveID},
				Published: published,
				Details:   details,
				References: []osvschema.Reference{
					{
						Type: "ADVISORY",
						URL:  "https://security.alpinelinux.org/vuln/" + cveID,
					},
				},
			},
		}

		for _, verPkg := range verPkgs {
			pkgInfo := vulns.PackageInfo{
				PkgName: verPkg.Pkg,
				VersionInfo: models.VersionInfo{
					AffectedVersions: []models.AffectedVersion{{Fixed: verPkg.Ver}},
				},
				Ecosystem: "Alpine:" + verPkg.AlpineVer,
				PURL:      "pkg:apk/alpine/" + verPkg.Pkg + "?arch=source",
			}
			v.AddPkgInfo(pkgInfo)
		}

		if len(v.Affected) == 0 {
			logger.Warn(fmt.Sprintf("Skipping %s as no affected versions found.", v.ID), slog.String("cveID", cveID))
			continue
		}
		if cve.CVE.Metrics != nil {
			v.AddSeverity(cve.CVE.Metrics)
		}

		osvVulnerabilities = append(osvVulnerabilities, v)
	}

	return osvVulnerabilities
}

// downloadAlpine downloads Alpine SecDB data from their API
func downloadAlpine(version string) AlpineSecDB {
	res, err := http.Get(fmt.Sprintf(alpineURLBase, version))
	if err != nil {
		logger.Fatal("Failed to get alpine file", slog.String("version", version), slog.Any("err", err))
	}
	defer res.Body.Close()

	var decodedSecdb AlpineSecDB

	if err := json.NewDecoder(res.Body).Decode(&decodedSecdb); err != nil {
		logger.Fatal("Failed to parse alpine json", slog.Any("err", err))
	}

	return decodedSecdb
}
