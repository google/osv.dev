// Package main converts alpine records to OSV parts for combine-to-osv to consume
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path"
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
	alpineOutputPathDefault = "parts/alpine"
	defaultCvePath          = "cve_jsons"
)

func main() {
	logger.InitGlobalLogger()

	alpineOutputPath := flag.String(
		"alpineOutput",
		alpineOutputPathDefault,
		"path to output general alpine affected package information")
	flag.Parse()

	err := os.MkdirAll(*alpineOutputPath, 0755)
	if err != nil {
		logger.Fatal("Can't create output path", slog.Any("err", err))
	}

	allCVEs := vulns.LoadAllCVEs(defaultCvePath)
	allAlpineSecDB := getAlpineSecDBData()
	generateAlpineOSV(allAlpineSecDB, *alpineOutputPath, allCVEs)
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
func generateAlpineOSV(allAlpineSecDb map[string][]VersionAndPkg, alpineOutputPath string, allCVEs map[cves.CVEID]cves.Vulnerability) {
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
		published := time.Time{}
		details := ""
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
				Modified:  time.Now().UTC(),
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

		file, err := os.OpenFile(path.Join(alpineOutputPath, v.ID+".json"), os.O_CREATE|os.O_RDWR|os.O_TRUNC, 0644)
		if err != nil {
			logger.Fatal("Failed to create/write osv output file", slog.Any("err", err))
		}
		encoder := json.NewEncoder(file)
		encoder.SetIndent("", "  ")
		err = encoder.Encode(v)
		if err != nil {
			logger.Fatal("Failed to encode package info output file", slog.Any("err", err))
		}
		_ = file.Close()
	}

	logger.Info("Finished")
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
