package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"regexp"
	"strings"

	"github.com/google/osv/vulnfeeds/common"
	"github.com/google/osv/vulnfeeds/utility"
	"github.com/google/osv/vulnfeeds/vulns"
)

const (
	alpineURLBase           = "https://secdb.alpinelinux.org/%s/main.json"
	alpineIndexURL          = "https://secdb.alpinelinux.org/"
	alpineOutputPathDefault = "parts/alpine"
)

var Logger utility.LoggerWrapper

func main() {
	var logCleanup func()
	Logger, logCleanup = utility.CreateLoggerWrapper("alpine-osv")
	defer logCleanup()

	alpineOutputPath := flag.String(
		"alpineOutput",
		alpineOutputPathDefault,
		"path to output general alpine affected package information")
	flag.Parse()

	err := os.MkdirAll(*alpineOutputPath, 0755)
	if err != nil {
		Logger.Fatalf("Can't create output path: %s", err)
	}

	allAlpineSecDB := getAlpineSecDBData()
	generateAlpineOSV(allAlpineSecDB, *alpineOutputPath)
}

// getAllAlpineVersions gets all available version name in alpine secdb
func getAllAlpineVersions() []string {
	res, err := http.Get(alpineIndexURL)
	if err != nil {
		Logger.Fatalf("Failed to get alpine index page: %s", err)
	}
	buf := new(strings.Builder)
	_, err = io.Copy(buf, res.Body)
	if err != nil {
		Logger.Fatalf("Failed to get alpine index page: %s", err)
	}

	exp := regexp.MustCompile("href=\"(v[\\d.]*)/\"")

	searchRes := exp.FindAllStringSubmatch(buf.String(), -1)
	alpineVersions := make([]string, 0, len(searchRes))

	for _, match := range searchRes {
		// The expression only has one capture that must always be there
		Logger.Infof("Found ver: %s", match[1])
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
			for version, cveIds := range pkg.Pkg.SecFixes {
				for _, cveId := range cveIds {
					cveId = strings.Split(cveId, " ")[0]

					if !validVersion(version) {
						Logger.Warnf("Invalid alpine version: '%s', on package: '%s', and alpine version: '%s'",
							version,
							pkg.Pkg.Name,
							alpineVer,
						)
						continue
					}

					allAlpineSecDb[cveId] = append(allAlpineSecDb[cveId],
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
func generateAlpineOSV(allAlpineSecDb map[string][]VersionAndPkg, alpineOutputPath string) {
	for cveId, verPkgs := range allAlpineSecDb {
		pkgInfos := make([]vulns.PackageInfo, 0, len(verPkgs))

		for _, verPkg := range verPkgs {
			pkgInfo := vulns.PackageInfo{
				PkgName: verPkg.Pkg,
				VersionInfo: common.VersionInfo{
					AffectedVersions: []common.AffectedVersion{{Fixed: verPkg.Ver}},
				},
				Ecosystem: "Alpine:" + verPkg.AlpineVer,
				PURL:      "pkg:apk/alpine/" + verPkg.Pkg + "?arch=source",
			}
			pkgInfos = append(pkgInfos, pkgInfo)
		}

		file, err := os.OpenFile(path.Join(alpineOutputPath, cveId+".alpine.json"), os.O_CREATE|os.O_RDWR, 0644)
		if err != nil {
			Logger.Fatalf("Failed to create/write osv output file: %s", err)
		}
		encoder := json.NewEncoder(file)
		encoder.SetIndent("", "  ")
		err = encoder.Encode(&pkgInfos)
		if err != nil {
			Logger.Fatalf("Failed to encode package info output file: %s", err)
		}
		_ = file.Close()
	}

	Logger.Infof("Finished")
}

// downloadAlpine downloads Alpine SecDB data from their API
func downloadAlpine(version string) AlpineSecDB {
	res, err := http.Get(fmt.Sprintf(alpineURLBase, version))
	if err != nil {
		Logger.Fatalf("Failed to get alpine file for version '%s' with error %s", version, err)
	}

	var decodedSecdb AlpineSecDB

	if err := json.NewDecoder(res.Body).Decode(&decodedSecdb); err != nil {
		Logger.Fatalf("Failed to parse alpine json: %s", err)
	}
	return decodedSecdb
}
