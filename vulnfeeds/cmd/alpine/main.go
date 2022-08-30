package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"regexp"
	"strings"

	"github.com/google/osv/vulnfeeds/vulns"
)

const (
	alpineUrlBase             = "https://secdb.alpinelinux.org/%s/main.json"
	alpineIndexUrl            = "https://secdb.alpinelinux.org/"
	alpineOutputPath          = "alpine_output"
	osvIntermediateOutputPath = "osv_interm_output"
)

func main() {
	flag.Parse()

	err := os.MkdirAll(alpineOutputPath, 0755)
	if err != nil {
		log.Fatalf("Can't create output path: %s", err)
	}

	generateAlpineOSV()
}

func getAllAlpineVersions() []string {
	res, err := http.Get(alpineIndexUrl)
	if err != nil {
		log.Fatalf("Failed to get alpine index page: %s", err)
	}
	buf := new(strings.Builder)
	_, err = io.Copy(buf, res.Body)
	if err != nil {
		log.Fatalf("Failed to get alpine index page: %s", err)
	}

	exp := regexp.MustCompile("href=\"(v[\\d.]*)/\"")

	searchRes := exp.FindAllStringSubmatch(buf.String(), -1)
	alpineVersions := make([]string, 0, len(searchRes))

	for _, match := range searchRes {
		// The expression only has one capture that must always be there
		log.Printf("Found ver: %s", match[1])
		alpineVersions = append(alpineVersions, match[1])
	}

	return alpineVersions
}

//func loadIntermediateCves() map[string]vulns.Vulnerability {
//	dir, err := os.ReadDir(osvIntermediateOutputPath)
//	if err != nil {
//		log.Fatalf("Failed to read dir? %s", err)
//	}
//
//	result := make(map[string]vulns.Vulnerability)
//
//	for _, entry := range dir {
//		file, err := os.Open(osvIntermediateOutputPath + "/" + entry.Name())
//		if err != nil {
//			log.Fatalf("Failed to open cve json: %s", err)
//		}
//		var vuln vulns.Vulnerability
//		err = json.NewDecoder(file).Decode(&vuln)
//		if err != nil {
//			log.Fatalf("Failed to decode json: %s", err)
//		}
//		result[vuln.ID] = vuln
//
//		file.Close()
//	}
//	log.Printf("Loaded %d Intermediate CVEs", len(result))
//
//	return result
//}

type VersionAndPkg struct {
	Ver       string
	Pkg       string
	AlpineVer string
}

func generateAlpineOSV() {
	allAlpineSecDb := make(map[string][]VersionAndPkg)
	allAlpineVers := getAllAlpineVersions()
	for _, alpineVer := range allAlpineVers {
		secdb := downloadAlpine(alpineVer)
		for _, pkg := range secdb.Packages {
			for version, cveIds := range pkg.Pkg.Secfixes {
				for _, cveId := range cveIds {
					cveId = strings.Split(cveId, " ")[0]
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

	for cveId, verPkgs := range allAlpineSecDb {
		pkgInfos := make([]vulns.PackageInfo, 0, len(verPkgs))

		for _, verPkg := range verPkgs {
			pkgInfo := vulns.PackageInfo{
				PkgName:      verPkg.Pkg,
				FixedVersion: verPkg.Ver,
				Ecosystem:    "Alpine:" + verPkg.AlpineVer,
				Purl:         "pkg:alpine/" + verPkg.Pkg,
			}
			pkgInfos = append(pkgInfos, pkgInfo)
		}
		if len(pkgInfos) > 1 {
			log.Println("Multiple lines: " + cveId)
		}

		file, err := os.OpenFile(alpineOutputPath+"/"+cveId+".alpine.json", os.O_CREATE|os.O_RDWR, 0644)
		if err != nil {
			log.Fatalf("Failed to create/write osv output file: %s", err)
		}
		encoder := json.NewEncoder(file)
		encoder.SetIndent("", "  ")
		err = encoder.Encode(&pkgInfos)
		if err != nil {
			log.Fatalf("Failed to encode package info output file: %s", err)
		}
		_ = file.Close()
	}

	log.Println("Finished")
}

func downloadAlpine(version string) AlpineSecDB {
	res, err := http.Get(fmt.Sprintf(alpineUrlBase, version))
	if err != nil {
		log.Fatalf("Failed to get alpine file for version '%s' with error %s", version, err)
	}

	var decodedSecdb AlpineSecDB

	if err := json.NewDecoder(res.Body).Decode(&decodedSecdb); err != nil {
		log.Fatalf("Failed to parse alpine json: %s", err)
	}
	return decodedSecdb
}
