package main

import (
	"bufio"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"github.com/google/osv/vulnfeeds/vulns"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/google/osv/vulnfeeds/cves"
)

const (
	cveURLBase     = "https://nvd.nist.gov/feeds/json/cve/1.1/"
	fileNameBase   = "nvdcve-1.1-"
	startingYear   = 2002
	cveOutputPath  = "output2"
	partsInputPath = "parts"
	osvOutputPath  = "osv_output"
)

func main() {
	flag.Parse()

	currentYear := time.Now().Year()
	err := os.MkdirAll(cveOutputPath, 0755)
	if err != nil {
		log.Fatalf("Can't create output path: %s", err)
	}
	err = os.MkdirAll(osvOutputPath, 0755)
	if err != nil {
		log.Fatalf("Can't create output path: %s", err)
	}

	for i := startingYear; i <= currentYear; i++ {
		downloadCVEAsNeeded(strconv.Itoa(i))
	}
	downloadCVEAsNeeded("modified")
	downloadCVEAsNeeded("recent")

	allCves := loadAllCVEs()
	allParts := loadParts()
	combineIntoOSV(allCves, allParts)
}

func loadParts() map[string][]vulns.PackageInfo {
	dir, err := os.ReadDir(partsInputPath)
	if err != nil {
		log.Fatalf("Failed to read dir? %s", err)
	}
	output := map[string][]vulns.PackageInfo{}
	for _, entry := range dir {
		if !entry.IsDir() {
			log.Println("Unexpected file entry in " + partsInputPath)
			continue
		}
		dirInner, err := os.ReadDir(partsInputPath + "/" + entry.Name())
		if err != nil {
			log.Fatalf("Failed to read dir? %s", err)
		}

		for _, entryInner := range dirInner {
			file, err := os.Open(partsInputPath + "/" + entry.Name() + "/" + entryInner.Name())
			if err != nil {
				log.Fatalf("Failed to open cve json: %s", err)
			}
			var pkgInfos []vulns.PackageInfo
			err = json.NewDecoder(file).Decode(&pkgInfos)
			if err != nil {
				log.Fatalf("Failed to decode json: %s", err)
			}

			cveId := strings.Split(entryInner.Name(), ".")[0]
			output[cveId] = append(output[cveId], pkgInfos...)

			log.Printf("Loaded Alpine Item: %s", entryInner.Name())
			file.Close()
		}
	}
	return output
}

func combineIntoOSV(loadedCves map[string]cves.CVEItem, allParts map[string][]vulns.PackageInfo) {
	log.Println("Begin writing OSV files")
	convertedCves := map[string]*vulns.Vulnerability{}
	for vId, v := range loadedCves {
		if len(allParts[vId]) == 0 {
			continue
		}
		cve, _ := vulns.FromCVE(vId, v, allParts[vId])
		convertedCves[vId] = cve
		file, err := os.OpenFile(osvOutputPath+"/"+vId+".json", os.O_CREATE|os.O_RDWR, 0644)
		if err != nil {
			log.Fatalf("Failed to create/open file to write: %s", err)
		}
		encoder := json.NewEncoder(file)
		encoder.SetIndent("", "  ")
		err = encoder.Encode(cve)
		if err != nil {
			log.Fatalf("Failed to encode OSVs")
		}
		file.Close()
	}

	log.Println("Successfully written all OSV files")
}

func loadAllCVEs() map[string]cves.CVEItem {
	dir, err := os.ReadDir(cveOutputPath)
	if err != nil {
		log.Fatalf("Failed to read dir? %s", err)
	}

	result := make(map[string]cves.CVEItem)

	for _, entry := range dir {
		file, err := os.Open(cveOutputPath + "/" + entry.Name())
		if err != nil {
			log.Fatalf("Failed to open cve json: %s", err)
		}
		var nvdcve cves.NVDCVE
		err = json.NewDecoder(file).Decode(&nvdcve)
		if err != nil {
			log.Fatalf("Failed to decode json: %s", err)
		}

		for _, item := range nvdcve.CVEItems {
			result[item.CVE.CVEDataMeta.ID] = item
		}
		log.Printf("Loaded CVE: %s", entry.Name())
		file.Close()
	}
	return result
}

func downloadCVEAsNeeded(version string) {
	file, err := os.OpenFile(cveOutputPath+"/"+fileNameBase+version+".json", os.O_CREATE|os.O_RDWR, 0644)
	defer file.Close()
	if err != nil { // There's an existing file, check if it matches server file
		log.Fatalf("Something's went wrong when creating/opening file %s, %s", version, err)
	}

	hasher := sha256.New()
	if written, err := io.Copy(hasher, file); err != nil {
		log.Fatal(err)
	} else if written > 0 {
		currentHash := strings.ToUpper(hex.EncodeToString(hasher.Sum(nil)))

		res, err := http.Get(cveURLBase + fileNameBase + version + ".meta")
		if err != nil {
			log.Fatalf("Failed to get meta file for version '%s' with error %s", version, err)
		}
		scanner := bufio.NewScanner(res.Body)
		for scanner.Scan() {
			if scanner.Err() != nil {
				log.Fatalf("Failed to read meta file: %s", scanner.Err())
			}
			splited := strings.Split(scanner.Text(), ":")
			if splited[0] == "sha256" {
				if splited[1] == currentHash {
					// Hashes of file on server and locally are identical, safely skip
					log.Printf("Skipping version %s as it's identical to cloud\n", version)
					return
				} else {
					// File has been changed, exit loop and continue
					break
				}
			}
		}
	}

	res, err := http.Get(cveURLBase + fileNameBase + version + ".json.gz")
	if err != nil {
		log.Fatalf("Failed to get meta file for version '%s' with error %s", version, err)
	}

	if res.StatusCode != 200 {
		log.Fatalf("Failed to retrieve cve json with: %d, for version: %s", res.StatusCode, version)
	}

	if err := file.Truncate(0); err != nil {
		log.Fatalf("Failed to truncate file %s: %s", version, err)
	}
	// Because truncate doesn't reset the cursor, manually seek to the start
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		log.Fatalf("Failed to seek file %s: %s", version, err)
	}

	reader, err := gzip.NewReader(res.Body)
	if err != nil {
		log.Fatalf("Failed to create gzip reader: %s", err)
	}

	if _, err := io.Copy(file, reader); err != nil {
		log.Fatalf("Failed to write to file %s: %s", version, err)
	}
	log.Printf("Success for %s\n", version)
}
