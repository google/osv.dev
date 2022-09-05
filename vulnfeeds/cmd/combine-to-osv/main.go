package main

import (
	"encoding/json"
	"flag"
	"log"
	"os"
	"strings"

	"github.com/google/osv/vulnfeeds/cves"
	"github.com/google/osv/vulnfeeds/vulns"
)

const (
	defaultCvePath        = "cve_jsons"
	defaultPartsInputPath = "parts"
	defaultOsvOutputPath  = "osv_output"
)

func main() {
	cvePath := flag.String("cvePath", defaultCvePath, "Path to CVE file")
	partsInputPath := flag.String("partsPath", defaultPartsInputPath, "Path to CVE file")
	osvOutputPath := flag.String("osvOutputPath", defaultOsvOutputPath, "Path to CVE file")
	flag.Parse()

	err := os.MkdirAll(*cvePath, 0755)
	if err != nil {
		log.Fatalf("Can't create output path: %s", err)
	}
	err = os.MkdirAll(*osvOutputPath, 0755)
	if err != nil {
		log.Fatalf("Can't create output path: %s", err)
	}

	allCves := loadAllCVEs(*cvePath)
	allParts := loadParts(*partsInputPath)
	combinedData := combineIntoOSV(allCves, allParts)
	writeOsvFile(combinedData, *osvOutputPath)
}

func loadParts(partsInputPath string) map[string][]vulns.PackageInfo {
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

func combineIntoOSV(loadedCves map[string]cves.CVEItem, allParts map[string][]vulns.PackageInfo) map[string]*vulns.Vulnerability {
	log.Println("Begin writing OSV files")
	convertedCves := map[string]*vulns.Vulnerability{}
	for vId, v := range loadedCves {
		if len(allParts[vId]) == 0 {
			continue
		}
		cve, _ := vulns.FromCVE(vId, v, allParts[vId])
		convertedCves[vId] = cve
	}
	return convertedCves
}

func writeOsvFile(osvData map[string]*vulns.Vulnerability, osvOutputPath string) {
	for vId, osv := range osvData {
		file, err := os.OpenFile(osvOutputPath+"/"+vId+".json", os.O_CREATE|os.O_RDWR, 0644)
		if err != nil {
			log.Fatalf("Failed to create/open file to write: %s", err)
		}
		encoder := json.NewEncoder(file)
		encoder.SetIndent("", "  ")
		err = encoder.Encode(osv)
		if err != nil {
			log.Fatalf("Failed to encode OSVs")
		}
		file.Close()
	}

	log.Println("Successfully written all OSV files")
}

func loadAllCVEs(cvePath string) map[string]cves.CVEItem {
	dir, err := os.ReadDir(cvePath)
	if err != nil {
		log.Fatalf("Failed to read dir? %s", err)
	}

	result := make(map[string]cves.CVEItem)

	for _, entry := range dir {
		file, err := os.Open(cvePath + "/" + entry.Name())
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
