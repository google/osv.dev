package main

import (
	"compress/gzip"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"time"
)

const (
	cveURLBase   = "https://nvd.nist.gov/feeds/json/cve/1.1/"
	fileNameBase = "nvdcve-1.1-"
	startingYear = 2002
	cvePath      = "cve_jsons"
)

func main() {
	currentYear := time.Now().Year()
	for i := startingYear; i <= currentYear; i++ {
		downloadCVE(strconv.Itoa(i))
	}
	downloadCVE("modified")
	downloadCVE("recent")
}

func downloadCVE(version string) {
	file, err := os.OpenFile(cvePath+"/"+fileNameBase+version+".json", os.O_CREATE|os.O_RDWR|os.O_TRUNC, 0644)
	defer file.Close()
	if err != nil { // There's an existing file, check if it matches server file
		log.Fatalf("Something's went wrong when creating/opening file %s, %s", version, err)
	}

	res, err := http.Get(cveURLBase + fileNameBase + version + ".json.gz")
	if err != nil {
		log.Fatalf("Failed to retrieve cve json with: %d, for version: %s", err, version)
	}

	if res.StatusCode != 200 {
		log.Fatalf("Failed to retrieve cve json with: %d, for version: %s", res.StatusCode, version)
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
