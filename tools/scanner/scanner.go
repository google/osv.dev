package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

const (
	// QueryEndpoint is the URL for posting queries to OSV.
	QueryEndpoint = "https://api.osv.dev/v1/query"
	// BaseVulnerabilityURL is the base URL for detailed vulnerability views.
	BaseVulnerabilityURL = "https://osv.dev/vulnerability/"
)

// OSVQuery represents a query to OSV.
type OSVQuery struct {
	Commit string `json:"commit"`
}

// OSVResponse represents a (simplified) response from OSV.
type OSVResponse struct {
	Vulns []struct {
		ID string `json:"id"`
		// Remainder of Vulnerability fields omitted for simplicity.
	} `json:"vulns"`
}

func usage() {
	fmt.Fprintf(flag.CommandLine.Output(), "%s [flags] dir1 dir2...\n", os.Args[0])
	flag.PrintDefaults()
}

func scan(dir string) error {
	return filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			log.Printf("Failed to walk %s: %v", path, err)
			return err
		}

		if info.IsDir() && info.Name() == ".git" {
			err = doScan(filepath.Dir(path))
			if err != nil {
				log.Printf("scan failed for %s: %v\n", path, err)
				return err
			}
		}

		return nil
	})
}

func getCommitSHA(repoDir string) (string, error) {
	cmd := exec.Command("git", "-C", repoDir, "rev-parse", "HEAD")
	var out bytes.Buffer
	cmd.Stdout = &out

	err := cmd.Run()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(out.String()), nil
}

func makeOSVRequest(commit string) (*OSVResponse, error) {
	request := OSVQuery{
		Commit: commit,
	}

	requestBytes, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}
	requestBuf := bytes.NewBuffer(requestBytes)

	endpoint := fmt.Sprintf("%s", QueryEndpoint)
	resp, err := http.Post(endpoint, "application/json", requestBuf)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var osvResp OSVResponse
	decoder := json.NewDecoder(resp.Body)
	err = decoder.Decode(&osvResp)
	if err != nil {
		return nil, err
	}

	return &osvResp, nil
}

func doScan(repoDir string) error {
	commit, err := getCommitSHA(repoDir)
	if err != nil {
		return err
	}

	log.Printf("Scanning %s at commit %s", repoDir, commit)
	resp, err := makeOSVRequest(commit)
	if err != nil {
		return err
	}

	if len(resp.Vulns) > 0 {
		var urls []string
		for _, vuln := range resp.Vulns {
			urls = append(urls, BaseVulnerabilityURL+vuln.ID)
		}

		log.Printf("%s is vulnerable to %s", repoDir, strings.Join(urls, ", "))
	}
	return nil
}

func main() {
	flag.Usage = usage
	flag.Parse()

	for _, dir := range flag.Args() {
		scan(dir)
	}
}
