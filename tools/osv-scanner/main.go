package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/google/osv.dev/tools/osv-scanner/internal/osv"
	"github.com/google/osv.dev/tools/osv-scanner/internal/sbom"
)

func usage() {
	fmt.Fprintf(flag.CommandLine.Output(), "%s [flags] dir1 dir2...\n", os.Args[0])
	flag.PrintDefaults()
}

func scan(query *osv.BatchedQuery, arg string) error {
	info, err := os.Stat(arg)
	if err != nil {
		return nil
	}

	if info.IsDir() {
		return scanDir(query, arg)
	}

	return scanFile(query, arg)
}

func scanDir(query *osv.BatchedQuery, dir string) error {
	log.Printf("Scanning dir %s\n", dir)
	return filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			log.Printf("Failed to walk %s: %v", path, err)
			return err
		}

		if info.IsDir() && info.Name() == ".git" {
			gitQuery, err := scanGit(filepath.Dir(path))
			if err != nil {
				log.Printf("scan failed for %s: %v\n", path, err)
				return err
			}
			query.Queries = append(query.Queries, gitQuery)
		}

		return nil
	})
}

func scanFile(query *osv.BatchedQuery, path string) error {
	log.Printf("Scanning file %s\n", path)
	file, err := os.Open(path)
	if err != nil {
		return err
	}

	for _, provider := range sbom.Providers {
		err := provider.GetPackages(file, func(id sbom.Identifier) error {
			query.Queries = append(query.Queries, osv.MakePURLRequest(id.PURL))
			return nil
		})
		if err == nil {
			// Found the right format.
			log.Printf("Scanned %s SBOM", provider.Name())
			return nil
		}

		if errors.Is(err, sbom.InvalidFormat) {
			continue
		}

		return err
	}
	return nil
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

func scanGit(repoDir string) (*osv.Query, error) {
	commit, err := getCommitSHA(repoDir)
	if err != nil {
		return nil, err
	}

	log.Printf("Scanning %s at commit %s", repoDir, commit)
	return osv.MakeCommitRequest(commit), nil
}

func printResults(query osv.BatchedQuery, resp *osv.BatchedResponse) {
	for i, query := range query.Queries {
		if len(resp.Results[i].Vulns) == 0 {
			continue
		}

		var urls []string
		for _, vuln := range resp.Results[i].Vulns {
			urls = append(urls, osv.BaseVulnerabilityURL+vuln.ID)
		}

		log.Printf("%v is vulnerable to %s", query, strings.Join(urls, ", "))
	}
}

// TODO(ochang): Machine readable output format.
// TODO(ochang): Ability to specify type of input.
func main() {
	flag.Usage = usage
	flag.Parse()

	var query osv.BatchedQuery

	for _, arg := range flag.Args() {
		if err := scan(&query, arg); err != nil {
			log.Printf("scan failed: %v\n", err)
			return
		}
	}

	resp, err := osv.MakeRequest(query)
	if err != nil {
		log.Printf("scan failed: %v\n", err)
		return
	}

	printResults(query, resp)
}
