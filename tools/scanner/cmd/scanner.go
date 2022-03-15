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

	"github.com/google/osv/tools/scanner/internal/osv"
	"github.com/google/osv/tools/scanner/internal/sbom"
)

func usage() {
	fmt.Fprintf(flag.CommandLine.Output(), "%s [flags] dir1 dir2...\n", os.Args[0])
	flag.PrintDefaults()
}

func scan(arg string) error {
	info, err := os.Stat(arg)
	if err != nil {
		return err
	}

	if info.IsDir() {
		return scanDir(arg)
	}

	return scanFile(arg)
}

func scanDir(dir string) error {
	log.Printf("Scanning dir %s\n", dir)
	return filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			log.Printf("Failed to walk %s: %v", path, err)
			return err
		}

		if info.IsDir() && info.Name() == ".git" {
			err = scanGit(filepath.Dir(path))
			if err != nil {
				log.Printf("scan failed for %s: %v\n", path, err)
				return err
			}
		}

		return nil
	})
}

func scanIdentifier(id sbom.Identifier) error {
	resp, err := osv.MakePURLRequest(id.PURL)
	if err != nil {
		return err
	}
	printResults(id.PURL, resp)
	return nil
}

func scanFile(path string) error {
	log.Printf("Scanning file %s\n", path)
	file, err := os.Open(path)
	if err != nil {
		return err
	}

	for _, provider := range sbom.Providers {
		file.Seek(0, os.SEEK_SET)
		err := provider.GetPackages(file, scanIdentifier)
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

func scanGit(repoDir string) error {
	commit, err := getCommitSHA(repoDir)
	if err != nil {
		return err
	}

	log.Printf("Scanning %s at commit %s", repoDir, commit)
	resp, err := osv.MakeCommitRequest(commit)
	if err != nil {
		return err
	}

	printResults(repoDir, resp)
	return nil
}

func printResults(id string, resp *osv.Response) {
	if len(resp.Vulns) > 0 {
		var urls []string
		for _, vuln := range resp.Vulns {
			urls = append(urls, osv.BaseVulnerabilityURL+vuln.ID)
		}

		log.Printf("%s is vulnerable to %s", id, strings.Join(urls, ", "))
	}
}

// TODO(ochang): Machine readable output format.
// TODO(ochang): Ability to specify type of input.
// TODO(ochang): Use batch API once available.
func main() {
	flag.Usage = usage
	flag.Parse()

	for _, arg := range flag.Args() {
		scan(arg)
	}
}
