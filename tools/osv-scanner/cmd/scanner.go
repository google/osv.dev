package main

import (
	"bufio"
	"bytes"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/google/osv/tools/scanner/internal/lockfiles"
	"github.com/google/osv/tools/scanner/internal/osv"
	"github.com/google/osv/tools/scanner/internal/sbom"
)

func usage() {
	fmt.Fprintf(flag.CommandLine.Output(), "%s [flags] dir1 dir2...\n", os.Args[0])
	flag.PrintDefaults()
}

func scan(query *osv.BatchedQuery, arg string) error {
	info, err := os.Stat(arg)
	if err != nil {
		// Assume it's a docker image if file can't be found
		// TODO: Have actual commands to differentiate these functions
		scanDebianDocker(query, arg)
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

	switch filepath.Base(path) {
	case "Cargo.lock":
		packagePurls := lockfiles.ScanCargoFile(file)
		for _, purl := range packagePurls {
			query.Queries = append(query.Queries, osv.MakePURLRequest(purl))
		}
		log.Printf("Scanned Cargo.lock file with %d packages", len(packagePurls))
	//case "package-lock.json", "yarn.lock", "pnpm-lock.yaml":
	//	lockfiles.ScanNpmFile(file)
	default:
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

type DockerPackageVersion struct {
	Name    string
	Version string
}

func scanDebianDocker(query *osv.BatchedQuery, dockerImageName string) {
	cmd := exec.Command("docker", "run", "--rm", dockerImageName, "/usr/bin/dpkg-query", "-f", "${Package}###${Version}\\n", "-W")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		log.Fatalf("Failed to get stdout: %s", err)
	}
	err = cmd.Start()
	if err != nil {
		log.Fatalf("Failed to start docker image: %s", err)
	}
	defer cmd.Wait()
	if err != nil {
		log.Fatalf("Failed to run docker: %s", err)
	}
	var allPackagesPurl []string
	scanner := bufio.NewScanner(stdout)
	for scanner.Scan() {
		text := scanner.Text()
		text = strings.TrimSpace(text)
		if len(text) == 0 {
			continue
		}
		splitText := strings.Split(text, "###")
		allPackagesPurl = append(allPackagesPurl, "pkg:deb/debian/"+splitText[0]+"@"+splitText[1])
	}
	for _, purl := range allPackagesPurl {
		query.Queries = append(query.Queries, osv.MakePURLRequest(purl))
	}
	log.Printf("Scanned docker image")
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
