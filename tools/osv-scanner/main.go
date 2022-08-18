package main

import (
	"bufio"
	"bytes"
	"errors"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/g-rath/osv-detector/pkg/lockfile"
	"github.com/urfave/cli/v2"

	"github.com/google/osv.dev/tools/osv-scanner/internal/osv"
	"github.com/google/osv.dev/tools/osv-scanner/internal/sbom"
)

// scanDir walks through the given directory to try to find any relevant files
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

		if !info.IsDir() {
			if parser, _ := lockfile.FindParser(path, ""); parser != nil {
				scanLockfile(query, path)
				if err != nil {
					log.Println("Attempted to scan lockfile but failed: " + path)
				}
			}
			scanSBOMFile(query, path)
		}

		return nil
	})
}

func scanLockfile(query *osv.BatchedQuery, path string) error {
	log.Printf("Scanning file %s\n", path)

	parsedLockfile, err := lockfile.Parse(path, "")
	if err != nil {
		return err
	}
	log.Printf("Scanned %s file with %d packages", parsedLockfile.ParsedAs, len(parsedLockfile.Packages))

	for _, pkgDetail := range parsedLockfile.Packages {
		query.Queries = append(query.Queries, osv.MakePkgRequest(pkgDetail))
	}
	return nil
}

func scanSBOMFile(query *osv.BatchedQuery, path string) error {
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

// Information about a docker package and it's version.
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
	scanner := bufio.NewScanner(stdout)
	for scanner.Scan() {
		text := scanner.Text()
		text = strings.TrimSpace(text)
		if len(text) == 0 {
			continue
		}
		splitText := strings.Split(text, "###")
		if len(splitText) != 2 {
			log.Fatalf("Unexpected output from Debian container: \n\n%s", text)
		}
		pkgDetails := osv.MakePkgRequest(lockfile.PackageDetails{
			Name:    splitText[0],
			Version: splitText[1],
			// TODO(rexpan): Get and specify exact debian release version
			Ecosystem: "Debian",
		})
		query.Queries = append(query.Queries, pkgDetails)
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
func main() {
	var query osv.BatchedQuery

	app := &cli.App{
		Name:  "osv-scanner",
		Usage: "scans various mediums for dependencies and matches it against the OSV database",
		Flags: []cli.Flag{
			&cli.StringSliceFlag{
				Name:      "docker",
				Aliases:   []string{"D"},
				Usage:     "scan docker image with this name",
				TakesFile: false,
			},
			&cli.StringSliceFlag{
				Name:      "lockfile",
				Aliases:   []string{"L"},
				Usage:     "scan package lockfile on this path",
				TakesFile: true,
			},
			&cli.StringSliceFlag{
				Name:      "sbom",
				Aliases:   []string{"S"},
				Usage:     "scan sbom file on this path",
				TakesFile: true,
			},
		},
		ArgsUsage: "[directory1 directory2...]",
		Action: func(context *cli.Context) error {
			containers := context.StringSlice("docker")
			for _, container := range containers {
				// TODO: Automatically figure out what docker base image
				// and scan appropriately.
				scanDebianDocker(&query, container)
			}

			lockfiles := context.StringSlice("lockfile")
			for _, lockfile := range lockfiles {
				err := scanLockfile(&query, lockfile)
				if err != nil {
					return err
				}
			}

			sboms := context.StringSlice("sbom")
			for _, sbom := range sboms {
				err := scanSBOMFile(&query, sbom)
				if err != nil {
					return err
				}
			}

			genericDirs := context.Args().Slice()
			for _, dir := range genericDirs {
				err := scanDir(&query, dir)
				if err != nil {
					return err
				}
			}

			if len(query.Queries) == 0 {
				cli.ShowAppHelpAndExit(context, 1)
			}

			return nil
		},
	}
	if err := app.Run(os.Args); err != nil {
		log.Fatal(err)
	}

	resp, err := osv.MakeRequest(query)
	if err != nil {
		log.Printf("scan failed: %v\n", err)
		return
	}

	printResults(query, resp)
}
