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

	"github.com/BurntSushi/toml"
	"github.com/g-rath/osv-detector/pkg/lockfile"
	"github.com/google/osv.dev/tools/osv-scanner/internal/osv"
	"github.com/google/osv.dev/tools/osv-scanner/internal/output"
	"github.com/google/osv.dev/tools/osv-scanner/internal/sbom"
	"github.com/urfave/cli/v2"
	"golang.org/x/exp/slices"
)

const osvScannerConfigName = "osv-scanner.toml"

var globalConfig *Config

// scanDir walks through the given directory to try to find any relevant files
func scanDir(query *osv.BatchedQuery, dir string, skipGit bool, configMap map[string]Config) error {
	return filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			log.Printf("Failed to walk %s: %v", path, err)
			return err
		}
		path, err = filepath.Abs(path)
		if err != nil {
			log.Fatalf("Failed to walk path %s", err)
		}

		if !skipGit && info.IsDir() && info.Name() == ".git" {
			err := scanGit(query, filepath.Dir(path)+"/", configMap)
			if err != nil {
				log.Printf("scan failed for %s: %v\n", path, err)
				return err
			}
			return filepath.SkipDir
		}

		if !info.IsDir() {
			if parser, _ := lockfile.FindParser(path, ""); parser != nil {
				err := scanLockfile(query, path, configMap)
				if err != nil {
					log.Println("Attempted to scan lockfile but failed: " + path)
				}
			}
			// No need to check for error
			// If scan fails, it means it isn't a valid SBOM file,
			// so just move onto the next file
			_ = scanSBOMFile(query, path, configMap)
		}

		return nil
	})
}

func scanLockfile(query *osv.BatchedQuery, path string, configMap map[string]Config) error {
	configPath := TryLoadConfig(path, configMap)
	parsedLockfile, err := lockfile.Parse(path, "")
	if err != nil {
		return err
	}
	log.Printf("Scanned %s file and found %d packages", path, len(parsedLockfile.Packages))
	if configPath != "" {
		log.Printf("Using config %s", configPath)
	}

	for _, pkgDetail := range parsedLockfile.Packages {
		pkgDetailQuery := osv.MakePkgRequest(pkgDetail)
		pkgDetailQuery.Source = "lockfile:" + path
		query.Queries = append(query.Queries, pkgDetailQuery)
	}
	return nil
}

func scanSBOMFile(query *osv.BatchedQuery, path string, configMap map[string]Config) error {
	configPath := TryLoadConfig(path, configMap)
	file, err := os.Open(path)
	if err != nil {
		return err
	}

	for _, provider := range sbom.Providers {
		if provider.Name() == "SPDX" &&
			!strings.Contains(strings.ToLower(filepath.Base(path)), ".spdx") {
			// All spdx files should have the .spdx in the filename, even if
			// it's not the extension:  https://spdx.github.io/spdx-spec/v2.3/conformance/
			// Skip if this isn't the case to avoid panics
			continue
		}
		err := provider.GetPackages(file, func(id sbom.Identifier) error {
			purlQuery := osv.MakePURLRequest(id.PURL)
			purlQuery.Source = "sbom:" + path
			query.Queries = append(query.Queries, purlQuery)
			return nil
		})
		if err == nil {
			// Found the right format.
			log.Printf("Scanned %s SBOM", provider.Name())
			if configPath != "" {
				log.Printf("Using config %s", configPath)
			}
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

// Scan git repository. Expects repoDir to end with /
func scanGit(query *osv.BatchedQuery, repoDir string, configMap map[string]Config) error {
	commit, err := getCommitSHA(repoDir)
	if err != nil {
		return err
	}

	log.Printf("Scanning %s at commit %s", repoDir, commit)
	configPath := TryLoadConfig(repoDir, configMap)
	if configPath != "" {
		log.Printf("With config located at %s", configPath)
	}

	gitQuery := osv.MakeCommitRequest(commit)
	gitQuery.Source = "git:" + repoDir
	query.Queries = append(query.Queries, gitQuery)
	return nil
}

func scanDebianDocker(query *osv.BatchedQuery, dockerImageName string) {
	cmd := exec.Command("docker", "run", "--rm", "--entrypoint", "/usr/bin/dpkg-query", dockerImageName, "-f", "${Package}###${Version}\\n", "-W")
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
	packages := 0
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
		pkgDetailsQuery := osv.MakePkgRequest(lockfile.PackageDetails{
			Name:    splitText[0],
			Version: splitText[1],
			// TODO(rexpan): Get and specify exact debian release version
			Ecosystem: "Debian",
		})
		pkgDetailsQuery.Source = "docker:" + dockerImageName
		query.Queries = append(query.Queries, pkgDetailsQuery)
		packages += 1
	}
	log.Printf("Scanned docker image with %d packages", packages)
}

// Filters response according to config, returns number of responses removed
func filterResponse(query osv.BatchedQuery, resp *osv.BatchedResponse, globalConfig *Config, configMap map[string]Config) int {
	//response := []osv.MinimalResponse{}
	hiddenVulns := map[string]struct{}{}

	for i, result := range resp.Results {
		var filteredVulns []osv.MinimalVulnerability
		var configToUse *Config
		if globalConfig != nil {
			configToUse = globalConfig
		} else {
			sourcePath := strings.SplitN(query.Queries[i].Source, ":", 2)[1]
			configToUseTemp, ok := configMap[sourcePath]
			if ok {
				configToUse = &configToUseTemp
			}
		}
		if configToUse != nil {
			for _, vuln := range result.Vulns {
				if slices.Contains(configToUse.IgnoredVulnIds, vuln.ID) {
					hiddenVulns[vuln.ID] = struct{}{}
				} else {
					filteredVulns = append(filteredVulns, vuln)
				}
			}
			resp.Results[i].Vulns = filteredVulns
		}
	}

	return len(hiddenVulns)
}

func main() {
	var query osv.BatchedQuery
	var outputJson bool
	configMap := map[string]Config{}

	app := &cli.App{
		Name:    "osv-scanner",
		Usage:   "scans various mediums for dependencies and matches it against the OSV database",
		Suggest: true,
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
			&cli.StringFlag{
				Name:      "config",
				Usage:     "set/override config file",
				TakesFile: true,
			},
			&cli.BoolFlag{
				Name:  "json",
				Usage: "sets output to json (WIP)",
			},
			&cli.BoolFlag{
				Name:  "skip-git",
				Usage: "skip scanning git repositories",
				Value: false,
			},
		},
		ArgsUsage: "[directory1 directory2...]",
		Action: func(context *cli.Context) error {

			configPath := context.String("config")
			if configPath != "" {
				config := Config{}
				_, err := toml.DecodeFile(configPath, &config)
				globalConfig = &config
				if err != nil {
					log.Fatalf("Failed to read config file: %s\n", err)
				}
			}

			containers := context.StringSlice("docker")
			for _, container := range containers {
				// TODO: Automatically figure out what docker base image
				// and scan appropriately.
				scanDebianDocker(&query, container)
			}

			lockfiles := context.StringSlice("lockfile")
			for _, lockfileElem := range lockfiles {
				lockfileElem, err := filepath.Abs(lockfileElem)
				if err != nil {
					log.Fatalf("Failed to resolved path with error %s", err)
				}
				err = scanLockfile(&query, lockfileElem, configMap)
				if err != nil {
					return err
				}
			}

			sboms := context.StringSlice("sbom")
			for _, sbomElem := range sboms {
				sbomElem, err := filepath.Abs(sbomElem)
				if err != nil {
					log.Fatalf("Failed to resolved path with error %s", err)
				}
				err = scanSBOMFile(&query, sbomElem, configMap)
				if err != nil {
					return err
				}
			}

			skipGit := context.Bool("skip-git")
			genericDirs := context.Args().Slice()
			for _, dir := range genericDirs {
				log.Printf("Scanning dir %s\n", dir)
				err := scanDir(&query, dir, skipGit, configMap)
				if err != nil {
					return err
				}
			}

			if len(query.Queries) == 0 {
				cli.ShowAppHelpAndExit(context, 1)
			}

			outputJson = context.Bool("json")

			return nil
		},
	}

	if err := app.Run(os.Args); err != nil {
		log.Fatal(err)
	}

	resp, err := osv.MakeRequest(query)
	if err != nil {
		log.Fatalf("Scan failed: %v", err)
	}

	filtered := filterResponse(query, resp, globalConfig, configMap)
	if filtered > 0 {
		log.Printf("Filtered %d vulnerabilities from output", filtered)
	}

	hydratedResp, err := osv.Hydrate(resp)
	if err != nil {
		log.Fatalf("Failed to hydrate OSV response: %v", err)
	}

	if outputJson {
		err = output.PrintJSONResults(query, hydratedResp, os.Stdout)
	} else {
		output.PrintTableResults(query, hydratedResp, os.Stdout)
	}

	if err != nil {
		log.Fatalf("Failed to write output: %s", err)
	}
}
