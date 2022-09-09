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
	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/jedib0t/go-pretty/v6/text"
	"github.com/package-url/packageurl-go"
	"github.com/urfave/cli/v2"
	"golang.org/x/crypto/ssh/terminal"

	"github.com/google/osv.dev/tools/osv-scanner/internal/grouper"
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
			gitQuery.Source = "git:" + filepath.Dir(path)
			query.Queries = append(query.Queries, gitQuery)
		}

		if !info.IsDir() {
			if parser, _ := lockfile.FindParser(path, ""); parser != nil {
				err := scanLockfile(query, path)
				if err != nil {
					log.Println("Attempted to scan lockfile but failed: " + path)
				}
			}
			// No need to check for error
			// If scan fails, it means it isn't a valid SBOM file,
			// so just move onto the next file
			_ = scanSBOMFile(query, path)
		}

		return nil
	})
}

func scanLockfile(query *osv.BatchedQuery, path string) error {
	parsedLockfile, err := lockfile.Parse(path, "")
	if err != nil {
		return err
	}
	log.Printf("Scanned %s file and found %d packages", path, len(parsedLockfile.Packages))

	for _, pkgDetail := range parsedLockfile.Packages {
		pkgDetailQuery := osv.MakePkgRequest(pkgDetail)
		pkgDetailQuery.Source = "lockfile:" + path
		query.Queries = append(query.Queries, pkgDetailQuery)
	}
	return nil
}

func scanSBOMFile(query *osv.BatchedQuery, path string) error {
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
		pkgDetailsQuery := osv.MakePkgRequest(lockfile.PackageDetails{
			Name:    splitText[0],
			Version: splitText[1],
			// TODO(rexpan): Get and specify exact debian release version
			Ecosystem: "Debian",
		})
		pkgDetailsQuery.Source = "docker:" + dockerImageName
		query.Queries = append(query.Queries, pkgDetailsQuery)
	}
	log.Printf("Scanned docker image")
}

// printResults prints the osv scan results into a human friendly table.
func printResults(query osv.BatchedQuery, resp *osv.HydratedBatchedResponse) {
	outputTable := table.NewWriter()
	outputTable.SetOutputMirror(os.Stdout)
	outputTable.AppendHeader(table.Row{"Source", "Ecosystem", "Affected Package", "Installed Version", "Vulnerability ID", "OSV URL"})

	for i, query := range query.Queries {
		if len(resp.Results[i].Vulns) == 0 {
			continue
		}
		for _, group := range grouper.Group(resp.Results[i].Vulns) {
			outputRow := table.Row{query.Source}
			shouldMerge := false
			if query.Commit != "" {
				outputRow = append(outputRow, "GIT", query.Commit, query.Commit)
				shouldMerge = true
			} else if query.Package.PURL != "" {
				parsedPURL, err := packageurl.FromString(query.Package.PURL)
				if err != nil {
					log.Println("Failed to parse purl")
					continue
				}
				purlVersion := parsedPURL.Version
				parsedPURL.Version = ""
				parsedPURL.Qualifiers = []packageurl.Qualifier{}
				outputRow = append(outputRow, "PURL", parsedPURL.ToString(), purlVersion)
				shouldMerge = true
			} else {
				outputRow = append(outputRow, query.Package.Ecosystem, query.Package.Name, query.Version)
			}

			var ids []string
			var links []string

			for _, vuln := range group {
				ids = append(ids, vuln.ID)
				links = append(links, osv.BaseVulnerabilityURL+vuln.ID)
			}

			outputRow = append(outputRow, strings.Join(ids, "\n"), strings.Join(links, "\n"))
			outputTable.AppendRow(outputRow, table.RowConfig{AutoMerge: shouldMerge})
		}
	}

	outputTable.SetStyle(table.StyleRounded)
	outputTable.Style().Color.Row = text.Colors{text.Reset, text.BgBlack}
	outputTable.Style().Color.RowAlternate = text.Colors{text.Reset, text.Reset}
	// TODO: Leave these here until styling is finalized
	//outputTable.Style().Color.Header = text.Colors{text.FgHiCyan, text.BgBlack}
	//outputTable.Style().Color.Row = text.Colors{text.Reset, text.Reset}
	//outputTable.Style().Options.SeparateRows = true
	//outputTable.Style().Options.SeparateColumns = true
	//outputTable.SetColumnConfigs([]table.ColumnConfig{
	//	{Number: 2, AutoMerge: true, WidthMax: maxCharacters},
	//	{Number: 3, AutoMerge: true, WidthMax: maxCharacters},
	//})

	width, _, err := terminal.GetSize(int(os.Stdout.Fd()))
	if err == nil { // If output is a terminal, set max length to width
		outputTable.SetAllowedRowLength(width)
	} // Otherwise don't set max width (e.g. getting piped to a file)
	if outputTable.Length() == 0 {
		return
	}
	outputTable.Render()
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
			&cli.BoolFlag{
				Name:  "json",
				Usage: "sets output to json (WIP)",
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
			for _, lockfileElem := range lockfiles {
				err := scanLockfile(&query, lockfileElem)
				if err != nil {
					return err
				}
			}

			sboms := context.StringSlice("sbom")
			for _, sbomElem := range sboms {
				err := scanSBOMFile(&query, sbomElem)
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
		log.Fatalf("Scan failed: %v", err)
	}

	hydratedResp, err := osv.Hydrate(resp)
	if err != nil {
		log.Fatalf("Failed to hydrate OSV response: %v", err)
	}

	printResults(query, hydratedResp)
}
