/*
cpe-repo-gen analyzes the NVD CPE Dictionary for Open Source repository information.
It reads NVD CPE Dictionary JSON files and outputs a JSON map of CPE products to discovered repository URLs.

It can also output on stdout additional data about colliding CPE package names.

Usage:

	go run cmd/cpe-repo-gen/main.go [flags]

The flags are:

	  --cpe-dictionary-dir
		The path to the directory of NVD CPE Dictionary JSON files, see https://nvd.nist.gov/products/cpe

	  --debian-metadata-path
	        The path to a directory containing a local mirror of Debian copyright metadata, see README.md

	  --output-dir
	        The directory to output cpe_product_to_repo.json and cpe_reference_description_frequency.csv in

	  --validate
	        Perform remote validation of repositories and only include ones that validate successfully

	  --verbose
		Output additional telemetry to stdout
*/
package main

import (
	"bufio"
	"bytes"
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"text/template"

	"github.com/google/osv/vulnfeeds/cves"
	"github.com/google/osv/vulnfeeds/git"
	"github.com/google/osv/vulnfeeds/utility"
	"github.com/google/osv/vulnfeeds/utility/logger"

	"slices"
)

// Reference is a reference from a CPE in the NVD CPE Dictionary.
type Reference struct {
	URL  string `json:"ref"`
	Type string `json:"type"`
}

// CPE is a CPE from the NVD CPE Dictionary.
type CPE struct {
	Deprecated bool        `json:"deprecated"`
	Name       string      `json:"cpeName"`
	References []Reference `json:"refs"`
}

// CPEProduct is a product from the NVD CPE Dictionary.
type CPEProduct struct {
	CPE CPE `json:"cpe"`
}

// CPEFeed is a feed of products from the NVD CPE Dictionary.
type CPEFeed struct {
	Products []CPEProduct `json:"products"`
}

// VendorProduct contains a CPE's Vendor and Product strings.
type VendorProduct struct {
	Vendor  string
	Product string
}

// VendorProducts in this denylist are known non-OSS and/or have generic
// product names, which cause undesired and incorrect repository attribution
// when resolved via Debian copyright metadata.
var DebianCopyrightDenylist = []VendorProduct{
	{"apple", "pdfkit"},
	{"f-secure", "safe"},
	{"ibm", "workflow"},
	{"inductiveautomation", "ignition"},
	{"jetbrains", "hub"},
	{"microsoft", "onedrive"},
	{"mirametrix", "glance"},
	{"nintext", "workflow"},
	{"oracle", "workflow"},
	{"thrivethemes", "ignition"},
	{"vmware", "horizon"},
}

// MarshalText is a helper for JSON rendering of a map with a struct key.
func (vp VendorProduct) MarshalText() ([]byte, error) { //nolint:unparam
	return []byte(vp.Vendor + ":" + vp.Product), nil
}

// VendorProductToRepoMap maps a VendorProduct to a repo URL.
type VendorProductToRepoMap map[VendorProduct][]string

const (
	OutputDirDefault = "."
	projectID        = "oss-vdb"
)

var (
	// These repos should never be considered authoritative for a product.
	// Match repos with "CVE", "CVEs" or a pure CVE number in their name, anything from GitHubAssessments
	CPEDictionaryDir   = flag.String("cpe-dictionary-dir", "cve_json/nvdcpe-2.0-chunks", "Directory of CPE dictionary JSON files to parse")
	OutputDir          = flag.String("output-dir", OutputDirDefault, "Directory to output cpe_product_to_repo.json and cpe_reference_description_frequency.csv in")
	GCPLoggingProject  = flag.String("gcp-logging-project", projectID, "GCP project ID to use for logging, set to an empty string to log locally only")
	DebianMetadataPath = flag.String("debian-metadata-path", "", "Path to Debian copyright metadata")
	Validate           = flag.Bool("validate", true, "Attempt to validate the repository is communicable")
	Verbose            = flag.Bool("verbose", false, "Output some telemetry to stdout during execution")
)

func LoadCPEsFromJSONDir(dir string) ([]CPE, error) {
	var cpes []CPE
	files, err := filepath.Glob(filepath.Join(dir, "*.json"))
	if err != nil {
		return nil, fmt.Errorf("failed to glob for json files in %s: %w", dir, err)
	}

	for _, filePath := range files {
		jsonFile, err := os.Open(filePath)
		if err != nil {
			logger.Warn("Failed to open", slog.String("path", filePath), slog.Any("err", err))
			continue
		}

		byteValue, err := io.ReadAll(jsonFile)
		if err != nil {
			jsonFile.Close()
			return nil, err
		}
		jsonFile.Close()
		var feed CPEFeed
		if err := json.Unmarshal(byteValue, &feed); err != nil {
			logger.Warn("Failed to unmarshal", slog.String("path", filePath), slog.Any("err", err))
			continue
		}
		for _, p := range feed.Products {
			cpes = append(cpes, p.CPE)
		}
	}

	return cpes, nil
}

// Outputs a JSON file of the product-to-repo map.
func outputProductToRepoMap(prm VendorProductToRepoMap, f io.Writer) error {
	productsWithoutRepos := 0
	for p := range prm {
		if len(prm[p]) == 0 {
			productsWithoutRepos++
			delete(prm, p) // we don't want the repo-less products in our JSON output

			continue
		}
	}

	e := json.NewEncoder(f)

	if err := e.Encode(&prm); err != nil {
		return err
	}

	logger.Info("Outputting information", slog.Int("products", len(prm)), slog.Int("without_repos", productsWithoutRepos))

	return nil
}

// Outputs a CSV file of the description frequency map, sorted in descending order.
func outputDescriptionFrequency(df map[string]int, f io.Writer) error {
	descriptions := make([]string, 0, len(df))
	for description := range df {
		descriptions = append(descriptions, description)
	}
	sort.SliceStable(descriptions, func(i, j int) bool {
		return df[descriptions[i]] > df[descriptions[j]]
	})

	w := csv.NewWriter(f)

	if err := w.Write([]string{"Description", "Frequency"}); err != nil {
		return err
	}
	for _, d := range descriptions {
		if err := w.Write([]string{d, strconv.Itoa(df[d])}); err != nil {
			return err
		}
	}

	w.Flush()

	if err := w.Error(); err != nil {
		return err
	}

	logger.Info("Seen distinct reference descriptions", slog.Int("count", len(df)))

	return nil
}

// Checks if a URL relates to the FSF.
func IsGNUURL(u string) bool {
	re := regexp.MustCompile(`^https?://.*
.(?:non)?gnu.org/`)

	return re.MatchString(u)
}

func IsGitHubURL(u string) bool {
	return strings.HasPrefix(strings.ToLower(u), "https://github.com/")
}

// Tries to translate Savannah URLs to their corresponding Git repository URL.
func MaybeTranslateSavannahURL(u string) (string, bool) {
	type GNUPlaceholder struct {
		GNUOrNonGNU string
		Path        string
	}
	var tpl bytes.Buffer

	supportedHostnames := []string{
		"download.savannah.gnu.org",
		"savannah.gnu.org",
		"download.savannah.gnu.org",
		"download-mirror.savannah.gnu.org",
		"download.savannah.nongnu.org",
		"savannah.nongnu.org",
		"download.savannah.nongnu.org",
		"download-mirror.savannah.nongnu.org",
	}

	// Get hostname out of URL
	parsedURL, err := url.Parse(u)
	if err != nil {
		panic(err)
	}

	if slices.Contains(supportedHostnames, parsedURL.Hostname()) {
		hostnameParts := strings.Split(parsedURL.Hostname(), ".")
		// Pull out the "nongnu" or "gnu" part of the hostname
		domain := GNUPlaceholder{hostnameParts[len(hostnameParts)-2], path.Base(parsedURL.Path)}
		savannahGitRepoTemplate, err := template.New("SavannahGitRepoURL").Parse("https://git.savannah.{{ .GNUOrNonGNU }}.org/git/{{ .Path }}.git")
		if err != nil {
			panic(err)
		}
		err = savannahGitRepoTemplate.Execute(&tpl, domain)
		if err != nil {
			panic(err)
		}

		return tpl.String(), true
	}

	// Return the original URL unmodified
	return u, false
}

// Returns the data associated with the ^Source: line of a machine-readable Debian copyright file
// See https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/
func MaybeGetSourceFromDebianCopyright(copyrightFile string) (string, bool) {
	re := regexp.MustCompile(`^Source: (.*)$`)

	file, err := os.Open(copyrightFile)
	if err != nil {
		logger.Fatal("Failed to open copyright file", slog.Any("err", err))
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)

	// Check the first line to see if we have a machine-readable copyright file
	scanner.Scan()
	if scanner.Text() != "Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/" {
		return "", false
	}

	for scanner.Scan() {
		line := scanner.Text()
		match := re.FindStringSubmatch(line)
		if match != nil {
			return match[1], true
		}
	}

	return "", false
}

// Tries to find a Debian copyright file for the package and returns the source URL if IsRepoURL() agrees.
func MaybeGetSourceRepoFromDebian(mdir string, pkg string) string {
	var metadata string
	if strings.HasPrefix(pkg, "lib") {
		metadata = path.Join(mdir, "changelogs/main", pkg[0:4], pkg, "unstable_copyright")
	} else {
		metadata = path.Join(mdir, "changelogs/main", string(pkg[0]), pkg, "unstable_copyright")
	}
	if _, err := os.Stat(metadata); err == nil {
		// parse the copyright file and go from here
		logger.Info("FYI: Looking at file for package", slog.String("metadata", metadata), slog.String("package", pkg))
		possibleRepo, ok := MaybeGetSourceFromDebianCopyright(metadata)
		if !ok {
			return ""
		}
		if utility.IsRepoURL(possibleRepo) {
			return possibleRepo
		}
		// Incorporate Savannah URL to Git translation here
		if IsGNUURL(possibleRepo) {
			repo, translated := MaybeTranslateSavannahURL(possibleRepo)
			if translated {
				return repo
			}
		}
		logger.Info("FYI: Disregarding", slog.String("repo", possibleRepo), slog.String("package", pkg))
	}

	return ""
}

// Analyze CPE Dictionary and return a product-to-repo map and a reference description frequency table.
func analyzeCPEDictionary(cpes []CPE) (productToRepo VendorProductToRepoMap, descriptionFrequency map[string]int) {
	productToRepo = make(VendorProductToRepoMap)
	descriptionFrequency = make(map[string]int)
	MaybeTryDebian := make(map[VendorProduct]bool)
	for _, c := range cpes {
		if c.Deprecated {
			logger.Info("Skipping deprecated", slog.String("cpe", c.Name))
			continue
		}
		parsedCPE, err := cves.ParseCPE(c.Name)
		if err != nil {
			logger.Info("Failed to parse", slog.String("cpe", c.Name))
			continue
		}
		if parsedCPE.Part != "a" {
			// Not interested in hardware or operating systems.
			continue
		}
		for _, r := range c.References {
			descriptionFrequency[r.Type] += 1
			repo, err := cves.Repo(r.URL)
			if err != nil {
				logger.Info("Disregarding", slog.String("url", r.URL), slog.String("vendor", parsedCPE.Vendor), slog.String("product", parsedCPE.Product), slog.String("type", r.Type), slog.Any("err", err))
				continue
			}
			if IsGitHubURL(repo) {
				repo = strings.ToLower(repo)
			}
			// If we already have an entry for this repo, don't add it again.
			if slices.Contains(productToRepo[VendorProduct{parsedCPE.Vendor, parsedCPE.Product}], repo) {
				continue
			}
			logger.Info("Liking", slog.String("repo", repo), slog.String("vendor", parsedCPE.Vendor), slog.String("product", parsedCPE.Product), slog.String("type", r.Type))
			productToRepo[VendorProduct{parsedCPE.Vendor, parsedCPE.Product}] = append(productToRepo[VendorProduct{parsedCPE.Vendor, parsedCPE.Product}], repo)
			// If this was queued for trying to find via Debian, and subsequently found, dequeue it.
			if *DebianMetadataPath != "" {
				delete(MaybeTryDebian, VendorProduct{parsedCPE.Vendor, parsedCPE.Product})
			}
		}
		// If we've arrived to this point, we've exhausted the
		// references and not calculated any repos for the product,
		// flag for trying Debian afterwards.
		// We may encounter another CPE item that *does* have a viable reference in the meantime.
		if len(productToRepo[VendorProduct{parsedCPE.Vendor, parsedCPE.Product}]) == 0 && *DebianMetadataPath != "" {
			// Check the denylist though.
			if slices.Contains(DebianCopyrightDenylist, VendorProduct{parsedCPE.Vendor, parsedCPE.Product}) {
				continue
			}
			MaybeTryDebian[VendorProduct{parsedCPE.Vendor, parsedCPE.Product}] = true
		}
	}
	// Try any Debian possible ones as a last resort.
	if len(MaybeTryDebian) > 0 && *DebianMetadataPath != "" {
		logger.Info("Trying to derive repos from Debian", slog.Int("products", len(MaybeTryDebian)))
		// This is likely to be time consuming, so give an impatient log watcher something to gauge progress by.
		entryCount := 0
		for vp := range MaybeTryDebian {
			entryCount++
			logger.Info("Trying to derive a repo from Debian", slog.Int("count", entryCount), slog.Int("total", len(MaybeTryDebian)), slog.String("vendor", vp.Vendor), slog.String("product", vp.Product))
			repo := MaybeGetSourceRepoFromDebian(*DebianMetadataPath, vp.Product)
			if repo != "" {
				logger.Info("Derived repo", slog.String("repo", repo), slog.String("vendor", vp.Vendor), slog.String("product", vp.Product))
				// Now check that what Debian gave us meets our expectations and is valid.
				repo, err := cves.Repo(repo)
				if err != nil {
					logger.Info("Disregarding derived repo", slog.String("repo", repo), slog.String("vendor", vp.Vendor), slog.String("product", vp.Product), slog.Any("err", err))
					continue
				}
				if !git.ValidRepoAndHasUsableRefs(repo) {
					logger.Info("Disregarding derived repo as unusable", slog.String("repo", repo), slog.String("vendor", vp.Vendor), slog.String("product", vp.Product))
					continue
				}
				productToRepo[VendorProduct{vp.Vendor, vp.Product}] = append(productToRepo[VendorProduct{vp.Vendor, vp.Product}], repo)
			}
		}
	}

	return productToRepo, descriptionFrequency
}

// validateRepos takes a VendorProductToRepoMap and removes any entries where the repository fails remote validation.
func validateRepos(prm VendorProductToRepoMap) (validated VendorProductToRepoMap) {
	validated = make(VendorProductToRepoMap)
	logger.Info("Validating repos", slog.Int("products", len(prm)))
	// This is likely to be time consuming, so give an impatient log watcher something to gauge progress by.
	entryCount := 0
	for vp := range prm {
		entryCount++
		// As a side-effect, this also omits any with no repos.
		for _, r := range prm[vp] {
			if !git.ValidRepoAndHasUsableRefs(r) {
				logger.Info("Invalid repo", slog.Int("count", entryCount), slog.Int("total", len(prm)), slog.String("repo", r), slog.String("vendor", vp.Vendor), slog.String("product", vp.Product))
				continue
			}
			validated[vp] = append(validated[vp], r)
		}
	}
	logger.Info("Validation complete", slog.Int("before", len(prm)), slog.Int("after", len(validated)), slog.Int("delta", len(prm)-len(validated)))

	return validated
}

func main() {
	flag.Usage = func() {
		fmt.Fprint(flag.CommandLine.Output(), "Utility to analyze NVD CPE Dictionary\n\n")
		fmt.Fprintf(flag.CommandLine.Output(), "Usage of %s:\n", os.Args[0])
		flag.PrintDefaults()
	}
	flag.Parse()

	logger.InitGlobalLogger()
	cpes, err := LoadCPEsFromJSONDir(*CPEDictionaryDir)
	if err != nil {
		logger.Fatal("Failed to load CPEs", slog.String("path", *CPEDictionaryDir), slog.Any("err", err))
	}

	productToRepo, descriptionFrequency := analyzeCPEDictionary(cpes)
	if *Validate {
		productToRepo = validateRepos(productToRepo)
	}

	mappingFile, err := os.Create(filepath.Join(*OutputDir, "cpe_product_to_repo.json"))
	if err != nil {
		logger.Fatal("Failed to create mapping file", slog.Any("err", err))
	}
	defer mappingFile.Close()
	err = outputProductToRepoMap(productToRepo, mappingFile)
	if err != nil {
		logger.Fatal("Failed to output product to repo map", slog.Any("err", err))
	}
	frequencyFile, err := os.Create(filepath.Join(*OutputDir, "cpe_reference_description_frequency.csv"))
	if err != nil {
		logger.Fatal("Failed to create frequency file", slog.Any("err", err))
	}
	defer frequencyFile.Close()
	err = outputDescriptionFrequency(descriptionFrequency, frequencyFile)
	if err != nil {
		logger.Fatal("Failed to output description frequency", slog.Any("err", err))
	}
}
