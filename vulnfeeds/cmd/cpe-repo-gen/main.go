/*
cpe-repo-gen analyzes the NVD CPE Dictionary for Open Source repository information.
It reads NVD CPE Dictionary JSON files and outputs a JSON map of CPE products to discovered repository URLs.

It can also output on stdout additional data about colliding CPE package names.

Usage:

	go run cmd/cpe-repo-gen/main.go [flags]

The flags are:

	  --cpe_dictionary_dir
		The path to the directory of NVD CPE Dictionary JSON files, see https://nvd.nist.gov/products/cpe

	  --debian_metadata_path
	        The path to a directory containing a local mirror of Debian copyright metadata, see README.md

	  --output_dir
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
	CPEDictionaryDir   = flag.String("cpe_dictionary_dir", "cve_json/nvdcpe-2.0-chunks", "Directory of CPE dictionary JSON files to parse")
	OutputDir          = flag.String("output_dir", OutputDirDefault, "Directory to output cpe_product_to_repo.json and cpe_reference_description_frequency.csv in")
	GCPLoggingProject  = flag.String("gcp_logging_project", projectID, "GCP project ID to use for logging, set to an empty string to log locally only")
	DebianMetadataPath = flag.String("debian_metadata_path", "", "Path to Debian copyright metadata")
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
			logger.Warnf("Failed to open %s: %v", filePath, err)
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
			logger.Warnf("Failed to unmarshal %s: %v", filePath, err)
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

	logger.Infof("Outputting information about %d application products, %d do not have repos", len(prm), productsWithoutRepos)

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

	logger.Infof("Seen %d distinct reference descriptions", len(df))

	return nil
}

// Checks if a URL relates to the FSF.
func IsGNUURL(u string) bool {
	re := regexp.MustCompile(`^https?://.*\.(?:non)?gnu\.org/`)

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
		logger.Fatalf("%v", err)
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
		logger.Infof("FYI: Looking at %s for %s", metadata, pkg)
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
		logger.Infof("FYI: Disregarding %s for %s", possibleRepo, pkg)
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
			logger.Infof("Skipping deprecated %q", c.Name)
			continue
		}
		parsedCPE, err := cves.ParseCPE(c.Name)
		if err != nil {
			logger.Infof("Failed to parse %q", c.Name)
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
				logger.Infof("Disregarding %q for %s:%s (%s) because %v", r.URL, parsedCPE.Vendor, parsedCPE.Product, r.Type, err)
				continue
			}
			if IsGitHubURL(repo) {
				repo = strings.ToLower(repo)
			}
			// If we already have an entry for this repo, don't add it again.
			if slices.Contains(productToRepo[VendorProduct{parsedCPE.Vendor, parsedCPE.Product}], repo) {
				continue
			}
			logger.Infof("Liking %q for %s:%s (%s)", repo, parsedCPE.Vendor, parsedCPE.Product, r.Type)
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
		logger.Infof("Trying to derive repos from Debian for %d products", len(MaybeTryDebian))
		// This is likely to be time consuming, so give an impatient log watcher something to gauge progress by.
		entryCount := 0
		for vp := range MaybeTryDebian {
			entryCount++
			logger.Infof("%d/%d: Trying to derive a repo from Debian for %s:%s", entryCount, len(MaybeTryDebian), vp.Vendor, vp.Product)
			repo := MaybeGetSourceRepoFromDebian(*DebianMetadataPath, vp.Product)
			if repo != "" {
				logger.Infof("Derived repo: %s for %s:%s", repo, vp.Vendor, vp.Product)
				// Now check that what Debian gave us meets our expectations and is valid.
				repo, err := cves.Repo(repo)
				if err != nil {
					logger.Infof("Disregarding derived repo %s for %s:%s because %v", repo, vp.Vendor, vp.Product, err)
					continue
				}
				if !git.ValidRepoAndHasUsableRefs(repo) {
					logger.Infof("Disregarding derived repo %s for %s:%s because it is unusable for version resolution", repo, vp.Vendor, vp.Product)
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
	logger.Infof("Validating repos for %d products", len(prm))
	// This is likely to be time consuming, so give an impatient log watcher something to gauge progress by.
	entryCount := 0
	for vp := range prm {
		entryCount++
		// As a side-effect, this also omits any with no repos.
		for _, r := range prm[vp] {
			if !git.ValidRepoAndHasUsableRefs(r) {
				logger.Infof("%d/%d: %q is not a valid repo for %s:%s", entryCount, len(prm), r, vp.Vendor, vp.Product)
				continue
			}
			validated[vp] = append(validated[vp], r)
		}
	}
	logger.Infof("Before validation: %d, after: %d. Delta: %d", len(prm), len(validated), len(prm)-len(validated))

	return validated
}

func main() {
	flag.Usage = func() {
		fmt.Fprint(flag.CommandLine.Output(), "Utility to analyze NVD CPE Dictionary\n\n")
		fmt.Fprintf(flag.CommandLine.Output(), "Usage of %s:\n", os.Args[0])
		flag.PrintDefaults()
	}
	flag.Parse()

	var logCleanup = logger.InitGlobalLogger("cpe-repo-gen", *Verbose)
	defer logCleanup()
	cpes, err := LoadCPEsFromJSONDir(*CPEDictionaryDir)
	if err != nil {
		logger.Fatalf("Failed to load CPEs from %s: %v", *CPEDictionaryDir, err)
	}

	productToRepo, descriptionFrequency := analyzeCPEDictionary(cpes)
	if *Validate {
		productToRepo = validateRepos(productToRepo)
	}

	mappingFile, err := os.Create(filepath.Join(*OutputDir, "cpe_product_to_repo.json"))
	if err != nil {
		logger.Fatalf("%v", err)
	}
	defer mappingFile.Close()
	err = outputProductToRepoMap(productToRepo, mappingFile)
	if err != nil {
		logger.Fatalf("%v", err)
	}
	frequencyFile, err := os.Create(filepath.Join(*OutputDir, "cpe_reference_description_frequency.csv"))
	if err != nil {
		logger.Fatalf("%v", err)
	}
	defer frequencyFile.Close()
	err = outputDescriptionFrequency(descriptionFrequency, frequencyFile)
	if err != nil {
		logger.Fatalf("%v", err)
	}
}
