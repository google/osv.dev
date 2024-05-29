/*
cpe-repo-gen analyzes the NVD CPE Dictionary for Open Source repository information.
It reads the NVD CPE Dictionary XML file and outputs a JSON map of CPE products to discovered repository URLs.

It can also output on stdout additional data about colliding CPE package names.

Usage:

	go run cmd/cpe-repo-gen/main.go [flags]

The flags are:

	  --cpe_dictionary
		The path to the uncompressed NVD CPE Dictionary XML file, see https://nvd.nist.gov/products/cpe

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
	"encoding/xml"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
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

	"golang.org/x/exp/slices"
)

type CPEDict struct {
	XMLName  xml.Name  `xml:"cpe-list"`
	CPEItems []CPEItem `xml:"cpe-item"`
}

type CPEItem struct {
	XMLName    xml.Name    `xml:"cpe-item" json:"-"`
	Name       string      `xml:"name,attr" json:"name"`
	Deprecated bool        `xml:"deprecated,attr" json:"deprecated"`
	Title      string      `xml:"title" json:"title"`
	References []Reference `xml:"references>reference" json:"references"`
	CPE23      CPE23Item   `xml:"cpe23-item" json:"cpe23-item"`
}

type Reference struct {
	URL         string `xml:"href,attr" json:"URL"`
	Description string `xml:",chardata" json:"description"`
}

type CPE23Item struct {
	Name string `xml:"name,attr"`
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

// Helper for JSON rendering of a map with a struct key.
func (vp VendorProduct) MarshalText() (text []byte, err error) {
	return []byte(vp.Vendor + ":" + vp.Product), nil
}

// VendorProductToRepoMap maps a VendorProduct to a repo URL.
type VendorProductToRepoMap map[VendorProduct][]string

const (
	CPEDictionaryDefault = "cve_jsons/official-cpe-dictionary_v2.3.xml"
	OutputDirDefault     = "."
	projectId            = "oss-vdb"
)

var (
	Logger utility.LoggerWrapper
	// These repos should never be considered authoritative for a product.
	// Match repos with "CVE", "CVEs" or a pure CVE number in their name, anything from GitHubAssessments
	CPEDictionaryFile  = flag.String("cpe_dictionary", CPEDictionaryDefault, "CPE Dictionary file to parse")
	OutputDir          = flag.String("output_dir", OutputDirDefault, "Directory to output cpe_product_to_repo.json and cpe_reference_description_frequency.csv in")
	GCPLoggingProject  = flag.String("gcp_logging_project", projectId, "GCP project ID to use for logging, set to an empty string to log locally only")
	DebianMetadataPath = flag.String("debian_metadata_path", "", "Path to Debian copyright metadata")
	Validate           = flag.Bool("validate", true, "Attempt to validate the repository is communicable")
	Verbose            = flag.Bool("verbose", false, "Output some telemetry to stdout during execution")
)

func LoadCPEDictionary(f string) (CPEDict, error) {
	xmlFile, err := os.Open(f)
	if err != nil {
		Logger.Fatalf("Failed to open %s: %v", f, err)
	}

	defer xmlFile.Close()

	byteValue, _ := ioutil.ReadAll(xmlFile)

	var c CPEDict
	xml.Unmarshal(byteValue, &c)

	return c, nil
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

	if *Verbose {
		fmt.Printf("Outputting information about %d application products, %d do not have repos\n", len(prm), productsWithoutRepos)
	}
	Logger.Infof("Outputting information about %d application products, %d do not have repos", len(prm), productsWithoutRepos)
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

	if *Verbose {
		fmt.Printf("Seen %d reference descriptions\n", len(df))
	}
	Logger.Infof("Seen %d distinct reference descriptions", len(df))
	return nil
}

// Checks if a URL relates to the FSF.
func IsGNUURL(url string) bool {
	re := regexp.MustCompile(`^https?://.*\.(?:non)?gnu\.org/`)

	return re.MatchString(url)
}

func IsGitHubURL(url string) bool {
	return strings.HasPrefix(strings.ToLower(url), "https://github.com/")
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
		Logger.Fatalf("%v", err)
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
		metadata = path.Join(mdir, "changelogs/main", string(pkg[0:4]), pkg, "unstable_copyright")
	} else {
		metadata = path.Join(mdir, "changelogs/main", string(pkg[0]), pkg, "unstable_copyright")
	}
	if _, err := os.Stat(metadata); err == nil {
		// parse the copyright file and go from here
		Logger.Infof("FYI: Looking at %s for %s", metadata, pkg)
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
		Logger.Infof("FYI: Disregarding %s for %s", possibleRepo, pkg)
	}
	return ""
}

// Analyze CPE Dictionary and return a product-to-repo map and a reference description frequency table.
func analyzeCPEDictionary(d CPEDict) (ProductToRepo VendorProductToRepoMap, DescriptionFrequency map[string]int) {
	ProductToRepo = make(VendorProductToRepoMap)
	DescriptionFrequency = make(map[string]int)
	MaybeTryDebian := make(map[VendorProduct]bool)
	for _, c := range d.CPEItems {
		if c.Deprecated {
			Logger.Infof("Skipping deprecated %q", c.Name)
			continue
		}
		CPE, err := cves.ParseCPE(c.CPE23.Name)
		if err != nil {
			Logger.Infof("Failed to parse %q", c.CPE23.Name)
			continue
		}
		if CPE.Part != "a" {
			// Not interested in hardware or operating systems.
			continue
		}
		for _, r := range c.References {
			DescriptionFrequency[r.Description] += 1
			repo, err := cves.Repo(r.URL)
			if err != nil {
				Logger.Infof("Disregarding %q for %s:%s (%s) because %v", r.URL, CPE.Vendor, CPE.Product, r.Description, err)
				continue
			}
			if IsGitHubURL(repo) {
				repo = strings.ToLower(repo)
			}
			// If we already have an entry for this repo, don't add it again.
			if slices.Contains(ProductToRepo[VendorProduct{CPE.Vendor, CPE.Product}], repo) {
				continue
			}
			Logger.Infof("Liking %q for %s:%s (%s)", repo, CPE.Vendor, CPE.Product, r.Description)
			ProductToRepo[VendorProduct{CPE.Vendor, CPE.Product}] = append(ProductToRepo[VendorProduct{CPE.Vendor, CPE.Product}], repo)
			// If this was queued for trying to find via Debian, and subsequently found, dequeue it.
			if *DebianMetadataPath != "" {
				delete(MaybeTryDebian, VendorProduct{CPE.Vendor, CPE.Product})
			}
		}
		// If we've arrived to this point, we've exhausted the
		// references and not calculated any repos for the product,
		// flag for trying Debian afterwards.
		// We may encounter another CPE item that *does* have a viable reference in the meantime.
		if len(ProductToRepo[VendorProduct{CPE.Vendor, CPE.Product}]) == 0 && *DebianMetadataPath != "" {
			// Check the denylist though.
			if slices.Contains(DebianCopyrightDenylist, VendorProduct{CPE.Vendor, CPE.Product}) {
				continue
			}
			MaybeTryDebian[VendorProduct{CPE.Vendor, CPE.Product}] = true
		}
	}
	// Try any Debian possible ones as a last resort.
	if len(MaybeTryDebian) > 0 && *DebianMetadataPath != "" {
		Logger.Infof("Trying to derive repos from Debian for %d products", len(MaybeTryDebian))
		// This is likely to be time consuming, so give an impatient log watcher something to gauge progress by.
		entryCount := 0
		for vp := range MaybeTryDebian {
			entryCount++
			Logger.Infof("%d/%d: Trying to derive a repo from Debian for %s:%s", entryCount, len(MaybeTryDebian), vp.Vendor, vp.Product)
			repo := MaybeGetSourceRepoFromDebian(*DebianMetadataPath, vp.Product)
			if repo != "" {
				Logger.Infof("Derived repo: %s for %s:%s", repo, vp.Vendor, vp.Product)
				// Now check that what Debian gave us meets our expectations and is valid.
				repo, err := cves.Repo(repo)
				if err != nil {
					Logger.Infof("Disregarding derived repo %s for %s:%s because %v", repo, vp.Vendor, vp.Product, err)
					continue
				}
				if !git.ValidRepoAndHasUsableRefs(repo) {
					Logger.Infof("Disregarding derived repo %s for %s:%s because it is unusable for version resolution", repo, vp.Vendor, vp.Product)
					continue
				}
				ProductToRepo[VendorProduct{vp.Vendor, vp.Product}] = append(ProductToRepo[VendorProduct{vp.Vendor, vp.Product}], repo)
			}
		}
	}
	return ProductToRepo, DescriptionFrequency
}

// validateRepos takes a VendorProductToRepoMap and removes any entries where the repository fails remote validation.
func validateRepos(prm VendorProductToRepoMap) (validated VendorProductToRepoMap) {
	validated = make(VendorProductToRepoMap)
	Logger.Infof("Validating repos for %d products", len(prm))
	// This is likely to be time consuming, so give an impatient log watcher something to gauge progress by.
	entryCount := 0
	for vp := range prm {
		entryCount++
		// As a side-effect, this also omits any with no repos.
		for _, r := range prm[vp] {
			if !git.ValidRepoAndHasUsableRefs(r) {
				Logger.Infof("%d/%d: %q is not a valid repo for %s:%s", entryCount, len(prm), r, vp.Vendor, vp.Product)
				continue
			}
			validated[vp] = append(validated[vp], r)
		}
	}
	Logger.Infof("Before validation: %d, after: %d. Delta: %d", len(prm), len(validated), len(prm)-len(validated))
	return validated
}

func main() {
	flag.Usage = func() {
		fmt.Fprint(flag.CommandLine.Output(), "Utility to analyze NVD CPE Dictionary\n\n")
		fmt.Fprintf(flag.CommandLine.Output(), "Usage of %s:\n", os.Args[0])
		flag.PrintDefaults()
	}
	flag.Parse()

	var logCleanup func()
	Logger, logCleanup = utility.CreateLoggerWrapper("cpe-repo-gen")
	defer logCleanup()

	CPEDictionary, err := LoadCPEDictionary(*CPEDictionaryFile)
	if err != nil {
		Logger.Fatalf("Failed to load %s: %v", *CPEDictionaryFile, err)
	}

	productToRepo, descriptionFrequency := analyzeCPEDictionary(CPEDictionary)
	if *Validate {
		productToRepo = validateRepos(productToRepo)
	}

	mappingFile, err := os.Create(filepath.Join(*OutputDir, "cpe_product_to_repo.json"))
	if err != nil {
		Logger.Fatalf("%v", err)
	}
	defer mappingFile.Close()
	err = outputProductToRepoMap(productToRepo, mappingFile)
	if err != nil {
		Logger.Fatalf("%v", err)
	}
	frequencyFile, err := os.Create(filepath.Join(*OutputDir, "cpe_reference_description_frequency.csv"))
	if err != nil {
		Logger.Fatalf("%v", err)
	}
	defer frequencyFile.Close()
	err = outputDescriptionFrequency(descriptionFrequency, frequencyFile)
	if err != nil {
		Logger.Fatalf("%v", err)
	}
}
